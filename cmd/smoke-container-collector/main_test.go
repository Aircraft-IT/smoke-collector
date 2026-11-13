package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.aircraft.tw/smoke/smoke-collector/internal/docker"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/upload"
)

const secret = "smk_secret_TOKEN_abcdefghijklmnop"

var (
	cid = strings.Repeat("c", 64)
	iid = "sha256:" + strings.Repeat("1", 64)
)

func tarFile(name, body string) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = io.WriteString(tw, body)
	_ = tw.Close()
	return b.Bytes()
}

// engine is a fake Docker Engine on a unix socket: one running Alpine container.
type engine struct {
	mu       sync.Mutex
	requests []string
}

func (e *engine) start(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "scc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"/etc/os-release":       tarFile("os-release", "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.21.2\n"),
		"/lib/apk/db/installed": tarFile("installed", "P:musl\nV:1.2.5-r8\nA:x86_64\nL:MIT\no:musl\n"),
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.requests = append(e.requests, r.Method+" "+r.URL.Path)
		e.mu.Unlock()
		switch r.URL.Path {
		case "/v1.41/version":
			io.WriteString(w, `{"Version":"27.3.1","ApiVersion":"1.47"}`)
		case "/v1.41/containers/json":
			io.WriteString(w, `[{"Id":"`+cid+`","Names":["/billing-db"],"Image":"redis:7-alpine","ImageID":"`+iid+`",`+
				`"Command":"redis-server --requirepass hunter2","Labels":{"com.acme.secret":"x"},"Ports":[{"PublicPort":6379}]}]`)
		case "/v1.41/images/" + iid + "/json":
			io.WriteString(w, `{"Id":"`+iid+`","RepoTags":["redis:7-alpine"],"RepoDigests":["redis@sha256:`+strings.Repeat("d", 64)+`"]}`)
		case "/v1.41/containers/" + cid + "/archive":
			if b, ok := files[r.URL.Query().Get("path")]; ok {
				w.Write(b)
				return
			}
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Could not find the file"}`)
		default:
			w.WriteHeader(500)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

type harness struct {
	app            *app
	stdout, stderr bytes.Buffer
	uploads        int
}

func newHarness(env map[string]string) *harness {
	h := &harness{}
	h.app = &app{
		stdout:    &h.stdout,
		stderr:    &h.stderr,
		getenv:    func(k string) string { return env[k] },
		newDocker: func(socket string) dockerAPI { return docker.New(socket) },
		newUploader: func(endpoint, token string) *upload.Client {
			h.uploads++
			return &upload.Client{Endpoint: endpoint, Token: token, Version: "0.2.0", UserAgent: "smoke-container-collector/0.2.0 (linux/amd64)",
				HTTP: upload.NewHTTPClient(), Backoff: []time.Duration{0, 0, 0},
				Sleep: func(context.Context, time.Duration) error { return nil }}
		},
	}
	return h
}

func (h *harness) noSecret(t *testing.T) {
	t.Helper()
	out := h.stdout.String() + h.stderr.String()
	for _, s := range []string{secret, "billing-db", "hunter2", "com.acme.secret", "6379"} {
		if strings.Contains(out, s) {
			t.Errorf("%q printed:\nstdout: %s\nstderr: %s", s, h.stdout.String(), h.stderr.String())
		}
	}
}

func TestDryRunPrintsTheReport(t *testing.T) {
	e := &engine{}
	sock := e.start(t)
	h := newHarness(map[string]string{"SMOKE_CONTAINER_COLLECTOR_DOCKER_HOST": "unix://" + sock})
	code := h.app.main(context.Background(), []string{"run", "--dry-run", "--config", "/nonexistent/containers.config"})
	if code != exitOK || h.uploads != 0 {
		t.Fatalf("code %d uploads %d stderr %s", code, h.uploads, h.stderr.String())
	}
	want := `{"images":[{"reference":"redis:7-alpine","imageId":"` + iid + `","repoDigest":"sha256:` + strings.Repeat("d", 64) +
		`","containers":1,"status":"ok","inventory":"#smoke-host 1\n#os-release\nID=alpine\nVERSION_ID=3.21.2\n#packages apk\nmusl-1.2.5-r8 x86_64 {musl} (MIT) [installed]\n"}]}` + "\n"
	if h.stdout.String() != want {
		t.Errorf("dry run:\n%s\nwant\n%s", h.stdout.String(), want)
	}
	h.noSecret(t)
	for _, r := range e.requests {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("non-GET request %s", r)
		}
	}
}

func TestRunUploads(t *testing.T) {
	e := &engine{}
	sock := e.start(t)
	var got struct {
		header http.Header
		body   []byte
	}
	smoke := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/collector/containers" {
			w.WriteHeader(404)
			return
		}
		got.header = r.Header.Clone()
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		got.body, _ = io.ReadAll(zr)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"images":[{"imageId":"`+iid+`","result":"created","assetId":"a-1","snapshotId":"s-1"},`+
			`{"imageId":"sha256:`+strings.Repeat("2", 64)+`","result":"something_new_`+secret+`","issue":"malformed_host_inventory"}]}`)
	}))
	defer smoke.Close()
	env := map[string]string{
		"SMOKE_CONTAINER_COLLECTOR_URL":         smoke.URL,
		"SMOKE_CONTAINER_COLLECTOR_TOKEN":       secret,
		"SMOKE_CONTAINER_COLLECTOR_DOCKER_HOST": "unix://" + sock,
	}
	h := newHarness(env)
	code := h.app.main(context.Background(), []string{"run", "--insecure-http", "--config", "/nonexistent"})
	if code != exitOK {
		t.Fatalf("code %d stderr %s", code, h.stderr.String())
	}
	for k, want := range map[string]string{
		"Authorization":             "Bearer " + secret,
		"Content-Type":              ContentType,
		"Content-Encoding":          "gzip",
		"X-Smoke-Collector-Version": "0.2.0",
		"User-Agent":                "smoke-container-collector/0.2.0 (linux/amd64)",
	} {
		if g := got.header.Get(k); g != want {
			t.Errorf("header %s = %q, want %q", k, g, want)
		}
	}
	// The upload is exactly what --dry-run prints.
	dry := newHarness(env)
	if dry.app.main(context.Background(), []string{"run", "--dry-run", "--config", "/nonexistent"}) != exitOK {
		t.Fatal(dry.stderr.String())
	}
	if !bytes.Equal(got.body, dry.stdout.Bytes()) {
		t.Errorf("uploaded body differs from --dry-run:\n%s\n%s", got.body, dry.stdout.String())
	}
	for _, s := range []string{"billing-db", "hunter2", "com.acme.secret", "Ports", "Names"} {
		if bytes.Contains(got.body, []byte(s)) {
			t.Errorf("the report contains %q", s)
		}
	}
	out := h.stdout.String()
	for _, s := range []string{"report accepted (HTTP 200, 1 images", "redis:7-alpine: created (asset a-1, snapshot s-1)",
		"sha256:222222222222: something_new_", "[malformed_host_inventory]"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	h.noSecret(t)
}

func TestRejectedAndUnreachable(t *testing.T) {
	e := &engine{}
	sock := e.start(t)
	smoke := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":{"code":"FORBIDDEN","message":"An asset token with containers:write is required"}}`)
	}))
	defer smoke.Close()
	env := map[string]string{
		"SMOKE_CONTAINER_COLLECTOR_URL":         smoke.URL,
		"SMOKE_CONTAINER_COLLECTOR_TOKEN":       secret,
		"SMOKE_CONTAINER_COLLECTOR_DOCKER_HOST": "unix://" + sock,
	}
	h := newHarness(env)
	if code := h.app.main(context.Background(), []string{"run", "--insecure-http", "--config", "/nonexistent"}); code != exitRejected {
		t.Fatalf("403: code %d", code)
	}
	if !strings.Contains(h.stderr.String(), "does not have containers:write") {
		t.Errorf("403 hint: %s", h.stderr.String())
	}
	h.noSecret(t)

	env["SMOKE_CONTAINER_COLLECTOR_DOCKER_HOST"] = "unix://" + filepath.Join(filepath.Dir(sock), "none.sock")
	h = newHarness(env)
	if code := h.app.main(context.Background(), []string{"run", "--insecure-http", "--config", "/nonexistent"}); code != exitCollect {
		t.Fatalf("no docker: code %d", code)
	}
	if !strings.Contains(h.stderr.String(), "docker group") || h.uploads != 0 {
		t.Errorf("no docker: %s (uploads %d)", h.stderr.String(), h.uploads)
	}
}

func TestConfigErrors(t *testing.T) {
	for name, c := range map[string]struct {
		env  map[string]string
		args []string
		want string
	}{
		"tcp docker host": {map[string]string{"SMOKE_CONTAINER_COLLECTOR_DOCKER_HOST": "tcp://10.0.0.1:2375"}, []string{"run", "--dry-run"}, "only unix sockets"},
		"no url":          {nil, []string{"run"}, "url is not set"},
		"http url":        {map[string]string{"SMOKE_CONTAINER_COLLECTOR_URL": "http://smoke.example.com", "SMOKE_CONTAINER_COLLECTOR_TOKEN": secret}, []string{"run"}, "https://"},
		"no token":        {map[string]string{"SMOKE_CONTAINER_COLLECTOR_URL": "https://smoke.example.com"}, []string{"run"}, "SMOKE_CONTAINER_COLLECTOR_TOKEN"},
		"unknown command": {nil, []string{"collect"}, "unknown command"},
	} {
		h := newHarness(c.env)
		args := append(c.args, "--config", "/nonexistent")
		if c.args[0] == "collect" {
			args = c.args
		}
		if code := h.app.main(context.Background(), args); code != exitConfig || !strings.Contains(h.stderr.String(), c.want) {
			t.Errorf("%s: code %d stderr %s", name, code, h.stderr.String())
		}
	}
}

func TestConfigFileAndPrintConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "containers.config")
	if err := os.WriteFile(p, []byte("url=https://smoke.example.com\ntoken="+secret+"\ndocker_host=unix:///run/docker.sock\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	h := newHarness(nil)
	if code := h.app.main(context.Background(), []string{"print-config", "--config", p}); code != exitOK {
		t.Fatalf("code %d %s", code, h.stderr.String())
	}
	for _, s := range []string{"endpoint:      https://smoke.example.com/api/v1/collector/containers",
		"token:         smk_secr…", "docker_host:   unix:///run/docker.sock (config file)", "status:        ok"} {
		if !strings.Contains(h.stdout.String(), s) {
			t.Errorf("print-config lacks %q:\n%s", s, h.stdout.String())
		}
	}
	h.noSecret(t)

	h = newHarness(nil)
	if code := h.app.main(context.Background(), []string{"print-config", "--config", "/nonexistent"}); code != exitConfig ||
		!strings.Contains(h.stdout.String(), "docker_host:   unix:///var/run/docker.sock (default)") {
		t.Errorf("default docker_host: %s", h.stdout.String())
	}

	// smoke-collector's file keys are not enough: docker_host is known here, other keys are not.
	if err := os.WriteFile(p, []byte("url=https://smoke.example.com\nproxy=x\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	h = newHarness(nil)
	if code := h.app.main(context.Background(), []string{"print-config", "--config", p}); code != exitConfig ||
		!strings.Contains(h.stderr.String(), "known: url, token, token_file, docker_host") {
		t.Errorf("unknown key: %s", h.stderr.String())
	}
}
