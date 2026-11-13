package docker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	iid = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func TestCheckAllows(t *testing.T) {
	for _, c := range []struct {
		p string
		q url.Values
	}{
		{"/version", nil},
		{"/containers/json", nil},
		{"/images/" + iid + "/json", nil},
		{"/containers/" + cid + "/archive", url.Values{"path": {"/etc/os-release"}}},
		{"/containers/" + cid + "/archive", url.Values{"path": {"/var/lib/dpkg/status.d"}}},
	} {
		if err := Check(http.MethodGet, c.p, c.q); err != nil {
			t.Errorf("Check(GET %s %v) = %v, want allowed", c.p, c.q, err)
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	for name, c := range map[string]struct {
		m, p string
		q    url.Values
	}{
		"POST version":            {"POST", "/version", nil},
		"DELETE container":        {"DELETE", "/containers/" + cid, nil},
		"PUT archive (docker cp)": {"PUT", "/containers/" + cid + "/archive", url.Values{"path": {"/tmp"}}},
		"HEAD archive":            {"HEAD", "/containers/" + cid + "/archive", url.Values{"path": {"/etc"}}},
		"exec":                    {"GET", "/containers/" + cid + "/exec", nil},
		"create exec":             {"POST", "/containers/" + cid + "/exec", nil},
		"containers all=1":        {"GET", "/containers/json", url.Values{"all": {"1"}}},
		"container inspect (env)": {"GET", "/containers/" + cid + "/json", nil},
		"container logs":          {"GET", "/containers/" + cid + "/logs", nil},
		"image export":            {"GET", "/images/" + iid + "/get", nil},
		"images by name":          {"GET", "/images/nginx/json", nil},
		"image short id":          {"GET", "/images/sha256:abc/json", nil},
		"image with query":        {"GET", "/images/" + iid + "/json", url.Values{"x": {"1"}}},
		"version with query":      {"GET", "/version", url.Values{"a": {"b"}}},
		"traversal":               {"GET", "/containers/json/../" + cid + "/logs", nil},
		"double slash":            {"GET", "//version", nil},
		"trailing slash":          {"GET", "/version/", nil},
		"encoded":                 {"GET", "/containers/" + cid + "%2farchive", nil},
		"container by name":       {"GET", "/containers/web/archive", url.Values{"path": {"/etc/os-release"}}},
		"archive no path":         {"GET", "/containers/" + cid + "/archive", nil},
		"archive two paths":       {"GET", "/containers/" + cid + "/archive", url.Values{"path": {"/a", "/b"}}},
		"archive extra param":     {"GET", "/containers/" + cid + "/archive", url.Values{"path": {"/etc"}, "x": {"1"}}},
		"archive relative":        {"GET", "/containers/" + cid + "/archive", url.Values{"path": {"etc/passwd"}}},
		"archive traversal":       {"GET", "/containers/" + cid + "/archive", url.Values{"path": {"/etc/../proc/1/environ"}}},
		"archive NUL":             {"GET", "/containers/" + cid + "/archive", url.Values{"path": {"/etc/os-release\x00"}}},
		"swarm":                   {"GET", "/swarm", nil},
		"empty":                   {"GET", "", nil},
	} {
		if err := Check(c.m, c.p, c.q); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: Check = %v, want ErrRefused", name, err)
		}
	}
}

// fakeEngine serves the Engine API on a unix socket and records every request it receives.
type fakeEngine struct {
	mu       sync.Mutex
	requests []string
	handler  http.HandlerFunc
}

func (f *fakeEngine) start(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dk") // short: unix socket paths are limited to ~104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		f.handler(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestClientOverUnixSocket(t *testing.T) {
	f := &fakeEngine{handler: func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.41/version":
			io.WriteString(w, `{"Version":"27.3.1","ApiVersion":"1.47"}`)
		case "/v1.41/containers/json":
			io.WriteString(w, `[{"Id":"`+cid+`","Names":["/secret-name"],"Image":"nginx:1.27","ImageID":"`+iid+`","Labels":{"k":"v"}}]`)
		case "/v1.41/images/" + iid + "/json":
			io.WriteString(w, `{"Id":"`+iid+`","RepoTags":["nginx:1.27"],"RepoDigests":["nginx@sha256:aa"]}`)
		case "/v1.41/containers/" + cid + "/archive":
			if r.URL.Query().Get("path") == "/missing" {
				w.WriteHeader(404)
				io.WriteString(w, `{"message":"Could not find the file /missing in container x"}`)
				return
			}
			io.WriteString(w, "tar bytes")
		default:
			w.WriteHeader(500)
		}
	}}
	c := New(f.start(t))
	ctx := context.Background()

	v, err := c.Version(ctx)
	if err != nil || v.APIVersion != "1.47" {
		t.Fatalf("Version = %+v, %v", v, err)
	}
	list, err := c.Containers(ctx)
	if err != nil || len(list) != 1 || list[0].ImageID != iid || list[0].Image != "nginx:1.27" {
		t.Fatalf("Containers = %+v, %v", list, err)
	}
	img, err := c.Image(ctx, iid)
	if err != nil || img.RepoTags[0] != "nginx:1.27" {
		t.Fatalf("Image = %+v, %v", img, err)
	}
	rc, err := c.Archive(ctx, cid, "/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if string(data) != "tar bytes" {
		t.Errorf("archive body %q", data)
	}
	if _, err := c.Archive(ctx, cid, "/missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing path: %v, want ErrNotFound", err)
	}
	// Refused requests never reach the socket.
	if _, err := c.Archive(ctx, cid, "/etc/../proc/self/environ"); !errors.Is(err, ErrRefused) {
		t.Errorf("traversal: %v", err)
	}
	if _, err := c.Image(ctx, "nginx"); !errors.Is(err, ErrRefused) {
		t.Errorf("image by name: %v", err)
	}
	want := []string{
		"GET /v1.41/version",
		"GET /v1.41/containers/json",
		"GET /v1.41/images/" + iid + "/json",
		"GET /v1.41/containers/" + cid + "/archive?path=%2Fetc%2Fos-release",
		"GET /v1.41/containers/" + cid + "/archive?path=%2Fmissing",
	}
	if strings.Join(f.requests, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s\nwant:\n%s", strings.Join(f.requests, "\n"), strings.Join(want, "\n"))
	}
}

// The transport refuses requests that did not come through get (defence in depth).
func TestGuardRefusesOtherRequests(t *testing.T) {
	f := &fakeEngine{handler: func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "{}") }}
	c := New(f.start(t))
	for _, r := range []struct{ m, u string }{
		{"POST", "http://docker/v1.41/containers/" + cid + "/exec"},
		{"GET", "http://docker/v1.41/containers/json?all=1"},
		{"GET", "http://docker/v1.40/version"},
		{"GET", "http://other/v1.41/version"},
		{"GET", "http://docker/v1.41/containers/" + cid + "%2Fexec"},
	} {
		req, _ := http.NewRequest(r.m, r.u, nil)
		if _, err := c.http.Do(req); !errors.Is(err, ErrRefused) {
			t.Errorf("%s %s: %v, want ErrRefused", r.m, r.u, err)
		}
	}
	if len(f.requests) != 0 {
		t.Errorf("the engine received %v", f.requests)
	}
}

func TestOldEngineAndErrors(t *testing.T) {
	f := &fakeEngine{handler: func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.41/version" {
			io.WriteString(w, `{"ApiVersion":"1.40"}`)
			return
		}
		w.WriteHeader(500)
		io.WriteString(w, `{"message":"boom\nsecond line"}`)
	}}
	c := New(f.start(t))
	if _, err := c.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "older than 1.41") {
		t.Errorf("old engine: %v", err)
	}
	if _, err := c.Containers(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 500: boom second line") {
		t.Errorf("500: %v", err)
	}
	c = New(filepath.Join(t.TempDir(), "none.sock"))
	if _, err := c.Containers(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot reach Docker at") {
		t.Errorf("no socket: %v", err)
	}
}
