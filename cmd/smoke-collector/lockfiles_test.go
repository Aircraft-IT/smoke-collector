package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type request struct {
	path   string
	header http.Header
	body   string
}

// fakeSmoke records every request and answers per path.
type fakeSmoke struct {
	mu      sync.Mutex
	reqs    []request
	replies map[string]struct {
		status int
		body   string
	}
	url string
}

func newFakeSmoke(t *testing.T) *fakeSmoke {
	t.Helper()
	f := &fakeSmoke{replies: map[string]struct {
		status int
		body   string
	}{}}
	f.reply("/api/v1/collector/report", 201, `{"status":"created","assetId":"a1","snapshotId":"s1"}`)
	f.reply("/api/v1/collector/lockfiles", 200, `{"lockfiles":[{"path":"/srv/app","status":"ok","result":"created","assetId":"a2","snapshotId":"s2","issue":null,"files":[]},`+
		`{"path":"/srv/missing","status":"not_found","result":"skipped","assetId":null,"snapshotId":null,"issue":null,"files":[]}]}`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		if r.Header.Get("Content-Encoding") == "gzip" {
			if zr, err := gzip.NewReader(r.Body); err == nil {
				b, _ := io.ReadAll(zr)
				body = string(b)
			}
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, request{path: r.URL.Path, header: r.Header.Clone(), body: body})
		rep, ok := f.replies[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			rep.status = 404
		}
		w.WriteHeader(rep.status)
		_, _ = io.WriteString(w, rep.body)
	}))
	t.Cleanup(ts.Close)
	f.url = ts.URL
	return f
}

func (f *fakeSmoke) reply(path string, status int, body string) {
	f.replies[path] = struct {
		status int
		body   string
	}{status, body}
}

func (f *fakeSmoke) paths() string {
	var out []string
	for _, r := range f.reqs {
		out = append(out, r.path)
	}
	return strings.Join(out, " ")
}

// lockfileTree makes /srv/app-like and missing paths under a temp dir.
func lockfileTree(t *testing.T) (app, missing string) {
	t.Helper()
	root := t.TempDir()
	app = filepath.Join(root, "app")
	for name, body := range map[string]string{
		"package-lock.json": "{\"lockfileVersion\": 3}\n",
		"go.mod":            "module example.com/x\n\ngo 1.22", // no final newline
		".env":              "SECRET=do-not-read\n",
		"server.js":         "require('x')\n",
	} {
		if err := os.MkdirAll(app, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(app, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return app, filepath.Join(root, "missing")
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func hexSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestRunLockfilesOnly(t *testing.T) {
	smoke := newFakeSmoke(t)
	app, missing := lockfileTree(t)
	cfg := writeConfig(t, "url="+smoke.url+"\ntoken="+secret+"\nscan=lockfiles\nlockfile="+app+"\nlockfile="+missing+"\n")
	// dpkg-query fails: the OS inventory must not even be collected.
	h := newHarness(t, nil, io.ErrUnexpectedEOF)
	if code := h.app.main(context.Background(), []string{"run", "--insecure-http", "--config", cfg}); code != exitOK {
		t.Fatalf("code = %d: %s", code, h.stderr.String())
	}
	if smoke.paths() != "/api/v1/collector/lockfiles" {
		t.Fatalf("requests: %s", smoke.paths())
	}
	r := smoke.reqs[0]
	for k, want := range map[string]string{
		"Authorization":             "Bearer " + secret,
		"Content-Type":              "application/vnd.smoke.lockfile-report+json",
		"Content-Encoding":          "gzip",
		"X-Smoke-Collector-Scans":   "lockfiles",
		"X-Smoke-Collector-Version": "0.1.0",
	} {
		if got := r.header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	var body struct {
		Lockfiles []struct {
			Path   string `json:"path"`
			Status string `json:"status"`
			Files  []struct {
				Name    string `json:"name"`
				Content string `json:"content"`
			} `json:"files"`
		} `json:"lockfiles"`
	}
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		t.Fatalf("body %q: %v", r.body, err)
	}
	if len(body.Lockfiles) != 2 || body.Lockfiles[0].Path != app || body.Lockfiles[0].Status != "ok" ||
		len(body.Lockfiles[0].Files) != 2 || body.Lockfiles[1].Path != missing || body.Lockfiles[1].Status != "not_found" ||
		body.Lockfiles[1].Files != nil {
		t.Fatalf("body = %s", r.body)
	}
	if f := body.Lockfiles[0].Files; f[0].Name != "go.mod" || f[0].Content != "module example.com/x\n\ngo 1.22" || f[1].Name != "package-lock.json" {
		t.Errorf("files = %+v", f)
	}
	if strings.Contains(r.body, "do-not-read") || strings.Contains(r.body, "require(") {
		t.Errorf("a file other than a lockfile was sent: %s", r.body)
	}
	out := h.stdout.String()
	for _, want := range []string{"lockfile report accepted (HTTP 200, 2 paths", "/srv/app: created (asset a2, snapshot s2)", "/srv/missing: skipped (not_found)"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(h.stderr.String(), missing+": not_found") {
		t.Errorf("no warning for the missing path: %s", h.stderr.String())
	}
	h.noSecret(t)
}

func TestRunOSAndLockfiles(t *testing.T) {
	smoke := newFakeSmoke(t)
	app, _ := lockfileTree(t)
	cfg := writeConfig(t, "url="+smoke.url+"\ntoken="+secret+"\nscan=os,lockfiles\nlockfile="+app+"\n")
	h := newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"run", "--insecure-http", "--config", cfg}); code != exitOK {
		t.Fatalf("code = %d: %s", code, h.stderr.String())
	}
	if smoke.paths() != "/api/v1/collector/report /api/v1/collector/lockfiles" {
		t.Fatalf("requests: %s", smoke.paths())
	}
	for _, r := range smoke.reqs {
		if got := r.header.Get("X-Smoke-Collector-Scans"); got != "os,lockfiles" {
			t.Errorf("%s: X-Smoke-Collector-Scans = %q", r.path, got)
		}
	}
	if ct := smoke.reqs[0].header.Get("Content-Type"); ct != "text/plain; charset=utf-8" || !strings.HasPrefix(smoke.reqs[0].body, "#smoke-host 1\n") {
		t.Errorf("OS report: %s %q", ct, smoke.reqs[0].body)
	}
	if out := h.stdout.String(); !strings.Contains(out, "report created") || !strings.Contains(out, "lockfile report accepted") {
		t.Errorf("stdout = %s", out)
	}
}

func TestOSOnlySendsScansHeader(t *testing.T) {
	smoke := newFakeSmoke(t)
	cfg := writeConfig(t, "url="+smoke.url+"\ntoken="+secret+"\n")
	h := newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"run", "--insecure-http", "--config", cfg}); code != exitOK {
		t.Fatalf("code = %d: %s", code, h.stderr.String())
	}
	if smoke.paths() != "/api/v1/collector/report" || smoke.reqs[0].header.Get("X-Smoke-Collector-Scans") != "os" {
		t.Errorf("requests: %s, scans %q", smoke.paths(), smoke.reqs[0].header.Get("X-Smoke-Collector-Scans"))
	}
}

func TestExitCodesWithBothParts(t *testing.T) {
	for _, tc := range []struct {
		name            string
		report, lock    int
		dpkgErr         error
		code            int
		requests, inOut string
	}{
		{"OS rejected, lockfiles ok", 401, 200, nil, exitRejected,
			"/api/v1/collector/report /api/v1/collector/lockfiles", "report: upload rejected: HTTP 401"},
		{"OS ok, old Smoke without the lockfile endpoint", 201, 404, nil, exitRejected,
			"/api/v1/collector/report /api/v1/collector/lockfiles", "does not accept lockfile reports"},
		{"collection failed, lockfiles still sent", 201, 200, io.ErrUnexpectedEOF, exitCollect,
			"/api/v1/collector/lockfiles", "dpkg-query failed"},
		{"first failure wins", 503, 401, nil, exitNetwork,
			"/api/v1/collector/report /api/v1/collector/report /api/v1/collector/report /api/v1/collector/report /api/v1/collector/lockfiles",
			"lockfile report: upload rejected: HTTP 401"},
		{"lockfiles server error", 201, 503, nil, exitNetwork,
			"/api/v1/collector/report /api/v1/collector/lockfiles /api/v1/collector/lockfiles /api/v1/collector/lockfiles /api/v1/collector/lockfiles",
			"lockfile report: server error: HTTP 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smoke := newFakeSmoke(t)
			smoke.reply("/api/v1/collector/report", tc.report, `{"error":{"code":"X"}}`)
			if tc.report < 300 {
				smoke.reply("/api/v1/collector/report", tc.report, `{"status":"created"}`)
			}
			if tc.lock != 200 {
				smoke.reply("/api/v1/collector/lockfiles", tc.lock, `{"error":{"code":"Y"}}`)
			}
			if tc.lock == 404 {
				delete(smoke.replies, "/api/v1/collector/lockfiles")
			}
			app, _ := lockfileTree(t)
			cfg := writeConfig(t, "url="+smoke.url+"\ntoken="+secret+"\nscan=os,lockfiles\nlockfile="+app+"\n")
			h := newHarness(t, nil, tc.dpkgErr)
			if code := h.app.main(context.Background(), []string{"run", "--insecure-http", "--config", cfg}); code != tc.code {
				t.Errorf("code = %d, want %d: %s", code, tc.code, h.stderr.String())
			}
			if smoke.paths() != tc.requests {
				t.Errorf("requests = %s", smoke.paths())
			}
			if all := h.stdout.String() + h.stderr.String(); !strings.Contains(all, tc.inOut) {
				t.Errorf("output lacks %q:\n%s", tc.inOut, all)
			}
			h.noSecret(t)
		})
	}
}

func TestLockfilesConfigError(t *testing.T) {
	smoke := newFakeSmoke(t)
	cfg := writeConfig(t, "url="+smoke.url+"\ntoken="+secret+"\nscan=lockfiles\n")
	for _, args := range [][]string{{"run", "--insecure-http", "--config", cfg}, {"run", "--dry-run", "--config", cfg}} {
		h := newHarness(t, nil, nil)
		if code := h.app.main(context.Background(), args); code != exitConfig || !strings.Contains(h.stderr.String(), "no lockfile=/path line") {
			t.Errorf("%v: code = %d: %s", args, code, h.stderr.String())
		}
	}
	if len(smoke.reqs) != 0 {
		t.Errorf("requests: %s", smoke.paths())
	}
}

func TestDryRunLockfiles(t *testing.T) {
	app, missing := lockfileTree(t)
	cfg := writeConfig(t, "scan=os,lockfiles\nlockfile="+app+"\nlockfile="+missing+"\nlockfile="+filepath.Join(app, "go.mod")+"\n")
	h := newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"run", "--dry-run", "--config", cfg}); code != exitOK || h.uploads != 0 {
		t.Fatalf("code = %d uploads = %d: %s", code, h.uploads, h.stderr.String())
	}
	out := h.stdout.String()
	gomod := "module example.com/x\n\ngo 1.22"
	lock := "{\"lockfileVersion\": 3}\n"
	for _, want := range []string{
		"#smoke-host 1\n",
		"#reboot-required\nno\n#lockfiles: 3 paths, sent as JSON (",
		app + ": ok, 2 files, digest ",
		"  go.mod  29 bytes  sha256 " + hexSHA(gomod) + "\n",
		"  package-lock.json  23 bytes  sha256 " + hexSHA(lock) + "\n",
		missing + ": not_found (",
		filepath.Join(app, "go.mod") + ": ok, 1 file,",
		"\n#lockfile " + filepath.Join(app, "go.mod") + " (29 bytes, sha256 " + hexSHA(gomod) + ")\n" + gomod + "\n#(no newline at end of file)\n#end " + filepath.Join(app, "go.mod") + "\n",
		"\n#lockfile " + filepath.Join(app, "package-lock.json") + " (23 bytes, sha256 " + hexSHA(lock) + ")\n" + lock + "#end ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "do-not-read") {
		t.Errorf(".env was read")
	}

	// lockfiles only: no OS collection at all (dpkg-query would fail).
	cfg = writeConfig(t, "scan=lockfiles\nlockfile="+app+"\n")
	h = newHarness(t, nil, io.ErrUnexpectedEOF)
	if code := h.app.main(context.Background(), []string{"run", "--dry-run", "--config", cfg}); code != exitOK {
		t.Fatalf("lockfiles only: code = %d: %s", code, h.stderr.String())
	}
	if out := h.stdout.String(); strings.Contains(out, "#smoke-host") || !strings.HasPrefix(out, "#lockfiles: 1 path,") {
		t.Errorf("lockfiles only:\n%s", out)
	}
}

func TestDryRunUnreadableConfigShowsOSReport(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	cfg := writeConfig(t, "scan=lockfiles\nlockfile=/srv/x\n")
	if err := os.Chmod(cfg, 0); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"run", "--dry-run", "--config", cfg}); code != exitOK {
		t.Fatalf("code = %d: %s", code, h.stderr.String())
	}
	if !strings.HasPrefix(h.stdout.String(), "#smoke-host 1\n") || !strings.Contains(h.stderr.String(), "showing the OS report only") {
		t.Errorf("stdout=%q stderr=%q", h.stdout.String(), h.stderr.String())
	}
}

func TestPrintConfigScans(t *testing.T) {
	cfg := writeConfig(t, "url=https://smoke.example.com\ntoken="+secret+"\nscan=lockfiles,os\nlockfile=/srv/billing/current/\nlockfile=/home/app/shop\n")
	h := newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"print-config", "--config", cfg}); code != exitOK {
		t.Fatalf("code = %d: %s", code, h.stdout.String())
	}
	out := h.stdout.String()
	for _, want := range []string{
		"endpoint:      https://smoke.example.com/api/v1/collector/report\n",
		"endpoint:      https://smoke.example.com/api/v1/collector/lockfiles\n",
		"scan:          os,lockfiles (config file)\n",
		"lockfile:      /srv/billing/current\nlockfile:      /home/app/shop\n",
		"status:        ok",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("print-config lacks %q:\n%s", want, out)
		}
	}

	cfg = writeConfig(t, "url=https://smoke.example.com\ntoken="+secret+"\nlockfile=/srv/a\n")
	h = newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"print-config", "--config", cfg}); code != exitOK {
		t.Fatalf("code = %d: %s", code, h.stdout.String())
	}
	out = h.stdout.String()
	for _, want := range []string{"scan:          os (default)\n", "lockfile:      /srv/a\n", "ignored: scan does not include lockfiles"} {
		if !strings.Contains(out, want) {
			t.Errorf("print-config lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/collector/lockfiles") {
		t.Errorf("lockfile endpoint shown without lockfiles in scan:\n%s", out)
	}

	cfg = writeConfig(t, "url=https://smoke.example.com\ntoken="+secret+"\nscan=lockfiles\n")
	h = newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"print-config", "--config", cfg}); code != exitConfig ||
		!strings.Contains(h.stdout.String(), "lockfile:      -\n") || !strings.Contains(h.stdout.String(), "status:        invalid: scan includes lockfiles") {
		t.Errorf("code = %d:\n%s", code, h.stdout.String())
	}
}
