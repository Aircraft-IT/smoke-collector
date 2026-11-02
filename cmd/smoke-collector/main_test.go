package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.aircraft.tw/smoke/smoke-collector/internal/collect"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/upload"
)

const secret = "smk_secret_TOKEN_abcdefghijklmnop"

// fakeCollector returns a collector over a fake Debian root.
func fakeCollector(t *testing.T, dpkgErr error) *collect.Collector {
	t.Helper()
	root := t.TempDir()
	for p, body := range map[string]string{
		"etc/os-release":     "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n",
		"usr/bin/dpkg-query": "#!/bin/false\n",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &collect.Collector{
		Root: root,
		Dirs: collect.SearchDirs,
		Exec: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("ii \tbase-files\t12.4+deb12u7\tamd64\t\t\n"), dpkgErr
		},
		KernelRelease: func() (string, error) { return "6.1.0-25-amd64", nil },
	}
}

type harness struct {
	app            *app
	stdout, stderr bytes.Buffer
	uploads        int
}

func newHarness(t *testing.T, env map[string]string, dpkgErr error) *harness {
	h := &harness{}
	h.app = &app{
		stdout:    &h.stdout,
		stderr:    &h.stderr,
		getenv:    func(k string) string { return env[k] },
		collector: fakeCollector(t, dpkgErr),
		newUploader: func(endpoint, token string) *upload.Client {
			h.uploads++
			return &upload.Client{Endpoint: endpoint, Token: token, Version: "0.1.0", UserAgent: "test",
				HTTP: upload.NewHTTPClient(), Backoff: []time.Duration{0, 0, 0},
				Sleep: func(context.Context, time.Duration) error { return nil }}
		},
	}
	return h
}

func (h *harness) noSecret(t *testing.T) {
	t.Helper()
	if strings.Contains(h.stdout.String()+h.stderr.String(), secret) {
		t.Errorf("token printed:\nstdout: %s\nstderr: %s", h.stdout.String(), h.stderr.String())
	}
}

func TestDryRunNeedsNoConfigAndNoNetwork(t *testing.T) {
	h := newHarness(t, nil, nil)
	code := h.app.main(context.Background(), []string{"run", "--dry-run", "--config", "/nonexistent/config"})
	if code != exitOK || h.uploads != 0 {
		t.Fatalf("code=%d uploads=%d stderr=%s", code, h.uploads, h.stderr.String())
	}
	want := "#smoke-host 1\n#os-release\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n#kernel\n6.1.0-25-amd64\n" +
		"#packages dpkg\nii \tbase-files\t12.4+deb12u7\tamd64\t\t\n#services\n#reboot-required\nno\n"
	if h.stdout.String() != want {
		t.Errorf("stdout = %q", h.stdout.String())
	}
}

func TestExitCodes(t *testing.T) {
	srv := func(status int, body string) string {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+secret {
				t.Errorf("Authorization header missing")
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(ts.Close)
		return ts.URL
	}
	created := srv(201, `{"status":"created","assetId":"a1","snapshotId":"s1"}`)
	unchanged := srv(200, `{"status":"unchanged","assetId":"a1","snapshotId":"s0"}`)
	unauth := srv(401, `{"error":{"code":"UNAUTHENTICATED","message":"bad token `+secret+`"}}`)
	broken := srv(503, ``)

	for _, tc := range []struct {
		name    string
		env     map[string]string
		args    []string
		dpkgErr error
		code    int
		out     string
	}{
		{"created", map[string]string{"SMOKE_COLLECTOR_URL": created, "SMOKE_COLLECTOR_TOKEN": secret},
			[]string{"run", "--insecure-http", "--config", "/nonexistent"}, nil, exitOK, "report created"},
		{"unchanged", map[string]string{"SMOKE_COLLECTOR_URL": unchanged, "SMOKE_COLLECTOR_TOKEN": secret},
			[]string{"run", "--insecure-http", "--config", "/nonexistent"}, nil, exitOK, "report unchanged"},
		{"http without flag", map[string]string{"SMOKE_COLLECTOR_URL": created, "SMOKE_COLLECTOR_TOKEN": secret},
			[]string{"run", "--config", "/nonexistent"}, nil, exitConfig, "https://"},
		{"no config", nil, []string{"run", "--config", "/nonexistent"}, nil, exitConfig, "url is not set"},
		{"collect fails", map[string]string{"SMOKE_COLLECTOR_URL": created, "SMOKE_COLLECTOR_TOKEN": secret},
			[]string{"run", "--insecure-http", "--config", "/nonexistent"}, io.ErrUnexpectedEOF, exitCollect, "dpkg-query failed"},
		{"rejected", map[string]string{"SMOKE_COLLECTOR_URL": unauth, "SMOKE_COLLECTOR_TOKEN": secret},
			[]string{"run", "--insecure-http", "--config", "/nonexistent"}, nil, exitRejected, "HTTP 401 UNAUTHENTICATED"},
		{"server error", map[string]string{"SMOKE_COLLECTOR_URL": broken, "SMOKE_COLLECTOR_TOKEN": secret},
			[]string{"run", "--insecure-http", "--config", "/nonexistent"}, nil, exitNetwork, "HTTP 503"},
		{"unknown command", nil, []string{"collect"}, nil, exitConfig, "unknown command"},
		{"stray argument", nil, []string{"run", "extra"}, nil, exitConfig, "no arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.env, tc.dpkgErr)
			if code := h.app.main(context.Background(), tc.args); code != tc.code {
				t.Errorf("code = %d, want %d (stderr: %s)", code, tc.code, h.stderr.String())
			}
			if all := h.stdout.String() + h.stderr.String(); !strings.Contains(all, tc.out) {
				t.Errorf("output %q does not contain %q", all, tc.out)
			}
			h.noSecret(t)
		})
	}
}

func TestPrintConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	if err := os.WriteFile(p, []byte("url=https://smoke.example.com\ntoken="+secret+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"print-config", "--config", p}); code != exitOK {
		t.Fatalf("code = %d: %s", code, h.stdout.String())
	}
	out := h.stdout.String()
	for _, want := range []string{"smk_secr…", "https://smoke.example.com/api/v1/collector/report", "status:        ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("print-config missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, secret[:9]) {
		t.Errorf("more than 8 characters of the token shown:\n%s", out)
	}
	h.noSecret(t)

	h = newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"print-config", "--config", filepath.Join(dir, "none")}); code != exitConfig {
		t.Errorf("incomplete config: code = %d", code)
	}
}

func TestVersion(t *testing.T) {
	h := newHarness(t, nil, nil)
	if code := h.app.main(context.Background(), []string{"version"}); code != exitOK ||
		!strings.HasPrefix(h.stdout.String(), "smoke-collector ") {
		t.Errorf("code=%d out=%q", code, h.stdout.String())
	}
}
