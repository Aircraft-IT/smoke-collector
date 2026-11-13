package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "smk_live_0123456789abcdefSECRET"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func write(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrecedence(t *testing.T) {
	dir := t.TempDir()
	tokFile := write(t, dir, "token", "  smk_from_token_file_xyz \n", 0o600)
	fileTok := write(t, dir, "a.conf", "# comment\n\nurl = https://file.example.com/\ntoken=\"smk_from_file_123\"\n", 0o640)
	fileTokFile := write(t, dir, "b.conf", "url=https://file.example.com\ntoken_file="+tokFile+"\n", 0o640)

	for _, tc := range []struct {
		name            string
		path            string
		env             map[string]string
		url, token      string
		urlSrc, tokSrc  Source
		found           bool
		wantTokenFile   string
		wantValidateErr bool
	}{
		{name: "file only", path: fileTok, url: "https://file.example.com/", token: "smk_from_file_123",
			urlSrc: SourceFile, tokSrc: SourceFile, found: true},
		{name: "token_file", path: fileTokFile, url: "https://file.example.com", token: "smk_from_token_file_xyz",
			urlSrc: SourceFile, tokSrc: SourceTokenFile, found: true, wantTokenFile: tokFile},
		{name: "env overrides file", path: fileTok,
			env: map[string]string{EnvURL: "https://env.example.com", EnvToken: "smk_from_env_456"},
			url: "https://env.example.com", token: "smk_from_env_456", urlSrc: SourceEnv, tokSrc: SourceEnv, found: true},
		{name: "env token overrides token_file", path: fileTokFile,
			env: map[string]string{EnvToken: "smk_from_env_456"},
			url: "https://file.example.com", token: "smk_from_env_456", urlSrc: SourceFile, tokSrc: SourceEnv, found: true},
		{name: "empty env is unset", path: fileTok, env: map[string]string{EnvURL: "  ", EnvToken: ""},
			url: "https://file.example.com/", token: "smk_from_file_123", urlSrc: SourceFile, tokSrc: SourceFile, found: true},
		{name: "no file, env only", path: filepath.Join(dir, "missing"),
			env: map[string]string{EnvURL: "https://env.example.com", EnvToken: "smk_from_env_456"},
			url: "https://env.example.com", token: "smk_from_env_456", urlSrc: SourceEnv, tokSrc: SourceEnv},
		{name: "no file, no env", path: filepath.Join(dir, "missing"), wantValidateErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(tc.path, env(tc.env))
			if err != nil {
				t.Fatal(err)
			}
			if c.URL != tc.url || c.Token != tc.token || c.URLSource != tc.urlSrc || c.TokenSource != tc.tokSrc ||
				c.FileFound != tc.found || c.TokenFile != tc.wantTokenFile {
				t.Errorf("got url=%q(%s) token=%q(%s) found=%v tokenFile=%q", c.URL, c.URLSource, c.Token,
					c.TokenSource, c.FileFound, c.TokenFile)
			}
			if err := c.Validate(); (err != nil) != tc.wantValidateErr {
				t.Errorf("Validate() = %v", err)
			}
		})
	}
}

func TestFileErrorsNeverContainLines(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bare token":  "url=https://x.example.com\n" + secret + "\n",
		"bad key":     secret + "=1\n",
		"unknown key": "url=https://x.example.com\ntokn=" + secret + "\n",
		"duplicate":   "token=" + secret + "\ntoken=" + secret + "\n",
		"both":        "token=" + secret + "\ntoken_file=/nonexistent\n",
	} {
		p := write(t, dir, "c", body, 0o640)
		_, err := Load(p, env(nil))
		var ce *Error
		if !errors.As(err, &ce) {
			t.Errorf("%s: err = %v, want *Error", name, err)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "smk_") {
			t.Errorf("%s: error contains the token: %v", name, err)
		}
	}
}

func TestTokenFileErrors(t *testing.T) {
	dir := t.TempDir()
	multi := write(t, dir, "tok", secret+"\n"+secret+"\n", 0o600)
	p := write(t, dir, "c", "token_file="+multi+"\n", 0o640)
	if _, err := Load(p, env(nil)); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("multi-line token_file: %v", err)
	}
	p = write(t, dir, "c", "token_file="+filepath.Join(dir, "nope")+"\n", 0o640)
	if _, err := Load(p, env(nil)); err == nil {
		t.Error("missing token_file accepted")
	}
}

func TestUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	p := write(t, t.TempDir(), "c", "token="+secret+"\n", 0o000)
	if _, err := Load(p, env(nil)); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("unreadable file: %v", err)
	}
}

func TestWorldReadableWarning(t *testing.T) {
	p := write(t, t.TempDir(), "c", "url=https://x.example.com\ntoken="+secret+"\n", 0o644)
	c, err := Load(p, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings) != 1 || strings.Contains(c.Warnings[0], secret) {
		t.Errorf("warnings = %q", c.Warnings)
	}
}

func TestEndpoint(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		insecure bool
		want     string
	}{
		{"https://smoke.example.com", false, "https://smoke.example.com/api/v1/collector/report"},
		{"HTTPS://smoke.example.com/", false, "https://smoke.example.com/api/v1/collector/report"},
		{"https://smoke.example.com:8443/smoke//", false, "https://smoke.example.com:8443/smoke/api/v1/collector/report"},
		{"http://localhost:8080", true, "http://localhost:8080/api/v1/collector/report"},
		{"http://127.0.0.1:8080", true, "http://127.0.0.1:8080/api/v1/collector/report"},
		{"http://[::1]:8080", true, "http://[::1]:8080/api/v1/collector/report"},
		{"https://localhost", true, "https://localhost/api/v1/collector/report"},
		{"http://localhost:8080", false, ""},
		{"http://smoke.example.com", true, ""},
		{"http://localhost.example.com", true, ""},
		{"ftp://smoke.example.com", false, ""},
		{"smoke.example.com", false, ""},
		{"https://user:pw@smoke.example.com", false, ""},
		{"https://smoke.example.com/?a=1", false, ""},
		{"https://smoke.example.com/#x", false, ""},
		{"https://", false, ""},
	} {
		got, err := Endpoint(tc.raw, tc.insecure)
		if (tc.want == "") != (err != nil) || got != tc.want {
			t.Errorf("Endpoint(%q, %v) = %q, %v; want %q", tc.raw, tc.insecure, got, err, tc.want)
		}
	}
}

func TestCheckToken(t *testing.T) {
	if err := CheckToken(secret); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"smk_a b", "smk_\tx", "smk_é", "smk_\x00", strings.Repeat("a", 513)} {
		err := CheckToken(bad)
		if err == nil || strings.Contains(err.Error(), bad) {
			t.Errorf("CheckToken(%q) = %v", bad, err)
		}
	}
}

func TestTokenPreview(t *testing.T) {
	if got := TokenPreview(secret); got != "smk_live…" {
		t.Errorf("TokenPreview = %q", got)
	}
	if got := TokenPreview("short"); strings.Contains(got, "short") {
		t.Errorf("short token shown: %q", got)
	}
	if got := TokenPreview(""); got != "(not set)" {
		t.Errorf("empty = %q", got)
	}
}

func TestScanAndLockfiles(t *testing.T) {
	dir := t.TempDir()
	base := "url=https://smoke.example.com\ntoken=" + secret + "\n"
	for _, tc := range []struct {
		name      string
		body      string
		scans     string
		src       Source
		lockfiles []string
		loadErr   string
		validErr  string
		ignored   bool
	}{
		{name: "default os", body: base, scans: "os"},
		{name: "os and lockfiles", body: base + "scan = lockfiles, os\nlockfile=/srv/billing/current/\n# c\nlockfile = \"/home/app/my shop\"\n",
			scans: "os,lockfiles", src: SourceFile, lockfiles: []string{"/srv/billing/current", "/home/app/my shop"}},
		{name: "lockfiles only", body: base + "scan=lockfiles,lockfiles\nlockfile=/srv/a/yarn.lock\n",
			scans: "lockfiles", src: SourceFile, lockfiles: []string{"/srv/a/yarn.lock"}},
		{name: "lockfiles without paths", body: base + "scan=lockfiles\n", scans: "lockfiles", src: SourceFile,
			validErr: "no lockfile=/path line"},
		{name: "paths without lockfiles", body: base + "lockfile=/srv/a\n", scans: "os", lockfiles: []string{"/srv/a"}, ignored: true},
		{name: "docker", body: base + "scan=os,docker\n", loadErr: "smoke-container-collector"},
		{name: "unknown", body: base + "scan=os,packages\n", loadErr: "unknown item (known: os, lockfiles)"},
		{name: "singular", body: base + "scan=lockfile\n", loadErr: "did you mean lockfiles"},
		{name: "empty scan", body: base + "scan=\n", loadErr: "comma-separated"},
		{name: "empty item", body: base + "scan=os,\n", loadErr: "comma-separated"},
		{name: "scan twice", body: base + "scan=os\nscan=lockfiles\n", loadErr: "line 4: scan is set twice"},
		{name: "relative", body: base + "lockfile=srv/a\n", loadErr: "line 3: lockfile must be an absolute path"},
		{name: "unclean", body: base + "lockfile=/srv/../etc\n", loadErr: "line 3: lockfile must be a clean path"},
		{name: "empty path", body: base + "lockfile=\n", loadErr: "absolute"},
		{name: "duplicate", body: base + "lockfile=/srv/a\nlockfile=/srv/a/\n", loadErr: "line 4: lockfile /srv/a is already on line 3"},
		{name: "too many", body: base + manyLockfiles(21), loadErr: "line 23: at most 20 lockfile lines"},
		{name: "twenty", body: base + "scan=lockfiles\n" + manyLockfiles(20), scans: "lockfiles", src: SourceFile, lockfiles: lockfilePaths(20)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := write(t, dir, "c", tc.body, 0o640)
			c, err := Load(p, env(nil))
			if tc.loadErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.loadErr) {
					t.Fatalf("Load() = %v, want %q", err, tc.loadErr)
				}
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error contains the token")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.ScanHeader() != tc.scans || c.ScanSource != tc.src || strings.Join(c.Lockfiles, "|") != strings.Join(tc.lockfiles, "|") {
				t.Errorf("scans=%q (%s) lockfiles=%q", c.ScanHeader(), c.ScanSource, c.Lockfiles)
			}
			err = c.Validate()
			if (err != nil) != (tc.validErr != "") || (err != nil && !strings.Contains(err.Error(), tc.validErr)) {
				t.Errorf("Validate() = %v, want %q", err, tc.validErr)
			}
			if err := c.ValidateScans(); (err != nil) != (tc.validErr != "") {
				t.Errorf("ValidateScans() = %v", err)
			}
			if (c.IgnoredLockfiles() != "") != tc.ignored {
				t.Errorf("IgnoredLockfiles() = %q", c.IgnoredLockfiles())
			}
		})
	}
}

func manyLockfiles(n int) string {
	var b strings.Builder
	for _, p := range lockfilePaths(n) {
		b.WriteString("lockfile=" + p + "\n")
	}
	return b.String()
}

func lockfilePaths(n int) []string {
	var out []string
	for i := range n {
		out = append(out, "/srv/app"+strings.Repeat("x", i))
	}
	return out
}

func TestScanKeysOnlyForTheOSCollector(t *testing.T) {
	dir := t.TempDir()
	for _, key := range []string{"scan=os", "lockfile=/srv/a"} {
		p := write(t, dir, "containers.config", "url=https://smoke.example.com\n"+key+"\n", 0o640)
		if _, err := LoadSpec(ContainerCollector, p, env(nil)); err == nil || !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s in containers.config: %v", key, err)
		}
	}
	c, err := LoadSpec(ContainerCollector, filepath.Join(dir, "missing"), env(nil))
	if err != nil || c.Scans != nil || c.ValidateScans() != nil {
		t.Errorf("container collector: scans=%v err=%v", c.Scans, err)
	}
}

func TestPermissionErrorIsDetectable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	p := write(t, t.TempDir(), "config", "url=https://x\n", 0)
	_, err := Load(p, env(nil))
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("Load() = %v, want a permission error", err)
	}
}
