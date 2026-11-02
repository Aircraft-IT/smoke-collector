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
