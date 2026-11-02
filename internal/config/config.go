// Package config loads the collector configuration (OS detection plan §5.1):
// the key=value file /etc/smoke-collector/config, overridden by the
// SMOKE_COLLECTOR_URL and SMOKE_COLLECTOR_TOKEN environment variables.
//
// The token is a secret. No error message or warning produced here contains
// it, or any line of the configuration file (a token may sit on a malformed line).
package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const (
	// DefaultPath is the configuration file installed by install.sh.
	DefaultPath = "/etc/smoke-collector/config"
	// EnvURL and EnvToken override the file.
	EnvURL   = "SMOKE_COLLECTOR_URL"
	EnvToken = "SMOKE_COLLECTOR_TOKEN"
	// ReportPath is the upload API (plan §5.2), relative to the Smoke URL.
	ReportPath = "/api/v1/collector/report"

	maxFileBytes  = 64 << 10
	maxTokenBytes = 512
)

// Source says where a setting came from.
type Source string

const (
	SourceNone      Source = ""
	SourceFile      Source = "config file"
	SourceTokenFile Source = "token_file"
	SourceEnv       Source = "environment"
)

// Config is the effective configuration.
type Config struct {
	// Path is the configuration file that was looked at; FileFound says whether it existed.
	Path      string
	FileFound bool

	URL       string
	URLSource Source

	Token       string
	TokenSource Source
	// TokenFile is the token_file setting, when used.
	TokenFile string

	// InsecureHTTP allows an http:// URL for localhost (tests only); set from the command line.
	InsecureHTTP bool

	// Warnings are non-fatal problems (for example a world-readable file holding the token).
	Warnings []string
}

// Error is a configuration error (exit code 1).
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func errorf(format string, args ...any) error { return &Error{msg: fmt.Sprintf(format, args...)} }

var keyRe = regexp.MustCompile(`^[a-z_]{1,32}$`)

// Load reads the file at path (a missing file is not an error: the environment
// may hold everything) and applies the environment. getenv is os.Getenv in production.
// Load does not check that the result is complete; call Validate for that.
func Load(path string, getenv func(string) string) (*Config, error) {
	c := &Config{Path: path}
	if err := c.loadFile(path); err != nil {
		return nil, err
	}
	if v := strings.TrimSpace(getenv(EnvURL)); v != "" {
		c.URL, c.URLSource = v, SourceEnv
	}
	if v := strings.TrimSpace(getenv(EnvToken)); v != "" {
		c.Token, c.TokenSource, c.TokenFile = v, SourceEnv, ""
	}
	return c, nil
}

func (c *Config) loadFile(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errorf("cannot read configuration file %s: %v", path, unwrapPathError(err))
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return errorf("cannot read configuration file %s: %v", path, unwrapPathError(err))
	}
	if !st.Mode().IsRegular() {
		return errorf("configuration file %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return errorf("cannot read configuration file %s: %v", path, unwrapPathError(err))
	}
	if len(data) > maxFileBytes {
		return errorf("configuration file %s is larger than %d bytes", path, maxFileBytes)
	}
	c.FileFound = true

	values := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxFileBytes+1)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !keyRe.MatchString(k) {
			// Never quote the line: it may be a pasted token.
			return errorf("%s line %d: expected key=value", path, n)
		}
		switch k {
		case "url", "token", "token_file":
		default:
			return errorf("%s line %d: unknown key %q (known: url, token, token_file)", path, n, k)
		}
		if _, dup := values[k]; dup {
			return errorf("%s line %d: %s is set twice", path, n, k)
		}
		values[k] = unquote(strings.TrimSpace(v))
	}
	if err := sc.Err(); err != nil {
		return errorf("cannot read configuration file %s: %v", path, err)
	}

	if v := values["url"]; v != "" {
		c.URL, c.URLSource = v, SourceFile
	}
	tok, tokFile := values["token"], values["token_file"]
	switch {
	case tok != "" && tokFile != "":
		return errorf("%s: set token or token_file, not both", path)
	case tok != "":
		c.Token, c.TokenSource = tok, SourceFile
		if st.Mode().Perm()&0o007 != 0 {
			c.Warnings = append(c.Warnings, fmt.Sprintf(
				"%s holds the token and is readable by other users; run: chmod 0640 %s", path, path))
		}
	case tokFile != "":
		t, err := readTokenFile(tokFile)
		if err != nil {
			return err
		}
		c.Token, c.TokenSource, c.TokenFile = t, SourceTokenFile, tokFile
	}
	return nil
}

func readTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errorf("cannot read token_file %s: %v", path, unwrapPathError(err))
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+64))
	if err != nil {
		return "", errorf("cannot read token_file %s: %v", path, unwrapPathError(err))
	}
	t := strings.TrimSpace(string(data))
	if strings.ContainsAny(t, "\r\n") {
		return "", errorf("token_file %s must hold a single line", path)
	}
	return t, nil
}

// unwrapPathError drops the path from an *os.PathError (callers print it once).
func unwrapPathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// Validate checks that the configuration can be used to upload.
func (c *Config) Validate() error {
	if c.URL == "" {
		return errorf("url is not set (in %s or %s)", c.Path, EnvURL)
	}
	if _, err := Endpoint(c.URL, c.InsecureHTTP); err != nil {
		return err
	}
	if c.Token == "" {
		return errorf("token is not set (token or token_file in %s, or %s)", c.Path, EnvToken)
	}
	return CheckToken(c.Token)
}

// CheckToken rejects tokens that cannot be sent in an Authorization header.
// The error never contains the token.
func CheckToken(t string) error {
	if len(t) > maxTokenBytes {
		return errorf("token is longer than %d characters", maxTokenBytes)
	}
	for i := 0; i < len(t); i++ {
		if t[i] <= ' ' || t[i] > '~' {
			return errorf("token contains a character that is not printable ASCII (character %d)", i+1)
		}
	}
	return nil
}

// Endpoint validates the Smoke URL and returns the report endpoint. Only https://
// is accepted, except http:// to localhost when insecureHTTP is set.
func Endpoint(raw string, insecureHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", errorf("url must look like https://smoke.example.com")
	}
	if u.User != nil {
		return "", errorf("url must not contain a user name or password")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errorf("url must not contain a query or fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !insecureHTTP {
			return "", errorf("url must use https:// (http:// is allowed only with --insecure-http and localhost)")
		}
		if !isLocalhost(u.Hostname()) {
			return "", errorf("--insecure-http is allowed only with localhost, 127.0.0.1 or [::1]")
		}
	default:
		return "", errorf("url must use https://")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Path = strings.TrimRight(u.Path, "/") + ReportPath
	u.RawPath = ""
	return u.String(), nil
}

func isLocalhost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// TokenPreview returns the first 8 characters of the token followed by an ellipsis.
func TokenPreview(t string) string {
	if t == "" {
		return "(not set)"
	}
	if len(t) <= 8 {
		// Too short to show any of it safely.
		return "(set, " + fmt.Sprint(len(t)) + " characters)"
	}
	return t[:8] + "…"
}
