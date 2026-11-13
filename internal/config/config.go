// Package config loads the collector configuration (OS detection plan §5.1):
// the key=value file /etc/smoke-collector/config, overridden by the
// SMOKE_COLLECTOR_URL and SMOKE_COLLECTOR_TOKEN environment variables.
// The container collector (plan §4a, spec FR-COL-08) uses the same rules with its own
// file, variables, endpoint and the extra docker_host key (ContainerCollector).
// The OS collector also has the scan and repeatable lockfile keys (plan §4b, decision 8).
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
	"path"
	"regexp"
	"slices"
	"strings"

	"gitlab.aircraft.tw/smoke/smoke-collector/internal/lockfiles"
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

// Spec says which file, environment variables and endpoint a program uses.
type Spec struct {
	// Path is the default configuration file.
	Path     string
	EnvURL   string
	EnvToken string
	// EnvDockerHost overrides docker_host; empty means the program has no docker_host key.
	EnvDockerHost string
	// ReportPath is the upload API, relative to the Smoke URL.
	ReportPath string
	// Scans says the program has the scan and lockfile keys (the OS collector).
	Scans bool
}

// Collector is the OS collector (smoke-collector).
var Collector = Spec{Path: DefaultPath, EnvURL: EnvURL, EnvToken: EnvToken, ReportPath: ReportPath, Scans: true}

// What the OS collector can scan (the scan key). docker belongs to smoke-container-collector.
const (
	ScanOS        = "os"
	ScanLockfiles = "lockfiles"
)

// scanOrder is the canonical order of the scan list (and of X-Smoke-Collector-Scans).
var scanOrder = []string{ScanOS, ScanLockfiles}

// ContainerCollector is the container collector (smoke-container-collector, spec FR-COL-08).
var ContainerCollector = Spec{
	Path:          "/etc/smoke-collector/containers.config",
	EnvURL:        "SMOKE_CONTAINER_COLLECTOR_URL",
	EnvToken:      "SMOKE_CONTAINER_COLLECTOR_TOKEN",
	EnvDockerHost: "SMOKE_CONTAINER_COLLECTOR_DOCKER_HOST",
	ReportPath:    "/api/v1/collector/containers",
}

// DefaultDockerHost is the Docker Engine socket used when docker_host is not set.
const DefaultDockerHost = "unix:///var/run/docker.sock"

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

	// DockerHost is docker_host (container collector only; DefaultDockerHost when not set).
	DockerHost       string
	DockerHostSource Source

	// Scans is the scan list in canonical order (OS collector only; [os] when not set).
	Scans      []string
	ScanSource Source
	// Lockfiles are the lockfile= paths (OS collector only), checked and in file order.
	Lockfiles []string

	// InsecureHTTP allows an http:// URL for localhost (tests only); set from the command line.
	InsecureHTTP bool

	spec Spec

	// Warnings are non-fatal problems (for example a world-readable file holding the token).
	Warnings []string
}

// Error is a configuration error (exit code 1).
type Error struct {
	msg string
	err error
}

func (e *Error) Error() string { return e.msg }

// Unwrap returns the underlying error (for errors.Is(err, fs.ErrPermission)), if any.
func (e *Error) Unwrap() error { return e.err }

func errorf(format string, args ...any) error { return &Error{msg: fmt.Sprintf(format, args...)} }

// readError is errorf for a failed read of path; it keeps err for errors.Is.
func readError(what, path string, err error) error {
	err = unwrapPathError(err)
	return &Error{msg: fmt.Sprintf("cannot read %s %s: %v", what, path, err), err: err}
}

var keyRe = regexp.MustCompile(`^[a-z_]{1,32}$`)

// Load reads the file at path (a missing file is not an error: the environment
// may hold everything) and applies the environment. getenv is os.Getenv in production.
// Load does not check that the result is complete; call Validate for that.
func Load(path string, getenv func(string) string) (*Config, error) {
	return LoadSpec(Collector, path, getenv)
}

// LoadSpec is Load for the program described by spec.
func LoadSpec(spec Spec, path string, getenv func(string) string) (*Config, error) {
	c := &Config{Path: path, spec: spec}
	if spec.Scans {
		c.Scans = []string{ScanOS}
	}
	if err := c.loadFile(path); err != nil {
		return nil, err
	}
	if v := strings.TrimSpace(getenv(spec.EnvURL)); v != "" {
		c.URL, c.URLSource = v, SourceEnv
	}
	if v := strings.TrimSpace(getenv(spec.EnvToken)); v != "" {
		c.Token, c.TokenSource, c.TokenFile = v, SourceEnv, ""
	}
	if spec.EnvDockerHost != "" {
		if v := strings.TrimSpace(getenv(spec.EnvDockerHost)); v != "" {
			c.DockerHost, c.DockerHostSource = v, SourceEnv
		}
		if c.DockerHost == "" {
			c.DockerHost = DefaultDockerHost
		}
	}
	return c, nil
}

func (c *Config) knownKeys() []string {
	keys := []string{"url", "token", "token_file"}
	if c.spec.EnvDockerHost != "" {
		keys = append(keys, "docker_host")
	}
	if c.spec.Scans {
		keys = append(keys, "scan", "lockfile")
	}
	return keys
}

func (c *Config) loadFile(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return readError("configuration file", path, err)
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
	var lockfileLines []int
	var lockfilePaths []string
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
		if !slices.Contains(c.knownKeys(), k) {
			return errorf("%s line %d: unknown key %q (known: %s)", path, n, k, strings.Join(c.knownKeys(), ", "))
		}
		if k == "lockfile" { // repeatable
			lockfileLines = append(lockfileLines, n)
			lockfilePaths = append(lockfilePaths, unquote(strings.TrimSpace(v)))
			continue
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
	if v := values["docker_host"]; v != "" {
		c.DockerHost, c.DockerHostSource = v, SourceFile
	}
	if v, ok := values["scan"]; ok {
		scans, err := ParseScans(v)
		if err != nil {
			return errorf("%s: scan: %v", path, err)
		}
		c.Scans, c.ScanSource = scans, SourceFile
	}
	if err := c.setLockfiles(path, lockfileLines, lockfilePaths); err != nil {
		return err
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

// setLockfiles checks the lockfile= values (lines are their line numbers).
func (c *Config) setLockfiles(file string, lines []int, paths []string) error {
	if len(paths) > lockfiles.MaxPaths {
		return errorf("%s line %d: at most %d lockfile lines", file, lines[lockfiles.MaxPaths], lockfiles.MaxPaths)
	}
	seen := map[string]int{}
	for i, raw := range paths {
		p, err := lockfiles.CheckPath(raw)
		if err != nil {
			// The value is a path set by root, not a secret, but stay with the rule above.
			return errorf("%s line %d: lockfile %v", file, lines[i], err)
		}
		if first, dup := seen[p]; dup {
			return errorf("%s line %d: lockfile %s is already on line %d", file, lines[i], p, first)
		}
		seen[p] = lines[i]
		c.Lockfiles = append(c.Lockfiles, p)
	}
	return nil
}

// ParseScans parses a scan value: a comma-separated, non-empty subset of os and lockfiles
// (blanks around items are ignored, duplicates are merged). The result is in canonical order.
func ParseScans(v string) ([]string, error) {
	set := map[string]bool{}
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		switch item {
		case ScanOS, ScanLockfiles:
			set[item] = true
		case "":
			return nil, errorf("expected a comma-separated list of os, lockfiles")
		case "docker":
			return nil, errorf("docker is scanned by smoke-container-collector, not smoke-collector (install.sh --scan docker installs it)")
		case "lockfile":
			return nil, errorf("unknown item lockfile (did you mean lockfiles?)")
		default:
			// Not quoted: the rule above (no part of a line in an error).
			return nil, errorf("unknown item (known: os, lockfiles)")
		}
	}
	var out []string
	for _, s := range scanOrder {
		if set[s] {
			out = append(out, s)
		}
	}
	return out, nil
}

// Scanning reports whether the scan list contains s.
func (c *Config) Scanning(s string) bool { return slices.Contains(c.Scans, s) }

// ScanHeader is the X-Smoke-Collector-Scans value: the scan list, comma-separated, no spaces.
func (c *Config) ScanHeader() string { return strings.Join(c.Scans, ",") }

// ValidateScans checks the scan list against the lockfile paths: lockfiles needs at least one
// lockfile line. Lockfile lines without lockfiles in scan are ignored with a warning.
// Validate calls it; run --dry-run calls it alone (no url or token needed).
func (c *Config) ValidateScans() error {
	if !c.Spec().Scans {
		return nil
	}
	if c.Scanning(ScanLockfiles) && len(c.Lockfiles) == 0 {
		return errorf("scan includes lockfiles but no lockfile=/path line is set in %s (install.sh --lockfile PATH)", c.Path)
	}
	return nil
}

// IgnoredLockfiles is the warning for lockfile lines that are not used, or "".
func (c *Config) IgnoredLockfiles() string {
	if c.Spec().Scans && len(c.Lockfiles) > 0 && !c.Scanning(ScanLockfiles) {
		return fmt.Sprintf("%d lockfile line(s) ignored: scan does not include lockfiles", len(c.Lockfiles))
	}
	return ""
}

func readTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", readError("token_file", path, err)
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
	spec := c.Spec()
	if c.URL == "" {
		return errorf("url is not set (in %s or %s)", c.Path, spec.EnvURL)
	}
	if _, err := c.Endpoint(); err != nil {
		return err
	}
	if c.Token == "" {
		return errorf("token is not set (token or token_file in %s, or %s)", c.Path, spec.EnvToken)
	}
	if err := CheckToken(c.Token); err != nil {
		return err
	}
	if spec.EnvDockerHost != "" {
		if _, err := DockerSocket(c.DockerHost); err != nil {
			return err
		}
	}
	return c.ValidateScans()
}

// Spec is the program the configuration was loaded for (Collector for a zero Config).
func (c *Config) Spec() Spec {
	if c.spec.ReportPath == "" {
		return Collector
	}
	return c.spec
}

// Endpoint is the report endpoint of the configured URL (see EndpointFor).
func (c *Config) Endpoint() (string, error) {
	return EndpointFor(c.URL, c.InsecureHTTP, c.Spec().ReportPath)
}

// LockfileEndpoint is the lockfile endpoint of the configured URL (OS collector).
func (c *Config) LockfileEndpoint() (string, error) {
	return EndpointFor(c.URL, c.InsecureHTTP, lockfiles.ReportPath)
}

// DockerSocket returns the socket path of a docker_host value: only unix:// with an absolute,
// clean path is accepted (no tcp://: the container collector talks to the local Engine only).
func DockerSocket(host string) (string, error) {
	p, ok := strings.CutPrefix(host, "unix://")
	if !ok {
		return "", errorf("docker_host must look like unix:///var/run/docker.sock (only unix sockets are supported)")
	}
	if !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsAny(p, "?#\x00") || len(p) > 1024 {
		return "", errorf("docker_host must be unix:// followed by an absolute path")
	}
	return p, nil
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
	return EndpointFor(raw, insecureHTTP, ReportPath)
}

// EndpointFor is Endpoint with another API path (reportPath, starting with /).
func EndpointFor(raw string, insecureHTTP bool, reportPath string) (string, error) {
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
	u.Path = strings.TrimRight(u.Path, "/") + reportPath
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
