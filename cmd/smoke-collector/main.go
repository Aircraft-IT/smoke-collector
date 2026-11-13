// Command smoke-collector collects the OS package inventory of a Linux host
// (Ubuntu, Debian, Alpine, RHEL, Rocky Linux, AlmaLinux) and uploads it to Smoke (OS detection plan §5.1),
// and/or the application lockfiles at the paths configured on the host (plan §4b): the scan key
// of the configuration (os, lockfiles; default os) says which.
//
//	smoke-collector run [--dry-run] [--config PATH] [--insecure-http]
//	smoke-collector print-config [--config PATH] [--insecure-http]
//	smoke-collector version
//
// Exit codes: 0 success (including unchanged), 1 configuration error,
// 2 collection failed, 3 upload rejected, 4 network or server error.
// With both os and lockfiles, both parts are always attempted (the OS report first) and the
// exit code is that of the first part that failed. A lockfile path that cannot be read is not a
// failure: it is reported to Smoke with its status (not_found, unreadable, ...).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"

	"gitlab.aircraft.tw/smoke/smoke-collector/internal/collect"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/config"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/lockfiles"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/upload"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/version"
)

// Exit codes (plan §5.1).
const (
	exitOK       = 0
	exitConfig   = 1
	exitCollect  = 2
	exitRejected = 3
	exitNetwork  = 4
)

const usage = `Usage:
  smoke-collector run [--dry-run] [--config PATH] [--insecure-http]
      Collect what scan lists and upload it to Smoke: the OS package inventory (os)
      and the lockfiles at the lockfile= paths (lockfiles).
      --dry-run prints instead the exact OS report and, for each lockfile path, its
      status and every file's name, size, SHA-256 and full contents; it makes no
      network connection (url and token are not needed).
  smoke-collector print-config [--config PATH] [--insecure-http]
      Show the effective configuration (the token is shortened to 8 characters).
  smoke-collector version

Configuration: %s (key=value: url, token or token_file,
scan=os,lockfiles (default os), lockfile=/absolute/path (repeatable, at most 20)),
url and token overridden by %s and %s.

Exit codes: 0 success, 1 configuration error, 2 collection failed,
3 upload rejected, 4 network or server error. With os and lockfiles both parts
run and the code is that of the first part that failed (OS report first).
`

// lockfileHints replace the OS report's hints for the lockfile endpoint.
var lockfileHints = map[int]string{
	http.StatusNotFound:              "this Smoke does not accept lockfile reports yet; update Smoke, or remove lockfiles from scan",
	http.StatusRequestEntityTooLarge: "the lockfile report is larger than 50 MB",
	http.StatusTooManyRequests:       "at most 6 reports per token every 10 minutes (shared with the OS report)",
}

// app holds the process dependencies so main can be tested.
type app struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	collector      *collect.Collector
	newUploader    func(endpoint, token string) *upload.Client
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	a := &app{
		stdout:    os.Stdout,
		stderr:    os.Stderr,
		getenv:    os.Getenv,
		collector: collect.New(),
		newUploader: func(endpoint, token string) *upload.Client {
			return &upload.Client{
				Endpoint:  endpoint,
				Token:     token,
				Version:   version.Version,
				UserAgent: version.UserAgent(),
				HTTP:      upload.NewHTTPClient(),
			}
		},
	}
	code := a.main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

func (a *app) main(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(a.stderr, usage, config.DefaultPath, config.EnvURL, config.EnvToken)
		return exitConfig
	}
	switch args[0] {
	case "run":
		return a.run(ctx, args[1:])
	case "print-config":
		return a.printConfig(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(a.stdout, "smoke-collector %s (%s/%s, %s)\n", version.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprintf(a.stdout, usage, config.DefaultPath, config.EnvURL, config.EnvToken)
		return exitOK
	default:
		a.errorf("unknown command %q", args[0])
		fmt.Fprintf(a.stderr, usage, config.DefaultPath, config.EnvURL, config.EnvToken)
		return exitConfig
	}
}

type commonFlags struct {
	configPath   string
	insecureHTTP bool
}

func (a *app) flags(name string, f *commonFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.StringVar(&f.configPath, "config", config.DefaultPath, "configuration file")
	fs.BoolVar(&f.insecureHTTP, "insecure-http", false, "allow an http:// url for localhost (testing only)")
	return fs
}

func (a *app) run(ctx context.Context, args []string) int {
	var f commonFlags
	fs := a.flags("run", &f)
	dryRun := fs.Bool("dry-run", false, "print the report and do not upload it")
	if err := fs.Parse(args); err != nil {
		return exitConfig
	}
	if fs.NArg() > 0 {
		a.errorf("run takes no arguments")
		return exitConfig
	}
	if *dryRun {
		return a.dryRun(ctx, f)
	}

	cfg, ok := a.loadConfig(f)
	if !ok {
		return exitConfig
	}
	code := exitOK
	if cfg.Scanning(config.ScanOS) {
		code = a.runOS(ctx, cfg)
	}
	if cfg.Scanning(config.ScanLockfiles) {
		if c := a.runLockfiles(ctx, cfg); code == exitOK {
			code = c
		}
	}
	return code
}

// runOS collects and uploads the OS report.
func (a *app) runOS(ctx context.Context, cfg *config.Config) int {
	res, err := a.collector.Collect(ctx)
	if err != nil {
		a.errorf("%v", err)
		return exitCollect
	}
	endpoint, _ := cfg.Endpoint() // checked by Validate
	up := a.uploader(endpoint, cfg)
	result, err := up.Upload(ctx, res.Body)
	if err != nil {
		return a.uploadFailed("report", err)
	}
	fmt.Fprintf(a.stdout, "smoke-collector: report %s (HTTP %d, %d bytes, asset %s, snapshot %s)\n",
		result.Status, result.HTTPStatus, len(res.Body), orDash(result.AssetID), orDash(result.SnapshotID))
	return exitOK
}

// runLockfiles reads the lockfile paths and uploads them.
func (a *app) runLockfiles(ctx context.Context, cfg *config.Config) int {
	report := a.readLockfiles(cfg.Lockfiles)
	body, err := report.Body()
	if err != nil {
		a.errorf("lockfiles: %v", err)
		return exitCollect
	}
	endpoint, _ := cfg.LockfileEndpoint() // same URL as Endpoint, checked by Validate
	up := a.uploader(endpoint, cfg)
	up.ContentType = lockfiles.ContentType
	up.Hints = lockfileHints
	result, err := up.Upload(ctx, body)
	if err != nil {
		return a.uploadFailed("lockfile report", err)
	}
	a.printLockfileResult(up, result, report, len(body))
	return exitOK
}

func (a *app) uploader(endpoint string, cfg *config.Config) *upload.Client {
	up := a.newUploader(endpoint, cfg.Token)
	up.Scans = cfg.ScanHeader()
	up.Logf = func(format string, args ...any) { a.errorf(format, args...) }
	return up
}

func (a *app) uploadFailed(what string, err error) int {
	a.errorf("%s: %v", what, err)
	var rejected *upload.RejectedError
	if errors.As(err, &rejected) {
		return exitRejected
	}
	return exitNetwork
}

func (a *app) readLockfiles(paths []string) *lockfiles.Report {
	r := &lockfiles.Reader{Logf: func(format string, args ...any) { a.errorf("warning: "+format, args...) }}
	return r.Read(paths)
}

// lockfileResponse is Smoke's answer; result is an open set of values, printed as they are.
type lockfileResponse struct {
	Lockfiles []struct {
		Path       string `json:"path"`
		Status     string `json:"status"`
		Result     string `json:"result"`
		AssetID    string `json:"assetId"`
		SnapshotID string `json:"snapshotId"`
		Issue      string `json:"issue"`
	} `json:"lockfiles"`
}

func (a *app) printLockfileResult(up *upload.Client, result *upload.Result, report *lockfiles.Report, size int) {
	fmt.Fprintf(a.stdout, "smoke-collector: lockfile report accepted (HTTP %d, %s, %d bytes)\n",
		result.HTTPStatus, plural(len(report.Lockfiles), "path"), size)
	var resp lockfileResponse
	if json.Unmarshal(result.Body, &resp) != nil {
		return
	}
	for _, r := range resp.Lockfiles {
		line := fmt.Sprintf("  %s: %s", up.Scrub(clip(r.Path, 512)), orDash(up.Scrub(clip(r.Result, 40))))
		if r.Status != "" && r.Status != string(lockfiles.StatusOK) {
			line += " (" + up.Scrub(clip(r.Status, 40)) + ")"
		}
		if r.AssetID != "" {
			line += " (asset " + up.Scrub(clip(r.AssetID, 64))
			if r.SnapshotID != "" {
				line += ", snapshot " + up.Scrub(clip(r.SnapshotID, 64))
			}
			line += ")"
		}
		if r.Issue != "" {
			line += " [" + up.Scrub(clip(r.Issue, 64)) + "]"
		}
		fmt.Fprintln(a.stdout, line)
	}
}

// dryRun prints what run would send. It reads the configuration only for scan and the lockfile
// paths; without a configuration file (or without permission to read it) it shows the OS report.
func (a *app) dryRun(ctx context.Context, f commonFlags) int {
	cfg, err := config.Load(f.configPath, a.getenv)
	switch {
	case errors.Is(err, fs.ErrPermission):
		a.errorf("warning: %v; showing the OS report only (run as root or smoke-collector to see the configured scan)", err)
		cfg, err = config.Load("", a.getenv)
		if err != nil {
			a.errorf("%v", err)
			return exitConfig
		}
	case err != nil:
		a.errorf("%v", err)
		return exitConfig
	}
	if w := cfg.IgnoredLockfiles(); w != "" {
		a.errorf("warning: %s", w)
	}
	if err := cfg.ValidateScans(); err != nil {
		a.errorf("%v", err)
		return exitConfig
	}
	if cfg.Scanning(config.ScanOS) {
		res, err := a.collector.Collect(ctx)
		if err != nil {
			a.errorf("%v", err)
			return exitCollect
		}
		if _, err := a.stdout.Write(res.Body); err != nil {
			return exitCollect
		}
	}
	if cfg.Scanning(config.ScanLockfiles) {
		report := a.readLockfiles(cfg.Lockfiles)
		body, err := report.Body()
		if err != nil {
			a.errorf("lockfiles: %v", err)
			return exitCollect
		}
		if err := printLockfiles(a.stdout, report, len(body)); err != nil {
			return exitCollect
		}
	}
	return exitOK
}

// printLockfiles prints the lockfile report for --dry-run: a summary per path, then the full
// contents of every file that would be sent.
func printLockfiles(w io.Writer, report *lockfiles.Report, size int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "#lockfiles: %s, sent as JSON (%d bytes before gzip) to %s\n",
		plural(len(report.Lockfiles), "path"), size, lockfiles.ReportPath)
	for _, e := range report.Lockfiles {
		if e.Status != lockfiles.StatusOK {
			fmt.Fprintf(&b, "%s: %s (%s)\n", e.Path, e.Status, e.Reason)
			continue
		}
		fmt.Fprintf(&b, "%s: ok, %s, digest %s\n", e.Path, plural(len(e.Files), "file"), lockfiles.Digest(e.Files))
		for _, file := range e.Files {
			fmt.Fprintf(&b, "  %s  %d bytes  sha256 %s\n", file.Name, file.Size, file.SHA256)
		}
	}
	for _, e := range report.Lockfiles {
		for _, file := range e.Files {
			full := e.Path
			if e.Dir {
				full = path.Join(e.Path, file.Name)
			}
			fmt.Fprintf(&b, "\n#lockfile %s (%d bytes, sha256 %s)\n", full, file.Size, file.SHA256)
			b.WriteString(file.Content)
			if !strings.HasSuffix(file.Content, "\n") {
				b.WriteString("\n#(no newline at end of file)\n")
			}
			fmt.Fprintf(&b, "#end %s\n", full)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func (a *app) loadConfig(f commonFlags) (*config.Config, bool) {
	cfg, err := config.Load(f.configPath, a.getenv)
	if err != nil {
		a.errorf("%v", err)
		return nil, false
	}
	cfg.InsecureHTTP = f.insecureHTTP
	for _, w := range cfg.Warnings {
		a.errorf("warning: %s", w)
	}
	if w := cfg.IgnoredLockfiles(); w != "" {
		a.errorf("warning: %s", w)
	}
	if err := cfg.Validate(); err != nil {
		a.errorf("%v", err)
		return nil, false
	}
	return cfg, true
}

func (a *app) printConfig(args []string) int {
	var f commonFlags
	fs := a.flags("print-config", &f)
	if err := fs.Parse(args); err != nil {
		return exitConfig
	}
	cfg, err := config.Load(f.configPath, a.getenv)
	if err != nil {
		a.errorf("%v", err)
		return exitConfig
	}
	cfg.InsecureHTTP = f.insecureHTTP
	found := "not found"
	if cfg.FileFound {
		found = "found"
	}
	w := a.stdout
	fmt.Fprintf(w, "version:       %s\n", version.Version)
	fmt.Fprintf(w, "config file:   %s (%s)\n", cfg.Path, found)
	fmt.Fprintf(w, "url:           %s%s\n", orDash(cfg.URL), source(cfg.URLSource, ""))
	if endpoint, err := cfg.Endpoint(); err == nil && cfg.Scanning(config.ScanOS) {
		fmt.Fprintf(w, "endpoint:      %s\n", endpoint)
	}
	if endpoint, err := cfg.LockfileEndpoint(); err == nil && cfg.Scanning(config.ScanLockfiles) {
		fmt.Fprintf(w, "endpoint:      %s\n", endpoint)
	}
	fmt.Fprintf(w, "token:         %s%s\n", config.TokenPreview(cfg.Token), source(cfg.TokenSource, cfg.TokenFile))
	scanSource := source(cfg.ScanSource, "")
	if cfg.ScanSource == config.SourceNone {
		scanSource = " (default)"
	}
	fmt.Fprintf(w, "scan:          %s%s\n", cfg.ScanHeader(), scanSource)
	if len(cfg.Lockfiles) == 0 {
		fmt.Fprintf(w, "lockfile:      -\n")
	}
	for _, p := range cfg.Lockfiles {
		fmt.Fprintf(w, "lockfile:      %s\n", p)
	}
	fmt.Fprintf(w, "insecure-http: %v\n", cfg.InsecureHTTP)
	for _, warn := range cfg.Warnings {
		fmt.Fprintf(w, "warning:       %s\n", warn)
	}
	if warn := cfg.IgnoredLockfiles(); warn != "" {
		fmt.Fprintf(w, "warning:       %s\n", warn)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(w, "status:        invalid: %v\n", err)
		return exitConfig
	}
	fmt.Fprintf(w, "status:        ok\n")
	return exitOK
}

func source(s config.Source, file string) string {
	switch {
	case s == config.SourceNone:
		return ""
	case file != "":
		return " (" + string(s) + " " + file + ")"
	default:
		return " (" + string(s) + ")"
	}
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) errorf(format string, args ...any) {
	fmt.Fprintf(a.stderr, "smoke-collector: "+format+"\n", args...)
}
