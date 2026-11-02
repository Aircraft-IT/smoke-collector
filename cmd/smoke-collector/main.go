// Command smoke-collector collects the OS package inventory of a Linux host
// (Ubuntu, Debian, Alpine) and uploads it to Smoke (OS detection plan §5.1).
//
//	smoke-collector run [--dry-run] [--config PATH] [--insecure-http]
//	smoke-collector print-config [--config PATH] [--insecure-http]
//	smoke-collector version
//
// Exit codes: 0 success (including unchanged), 1 configuration error,
// 2 collection failed, 3 upload rejected, 4 network or server error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"gitlab.aircraft.tw/smoke/smoke-collector/internal/collect"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/config"
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
      Collect the OS package inventory and upload it to Smoke.
      --dry-run prints the exact report instead and makes no network connection
      (no configuration needed).
  smoke-collector print-config [--config PATH] [--insecure-http]
      Show the effective configuration (the token is shortened to 8 characters).
  smoke-collector version

Configuration: %s (key=value: url, token or token_file),
overridden by %s and %s.

Exit codes: 0 success, 1 configuration error, 2 collection failed,
3 upload rejected, 4 network or server error.
`

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
		res, err := a.collector.Collect(ctx)
		if err != nil {
			a.errorf("%v", err)
			return exitCollect
		}
		if _, err := a.stdout.Write(res.Body); err != nil {
			return exitCollect
		}
		return exitOK
	}

	cfg, ok := a.loadConfig(f)
	if !ok {
		return exitConfig
	}
	endpoint, _ := config.Endpoint(cfg.URL, cfg.InsecureHTTP) // checked by Validate

	res, err := a.collector.Collect(ctx)
	if err != nil {
		a.errorf("%v", err)
		return exitCollect
	}

	up := a.newUploader(endpoint, cfg.Token)
	up.Logf = func(format string, args ...any) { a.errorf(format, args...) }
	result, err := up.Upload(ctx, res.Body)
	var rejected *upload.RejectedError
	switch {
	case err == nil:
		fmt.Fprintf(a.stdout, "smoke-collector: report %s (HTTP %d, %d bytes, asset %s, snapshot %s)\n",
			result.Status, result.HTTPStatus, len(res.Body), orDash(result.AssetID), orDash(result.SnapshotID))
		return exitOK
	case errors.As(err, &rejected):
		a.errorf("%v", err)
		return exitRejected
	default:
		a.errorf("%v", err)
		return exitNetwork
	}
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
	if endpoint, err := config.Endpoint(cfg.URL, cfg.InsecureHTTP); err == nil {
		fmt.Fprintf(w, "endpoint:      %s\n", endpoint)
	}
	fmt.Fprintf(w, "token:         %s%s\n", config.TokenPreview(cfg.Token), source(cfg.TokenSource, cfg.TokenFile))
	fmt.Fprintf(w, "insecure-http: %v\n", cfg.InsecureHTTP)
	for _, warn := range cfg.Warnings {
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

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) errorf(format string, args ...any) {
	fmt.Fprintf(a.stderr, "smoke-collector: "+format+"\n", args...)
}
