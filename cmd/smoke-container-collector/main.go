// Command smoke-container-collector reports the images of the running Docker containers of a
// Linux host to Smoke (OS detection plan §4a, spec FR-COL-08 to 12): for each distinct image its
// reference, digest and the package list read from one of its containers.
//
// It is a separate program from smoke-collector on purpose: the account that runs it is in the
// docker group, which is equivalent to root. It only sends GET requests to four Docker Engine API
// paths (internal/docker), never runs anything inside containers and never pulls images.
//
//	smoke-container-collector run [--dry-run] [--config PATH] [--insecure-http]
//	smoke-container-collector print-config [--config PATH] [--insecure-http]
//	smoke-container-collector version
//
// Exit codes: 0 success, 1 configuration error, 2 collection failed (Docker not reachable),
// 3 upload rejected, 4 network or server error.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/aircraft-it/smoke-collector/internal/config"
	"github.com/aircraft-it/smoke-collector/internal/containers"
	"github.com/aircraft-it/smoke-collector/internal/docker"
	"github.com/aircraft-it/smoke-collector/internal/upload"
	"github.com/aircraft-it/smoke-collector/internal/version"
)

const program = "smoke-container-collector"

// Exit codes (same as smoke-collector).
const (
	exitOK       = 0
	exitConfig   = 1
	exitCollect  = 2
	exitRejected = 3
	exitNetwork  = 4
)

// ContentType of the report. Not application/json: Smoke checks the token before it parses
// the body.
const ContentType = "application/vnd.smoke.container-report+json"

const usage = `Usage:
  smoke-container-collector run [--dry-run] [--config PATH] [--insecure-http]
      Report the images of the running Docker containers and their packages to Smoke.
      --dry-run prints the exact report instead and makes no connection to Smoke
      (it still reads Docker; url and token are not needed).
  smoke-container-collector print-config [--config PATH] [--insecure-http]
      Show the effective configuration (the token is shortened to 8 characters).
  smoke-container-collector version

Configuration: %s (key=value: url, token or token_file, docker_host),
overridden by %s, %s and %s.

Docker: only GET /version, /containers/json, /images/{id}/json and
/containers/{id}/archive (what docker cp reads) are ever requested.

Exit codes: 0 success, 1 configuration error, 2 collection failed (Docker not
reachable), 3 upload rejected, 4 network or server error.
`

var spec = config.ContainerCollector

// hints replace smoke-collector's hints for this endpoint.
var hints = map[int]string{
	http.StatusForbidden:             "the token does not have containers:write, or the asset is not an active host (create the token with \"Install container collector\" on the host page)",
	http.StatusRequestEntityTooLarge: "the report is larger than 20 MB",
	http.StatusTooManyRequests:       "at most 6 reports per token every 10 minutes",
}

// dockerAPI is what the program needs from Docker (docker.Client; a fake in tests).
type dockerAPI interface {
	containers.API
	Version(ctx context.Context) (*docker.VersionInfo, error)
}

type app struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	newDocker      func(socket string) dockerAPI
	newUploader    func(endpoint, token string) *upload.Client
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	a := &app{
		stdout:    os.Stdout,
		stderr:    os.Stderr,
		getenv:    os.Getenv,
		newDocker: func(socket string) dockerAPI { return docker.New(socket) },
		newUploader: func(endpoint, token string) *upload.Client {
			return &upload.Client{
				Endpoint:  endpoint,
				Token:     token,
				Version:   version.Version,
				UserAgent: version.UserAgentFor(program),
				HTTP:      upload.NewHTTPClient(),
			}
		},
	}
	code := a.main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

func (a *app) usage(w io.Writer) {
	fmt.Fprintf(w, usage, spec.Path, spec.EnvURL, spec.EnvToken, spec.EnvDockerHost)
}

func (a *app) main(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.usage(a.stderr)
		return exitConfig
	}
	switch args[0] {
	case "run":
		return a.run(ctx, args[1:])
	case "print-config":
		return a.printConfig(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(a.stdout, "%s %s (%s/%s, %s)\n", program, version.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return exitOK
	case "help", "--help", "-h":
		a.usage(a.stdout)
		return exitOK
	default:
		a.errorf("unknown command %q", args[0])
		a.usage(a.stderr)
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
	fs.StringVar(&f.configPath, "config", spec.Path, "configuration file")
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

	cfg, err := config.LoadSpec(spec, f.configPath, a.getenv)
	if err != nil {
		a.errorf("%v", err)
		return exitConfig
	}
	cfg.InsecureHTTP = f.insecureHTTP
	for _, w := range cfg.Warnings {
		a.errorf("warning: %s", w)
	}
	socket, err := config.DockerSocket(cfg.DockerHost)
	if err != nil {
		a.errorf("%v", err)
		return exitConfig
	}
	if !*dryRun {
		if err := cfg.Validate(); err != nil {
			a.errorf("%v", err)
			return exitConfig
		}
	}

	body, report, err := a.collect(ctx, socket)
	if err != nil {
		a.errorf("%v", err)
		return exitCollect
	}
	if *dryRun {
		if _, err := a.stdout.Write(body); err != nil {
			return exitCollect
		}
		return exitOK
	}

	endpoint, _ := cfg.Endpoint() // checked by Validate
	up := a.newUploader(endpoint, cfg.Token)
	up.ContentType = ContentType
	up.Hints = hints
	up.Logf = func(format string, args ...any) { a.errorf(format, args...) }
	result, err := up.Upload(ctx, body)
	var rejected *upload.RejectedError
	switch {
	case err == nil:
		a.printResult(up, result, report, len(body))
		return exitOK
	case errors.As(err, &rejected):
		a.errorf("%v", err)
		return exitRejected
	default:
		a.errorf("%v", err)
		return exitNetwork
	}
}

// collect reads Docker and returns the request body (JSON followed by a newline; --dry-run
// prints exactly these bytes).
func (a *app) collect(ctx context.Context, socket string) ([]byte, *containers.Report, error) {
	d := a.newDocker(socket)
	if _, err := d.Version(ctx); err != nil {
		return nil, nil, fmt.Errorf("%v (is this account in the docker group? see docker_host in %s)", err, spec.Path)
	}
	c := &containers.Collector{API: d, Logf: func(format string, args ...any) { a.errorf("warning: "+format, args...) }}
	report, err := c.Collect(ctx)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), report, nil
}

// response is the backend's answer; result is an open set of values, printed as they are.
type response struct {
	Images []struct {
		ImageID    string `json:"imageId"`
		Result     string `json:"result"`
		AssetID    string `json:"assetId"`
		SnapshotID string `json:"snapshotId"`
		Issue      string `json:"issue"`
	} `json:"images"`
}

func (a *app) printResult(up *upload.Client, result *upload.Result, report *containers.Report, size int) {
	fmt.Fprintf(a.stdout, "%s: report accepted (HTTP %d, %d images, %d bytes)\n",
		program, result.HTTPStatus, len(report.Images), size)
	names := map[string]string{}
	for _, img := range report.Images {
		if img.Reference != nil {
			names[img.ImageID] = *img.Reference
		}
	}
	var resp response
	if json.Unmarshal(result.Body, &resp) != nil {
		return
	}
	for _, r := range resp.Images {
		name := names[r.ImageID]
		if name == "" {
			name = shortID(up.Scrub(r.ImageID))
		}
		line := fmt.Sprintf("  %s: %s", name, orDash(up.Scrub(clip(r.Result, 40))))
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

func (a *app) printConfig(args []string) int {
	var f commonFlags
	fs := a.flags("print-config", &f)
	if err := fs.Parse(args); err != nil {
		return exitConfig
	}
	cfg, err := config.LoadSpec(spec, f.configPath, a.getenv)
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
	if endpoint, err := cfg.Endpoint(); err == nil {
		fmt.Fprintf(w, "endpoint:      %s\n", endpoint)
	}
	fmt.Fprintf(w, "token:         %s%s\n", config.TokenPreview(cfg.Token), source(cfg.TokenSource, cfg.TokenFile))
	dockerSource := source(cfg.DockerHostSource, "")
	if cfg.DockerHostSource == config.SourceNone {
		dockerSource = " (default)"
	}
	fmt.Fprintf(w, "docker_host:   %s%s\n", cfg.DockerHost, dockerSource)
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

func shortID(id string) string {
	if len(id) > 19 {
		return id[:19]
	}
	return id
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
	fmt.Fprintf(a.stderr, program+": "+format+"\n", args...)
}
