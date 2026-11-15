// Package docker is the container collector's Docker Engine API client (spec FR-COL-09).
//
// The account that runs the container collector can control Docker, which is equivalent to
// root, so the client can do very little on purpose: it talks to the Engine over a unix socket,
// sends GET only, and only to these paths (API v1.41, Docker 20.10 or later):
//
//	GET /version
//	GET /containers/json                      (running containers; no query)
//	GET /images/sha256:<64 hex>/json
//	GET /containers/<64 hex>/archive?path=<absolute clean path>   (what `docker cp` reads)
//
// Every request is checked twice before any I/O: when it is built and again in the transport
// (Check), so no code path can reach anything else (no exec, create, pull, export or delete).
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// APIVersion is the Engine API version every request uses.
const APIVersion = "1.41"

const (
	// MaxJSONBytes caps a JSON response (the container list of a busy host is the largest).
	MaxJSONBytes = 8 << 20
	// JSONTimeout and ArchiveTimeout bound one request.
	JSONTimeout    = 30 * time.Second
	ArchiveTimeout = 2 * time.Minute
	maxArchivePath = 1024
)

var (
	containerIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	imageIDRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ErrNotFound is a 404 from the Engine (for an archive: the path does not exist in the container).
var ErrNotFound = errors.New("not found")

// ErrRefused is returned for a request outside the allowlist.
var ErrRefused = errors.New("request refused by the container collector's allowlist")

// Check reports whether a request may be sent: method GET and one of the four paths of the
// package comment (path without the /v1.41 prefix), with exactly the query each one allows.
func Check(method, p string, query url.Values) error {
	refuse := func(why string) error { return fmt.Errorf("%w: %s %s (%s)", ErrRefused, method, p, why) }
	if method != http.MethodGet {
		return refuse("only GET is allowed")
	}
	if p == "" || path.Clean(p) != p || strings.ContainsAny(p, "\x00%?#\\") {
		return refuse("not a clean path")
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case p == "/version", p == "/containers/json":
		if len(query) != 0 {
			return refuse("no query is allowed")
		}
		return nil
	case len(parts) == 3 && parts[0] == "images" && parts[2] == "json" && imageIDRe.MatchString(parts[1]):
		if len(query) != 0 {
			return refuse("no query is allowed")
		}
		return nil
	case len(parts) == 3 && parts[0] == "containers" && parts[2] == "archive" && containerIDRe.MatchString(parts[1]):
		if len(query) != 1 || len(query["path"]) != 1 {
			return refuse("archive takes exactly one path parameter")
		}
		ap := query.Get("path")
		if !path.IsAbs(ap) || path.Clean(ap) != ap || strings.ContainsRune(ap, 0) || len(ap) > maxArchivePath {
			return refuse("archive path must be absolute and clean")
		}
		return nil
	default:
		return refuse("path not allowed")
	}
}

// guard is the transport: it checks every request again right before it is sent.
type guard struct{ next http.RoundTripper }

func (g guard) RoundTrip(req *http.Request) (*http.Response, error) {
	p, ok := strings.CutPrefix(req.URL.Path, "/v"+APIVersion)
	if !ok || req.URL.RawPath != "" || req.URL.Host != "docker" || req.URL.User != nil || req.URL.Fragment != "" {
		return nil, fmt.Errorf("%w: unexpected URL", ErrRefused)
	}
	q, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: bad query", ErrRefused)
	}
	if err := Check(req.Method, p, q); err != nil {
		return nil, err
	}
	if req.Body != nil && req.Body != http.NoBody {
		return nil, fmt.Errorf("%w: a request body is not allowed", ErrRefused)
	}
	return g.next.RoundTrip(req)
}

// Client calls the Engine API over a unix socket.
type Client struct {
	socket string
	http   *http.Client
}

// New returns a client for the socket at socketPath.
func New(socketPath string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression:    true,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: JSONTimeout,
	}
	return &Client{
		socket: socketPath,
		http: &http.Client{
			Transport: guard{next: tr},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Socket is the socket path the client talks to.
func (c *Client) Socket() string { return c.socket }

// get sends one checked GET. The caller closes the body of a 2xx response; other statuses are
// returned as errors (404 as ErrNotFound).
func (c *Client) get(ctx context.Context, p string, query url.Values) (*http.Response, error) {
	if err := Check(http.MethodGet, p, query); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "http", Host: "docker", Path: "/v" + APIVersion + p, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		var ne *net.OpError
		if errors.As(err, &ne) {
			return nil, fmt.Errorf("cannot reach Docker at %s: %v", c.socket, ne.Err)
		}
		return nil, fmt.Errorf("docker %s: %w", p, err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var body struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(data, &body)
	// A container that stopped meanwhile is also a 404; it is not a missing path.
	if resp.StatusCode == http.StatusNotFound && !strings.HasPrefix(body.Message, "No such container") {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, clip(body.Message))
	}
	msg := clip(body.Message)
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return nil, fmt.Errorf("docker %s: HTTP %d: %s", p, resp.StatusCode, msg)
}

func (c *Client) getJSON(ctx context.Context, p string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, JSONTimeout)
	defer cancel()
	resp, err := c.get(ctx, p, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxJSONBytes+1))
	if err != nil {
		return fmt.Errorf("docker %s: reading the response: %w", p, err)
	}
	if len(data) > MaxJSONBytes {
		return fmt.Errorf("docker %s: response larger than %d bytes", p, MaxJSONBytes)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("docker %s: invalid JSON: %w", p, err)
	}
	return nil
}

// VersionInfo is the part of GET /version that is used.
type VersionInfo struct {
	Version    string `json:"Version"`
	APIVersion string `json:"ApiVersion"`
}

// Version checks that the Engine is reachable and supports API v1.41.
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	var v VersionInfo
	if err := c.getJSON(ctx, "/version", &v); err != nil {
		return nil, err
	}
	if !atLeast(v.APIVersion, APIVersion) {
		return nil, fmt.Errorf("docker Engine API %q is older than %s (Docker 20.10 or later is needed)", clip(v.APIVersion), APIVersion)
	}
	return &v, nil
}

// Container is the part of a GET /containers/json entry that is used. Names, labels, ports,
// mounts and the command are in the response but are not decoded.
type Container struct {
	ID      string `json:"Id"`
	Image   string `json:"Image"`
	ImageID string `json:"ImageID"`
}

// Containers lists the running containers.
func (c *Client) Containers(ctx context.Context) ([]Container, error) {
	var list []Container
	if err := c.getJSON(ctx, "/containers/json", &list); err != nil {
		return nil, err
	}
	return list, nil
}

// Image is the part of GET /images/{id}/json that is used.
type Image struct {
	ID          string       `json:"Id"`
	RepoTags    []string     `json:"RepoTags"`
	RepoDigests []string     `json:"RepoDigests"`
	Config      *ImageConfig `json:"Config"`
}

// ImageConfig is the part of an image's configuration that is used: its labels (the collector
// keeps only the standard ones in containers.LabelKeys).
type ImageConfig struct {
	Labels map[string]string `json:"Labels"`
}

// Image inspects an image by its ID (sha256:<64 hex>).
func (c *Client) Image(ctx context.Context, id string) (*Image, error) {
	var img Image
	if err := c.getJSON(ctx, "/images/"+id+"/json", &img); err != nil {
		return nil, err
	}
	return &img, nil
}

// Archive returns the tar stream of path inside the container (what `docker cp` reads). The
// caller closes it and bounds how much it reads; the stream ends after ArchiveTimeout.
// A path that does not exist gives ErrNotFound.
func (c *Client) Archive(ctx context.Context, containerID, p string) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, ArchiveTimeout)
	resp, err := c.get(ctx, "/containers/"+containerID+"/archive", url.Values{"path": {p}})
	if err != nil {
		cancel()
		return nil, err
	}
	return &cancelBody{ReadCloser: resp.Body, cancel: cancel}, nil
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// atLeast compares "major.minor" API versions.
func atLeast(have, want string) bool {
	hm, hn, ok1 := majorMinor(have)
	wm, wn, ok2 := majorMinor(want)
	if !ok1 || !ok2 {
		return false
	}
	return hm > wm || (hm == wm && hn >= wn)
}

func majorMinor(v string) (int, int, bool) {
	a, b, ok := strings.Cut(v, ".")
	if !ok {
		return 0, 0, false
	}
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	return x, y, err1 == nil && err2 == nil
}

// clip shortens and cleans text from the Engine before it is printed.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
