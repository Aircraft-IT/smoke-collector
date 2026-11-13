// Package upload sends the inventory to Smoke (OS detection plan §5.2:
// POST /api/v1/collector/report) with the retry rules of §5.1: network errors
// and 5xx are retried 3 times with exponential backoff (about 5 minutes at
// most); 4xx are not retried.
//
// The token is only ever placed in the Authorization header. Errors and log
// lines never contain it; text from the server is scrubbed of it as well.
package upload

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultBackoff is the wait before retries 1, 2 and 3. With 45 s per attempt the
// worst case is about 5 minutes.
var DefaultBackoff = []time.Duration{15 * time.Second, 30 * time.Second, 60 * time.Second}

const (
	maxResponseBytes = 64 << 10
	// maxServerRetryAfter caps how long a 5xx Retry-After may stretch one wait.
	maxServerRetryAfter = 2 * time.Minute
)

// Client uploads reports.
type Client struct {
	// Endpoint is the full report URL (config.Endpoint).
	Endpoint string
	Token    string
	// Version and UserAgent are sent as X-Smoke-Collector-Version and User-Agent.
	Version   string
	UserAgent string
	// Scans is sent as X-Smoke-Collector-Scans when set (smoke-collector: "os,lockfiles").
	Scans string
	// ContentType of the body; empty means the `#smoke-host 1` text (text/plain; charset=utf-8).
	ContentType string
	// Hints replace the default hints of RejectedError for some status codes (may be nil).
	Hints map[int]string
	HTTP  *http.Client
	// Backoff lists the waits between attempts; its length is the number of retries.
	Backoff []time.Duration
	// Sleep waits (replaced in tests). It returns ctx.Err() when the context ends first.
	Sleep func(ctx context.Context, d time.Duration) error
	// Logf reports retries (stderr in production). May be nil.
	Logf func(format string, args ...any)
}

// Result is a successful upload.
type Result struct {
	HTTPStatus int    `json:"-"`
	Status     string `json:"status"` // "created" or "unchanged"
	AssetID    string `json:"assetId"`
	SnapshotID string `json:"snapshotId"`
	// Body is the raw response (at most 64 KiB), for callers with their own response shape.
	// Text taken from it must go through Scrub before it is printed.
	Body []byte `json:"-"`
}

// RejectedError is a 4xx (or unexpected 3xx) response: not retried, exit code 3.
type RejectedError struct {
	HTTPStatus int
	Code       string   // error.code, e.g. UNAUTHENTICATED
	Message    string   // error.message (scrubbed)
	Issues     []string // error.details[].issue, e.g. unsupported_os
	RetryAfter time.Duration
	// Hint replaces the default hint for HTTPStatus when set.
	Hint string
}

func (e *RejectedError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "upload rejected: HTTP %d", e.HTTPStatus)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if len(e.Issues) > 0 {
		b.WriteString(" (" + strings.Join(e.Issues, ", ") + ")")
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	if e.RetryAfter > 0 {
		fmt.Fprintf(&b, "; retry after %s", e.RetryAfter.Round(time.Second))
	}
	hint := e.Hint
	if hint == "" {
		hint = hints[e.HTTPStatus]
	}
	if hint != "" {
		b.WriteString(" — " + hint)
	}
	return b.String()
}

var hints = map[int]string{
	http.StatusUnauthorized:          "the token is invalid, revoked or expired; create a new one on the asset page",
	http.StatusForbidden:             "the token does not have inventory:write, or the asset is not an active host",
	http.StatusRequestEntityTooLarge: "the report is larger than 5 MB",
	http.StatusTooManyRequests:       "at most 6 reports per token every 10 minutes",
}

// ServerError is a network error or 5xx after all retries: exit code 4.
type ServerError struct {
	HTTPStatus int // 0 for network errors
	Code       string
	Attempts   int
	Err        error
}

func (e *ServerError) Error() string {
	if e.HTTPStatus != 0 {
		s := fmt.Sprintf("server error: HTTP %d", e.HTTPStatus)
		if e.Code != "" {
			s += " " + e.Code
		}
		return fmt.Sprintf("%s (after %d attempts)", s, e.Attempts)
	}
	return fmt.Sprintf("network error: %v (after %d attempts)", e.Err, e.Attempts)
}

func (e *ServerError) Unwrap() error { return e.Err }

// NewHTTPClient returns the production client: TLS 1.2+, proxy from the environment,
// 45 s per attempt, and no redirects (a redirect could carry the token elsewhere).
func NewHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: tr,
		Timeout:   45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Gzip compresses the body.
func Gzip(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(body); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Upload sends body (the plain `#smoke-host 1` text; it is gzipped here).
func (c *Client) Upload(ctx context.Context, body []byte) (*Result, error) {
	gz, err := Gzip(body)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	backoff := c.Backoff
	if backoff == nil {
		backoff = DefaultBackoff
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	attempts := len(backoff) + 1
	for attempt := 1; ; attempt++ {
		res, retryAfter, err := c.once(ctx, gz)
		var se *ServerError
		if err == nil || !errors.As(err, &se) || ctx.Err() != nil {
			return res, err
		}
		se.Attempts = attempt
		if attempt >= attempts {
			return nil, se
		}
		wait := jitter(backoff[attempt-1])
		if retryAfter > wait {
			wait = min(retryAfter, maxServerRetryAfter)
		}
		c.logf("upload attempt %d/%d failed (%s); retrying in %s", attempt, attempts, se.short(), wait.Round(time.Second))
		if err := sleep(ctx, wait); err != nil {
			return nil, se
		}
	}
}

func (e *ServerError) short() string {
	if e.HTTPStatus != 0 {
		return "HTTP " + strconv.Itoa(e.HTTPStatus)
	}
	return e.Err.Error()
}

// once makes one attempt. Retryable failures are *ServerError.
func (c *Client) once(ctx context.Context, gz []byte) (*Result, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(gz))
	if err != nil {
		return nil, 0, fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	contentType := c.ContentType
	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-Smoke-Collector-Version", c.Version)
	if c.Scans != "" {
		req.Header.Set("X-Smoke-Collector-Scans", c.Scans)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, &ServerError{Err: errors.New(c.scrub(err.Error()))}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, 0, &ServerError{Err: fmt.Errorf("reading the response: %s", c.scrub(err.Error()))}
	}

	switch s := resp.StatusCode; {
	case s >= 200 && s < 300:
		res := &Result{}
		_ = json.Unmarshal(data, res) // the status code alone decides success
		res.HTTPStatus = s
		res.Body = data
		res.Status, res.AssetID, res.SnapshotID = c.scrub(res.Status), c.scrub(res.AssetID), c.scrub(res.SnapshotID)
		if res.Status == "" {
			res.Status = map[int]string{http.StatusOK: "unchanged", http.StatusCreated: "created"}[s]
		}
		return res, 0, nil
	case s >= 500:
		code, _, _ := c.errorBody(data)
		return nil, retryAfter(resp.Header.Get("Retry-After")), &ServerError{HTTPStatus: s, Code: code}
	case s >= 300 && s < 400:
		return nil, 0, &RejectedError{HTTPStatus: s, Message: "unexpected redirect; check url (it must be the Smoke address itself)"}
	default:
		code, msg, issues := c.errorBody(data)
		e := &RejectedError{HTTPStatus: s, Code: code, Message: msg, Issues: issues, Hint: c.Hints[s]}
		if s == http.StatusTooManyRequests {
			e.RetryAfter = retryAfter(resp.Header.Get("Retry-After"))
		}
		return nil, 0, e
	}
}

// errorBody reads `{ "error": { "code", "message", "details": [{ "issue" }] } }`.
func (c *Client) errorBody(data []byte) (code, msg string, issues []string) {
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details []struct {
				Issue string `json:"issue"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &body) != nil {
		return "", "", nil
	}
	for _, d := range body.Error.Details {
		if d.Issue != "" && len(issues) < 5 {
			issues = append(issues, c.scrub(clip(d.Issue, 64)))
		}
	}
	return c.scrub(clip(body.Error.Code, 64)), c.scrub(clip(body.Error.Message, 300)), issues
}

// Scrub removes the token and control characters from text that will be printed.
func (c *Client) Scrub(s string) string { return c.scrub(s) }

// scrub removes the token and control characters from text that will be printed.
func (c *Client) scrub(s string) string {
	if c.Token != "" {
		s = strings.ReplaceAll(s, c.Token, "[token]")
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// retryAfter parses Retry-After (seconds or an HTTP date). Zero when absent or invalid.
func retryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 || n > 86400 {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// jitter spreads retries by ±20 %.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return d + time.Duration((rand.Float64()*0.4-0.2)*float64(d))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
