package upload

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	token = "smk_test_TOKEN_0123456789abcdef"
	body  = "#smoke-host 1\n#os-release\nID=debian\nVERSION_ID=\"12\"\n"
)

type recorded struct {
	header http.Header
	body   string
}

type server struct {
	t       *testing.T
	mu      sync.Mutex
	reqs    []recorded
	respond func(n int, w http.ResponseWriter)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/v1/collector/report" {
		s.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
	}
	var plain string
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			s.t.Errorf("not gzip: %v", err)
		} else {
			b, _ := io.ReadAll(zr)
			plain = string(b)
		}
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, recorded{header: r.Header.Clone(), body: plain})
	n := len(s.reqs)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	s.respond(n, w)
}

func newClient(t *testing.T, respond func(n int, w http.ResponseWriter)) (*Client, *server, *[]time.Duration) {
	t.Helper()
	s := &server{t: t, respond: respond}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	var waits []time.Duration
	c := &Client{
		Endpoint:  ts.URL + "/api/v1/collector/report",
		Token:     token,
		Version:   "0.1.0",
		UserAgent: "smoke-collector/0.1.0 (linux/amd64)",
		HTTP:      NewHTTPClient(),
		Sleep: func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		},
	}
	return c, s, &waits
}

func reply(status int, json string) func(int, http.ResponseWriter) {
	return func(_ int, w http.ResponseWriter) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, json)
	}
}

func TestCreatedAndRequestShape(t *testing.T) {
	c, s, waits := newClient(t, reply(201, `{"status":"created","assetId":"a1","snapshotId":"s1"}`))
	res, err := c.Upload(context.Background(), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if res.HTTPStatus != 201 || res.Status != "created" || res.AssetID != "a1" || res.SnapshotID != "s1" {
		t.Errorf("res = %+v", res)
	}
	if len(s.reqs) != 1 || len(*waits) != 0 {
		t.Fatalf("requests=%d waits=%v", len(s.reqs), *waits)
	}
	h := s.reqs[0].header
	for k, want := range map[string]string{
		"Authorization":             "Bearer " + token,
		"Content-Type":              "text/plain; charset=utf-8",
		"Content-Encoding":          "gzip",
		"User-Agent":                "smoke-collector/0.1.0 (linux/amd64)",
		"X-Smoke-Collector-Version": "0.1.0",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if s.reqs[0].body != body {
		t.Errorf("gunzipped body = %q", s.reqs[0].body)
	}
	if _, set := h["X-Smoke-Collector-Scans"]; set {
		t.Errorf("X-Smoke-Collector-Scans sent without Scans")
	}
}

func TestScansHeader(t *testing.T) {
	c, s, _ := newClient(t, reply(201, `{"status":"created"}`))
	c.Scans = "os,lockfiles"
	if _, err := c.Upload(context.Background(), []byte(body)); err != nil {
		t.Fatal(err)
	}
	if got := s.reqs[0].header.Get("X-Smoke-Collector-Scans"); got != "os,lockfiles" {
		t.Errorf("X-Smoke-Collector-Scans = %q", got)
	}
}

func TestUnchanged(t *testing.T) {
	c, _, _ := newClient(t, reply(200, `{"status":"unchanged","assetId":"a1","snapshotId":"s0"}`))
	res, err := c.Upload(context.Background(), []byte(body))
	if err != nil || res.Status != "unchanged" || res.SnapshotID != "s0" || res.HTTPStatus != 200 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRejectedNotRetried(t *testing.T) {
	for _, tc := range []struct {
		status int
		json   string
		code   string
		issues []string
	}{
		{401, `{"error":{"code":"UNAUTHENTICATED","message":"Invalid token ` + token + `"}}`, "UNAUTHENTICATED", nil},
		{403, `{"error":{"code":"FORBIDDEN","message":"no"}}`, "FORBIDDEN", nil},
		{422, `{"error":{"code":"VALIDATION_FAILED","message":"bad","details":[{"issue":"unsupported_os","message":"x"}]}}`,
			"VALIDATION_FAILED", []string{"unsupported_os"}},
		{413, `not json`, "", nil},
	} {
		c, s, waits := newClient(t, reply(tc.status, tc.json))
		_, err := c.Upload(context.Background(), []byte(body))
		var re *RejectedError
		if !errors.As(err, &re) {
			t.Fatalf("%d: err = %v", tc.status, err)
		}
		if re.HTTPStatus != tc.status || re.Code != tc.code || strings.Join(re.Issues, ",") != strings.Join(tc.issues, ",") {
			t.Errorf("%d: %+v", tc.status, re)
		}
		if len(s.reqs) != 1 || len(*waits) != 0 {
			t.Errorf("%d: retried (requests=%d)", tc.status, len(s.reqs))
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("%d: error contains the token: %v", tc.status, err)
		}
	}
}

func TestRateLimited(t *testing.T) {
	c, s, waits := newClient(t, func(_ int, w http.ResponseWriter) {
		w.Header().Set("Retry-After", "420")
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"error":{"code":"RATE_LIMITED","message":"Too many attempts"}}`)
	})
	_, err := c.Upload(context.Background(), []byte(body))
	var re *RejectedError
	if !errors.As(err, &re) || re.Code != "RATE_LIMITED" || re.RetryAfter != 420*time.Second {
		t.Fatalf("err = %#v", err)
	}
	if !strings.Contains(err.Error(), "retry after 7m0s") {
		t.Errorf("message = %v", err)
	}
	if len(s.reqs) != 1 || len(*waits) != 0 {
		t.Errorf("4xx retried: requests=%d", len(s.reqs))
	}
}

func TestServerErrorRetriedThenSucceeds(t *testing.T) {
	c, s, waits := newClient(t, func(n int, w http.ResponseWriter) {
		if n < 3 {
			if n == 2 {
				w.Header().Set("Retry-After", "100")
			}
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"status":"created","assetId":"a","snapshotId":"s"}`)
	})
	res, err := c.Upload(context.Background(), []byte(body))
	if err != nil || res.Status != "created" {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if len(s.reqs) != 3 || len(*waits) != 2 {
		t.Fatalf("requests=%d waits=%v", len(s.reqs), *waits)
	}
	if w := (*waits)[0]; w < 12*time.Second || w > 18*time.Second {
		t.Errorf("first wait %s, want 15s ±20%%", w)
	}
	if w := (*waits)[1]; w != 100*time.Second {
		t.Errorf("second wait %s, want Retry-After 100s", w)
	}
	for i, r := range s.reqs {
		if r.body != body {
			t.Errorf("attempt %d body = %q", i+1, r.body)
		}
	}
}

func TestServerErrorGivesUp(t *testing.T) {
	c, s, waits := newClient(t, reply(500, `{"error":{"code":"INTERNAL","message":"x"}}`))
	_, err := c.Upload(context.Background(), []byte(body))
	var se *ServerError
	if !errors.As(err, &se) || se.HTTPStatus != 500 || se.Attempts != 4 || se.Code != "INTERNAL" {
		t.Fatalf("err = %#v", err)
	}
	if len(s.reqs) != 4 || len(*waits) != 3 {
		t.Errorf("requests=%d waits=%v", len(s.reqs), *waits)
	}
	var total time.Duration
	for _, w := range *waits {
		total += w
	}
	if total > 130*time.Second {
		t.Errorf("total wait %s", total)
	}
}

func TestNetworkErrorRetried(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	endpoint := ts.URL + "/api/v1/collector/report"
	ts.Close() // connection refused from now on
	var waits []time.Duration
	c := &Client{Endpoint: endpoint, Token: token, Version: "0.1.0", UserAgent: "x", HTTP: NewHTTPClient(),
		Sleep: func(context.Context, time.Duration) error { waits = append(waits, 0); return nil }}
	_, err := c.Upload(context.Background(), []byte(body))
	var se *ServerError
	if !errors.As(err, &se) || se.HTTPStatus != 0 || se.Attempts != 4 || len(waits) != 3 {
		t.Fatalf("err=%v waits=%d", err, len(waits))
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error contains the token")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	c, _, _ := newClient(t, func(_ int, w http.ResponseWriter) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	_, err := c.Upload(context.Background(), []byte(body))
	var re *RejectedError
	if !errors.As(err, &re) || re.HTTPStatus != 307 || hits != 0 {
		t.Fatalf("err=%v hits=%d", err, hits)
	}
}

func TestContextCancelStopsRetries(t *testing.T) {
	c, s, _ := newClient(t, reply(502, ``))
	ctx, cancel := context.WithCancel(context.Background())
	c.Sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	_, err := c.Upload(ctx, []byte(body))
	var se *ServerError
	if !errors.As(err, &se) || len(s.reqs) != 1 {
		t.Fatalf("err=%v requests=%d", err, len(s.reqs))
	}
}

func TestGzipRoundTrip(t *testing.T) {
	big := strings.Repeat("ii \tlibfoo\t1.0-1\tamd64\tfoo\t1.0-1\n", 5000)
	gz, err := Gzip([]byte(big))
	if err != nil {
		t.Fatal(err)
	}
	if len(gz) >= len(big)/10 {
		t.Errorf("gzip %d of %d bytes", len(gz), len(big))
	}
	zr, err := gzip.NewReader(strings.NewReader(string(gz)))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(zr)
	if string(out) != big {
		t.Error("round trip mismatch")
	}
}

func TestRetryAfterParsing(t *testing.T) {
	future := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	for v, want := range map[string]time.Duration{"": 0, "30": 30 * time.Second, "-1": 0, "abc": 0, "999999": 0} {
		if got := retryAfter(v); got != want {
			t.Errorf("retryAfter(%q) = %s", v, got)
		}
	}
	if d := retryAfter(future); d < 80*time.Second || d > 91*time.Second {
		t.Errorf("date: %s", d)
	}
}
