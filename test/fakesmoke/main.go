// Command fakesmoke is a stand-in for Smoke used by scripts/test-install.sh: it serves a
// download tree under /downloads/collector/ and implements enough of
// POST /api/v1/collector/report (OS detection plan §5.2) to exercise the collector:
// bearer token, gzip, the #smoke-host 1 marker, 201 created / 200 unchanged by SHA-256.
// It also accepts POST /api/v1/collector/containers (the container collector) and, with
// -docker-socket, serves a minimal Docker Engine API on that unix socket: one running container
// whose files are this machine's own (see docker.go).
// It never prints the token. Test use only.
package main

import (
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const maxBody = 5 << 20

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	dir := flag.String("dir", "", "download tree served at /downloads/collector/")
	tokenFile := flag.String("token-file", "", "file holding the accepted token")
	save := flag.String("save", "", "write the last accepted report here")
	saveContainers := flag.String("save-containers", "", "write the last accepted container report here")
	dockerSocket := flag.String("docker-socket", "", "serve a fake Docker Engine API on this unix socket")
	dockerGroup := flag.Int("docker-gid", -1, "group of the fake Docker socket (mode 0660)")
	flag.Parse()
	tok, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatal(err)
	}
	token := strings.TrimSpace(string(tok))

	var mu sync.Mutex
	var last string
	mux := http.NewServeMux()
	mux.Handle("GET /downloads/collector/", http.StripPrefix("/downloads/collector/", http.FileServer(http.Dir(*dir))))
	mux.HandleFunc("POST /api/v1/collector/report", func(w http.ResponseWriter, r *http.Request) {
		reply := func(status int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
		apiErr := func(status int, code, msg, issue string) {
			e := map[string]any{"code": code, "message": msg}
			if issue != "" {
				e["details"] = []map[string]string{{"issue": issue}}
			}
			log.Printf("report rejected: %d %s", status, code)
			reply(status, map[string]any{"error": e})
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			apiErr(401, "UNAUTHENTICATED", "Invalid token", "")
			return
		}
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				apiErr(400, "BAD_REQUEST", "bad gzip", "")
				return
			}
			body = zr
		}
		data, err := io.ReadAll(io.LimitReader(body, maxBody+1))
		if err != nil || len(data) > maxBody {
			apiErr(413, "PAYLOAD_TOO_LARGE", "too large", "")
			return
		}
		if !strings.HasPrefix(string(data), "#smoke-host 1\n") {
			apiErr(422, "VALIDATION_FAILED", "not #smoke-host 1", "malformed_host_inventory")
			return
		}
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		mu.Lock()
		unchanged := h == last
		last = h
		mu.Unlock()
		if *save != "" {
			_ = os.WriteFile(*save, data, 0o600)
		}
		status, code := "created", 201
		if unchanged {
			status, code = "unchanged", 200
		}
		//nolint:gosec // header values are %q-quoted; test server only
		log.Printf("report %s: %d bytes sha256=%s gzip=%v ua=%q version=%q", status, len(data), h[:12],
			r.Header.Get("Content-Encoding") == "gzip", r.UserAgent(), r.Header.Get("X-Smoke-Collector-Version"))
		reply(code, map[string]string{"status": status, "assetId": "asset-1", "snapshotId": "snap-" + h[:8]})
	})
	mux.HandleFunc("POST /api/v1/collector/containers", func(w http.ResponseWriter, r *http.Request) {
		reply := func(status int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			log.Printf("container report rejected: 401")
			reply(401, map[string]any{"error": map[string]string{"code": "UNAUTHENTICATED", "message": "Invalid token"}})
			return
		}
		if r.Header.Get("Content-Type") != "application/vnd.smoke.container-report+json" || r.Header.Get("Content-Encoding") != "gzip" {
			log.Printf("container report rejected: 415")
			reply(415, map[string]any{"error": map[string]string{"code": "UNSUPPORTED_MEDIA_TYPE", "message": "bad content type"}})
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			reply(400, map[string]any{"error": map[string]string{"code": "BAD_REQUEST", "message": "bad gzip"}})
			return
		}
		data, err := io.ReadAll(io.LimitReader(zr, 4*maxBody+1))
		var report struct {
			Images []struct {
				ImageID string `json:"imageId"`
				Status  string `json:"status"`
			} `json:"images"`
		}
		if err != nil || len(data) > 4*maxBody || json.Unmarshal(data, &report) != nil || report.Images == nil {
			reply(400, map[string]any{"error": map[string]string{"code": "VALIDATION_FAILED", "message": "bad report"}})
			return
		}
		if *saveContainers != "" {
			_ = os.WriteFile(*saveContainers, data, 0o600)
		}
		var results []map[string]string
		for _, img := range report.Images {
			res := map[string]string{"imageId": img.ImageID, "result": "linked", "assetId": "asset-c"}
			if img.Status == "ok" {
				res["result"], res["snapshotId"] = "created", "snap-c"
			}
			results = append(results, res)
		}
		//nolint:gosec // header values are %q-quoted; test server only
		log.Printf("container report accepted: %d images, %d bytes ua=%q", len(report.Images), len(data), r.UserAgent())
		reply(200, map[string]any{"images": results})
	})
	if *dockerSocket != "" {
		go serveDocker(*dockerSocket, *dockerGroup)
	}
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintf(os.Stderr, "fakesmoke listening on %s\n", *addr)
	log.Fatal(srv.ListenAndServe())
}
