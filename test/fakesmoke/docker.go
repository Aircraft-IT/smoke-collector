package main

import (
	"archive/tar"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Fake Docker Engine API for install tests: one running container ("local/install-test:1")
// whose file system is this machine's own, so the container collector reads the test image's
// real os-release and package database. Only the four GET paths the collector uses exist;
// every other request is answered 403 and logged, so a test can check nothing else was asked.
const (
	fakeContainerID = "1111111111111111111111111111111111111111111111111111111111111111"
	fakeImageID     = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func serveDocker(socket string, gid int) {
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	if gid >= 0 {
		if err := os.Chown(socket, 0, gid); err != nil {
			log.Fatal(err)
		}
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1.41/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Version":"27.0.0-fake","ApiVersion":"1.47"}`)
	})
	mux.HandleFunc("GET /v1.41/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"Id":"`+fakeContainerID+`","Names":["/install-test"],"Image":"local/install-test:1","ImageID":"`+fakeImageID+`"}]`)
	})
	mux.HandleFunc("GET /v1.41/images/"+fakeImageID+"/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Id":"`+fakeImageID+`","RepoTags":["local/install-test:1"],"RepoDigests":[]}`)
	})
	mux.HandleFunc("GET /v1.41/containers/"+fakeContainerID+"/archive", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if _, err := os.Lstat(p); err != nil {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"message":"Could not find the file `+p+` in container"}`)
			return
		}
		w.Header().Set("Content-Type", "application/x-tar")
		tw := tar.NewWriter(w)
		writeTree(tw, p, filepath.Base(p))
		_ = tw.Close()
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("docker: refused %s %s", r.Method, r.URL.Path)
		w.WriteHeader(403)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.Serve(ln))
}

// writeTree writes p (a file, symlink or directory one level deep) like `docker cp` does.
func writeTree(tw *tar.Writer, p, name string) {
	st, err := os.Lstat(p)
	if err != nil {
		return
	}
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		target, _ := os.Readlink(p)
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777})
	case st.IsDir():
		_ = tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		entries, _ := os.ReadDir(p)
		for _, e := range entries {
			if !strings.HasPrefix(name, "rpm") && e.Type().IsRegular() {
				writeTree(tw, filepath.Join(p, e.Name()), name+"/"+e.Name())
			}
		}
	case st.Mode().IsRegular():
		data, err := os.ReadFile(p)
		if err != nil {
			return
		}
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(data)), Mode: 0o644})
		_, _ = tw.Write(data)
	}
}
