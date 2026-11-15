package containers

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"gitlab.aircraft.tw/smoke/smoke-collector/internal/docker"
)

func id64(c byte) string  { return strings.Repeat(string(c), 64) }
func imgID(c byte) string { return "sha256:" + id64(c) }

// entry is one tar entry of a fake archive.
type entry struct {
	name, body, link string
	dir              bool
}

func tarOf(entries ...entry) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644}
		switch {
		case e.dir:
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		case e.link != "":
			h.Typeflag, h.Linkname = tar.TypeSymlink, e.link
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			panic(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = io.WriteString(tw, e.body)
		}
	}
	_ = tw.Close()
	return b.Bytes()
}

// fakeFS is a container file system: path → archive, as the Engine would return it.
type fakeFS map[string][]byte

func file(p, body string) (string, []byte) {
	return p, tarOf(entry{name: p[strings.LastIndex(p, "/")+1:], body: body})
}

type fakeAPI struct {
	containers []docker.Container
	images     map[string]*docker.Image
	fs         map[string]fakeFS // container ID → files
	archives   []string          // requested container:path
	failList   error
}

func (f *fakeAPI) Containers(context.Context) ([]docker.Container, error) {
	return f.containers, f.failList
}

func (f *fakeAPI) Image(_ context.Context, id string) (*docker.Image, error) {
	if img, ok := f.images[id]; ok {
		return img, nil
	}
	return nil, fmt.Errorf("%w: no such image", docker.ErrNotFound)
}

func (f *fakeAPI) Archive(_ context.Context, id, p string) (io.ReadCloser, error) {
	f.archives = append(f.archives, id[:4]+":"+p)
	fs, ok := f.fs[id]
	if !ok {
		return nil, errors.New("docker: HTTP 404: No such container")
	}
	data, ok := fs[p]
	if !ok {
		return nil, fmt.Errorf("%w: Could not find the file %s", docker.ErrNotFound, p)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func fsOf(files ...any) fakeFS {
	fs := fakeFS{}
	for i := 0; i < len(files); i += 2 {
		fs[files[i].(string)] = files[i+1].([]byte)
	}
	return fs
}

const ubuntuOS = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n"

const dpkgStatus = `Package: libssl3t64
Status: install ok installed
Priority: optional
Architecture: amd64
Multi-Arch: same
Source: openssl (3.0.13-0ubuntu3.4)
Version: 3.0.13-0ubuntu3.4
Description: Secure Sockets Layer toolkit
 This package is part of the OpenSSL project.
 .
 Status: not a field

Package: base-files
Essential: yes
Status: install ok installed
Architecture: amd64
Version: 13ubuntu10.1

Package: removed-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: purged
Status: purge ok not-installed
Architecture: amd64

Package: held
Status: hold ok installed
Architecture: all
Source: heldsrc
Version: 2:1.0-1
`

func TestDpkgLines(t *testing.T) {
	got := string(dpkgLines([]byte(dpkgStatus)))
	want := "ii \tbase-files\t13ubuntu10.1\tamd64\tbase-files\t13ubuntu10.1\n" +
		"hi \theld\t2:1.0-1\tall\theldsrc\t2:1.0-1\n" +
		"ii \tlibssl3t64\t3.0.13-0ubuntu3.4\tamd64\topenssl\t3.0.13-0ubuntu3.4\n" +
		"rc \tremoved-pkg\t1.0\tamd64\tremoved-pkg\t1.0\n"
	if got != want {
		t.Errorf("dpkgLines:\n%q\nwant\n%q", got, want)
	}
}

func TestApkLines(t *testing.T) {
	db := "C:Q1abc=\nP:musl\nV:1.2.5-r0\nA:x86_64\nS:1\nI:2\nT:the musl c library\nU:https://musl.libc.org/\nL:MIT\no:musl\nm:Maintainer <m@example.org>\nt:1\nc:abc\nF:lib\nR:ld-musl-x86_64.so.1\n\n" +
		"P:busybox-binsh\nV:1.36.1-r29\nA:x86_64\nL:GPL-2.0-only\no:busybox\n\n" +
		"P:alpine-baselayout-data\nV:3.6.5-r0\nA:x86_64\nL:GPL-2.0-only\no:alpine-baselayout\n"
	want := "alpine-baselayout-data-3.6.5-r0 x86_64 {alpine-baselayout} (GPL-2.0-only) [installed]\n" +
		"busybox-binsh-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only) [installed]\n" +
		"musl-1.2.5-r0 x86_64 {musl} (MIT) [installed]\n"
	if got := string(apkLines([]byte(db))); got != want {
		t.Errorf("apkLines:\n%s\nwant\n%s", got, want)
	}
}

func TestCollect(t *testing.T) {
	ubuntu := fsOf(
		"/etc/os-release", tarOf(entry{name: "os-release", link: "../usr/lib/os-release"}),
		"/usr/lib/os-release", tarOf(entry{name: "os-release", body: ubuntuOS}),
		"/var/lib/dpkg/status", tarOf(entry{name: "status", body: dpkgStatus}),
	)
	distroless := fsOf(
		"/etc/os-release", tarOf(entry{name: "os-release", body: "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n"}),
		"/var/lib/dpkg/status.d", tarOf(
			entry{name: "status.d/", dir: true},
			entry{name: "status.d/libc6", body: "Package: libc6\nVersion: 2.36-9+deb12u9\nArchitecture: amd64\nSource: glibc\n"},
			entry{name: "status.d/libc6.md5sums", body: "abc  lib/x\n"},
			entry{name: "status.d/base-files", body: "Package: base-files\nVersion: 12.4+deb12u9\nArchitecture: amd64\n"},
		),
	)
	alpine := fsOf(
		"/etc/os-release", tarOf(entry{name: "os-release", body: "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.21.2\nPRETTY_NAME=\"Alpine Linux v3.21\"\n"}),
		"/lib/apk/db/installed", tarOf(entry{name: "installed", body: "P:musl\nV:1.2.5-r8\nA:aarch64\nL:MIT\no:musl\n"}),
	)
	ubi := fsOf(
		"/etc/os-release", tarOf(entry{name: "os-release", body: "ID=\"rhel\"\nVERSION_ID=\"9.5\"\n"}),
		"/var/lib/rpm", tarOf(entry{name: "rpm/", dir: true}),
	)
	scratch := fsOf()
	fedoraDpkg := fsOf( // dpkg database, unsupported distribution
		"/etc/os-release", tarOf(entry{name: "os-release", body: "ID=linuxmint\nVERSION_ID=22\n"}),
		"/var/lib/dpkg/status", tarOf(entry{name: "status", body: dpkgStatus}),
	)
	api := &fakeAPI{
		containers: []docker.Container{
			{ID: id64('a'), Image: "ubuntu:24.04", ImageID: imgID('1')},
			{ID: id64('b'), Image: "ubuntu:24.04", ImageID: imgID('1')},
			{ID: id64('c'), Image: imgID('2'), ImageID: imgID('2')}, // started by ID: tag from the image
			{ID: id64('d'), Image: "registry.acme.internal:5000/team/api:1.4", ImageID: imgID('3')},
			{ID: id64('e'), Image: "ubi9/ubi-micro", ImageID: imgID('4')},
			{ID: id64('f'), Image: "scratch-app", ImageID: imgID('5')},
			{ID: id64('9'), Image: "deadbeef0123", ImageID: imgID('6')}, // short ID, image untagged
			{ID: id64('8'), Image: "mint", ImageID: imgID('7')},
			{ID: id64('7'), Image: "x", ImageID: "not-an-id"},
		},
		images: map[string]*docker.Image{
			imgID('1'): {RepoTags: []string{"ubuntu:24.04"}, RepoDigests: []string{"ubuntu@sha256:" + id64('d')}},
			imgID('2'): {RepoTags: []string{"gcr.io/distroless/base-debian12:latest"}},
			imgID('3'): {RepoTags: []string{"registry.acme.internal:5000/team/api:1.4"}, RepoDigests: []string{
				"other/repo@sha256:" + id64('e'), "registry.acme.internal:5000/team/api@sha256:" + id64('f')}},
			imgID('6'): {RepoTags: []string{"<none>:<none>"}},
			imgID('4'): {RepoTags: []string{"ubi9/ubi-micro:latest"}},
			imgID('5'): {},
			imgID('7'): {RepoTags: []string{"mint:latest"}},
		},
		fs: map[string]fakeFS{id64('a'): ubuntu, id64('c'): distroless, id64('d'): alpine, id64('e'): ubi, id64('f'): scratch, id64('8'): fedoraDpkg},
	}
	var logs []string
	c := &Collector{API: api, Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Image{}
	for _, img := range r.Images {
		got[img.ImageID] = img
	}
	if len(r.Images) != 7 || r.Images[0].ImageID != imgID('1') || r.Images[0].Containers != 2 {
		t.Fatalf("images: %+v", r.Images)
	}
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	for id, want := range map[string]struct{ ref, digest, status, inventory string }{
		imgID('1'): {"ubuntu:24.04", "sha256:" + id64('d'), "ok", "#smoke-host 1\n#os-release\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\n#packages dpkg\n" +
			string(dpkgLines([]byte(dpkgStatus)))},
		imgID('2'): {"gcr.io/distroless/base-debian12:latest", "<nil>", "ok", "#smoke-host 1\n#os-release\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n#packages dpkg\n" +
			"ii \tbase-files\t12.4+deb12u9\tamd64\tbase-files\t12.4+deb12u9\nii \tlibc6\t2.36-9+deb12u9\tamd64\tglibc\t2.36-9+deb12u9\n"},
		imgID('3'): {"registry.acme.internal:5000/team/api:1.4", "sha256:" + id64('f'), "ok", "#smoke-host 1\n#os-release\nID=alpine\nVERSION_ID=3.21.2\n#packages apk\nmusl-1.2.5-r8 aarch64 {musl} (MIT) [installed]\n"},
		imgID('4'): {"ubi9/ubi-micro", "<nil>", "unsupported", ""},
		imgID('5'): {"scratch-app", "<nil>", "no_packages", ""},
		imgID('6'): {"<nil>", "<nil>", "untagged", ""},
		imgID('7'): {"mint", "<nil>", "unsupported", ""},
	} {
		g := got[id]
		if str(g.Reference) != want.ref || str(g.RepoDigest) != want.digest || g.Status != want.status || g.Inventory != want.inventory {
			t.Errorf("%s:\n got  ref=%s digest=%s status=%s inventory=%q\n want ref=%s digest=%s status=%s inventory=%q",
				id[:9], str(g.Reference), str(g.RepoDigest), g.Status, g.Inventory, want.ref, want.digest, want.status, want.inventory)
		}
	}
	// One container per image is read; the untagged image is not read at all.
	for _, a := range api.archives {
		if strings.HasPrefix(a, "bbbb") || strings.HasPrefix(a, "9999") {
			t.Errorf("unexpected read %s", a)
		}
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "unexpected image ID") {
		t.Errorf("logs: %q", logs)
	}
}

func TestCollectLimitAndFallback(t *testing.T) {
	alpine := fsOf(
		"/etc/os-release", tarOf(entry{name: "os-release", body: "ID=alpine\nVERSION_ID=3.21.0\n"}),
		"/lib/apk/db/installed", tarOf(entry{name: "installed", body: "P:musl\nV:1.2.5-r8\nA:x86_64\nL:MIT\no:musl\n"}),
	)
	api := &fakeAPI{
		containers: []docker.Container{
			// The first container of image 1 is gone (stopped meanwhile): the second one is read.
			{ID: id64('a'), Image: "a:1", ImageID: imgID('1')},
			{ID: id64('b'), Image: "a:1", ImageID: imgID('1')},
			{ID: id64('c'), Image: "b:1", ImageID: imgID('2')},
			{ID: id64('d'), Image: "c:1", ImageID: imgID('3')},
		},
		fs: map[string]fakeFS{id64('b'): alpine, id64('c'): alpine, id64('d'): alpine},
	}
	var logs []string
	c := &Collector{API: api, MaxImages: 2, Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	statuses := []string{}
	for _, img := range r.Images {
		statuses = append(statuses, img.Status)
	}
	if strings.Join(statuses, ",") != "ok,ok,skipped_limit" {
		t.Errorf("statuses %v", statuses)
	}
	if r.Images[2].Inventory != "" || r.Images[2].Reference == nil {
		t.Errorf("skipped image: %+v", r.Images[2])
	}
}

func TestCollectEdgeCases(t *testing.T) {
	big := strings.Repeat("x", MaxFileBytes+1)
	loop := fsOf(
		"/etc/os-release", tarOf(entry{name: "os-release", link: "/etc/os-release"}),
	)
	huge := fsOf(
		"/etc/os-release", tarOf(entry{name: "os-release", body: "ID=alpine\nVERSION_ID=3.21.0\n"}),
		"/lib/apk/db/installed", tarOf(entry{name: "installed", body: big}),
	)
	api := &fakeAPI{
		containers: []docker.Container{
			{ID: id64('a'), Image: "loop:1", ImageID: imgID('1')},
			{ID: id64('b'), Image: "huge:1", ImageID: imgID('2')},
		},
		fs: map[string]fakeFS{id64('a'): loop, id64('b'): huge},
	}
	var logs []string
	c := &Collector{API: api, Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range r.Images {
		if img.Status != StatusNoPackages {
			t.Errorf("%s: %s", img.ImageID[:9], img.Status)
		}
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "symbolic links") || !strings.Contains(joined, "larger than") {
		t.Errorf("logs: %s", joined)
	}

	// No running containers: an empty list (still sent: it clears the deployment links).
	r, err = (&Collector{API: &fakeAPI{}}).Collect(context.Background())
	if err != nil || r.Images == nil || len(r.Images) != 0 {
		t.Errorf("empty: %+v %v", r, err)
	}
	// Docker unreachable: an error.
	if _, err := (&Collector{API: &fakeAPI{failList: errors.New("cannot reach Docker")}}).Collect(context.Background()); err == nil {
		t.Error("want an error")
	}
}

func TestRepository(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                          "nginx",
		"nginx:1.27":                     "nginx",
		"registry:5000/a/b":              "registry:5000/a/b",
		"registry:5000/a/b:1.0":          "registry:5000/a/b",
		"nginx@sha256:" + id64('a'):      "nginx",
		"nginx:1.27@sha256:" + id64('a'): "nginx",
	} {
		if got := repository(in); got != want {
			t.Errorf("repository(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLabels(t *testing.T) {
	long := strings.Repeat("x", maxLabelValue+1)
	img := &docker.Image{Config: &docker.ImageConfig{Labels: map[string]string{
		"org.opencontainers.image.source":        "https://github.com/gotenberg/gotenberg",
		"org.opencontainers.image.title":         "Gotenberg",
		"org.opencontainers.image.version":       "8.34.0",
		"org.opencontainers.image.authors":       "Someone <someone@example.com>",
		"org.opencontainers.image.documentation": "https://gotenberg.dev",
		"com.acme.secret":                        "hunter2",
		"org.opencontainers.image.base.name":     long,
	}}}
	got := labels(img)
	want := map[string]string{
		"org.opencontainers.image.source":  "https://github.com/gotenberg/gotenberg",
		"org.opencontainers.image.title":   "Gotenberg",
		"org.opencontainers.image.version": "8.34.0",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("labels = %v, want %v", got, want)
	}
	ctrl := &docker.Image{Config: &docker.ImageConfig{Labels: map[string]string{
		"org.opencontainers.image.title": "a\nb", "org.opencontainers.image.version": "ünï",
	}}}
	for _, i := range []*docker.Image{nil, {}, ctrl} {
		if l := labels(i); l == nil || len(l) != 0 {
			t.Errorf("labels(%+v) = %v, want empty", i, l)
		}
	}
	// The report always carries the field, so Smoke can tell this collector reads labels.
	b, _ := json.Marshal(Image{ImageID: imgID('1'), Labels: labels(nil)})
	if !strings.Contains(string(b), `"labels":{}`) {
		t.Errorf("report: %s", b)
	}
}
