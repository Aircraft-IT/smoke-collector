package lockfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func write(t *testing.T, p, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func symlink(t *testing.T, target, p string) {
	t.Helper()
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestSupported(t *testing.T) {
	for name, want := range map[string]bool{
		"package-lock.json": true, "npm-shrinkwrap.json": true, "pnpm-lock.yaml": true, "yarn.lock": true,
		"composer.lock": true, "poetry.lock": true, "uv.lock": true, "Pipfile.lock": true, "go.mod": true,
		"Cargo.lock": true, "gradle.lockfile": true, "packages.lock.json": true, "pubspec.lock": true,
		"requirements.txt": true, "requirements-dev.txt": true, "requirements_prod.txt": true,
		"requirements.in.txt": true, "dev-requirements.txt": true, "REQUIREMENTS.TXT": true,
		"base.requirements.txt": true,
		"package.json":          false, "bom.json": false, "app.cdx.json": false, ".env": false, "go.sum": false,
		"pipfile.lock": false, "Cargo.toml": false, "requirements": false, "requirementstxt": false,
		"requirements-.txt": false, "my requirements.txt": false, "sub/yarn.lock": false, "": false,
		"yarn.lock.bak": false,
	} {
		if got := Supported(name); got != want {
			t.Errorf("Supported(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCheckPath(t *testing.T) {
	long := "/" + strings.Repeat("a", MaxPathLen)
	for in, want := range map[string]string{
		"/srv/app":          "/srv/app",
		"/srv/app/":         "/srv/app",
		"/srv/app///":       "/srv/app",
		"/":                 "/",
		"/srv/my app/x.txt": "/srv/my app/x.txt",
		"srv/app":           "",
		"":                  "",
		"/srv//app":         "",
		"/srv/./app":        "",
		"/srv/../etc":       "",
		"/srv/a\tb":         "",
		"/srv/a\x7fb":       "",
		"/srv/\xff":         "",
		long:                "",
	} {
		got, err := CheckPath(in)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("CheckPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestReadDirectoryOnlySupportedNamesNotRecursive(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "app")
	write(t, filepath.Join(app, "package-lock.json"), `{"lockfileVersion":3}`+"\n")
	write(t, filepath.Join(app, "requirements-dev.txt"), "flask==3.0.0\n")
	write(t, filepath.Join(app, ".env"), "SECRET=1\n")
	write(t, filepath.Join(app, "package.json"), "{}\n")
	write(t, filepath.Join(app, "index.js"), "console.log(1)\n")
	write(t, filepath.Join(app, "sub", "yarn.lock"), "# nested\n")
	write(t, filepath.Join(app, "node_modules", "x", "package-lock.json"), "{}\n")
	if err := os.Mkdir(filepath.Join(app, "go.mod"), 0o755); err != nil { // a directory with a supported name
		t.Fatal(err)
	}
	symlink(t, filepath.Join(root, "nowhere", "Cargo.lock"), filepath.Join(app, "Cargo.lock")) // dangling
	if os.Geteuid() != 0 {
		// Never opened: an unreadable .env does not make the path unreadable.
		if err := os.Chmod(filepath.Join(app, ".env"), 0); err != nil {
			t.Fatal(err)
		}
	}

	rep := (&Reader{}).Read([]string{app})
	if len(rep.Lockfiles) != 1 {
		t.Fatalf("entries = %+v", rep.Lockfiles)
	}
	e := rep.Lockfiles[0]
	if e.Status != StatusOK || !e.Dir || len(e.Files) != 2 {
		t.Fatalf("entry = %+v", e)
	}
	if e.Files[0].Name != "package-lock.json" || e.Files[1].Name != "requirements-dev.txt" {
		t.Errorf("names = %s, %s", e.Files[0].Name, e.Files[1].Name)
	}
	f := e.Files[1]
	if f.Content != "flask==3.0.0\n" || f.Size != 13 || f.SHA256 != sha("flask==3.0.0\n") {
		t.Errorf("file = %+v", f)
	}
}

func TestReadStatuses(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "releases", "20261113", "Gemfile"), "x")
	write(t, filepath.Join(root, "releases", "20261113", "composer.lock"), `{"packages":[]}`)
	symlink(t, filepath.Join(root, "releases", "20261113"), filepath.Join(root, "current")) // Capistrano
	lock := write(t, filepath.Join(root, "single", "yarn.lock"), "# yarn lockfile v1\n")
	symlink(t, lock, filepath.Join(root, "linked-yarn.lock")) // a link with an unsupported name
	symlink(t, lock, filepath.Join(root, "yarn.lock"))        // a link with a supported name
	write(t, filepath.Join(root, "notes.txt"), "x")
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "fifo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo", "yarn.lock"), 0o644); err != nil {
		t.Fatal(err)
	}

	paths := []string{
		filepath.Join(root, "current"),
		lock,
		filepath.Join(root, "yarn.lock"),
		filepath.Join(root, "linked-yarn.lock"),
		filepath.Join(root, "notes.txt"),
		filepath.Join(root, "missing"),
		filepath.Join(root, "notes.txt", "sub"), // through a file: ENOTDIR
		filepath.Join(root, "empty"),
		filepath.Join(root, "fifo"),
		filepath.Join(root, "fifo", "yarn.lock"),
	}
	want := []Status{StatusOK, StatusOK, StatusOK, StatusNoLockfile, StatusNoLockfile, StatusNotFound,
		StatusNotFound, StatusNoLockfile, StatusUnreadable, StatusUnreadable}

	done := make(chan *Report)
	go func() { done <- (&Reader{}).Read(paths) }()
	var rep *Report
	select {
	case rep = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Read blocked (a FIFO opened?)")
	}
	for i, e := range rep.Lockfiles {
		if e.Path != paths[i] || e.Status != want[i] {
			t.Errorf("%s: status %s (%s), want %s", paths[i], e.Status, e.Reason, want[i])
		}
		if (e.Status == StatusOK) != (len(e.Files) > 0) {
			t.Errorf("%s: %d files with status %s", paths[i], len(e.Files), e.Status)
		}
		if e.Status != StatusOK && e.Reason == "" {
			t.Errorf("%s: no reason", paths[i])
		}
	}
	if fs := rep.Lockfiles[0].Files; len(fs) != 1 || fs[0].Name != "composer.lock" {
		t.Errorf("symlinked release directory: %+v", fs)
	}
	if fs := rep.Lockfiles[2].Files; len(fs) != 1 || fs[0].Name != "yarn.lock" || rep.Lockfiles[2].Dir {
		t.Errorf("symlinked file: %+v", rep.Lockfiles[2])
	}
}

func TestReadPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := t.TempDir()
	write(t, filepath.Join(root, "closed", "go.mod"), "module x\n")
	write(t, filepath.Join(root, "file", "go.mod"), "module x\n")
	write(t, filepath.Join(root, "file", "uv.lock"), "version = 1\n")
	for p, mode := range map[string]os.FileMode{"closed": 0, "file/go.mod": 0} {
		if err := os.Chmod(filepath.Join(root, p), mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "closed"), 0o755) })
	var logs []string
	r := &Reader{Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	rep := r.Read([]string{
		filepath.Join(root, "closed"),
		filepath.Join(root, "closed", "go.mod"),
		filepath.Join(root, "file"),
		filepath.Join(root, "file", "go.mod"),
	})
	for i, e := range rep.Lockfiles {
		if e.Status != StatusUnreadable || len(e.Files) != 0 {
			t.Errorf("%d %s: %s (%s)", i, e.Path, e.Status, e.Reason)
		}
	}
	if !strings.Contains(rep.Lockfiles[2].Reason, "go.mod") {
		t.Errorf("reason does not name the file: %q", rep.Lockfiles[2].Reason)
	}
	if len(logs) != 4 || !strings.Contains(logs[0], "unreadable") {
		t.Errorf("logs = %q", logs)
	}
}

func TestSizeLimits(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "small", "go.mod"), strings.Repeat("a", 100))
	write(t, filepath.Join(root, "big", "go.mod"), strings.Repeat("a", 1001))
	write(t, filepath.Join(root, "big", "uv.lock"), "small")
	write(t, filepath.Join(root, "edge", "go.mod"), strings.Repeat("b", 1000))
	write(t, filepath.Join(root, "more", "go.mod"), strings.Repeat("c", 600))

	r := &Reader{MaxFileBytes: 1000, MaxTotalBytes: 2000}
	rep := r.Read([]string{
		filepath.Join(root, "small"),
		filepath.Join(root, "big"),
		filepath.Join(root, "edge"),
		filepath.Join(root, "more"), // 100 + 1000 + 600 content plus JSON > 2000
		filepath.Join(root, "small"),
	})
	want := []Status{StatusOK, StatusTooLarge, StatusOK, StatusTooLarge, StatusOK}
	for i, e := range rep.Lockfiles {
		if e.Status != want[i] {
			t.Errorf("%d %s: %s (%s), want %s", i, e.Path, e.Status, e.Reason, want[i])
		}
	}
	body, err := rep.Body()
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 2000 {
		t.Errorf("body is %d bytes, over the total", len(body))
	}

	// More than 20 lockfiles in one directory.
	many := filepath.Join(root, "many")
	for i := 0; i <= MaxFilesPerPath; i++ {
		write(t, filepath.Join(many, fmt.Sprintf("requirements-%02d.txt", i)), "x==1\n")
	}
	if e := (&Reader{}).Read([]string{many}).Lockfiles[0]; e.Status != StatusTooLarge {
		t.Errorf("21 files: %s", e.Status)
	}
}

func TestInvalidUTF8(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "yarn.lock"), "a\xffb\n")
	var logs []string
	r := &Reader{Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	e := r.Read([]string{filepath.Join(root, "yarn.lock")}).Lockfiles[0]
	if e.Status != StatusOK || e.Files[0].Content != "a�b\n" || e.Files[0].SHA256 != sha("a�b\n") ||
		e.Files[0].Size != len("a�b\n") || len(logs) != 1 {
		t.Errorf("entry = %+v logs = %q", e, logs)
	}
}

func TestBodyAndDigest(t *testing.T) {
	rep := &Report{Lockfiles: []Entry{
		{Path: "/srv/billing/current", Status: StatusOK, Dir: true, Files: []File{
			{Name: "yarn.lock", Content: "<a>&\"q\"\n", SHA256: sha("<a>&\"q\"\n")},
			{Name: "package-lock.json", Content: "{}", SHA256: sha("{}")},
		}},
		{Path: "/home/app/shop", Status: StatusUnreadable, Reason: "permission denied"},
	}}
	body, err := rep.Body()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"lockfiles":[{"path":"/srv/billing/current","status":"ok","files":[{"name":"yarn.lock","content":"<a>&\"q\"\n"},` +
		`{"name":"package-lock.json","content":"{}"}]},{"path":"/home/app/shop","status":"unreadable"}]}` + "\n"
	if string(body) != want {
		t.Errorf("body =\n%s\nwant\n%s", body, want)
	}
	var back Report
	if err := json.Unmarshal(body, &back); err != nil || back.Lockfiles[0].Files[0].Content != "<a>&\"q\"\n" {
		t.Errorf("round trip: %v %+v", err, back)
	}
	empty, _ := (&Report{Lockfiles: []Entry{}}).Body()
	if string(empty) != `{"lockfiles":[]}`+"\n" {
		t.Errorf("empty body = %s", empty)
	}

	lines := "package-lock.json\t" + sha("{}") + "\n" + "yarn.lock\t" + sha("<a>&\"q\"\n") + "\n"
	if got := Digest(rep.Lockfiles[0].Files); got != sha(lines) {
		t.Errorf("Digest = %s, want %s", got, sha(lines))
	}
	if rep.Lockfiles[0].Files[0].Name != "yarn.lock" {
		t.Error("Digest reordered its argument")
	}
}
