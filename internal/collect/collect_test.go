package collect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeProgram struct {
	out string
	err error
	// byVerb, when set, gives the output by first argument (systemctl list-units / show).
	byVerb map[string]string
}

type fakeHost struct {
	t     *testing.T
	root  string
	progs map[string]fakeProgram
	calls [][]string
}

func newHost(t *testing.T, osRelease string) *fakeHost {
	t.Helper()
	h := &fakeHost{t: t, root: t.TempDir(), progs: map[string]fakeProgram{}}
	h.file("etc/os-release", osRelease)
	return h
}

func (h *fakeHost) file(rel, body string) {
	h.t.Helper()
	p := filepath.Join(h.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// program installs an executable placeholder at dir/name whose run returns out.
func (h *fakeHost) program(dir, name, out string, err error) {
	h.t.Helper()
	p := filepath.Join(h.root, dir, name)
	if e := os.MkdirAll(filepath.Dir(p), 0o755); e != nil {
		h.t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte("#!/bin/false\n"), 0o755); e != nil {
		h.t.Fatal(e)
	}
	h.progs[p] = fakeProgram{out: out, err: err}
}

func (h *fakeHost) collector() *Collector {
	return &Collector{
		Root: h.root,
		Dirs: SearchDirs,
		Exec: func(_ context.Context, path string, args ...string) ([]byte, error) {
			h.calls = append(h.calls, append([]string{strings.TrimPrefix(path, h.root)}, args...))
			p, ok := h.progs[path]
			if !ok {
				h.t.Fatalf("unexpected program %s", path)
			}
			if p.byVerb != nil && len(args) > 0 {
				return []byte(p.byVerb[args[0]]), p.err
			}
			return []byte(p.out), p.err
		},
		KernelRelease: func() (string, error) { return "6.8.0-45-generic", nil },
	}
}

const ubuntuOSRelease = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble
`

const dpkgOut = "ii \tlibssl3t64\t3.0.13-0ubuntu3.4\tamd64\topenssl\t3.0.13-0ubuntu3.4\n" +
	"ii \topenssl\t3.0.13-0ubuntu3.4\tamd64\t\t\n" +
	"hi \tbash\t5.2.21-2ubuntu4\tamd64\tbash\t5.2.21-2ubuntu4\n" +
	"rc \told-lib\t1.0-1\tamd64\told-lib\t1.0-1\n"

const systemctlOut = "nginx.service loaded active running A high performance web server\n" +
	"ssh.service   loaded active running OpenBSD Secure Shell server\n" +
	"user@1000.service loaded active running User Manager for UID 1000\n"

func TestUbuntu(t *testing.T) {
	h := newHost(t, ubuntuOSRelease)
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	h.program("usr/bin", "systemctl", systemctlOut, nil)
	h.file("var/run/reboot-required", "*** System restart required ***\n")
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "#smoke-host 1\n" +
		"#os-release\n" +
		"VERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\n" +
		"#kernel\n6.8.0-45-generic\n" +
		"#packages dpkg\n" + dpkgOut +
		"#services\nnginx.service\nssh.service\nuser@1000.service\n" +
		"#service-packages\n" +
		"#reboot-required\nyes\n"
	if got := string(res.Body); got != want {
		t.Errorf("body:\n%s\nwant:\n%s", got, want)
	}
	if res.Manager != Dpkg || res.OSID != "ubuntu" {
		t.Errorf("manager=%s id=%s", res.Manager, res.OSID)
	}
	wantCalls := [][]string{
		{"/usr/bin/dpkg-query", "-W", `-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n`},
		{"/usr/bin/systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"},
	}
	if !reflect.DeepEqual(h.calls, wantCalls) {
		t.Errorf("calls = %q", h.calls)
	}
}

func TestDebianContainer(t *testing.T) {
	// No systemctl, no reboot-required file, os-release without a final newline.
	h := newHost(t, "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian")
	h.program("usr/bin", "dpkg-query", "ii \tbase-files\t12.4+deb12u7\tarm64\t\t\n", nil)
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "#smoke-host 1\n#os-release\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nID=debian\n" +
		"#kernel\n6.8.0-45-generic\n#packages dpkg\nii \tbase-files\t12.4+deb12u7\tarm64\t\t\n" +
		"#services\n#service-packages\n#reboot-required\nno\n"
	if string(res.Body) != want {
		t.Errorf("body:\n%q\nwant:\n%q", res.Body, want)
	}
}

func TestAlpine(t *testing.T) {
	h := newHost(t, "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.21.3\nPRETTY_NAME=\"Alpine Linux v3.21\"\nHOME_URL=\"https://alpinelinux.org/\"\n")
	apkOut := "musl-1.2.5-r9 aarch64 {musl} (MIT) [installed]\nbusybox-1.37.0-r12 aarch64 {busybox} (GPL-2.0-only) [installed]\n"
	h.program("sbin", "apk", apkOut, nil)
	h.program("bin", "systemctl", "should not run", nil)
	h.file("var/run/reboot-required", "") // ignored: §2.2 always says no
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "#smoke-host 1\n#os-release\nID=alpine\nVERSION_ID=3.21.3\n#kernel\n6.8.0-45-generic\n" +
		"#packages apk\n" + apkOut + "#reboot-required\nno\n"
	if string(res.Body) != want {
		t.Errorf("body:\n%s\nwant:\n%s", res.Body, want)
	}
	if len(h.calls) != 1 || !reflect.DeepEqual(h.calls[0], []string{"/sbin/apk", "list", "--installed"}) {
		t.Errorf("calls = %q", h.calls)
	}
}

func TestSystemctlFailureKeepsPartialOutput(t *testing.T) {
	h := newHost(t, ubuntuOSRelease)
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	// cut prints lines without a delimiter whole, and a final line without a newline gets one.
	h.program("bin", "systemctl", "a.service x\nnodelimiter\n\nb.service", errors.New("exit status 1"))
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Body), "#services\na.service\nnodelimiter\n\nb.service\n#service-packages\n#reboot-required\nno\n") {
		t.Errorf("body:\n%s", res.Body)
	}
}

func TestPackageManagerFailure(t *testing.T) {
	h := newHost(t, ubuntuOSRelease)
	h.program("usr/bin", "dpkg-query", "partial", errors.New("exit status 2"))
	_, err := h.collector().Collect(context.Background())
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
}

func TestNoPackageManager(t *testing.T) {
	h := newHost(t, ubuntuOSRelease)
	_, err := h.collector().Collect(context.Background())
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
	h = newHost(t, "ID=alpine\nVERSION_ID=3.21.0\n")
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	if _, err := h.collector().Collect(context.Background()); !errors.As(err, &ce) {
		t.Fatalf("alpine without apk: err = %v", err)
	}
}

func TestMissingOSRelease(t *testing.T) {
	h := newHost(t, "")
	os.Remove(filepath.Join(h.root, "etc/os-release"))
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	_, err := h.collector().Collect(context.Background())
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookPathRules(t *testing.T) {
	h := newHost(t, "ID=debian\nVERSION_ID=\"12\"\n")
	// Not executable: ignored. A directory: ignored. Outside the fixed dirs: ignored.
	h.file("usr/bin/dpkg-query", "x")
	h.file("usr/local/bin/apk", "x")
	if err := os.MkdirAll(filepath.Join(h.root, "bin/dpkg-query"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.program("usr/sbin", "dpkg-query", "ii \tx\t1\tall\t\t\n", nil)
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.calls[0][0] != "/usr/sbin/dpkg-query" || res.Manager != Dpkg {
		t.Errorf("calls = %q", h.calls)
	}
}

func TestDpkgWinsOverApkOnDebian(t *testing.T) {
	h := newHost(t, ubuntuOSRelease)
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	h.program("sbin", "apk", "x", nil)
	res, err := h.collector().Collect(context.Background())
	if err != nil || res.Manager != Dpkg {
		t.Fatalf("res=%v err=%v", res, err)
	}
}

func TestRebootRequiredMustBeRegularFile(t *testing.T) {
	h := newHost(t, ubuntuOSRelease)
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	if err := os.MkdirAll(filepath.Join(h.root, "var/run/reboot-required"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(res.Body), "#reboot-required\nno\n") {
		t.Errorf("body:\n%s", res.Body)
	}
}

func TestRunRealProgram(t *testing.T) {
	// The production ExecFunc: no shell, so shell syntax is passed literally.
	for _, p := range []string{"/bin/echo", "/usr/bin/echo"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		out, err := Run(context.Background(), p, "a;b", "$HOME", "`x`")
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != "a;b $HOME `x`\n" {
			t.Errorf("out = %q", out)
		}
		return
	}
	t.Skip("no echo")
}

func TestRunTimeout(t *testing.T) {
	for _, p := range []string{"/bin/sleep", "/usr/bin/sleep"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		c := &Collector{Timeout: 50 * time.Millisecond, Exec: Run}
		if _, err := c.run(context.Background(), p, "5"); err == nil || !strings.Contains(err.Error(), "in time") {
			t.Errorf("err = %v", err)
		}
		return
	}
	t.Skip("no sleep")
}

func TestKernelRelease(t *testing.T) {
	r, err := kernelRelease()
	if err != nil || r == "" || strings.ContainsRune(r, 0) {
		t.Errorf("kernelRelease() = %q, %v", r, err)
	}
}
