package collect

import (
	"context"
	"errors"
	"fmt"
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

// exitErr is a program that ran and exited with a status, like *exec.ExitError.
type exitErr int

func (e exitErr) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitErr) ExitCode() int { return int(e) }

const rockyOSRelease = `NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
ROCKY_SUPPORT_PRODUCT="Rocky-Linux-9"
`

const rpmOut = "openssl-libs\t1\t3.0.7-27.el9_4\tx86_64\topenssl-3.0.7-27.el9_4.src.rpm\n" +
	"bash\t(none)\t5.1.8-9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\n" +
	"gpg-pubkey\t(none)\t5a6340b3-6229229e\t(none)\t(none)\n"

func TestRocky(t *testing.T) {
	h := newHost(t, rockyOSRelease)
	h.programVerbs("usr/bin", "rpm", map[string]string{"-qa": rpmOut})
	h.program("usr/bin", "systemctl", systemctlOut, nil)
	h.program("usr/bin", "needs-restarting", "Core libraries or services have been updated since boot-up:\n", exitErr(1))
	h.file("var/run/reboot-required", "") // Debian only: ignored on rpm hosts
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "#smoke-host 1\n" +
		"#os-release\n" +
		"ID=\"rocky\"\nVERSION_ID=\"9.4\"\n" +
		"#kernel\n6.8.0-45-generic\n" +
		"#packages rpm\n" + rpmOut +
		"#services\nnginx.service\nssh.service\nuser@1000.service\n" +
		"#service-packages\n" +
		"#reboot-required\nyes\n"
	if got := string(res.Body); got != want {
		t.Errorf("body:\n%s\nwant:\n%s", got, want)
	}
	if res.Manager != Rpm || res.OSID != "rocky" {
		t.Errorf("manager=%s id=%s", res.Manager, res.OSID)
	}
	wantCalls := [][]string{
		{"/usr/bin/rpm", "-qa", "--qf", `%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`},
		{"/usr/bin/systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"},
		{"/usr/bin/needs-restarting", "-r"},
	}
	if !reflect.DeepEqual(h.calls, wantCalls) {
		t.Errorf("calls = %q", h.calls)
	}
}

func TestRpmRebootRequired(t *testing.T) {
	const needed = "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n"
	for _, tc := range []struct {
		name    string
		install bool
		out     string
		err     error
		want    string
	}{
		{"missing", false, "", nil, "#reboot-required\n"},
		{"not needed", true, "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n", nil, "#reboot-required\nno\n"},
		{"needed", true, needed, exitErr(1), "#reboot-required\nyes\n"},
		{"wrapped status", true, needed, fmt.Errorf("%w: wrapped", exitErr(1)), "#reboot-required\nyes\n"},
		// dnf exits 1 on errors too: without its report that is not a reboot.
		{"error exit 1", true, "Error: rpmdb open failed\n", exitErr(1), "#reboot-required\n"},
		{"other status", true, "", exitErr(2), "#reboot-required\n"},
		{"killed", true, "", exitErr(-1), "#reboot-required\n"},
		{"timeout", true, "", errors.New("needs-restarting did not finish in time"), "#reboot-required\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, "ID=almalinux\nVERSION_ID=\"9.4\"\n")
			h.programVerbs("usr/bin", "rpm", map[string]string{"-qa": rpmOut})
			if tc.install {
				h.program("usr/bin", "needs-restarting", tc.out, tc.err)
			}
			res, err := h.collector().Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(string(res.Body), "#service-packages\n"+tc.want) {
				t.Errorf("body:\n%s", res.Body)
			}
		})
	}
}

func TestRpmFailure(t *testing.T) {
	h := newHost(t, "ID=rhel\nVERSION_ID=\"9.4\"\n")
	h.program("usr/bin", "rpm", "partial", exitErr(1))
	_, err := h.collector().Collect(context.Background())
	var ce *Error
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "rpm -qa failed") {
		t.Fatalf("err = %v", err)
	}
}

func TestRpmOnlyOnRhelFamily(t *testing.T) {
	collect := func(osRelease string, progs ...string) (*Result, error) {
		h := newHost(t, osRelease)
		for _, p := range progs {
			switch p {
			case "dpkg-query":
				h.program("usr/bin", p, dpkgOut, nil)
			case "apk":
				h.program("sbin", p, "", nil)
			case "rpm":
				h.programVerbs("usr/bin", p, map[string]string{"-qa": rpmOut})
			}
		}
		return h.collector().Collect(context.Background())
	}
	for _, tc := range []struct {
		name, osRelease string
		progs           []string
		want            Manager
		wantErr         string
	}{
		{"ubuntu with rpm installed", ubuntuOSRelease, []string{"dpkg-query", "rpm"}, Dpkg, ""},
		{"alpine with rpm installed", "ID=alpine\n", []string{"apk", "rpm"}, Apk, ""},
		{"rhel (UBI)", "ID=\"rhel\"\nVERSION_ID=\"9.4\"\n", []string{"rpm"}, Rpm, ""},
		{"rocky with dpkg from EPEL", rockyOSRelease, []string{"dpkg-query", "rpm"}, Rpm, ""},
		{"almalinux", "ID=almalinux\nVERSION_ID=\"10.0\"\n", []string{"rpm"}, Rpm, ""},
		{"centos", "ID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"9\"\n", []string{"rpm"}, "",
			`os-release ID "centos" is not supported with rpm (supported: Ubuntu, Debian, Alpine, RHEL, Rocky Linux, AlmaLinux)`},
		{"fedora", "ID=fedora\nVERSION_ID=41\n", []string{"rpm"}, "", `"fedora" is not supported`},
		{"rhel without rpm (UBI micro)", "ID=\"rhel\"\n", nil, "", "rpm not found in /usr/bin, /bin, /sbin, /usr/sbin"},
		{"nothing", "ID=arch\n", nil, "", "none of dpkg-query, apk or rpm found in /usr/bin, /bin, /sbin, /usr/sbin (supported: Ubuntu, Debian, Alpine, RHEL, Rocky Linux, AlmaLinux)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := collect(tc.osRelease, tc.progs...)
			if tc.wantErr != "" {
				var ce *Error
				if !errors.As(err, &ce) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || res.Manager != tc.want {
				t.Fatalf("res=%+v err=%v", res, err)
			}
		})
	}
}

// The collector runs the same programs with the same formats as the page's shell commands
// (testdata/plan-commands, compared byte for byte by scripts/test-identity.sh).
func TestPlanCommandFormats(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plan-commands", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	deb, rpm := read("deb.sh"), read("rpm.sh")
	// The shell gets \${…} inside double quotes; dpkg-query and rpm expand \t and \n themselves.
	if want := `dpkg-query -W -f="` + strings.ReplaceAll(DpkgFormat, "$", `\$`) + `"; `; !strings.Contains(deb, want) {
		t.Errorf("deb.sh lacks %s", want)
	}
	for _, want := range []string{
		`echo "#os-release"; grep -E "^(ID|VERSION_ID|VERSION_CODENAME)=" /etc/os-release; `,
		`echo "#packages rpm"; rpm -qa --qf "` + RpmFormat + `"; echo "#services"; `,
		`xargs -0r rpm -qf --qf "%{NAME}\n" 2>/dev/null | grep -v " " | LC_ALL=C sort -u | tr "\n" "\0" | xargs -0r rpm -q --qf "[%{FILENAMES}\t%{=NAME}\n]" 2>/dev/null >"$t/s"; `,
		`echo "#reboot-required"; if command -v needs-restarting >/dev/null 2>&1; then o=$(LC_ALL=C needs-restarting -r 2>/dev/null); rc=$?; if [ "$rc" = 1 ] && printf %s "$o" | grep -Eq "Reboot is required|updated since boot-up"; then echo yes; elif [ "$rc" = 0 ]; then echo no; fi; fi' > smoke-host.txt`,
	} {
		if !strings.Contains(rpm, want) {
			t.Errorf("rpm.sh lacks %s", want)
		}
	}
	// Everything else is the dpkg command: the same #services and #service-packages analysis.
	debServices := deb[strings.Index(deb, `echo "#services"`):strings.Index(deb, `cut -f2 "$t/o"`)]
	if !strings.Contains(rpm, debServices) {
		t.Error("rpm.sh and deb.sh differ in #services or the /proc scan")
	}
}
