package collect

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// writeELF writes a minimal little-endian ELF64 shared object with the given DT_NEEDED,
// DT_RUNPATH and PT_INTERP, readable by debug/elf (sections: null, .dynstr, .dynamic, .shstrtab).
func (h *fakeHost) elf(rel string, m elf.Machine, interp, runpath string, needed ...string) {
	h.t.Helper()
	var dynstr bytes.Buffer
	dynstr.WriteByte(0)
	str := func(s string) uint64 {
		off := dynstr.Len()
		dynstr.WriteString(s + "\x00")
		return uint64(off)
	}
	var dyn []elf.Dyn64
	for _, n := range needed {
		dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: str(n)})
	}
	if runpath != "" {
		dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_RUNPATH), Val: str(runpath)})
	}
	dyn = append(dyn, elf.Dyn64{})
	shstr := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")
	align := func(n int) int { return (n + 7) &^ 7 }

	phnum := 0
	if interp != "" {
		phnum = 1
	}
	interpOff := 64 + 56*phnum
	dynstrOff := interpOff
	if interp != "" {
		dynstrOff += len(interp) + 1
	}
	dynOff := align(dynstrOff + dynstr.Len())
	shstrOff := dynOff + 16*len(dyn)
	shOff := align(shstrOff + len(shstr))

	hdr := elf.Header64{
		Type: uint16(elf.ET_DYN), Machine: uint16(m), Version: uint32(elf.EV_CURRENT),
		Shoff: uint64(shOff), Ehsize: 64, Phentsize: 56, Phnum: uint16(phnum),
		Shentsize: 64, Shnum: 4, Shstrndx: 3,
	}
	if phnum > 0 {
		hdr.Phoff = 64
	}
	copy(hdr.Ident[:], elf.ELFMAG)
	hdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	hdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	hdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	var b bytes.Buffer
	w := func(v any) {
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			h.t.Fatal(err)
		}
	}
	pad := func(to int) { b.Write(make([]byte, to-b.Len())) }
	w(&hdr)
	if interp != "" {
		w(&elf.Prog64{Type: uint32(elf.PT_INTERP), Off: uint64(interpOff), Filesz: uint64(len(interp) + 1)})
		b.WriteString(interp + "\x00")
	}
	b.Write(dynstr.Bytes())
	pad(dynOff)
	w(dyn)
	b.Write(shstr)
	pad(shOff)
	w(&elf.Section64{})
	w(&elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(dynstrOff), Size: uint64(dynstr.Len())})
	w(&elf.Section64{Name: 9, Type: uint32(elf.SHT_DYNAMIC), Off: uint64(dynOff), Size: uint64(16 * len(dyn)), Link: 1, Entsize: 16})
	w(&elf.Section64{Name: 18, Type: uint32(elf.SHT_STRTAB), Off: uint64(shstrOff), Size: uint64(len(shstr))})
	h.file(rel, b.String())
}

func (h *fakeHost) symlink(rel, target string) {
	h.t.Helper()
	p := filepath.Join(h.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		h.t.Fatal(err)
	}
}

// proc adds /proc/<pid>. maps "" with unreadable: maps cannot be opened (a dangling link, like
// EACCES for another user's process).
func (h *fakeHost) proc(pid int, cgroup, cmdline, maps string, unreadable bool) {
	h.t.Helper()
	dir := fmt.Sprintf("proc/%d/", pid)
	h.file(dir+"cgroup", cgroup)
	h.file(dir+"cmdline", cmdline)
	os.Remove(filepath.Join(h.root, dir+"maps"))
	if unreadable {
		h.symlink(dir+"maps", "/nonexistent/maps")
	} else {
		h.file(dir+"maps", maps)
	}
}

func mapsLine(path string) string {
	return "7f0000000000-7f0000001000 r-xp 00000000 fe:01 1234                       " + path + "\n"
}

const showOut = "ExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" +
	"Id=nginx.service\n\n" +
	"Id=postgresql@16-main.service\n" +
	"ExecStart={ path=/usr/bin/pg_ctlcluster ; argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n\n" +
	"Id=app.service\n\n" +
	"Id=cron.service\n\n" +
	"Id=script.service\n"

// debianHost is an x86_64 usr-merged Ubuntu root with nginx (maps unreadable: linked),
// postgres (maps readable), an /opt app with RUNPATH $ORIGIN, cron (no mappings) and a
// script service (nothing known).
func debianHost(t *testing.T) *fakeHost {
	h := newHost(t, ubuntuOSRelease)
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	h.programVerbs("usr/bin", "systemctl", map[string]string{
		"list-units": "nginx.service loaded active running nginx\n" +
			"postgresql@16-main.service loaded active running PostgreSQL Cluster 16-main\n" +
			"app.service loaded active running App\n" +
			"cron.service loaded active running cron\n" +
			"script.service loaded active running script\n" +
			"user@1000.service loaded active running User Manager for UID 1000\n",
		"show": showOut,
	})
	const lib = "usr/lib/x86_64-linux-gnu/"
	h.symlink("lib", "usr/lib")
	h.symlink("bin", "usr/bin")
	h.symlink("lib64/ld-linux-x86-64.so.2", "../"+lib+"ld-linux-x86-64.so.2")
	h.elf(lib+"ld-linux-x86-64.so.2", elf.EM_X86_64, "", "")
	h.elf(lib+"libc.so.6", elf.EM_X86_64, "", "")
	// libcrypto needs libssl again: a loop the visited set must stop.
	h.elf(lib+"libcrypto.so.3", elf.EM_X86_64, "", "", "libssl.so.3", "libc.so.6")
	h.elf(lib+"libssl.so.3.0", elf.EM_X86_64, "", "", "libcrypto.so.3", "libc.so.6")
	h.symlink(lib+"libssl.so.3", "libssl.so.3.0")
	h.elf("usr/sbin/nginx", elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2", "", "libssl.so.3", "libc.so.6")
	h.elf("usr/lib/postgresql/16/bin/postgres", elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2", "", "libc.so.6")
	h.file("usr/bin/pg_ctlcluster", "#!/usr/bin/perl\n")
	h.file("usr/bin/script-daemon", "#!/bin/sh\n")
	h.elf("opt/app/bin/app", elf.EM_X86_64, "", "$ORIGIN/../lib", "libapp.so")
	h.elf("opt/app/lib/libapp.so", elf.EM_X86_64, "", "", "libc.so.6")
	// ld.so.conf lists a directory with an aarch64 libc first: it must be skipped.
	h.file("etc/ld.so.conf", "include /etc/ld.so.conf.d/*.conf\n")
	h.file("etc/ld.so.conf.d/arm.conf", "# cross libraries\n/opt/arm\n")
	h.elf("opt/arm/libc.so.6", elf.EM_AARCH64, "", "")

	info := "var/lib/dpkg/info/"
	h.file(info+"nginx.list", "/.\n/usr\n/usr/sbin\n/usr/sbin/nginx\n")
	h.file(info+"libssl3t64:amd64.list", "/usr/lib/x86_64-linux-gnu/libssl.so.3\n/usr/lib/x86_64-linux-gnu/libssl.so.3.0\n/usr/lib/x86_64-linux-gnu/libcrypto.so.3\n")
	// Listed under /lib (before the usr merge) and the loader only under its real path.
	h.file(info+"libc6:amd64.list", "/lib/x86_64-linux-gnu/libc.so.6\n/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n")
	h.file(info+"postgresql-16.list", "/usr/lib/postgresql/16/bin/postgres\n")
	h.file(info+"postgresql-common.list", "/usr/bin/pg_ctlcluster\n")
	h.file(info+"wrong-arch.list", "/opt/arm/libc.so.6\n")
	h.file(info+"app.list", "/opt/app/bin/app\n/opt/app/lib/libapp.so\n")
	h.file(info+"cron.list", "/usr/sbin/cron\n")
	h.file(info+"unrelated.md5sums", "/usr/sbin/nginx\n")

	// nginx: process titles carry the path; maps of both is unreadable.
	h.proc(100, "0::/system.slice/nginx.service\n", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", "", true)
	h.proc(101, "0::/system.slice/nginx.service\n", "nginx: worker process", "", true)
	// postgres: nested slice, a v1-only process, a deleted (upgraded) library still mapped.
	h.proc(200, "0::/system.slice/system-postgresql.slice/postgresql@16-main.service\n",
		"/usr/lib/postgresql/16/bin/postgres\x00-D\x00/var/lib/postgresql/16/main\x00",
		mapsLine("/usr/lib/postgresql/16/bin/postgres")+
			mapsLine("/usr/lib/x86_64-linux-gnu/libssl.so.3.0 (deleted)")+
			"7f0000002000-7f0000003000 rw-p 00000000 00:00 0 \n"+
			"7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0                          [stack]\n", false)
	h.proc(201, "12:pids:/system.slice/system-postgresql.slice/postgresql@16-main.service\n"+
		"1:name=systemd:/system.slice/system-postgresql.slice/postgresql@16-main.service\n",
		"postgres: 16/main: checkpointer ", mapsLine("/usr/lib/x86_64-linux-gnu/libc.so.6"), false)
	h.proc(300, "0::/system.slice/app.service\n", "/opt/app/bin/app\x00--serve\x00", "", true)
	h.proc(400, "0::/system.slice/cron.service\n", "", "", false)
	h.proc(500, "0::/system.slice/script.service\n", "/bin/sh\x00/usr/bin/script-daemon\x00", "", true)
	// Not running, a user unit, a kernel thread, a non-pid entry.
	h.proc(600, "0::/system.slice/stopped.service\n", "/usr/sbin/nginx", mapsLine("/usr/sbin/nginx"), false)
	h.proc(700, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app.service\n", "", "", false)
	h.proc(2, "0::/\n", "", "", false)
	h.file("proc/self/cgroup", "0::/system.slice/cron.service\n")
	return h
}

// programVerbs installs a program whose output depends on its first argument.
func (h *fakeHost) programVerbs(dir, name string, byVerb map[string]string) {
	h.program(dir, name, "", nil)
	p := filepath.Join(h.root, dir, name)
	h.progs[p] = fakeProgram{byVerb: byVerb}
}

func section(body []byte) string {
	s := string(body)
	start := strings.Index(s, "#service-packages\n")
	end := strings.Index(s, "#reboot-required\n")
	if start < 0 || end < start {
		return "missing"
	}
	return s[start+len("#service-packages\n") : end]
}

func TestServicePackages(t *testing.T) {
	h := debianHost(t)
	// /bin/sh -> usr/bin/sh does not exist here, so script.service has no ELF program.
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "app.service\tlinked\tapp libc6\n" +
		"cron.service\tmaps\t\n" +
		"nginx.service\tlinked\tlibc6 libssl3t64 nginx\n" +
		"postgresql@16-main.service\tmaps\tlibc6 libssl3t64 postgresql-16\n"
	if got := section(res.Body); got != want {
		t.Errorf("#service-packages:\n%s\nwant:\n%s", got, want)
	}
	// One systemctl show for the units that have processes, in name order.
	wantShow := []string{"/usr/bin/systemctl", "show", "--property=Id,ExecStart",
		"app.service", "cron.service", "nginx.service", "postgresql@16-main.service", "script.service"}
	if len(h.calls) != 3 || !reflect.DeepEqual(h.calls[2], wantShow) {
		t.Errorf("calls = %q", h.calls)
	}
	if !strings.Contains(string(res.Body), "#services\nnginx.service\n") ||
		!strings.Contains(string(res.Body), "user@1000.service\n#service-packages\n") {
		t.Errorf("section order:\n%s", res.Body)
	}
}

func TestServicePackagesWithoutShow(t *testing.T) {
	// systemctl show fails: the cmdline paths are still used.
	h := debianHost(t)
	p := filepath.Join(h.root, "usr/bin/systemctl")
	prog := h.progs[p]
	prog.byVerb = map[string]string{"list-units": prog.byVerb["list-units"]}
	h.progs[p] = prog
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := section(res.Body); !strings.Contains(got, "nginx.service\tlinked\tlibc6 libssl3t64 nginx\n") {
		t.Errorf("#service-packages:\n%s", got)
	}
}

func TestServicePackagesRoot(t *testing.T) {
	// As root every maps is readable: maps for all, and only mapped files and programs count.
	h := debianHost(t)
	h.proc(100, "0::/system.slice/nginx.service\n", "nginx: master process /usr/sbin/nginx",
		mapsLine("/usr/sbin/nginx"), false)
	h.proc(101, "0::/system.slice/nginx.service\n", "nginx: worker process",
		mapsLine("/usr/lib/x86_64-linux-gnu/libc.so.6"), false)
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := section(res.Body); !strings.Contains(got, "nginx.service\tmaps\tlibc6 nginx\n") {
		t.Errorf("#service-packages:\n%s", got)
	}
}

func TestServicePackagesNoProcesses(t *testing.T) {
	// Containers: services listed (stand-in systemctl) but no process in their cgroups.
	h := newHost(t, ubuntuOSRelease)
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	h.program("usr/bin", "systemctl", systemctlOut, nil)
	h.proc(1, "0::/\n", "sh", mapsLine("/usr/bin/dash"), false)
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := section(res.Body); got != "" {
		t.Errorf("#service-packages:\n%s", got)
	}
	if len(h.calls) != 2 {
		t.Errorf("systemctl show must not run: %q", h.calls)
	}
}

func TestServicePackagesBudget(t *testing.T) {
	h := debianHost(t)
	c := h.collector()
	c.ServicePackagesBudget = 1 // already over: nothing is analysed, the run goes on
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := section(res.Body); got != "" {
		t.Errorf("#service-packages:\n%s", got)
	}
}

func TestServicePackagesLimits(t *testing.T) {
	h := newHost(t, ubuntuOSRelease)
	h.program("usr/bin", "dpkg-query", dpkgOut, nil)
	var units strings.Builder
	var big strings.Builder
	for i := range 301 {
		h.file(fmt.Sprintf("var/lib/dpkg/info/p%03d.list", i), fmt.Sprintf("/usr/lib/p%03d.so\n", i))
		big.WriteString(mapsLine(fmt.Sprintf("/usr/lib/p%03d.so", i)))
	}
	units.WriteString("a-big.service x\n")
	h.proc(1, "0::/system.slice/a-big.service\n", "", big.String(), false)
	for i := range 205 {
		fmt.Fprintf(&units, "u%03d.service x\n", i)
		h.proc(100+i, fmt.Sprintf("0::/system.slice/u%03d.service\n", i), "", mapsLine("/usr/lib/p000.so"), false)
	}
	h.program("usr/bin", "systemctl", units.String(), nil)
	res, err := h.collector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(section(res.Body), "\n"), "\n")
	// a-big.service (301 packages) is omitted, not truncated; then the first 200 by name.
	if len(lines) != 200 || lines[0] != "u000.service\tmaps\tp000" || lines[199] != "u199.service\tmaps\tp000" {
		t.Errorf("%d lines, first %q, last %q", len(lines), lines[0], lines[len(lines)-1])
	}
}

func TestCgroupUnit(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/nginx.service\n":                                                                      "nginx.service",
		"0::/system.slice/system-postgresql.slice/postgresql@14-main.service":                                   "postgresql@14-main.service",
		"0::/system.slice/docker.service/sub\n":                                                                 "docker.service",
		"0::/user.slice/user-1000.slice/user@1000.service/init.scope\n":                                         "user@1000.service",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service":                                  "x.service",
		"12:pids:/system.slice/a.service\n1:name=systemd:/system.slice/b.service\n0::/system.slice/c.service\n": "b.service",
		"12:cpu,cpuacct:/system.slice/a.service\n":                                                              "",
		"0::/system.slice/docker-1234.scope\n":                                                                  "",
		"0::/\n":                                                                                                "",
		"0::/system.slice/a.service.d\n":                                                                        "",
		"0::/init.scope\n1:name=systemd:/system.slice/late.service\n":                                           "late.service",
	} {
		if got := cgroupUnit([]byte(in)); got != want {
			t.Errorf("cgroupUnit(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMappedFiles(t *testing.T) {
	maps := mapsLine("/usr/lib/a.so") +
		mapsLine("/usr/lib/b.so (deleted)") +
		mapsLine("/opt/with space/c.so") +
		"7f0000002000-7f0000003000 rw-p 00000000 00:00 0 \n" +
		"7f0000002000-7f0000003000 rw-p 00000000 00:00 0\n" +
		mapsLine("[heap]") +
		mapsLine("anon_inode:[perf_event]") +
		"7f0000002000-7f0000003000 r--s 00000000 00:01 7 /memfd:x (deleted)"
	want := []string{"/usr/lib/a.so", "/usr/lib/b.so", "/opt/with space/c.so", "/memfd:x"}
	if got := mappedFiles([]byte(maps)); !reflect.DeepEqual(got, want) {
		t.Errorf("mappedFiles = %q", got)
	}
}

func TestParseExecStart(t *testing.T) {
	out := "ExecStart={ path=/usr/sbin/a ; argv[]=/usr/sbin/a -x ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" +
		"ExecStart={ path=/usr/bin/b ; argv[]=b ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" +
		"Id=a.service\n\nId=b.service\nExecStart=\n\nExecStart={ path=relative ; argv[]=x ; }\nId=c.service"
	got := parseExecStart([]byte(out))
	want := map[string][]string{"a.service": {"/usr/sbin/a", "/usr/bin/b"}, "b.service": nil, "c.service": nil}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseExecStart = %q", got)
	}
}

func TestUsrAlt(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/lib/x86_64-linux-gnu/libc.so.6": "/lib/x86_64-linux-gnu/libc.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6":     "/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/ld-linux-x86-64.so.2":         "/usr/lib64/ld-linux-x86-64.so.2",
		"/usr/sbin/nginx":                     "/sbin/nginx",
		"/bin/sh":                             "/usr/bin/sh",
		"/usr/share/x":                        "",
		"/opt/lib/x":                          "",
		"/library/x":                          "/usr/library/x", // lib*, like the shell regex
	} {
		if got := usrAlt(in); got != want {
			t.Errorf("usrAlt(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApkOwners(t *testing.T) {
	h := newHost(t, "ID=alpine\n")
	h.file("lib/apk/db/installed", "C:Q1x=\nP:musl\nV:1.2.5-r9\nF:lib\nR:ld-musl-aarch64.so.1\nR:libc.musl-aarch64.so.1\n\n"+
		"P:nginx\nV:1.26.2-r4\nF:usr\nF:usr/sbin\nR:nginx\nF:var/lib/nginx\n\nP:busybox\nF:bin\nR:busybox\n")
	need := map[string]bool{"/lib/ld-musl-aarch64.so.1": true, "/usr/sbin/nginx": true, "/bin/busybox": true, "/usr/bin/x": true}
	got := h.collector().apkOwners(context.Background(), need)
	want := map[string][]string{"/lib/ld-musl-aarch64.so.1": {"musl"}, "/usr/sbin/nginx": {"nginx"}, "/bin/busybox": {"busybox"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("apkOwners = %q", got)
	}
}

func TestReadELFRejects(t *testing.T) {
	h := newHost(t, ubuntuOSRelease)
	h.file("usr/bin/script", "#!/bin/sh\n")
	h.file("usr/bin/short", "\x7fEL")
	h.file("usr/bin/broken", "\x7fELF\x02\x01\x01garbage")
	if err := os.MkdirAll(filepath.Join(h.root, "usr/bin/dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.elf("proc/1/exe-copy", elf.EM_X86_64, "", "")
	c := h.collector()
	for _, p := range []string{"/usr/bin/script", "/usr/bin/short", "/usr/bin/broken", "/usr/bin/dir", "/usr/bin/missing", "relative", "/proc/1/exe-copy"} {
		if o := c.readELF(p); o != nil {
			t.Errorf("readELF(%s) = %+v", p, o)
		}
	}
	h.elf("usr/bin/ok", elf.EM_AARCH64, "/lib/ld-linux-aarch64.so.1", "/a:$ORIGIN/x", "libc.so.6", "libm.so.6")
	o := c.readELF("/usr/bin/ok")
	if o == nil || o.machine != elf.EM_AARCH64 || o.interp != "/lib/ld-linux-aarch64.so.1" ||
		!reflect.DeepEqual(o.needed, []string{"libc.so.6", "libm.so.6"}) || !reflect.DeepEqual(o.runpath, []string{"/a", "$ORIGIN/x"}) {
		t.Errorf("readELF(ok) = %+v", o)
	}
}

// rhelHost is an x86_64 RHEL 9 root (/lib64 -> usr/lib64) with nginx (maps unreadable: linked)
// and chronyd (maps readable). rpm answers -qa, -qf (owner names) and -q (file lists).
func rhelHost(t *testing.T, qf, q string) *fakeHost {
	h := newHost(t, "NAME=\"Red Hat Enterprise Linux\"\nVERSION=\"9.4 (Plow)\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"\n")
	h.programVerbs("usr/bin", "rpm", map[string]string{"-qa": rpmOut, "-qf": qf, "-q": q})
	h.programVerbs("usr/bin", "systemctl", map[string]string{
		"list-units": "nginx.service loaded active running nginx\nchronyd.service loaded active running NTP client/server\n",
		"show": "Id=nginx.service\nExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n\n" +
			"Id=chronyd.service\n",
	})
	const lib = "usr/lib64/"
	h.symlink("lib64", "usr/lib64")
	h.symlink("bin", "usr/bin")
	h.elf(lib+"ld-linux-x86-64.so.2", elf.EM_X86_64, "", "")
	h.elf(lib+"libc.so.6", elf.EM_X86_64, "", "")
	h.elf(lib+"libssl.so.3.0.7", elf.EM_X86_64, "", "", "libc.so.6")
	h.symlink(lib+"libssl.so.3", "libssl.so.3.0.7")
	h.elf("usr/sbin/nginx", elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2", "", "libssl.so.3", "libc.so.6")
	h.proc(100, "0::/system.slice/nginx.service\n", "nginx: master process /usr/sbin/nginx", "", true)
	h.proc(200, "0::/system.slice/chronyd.service\n", "/usr/sbin/chronyd\x00-F\x002\x00",
		mapsLine("/usr/sbin/chronyd")+mapsLine("/usr/lib64/libc.so.6"), false)
	return h
}

// rpmErr makes the collector's rpm runs with the first argument verb return err, with the
// output cut to keep bytes.
func rpmErr(c *Collector, verb string, keep func(out []byte) []byte, err error) {
	run := c.Exec
	c.Exec = func(ctx context.Context, path string, args ...string) ([]byte, error) {
		out, e := run(ctx, path, args...)
		if strings.HasSuffix(path, "/rpm") && args[0] == verb {
			return keep(out), err
		}
		return out, e
	}
}

// What rpm prints for those paths: unowned paths get a sentence (and a non-zero exit), a
// path owned twice gets two names.
const rhelQF = "glibc\nfile /lib64/libssl.so.3 is not owned by any package\nnginx\nchrony\nopenssl-libs\nglibc\n"

const rhelQ = "/usr/lib64/libc.so.6\tglibc\n/usr/lib64/ld-linux-x86-64.so.2\tglibc\n/usr/share/doc/glibc\tglibc\n" +
	"/usr/sbin/nginx\tnginx\n/usr/sbin/chronyd\tchrony\n" +
	"/usr/lib64/libssl.so.3\topenssl-libs\n/usr/lib64/libssl.so.3.0.7\topenssl-libs\n/usr/lib64/libssl.so.3.0.7\tcompat-openssl\n" +
	"(contains no files)\n/usr/sbin/nginx\tbad name\n"

func TestServicePackagesRpm(t *testing.T) {
	h := rhelHost(t, rhelQF, rhelQ)
	c := h.collector()
	rpmErr(c, "-qf", func(out []byte) []byte { return out }, exitErr(1))
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "chronyd.service\tmaps\tchrony glibc\n" +
		"nginx.service\tlinked\tcompat-openssl glibc nginx openssl-libs\n"
	if got := section(res.Body); got != want {
		t.Errorf("#service-packages:\n%s\nwant:\n%s", got, want)
	}
	var qf, q []string
	for _, c := range h.calls {
		switch {
		case len(c) > 1 && c[1] == "-qf":
			qf = c
		case len(c) > 1 && c[1] == "-q":
			q = c
		}
	}
	if len(qf) < 4 || !reflect.DeepEqual(qf[:4], []string{"/usr/bin/rpm", "-qf", "--qf", `%{NAME}\n`}) ||
		!slices.IsSorted(qf[4:]) || !slices.Contains(qf[4:], "/lib64/libc.so.6") || !slices.Contains(qf[4:], "/usr/lib64/libc.so.6") {
		t.Errorf("rpm -qf call = %q", qf)
	}
	// Each owner once, in name order; the unowned sentence is not a name.
	if !reflect.DeepEqual(q, []string{"/usr/bin/rpm", "-q", "--qf", `[%{FILENAMES}\t%{=NAME}\n]`, "chrony", "glibc", "nginx", "openssl-libs"}) {
		t.Errorf("rpm -q call = %q", q)
	}
	if !strings.HasSuffix(string(res.Body), "#service-packages\n"+want+"#reboot-required\n") {
		t.Errorf("body:\n%s", res.Body)
	}
}

func TestServicePackagesRpmFailure(t *testing.T) {
	// rpm did not exit (timeout, output too large): unknown, the run goes on.
	for _, verb := range []string{"-qf", "-q"} {
		h := rhelHost(t, rhelQF, rhelQ)
		c := h.collector()
		rpmErr(c, verb, func(out []byte) []byte { return out[:len(out)/2] }, errors.New("output is larger than 33554432 bytes"))
		res, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := section(res.Body); got != "" {
			t.Errorf("%s fails: #service-packages:\n%s", verb, got)
		}
	}
}

func TestRpmOwnersBatches(t *testing.T) {
	h := rhelHost(t, "glibc\n", "/p/0\tglibc\n/p/1199\tglibc\n")
	need := map[string]bool{}
	for i := range 1200 {
		need[fmt.Sprintf("/p/%d", i)] = true
	}
	got := h.collector().rpmOwners(context.Background(), need)
	if want := map[string][]string{"/p/0": {"glibc"}, "/p/1199": {"glibc"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("rpmOwners = %q", got)
	}
	var sizes []int
	for _, c := range h.calls {
		sizes = append(sizes, len(c)-4)
	}
	if !reflect.DeepEqual(sizes, []int{500, 500, 200, 1}) {
		t.Errorf("operands per run = %v", sizes)
	}
}
