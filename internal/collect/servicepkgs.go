package collect

// The #service-packages section: which binary packages each running systemd service uses, so
// Smoke can tell which services must be restarted after a library upgrade. One line per
// analysed unit:
//
//	<unit>\t<method>\t<pkg> <pkg> ...
//
// method "maps": every process of the unit had a readable /proc/<pid>/maps; the packages own
// a file-backed mapping (deleted mappings included: the old library is still loaded) or a
// program file. method "linked": otherwise (the usual case without root); the packages own a
// program file or a shared library it links (DT_NEEDED, recursively). A unit that could not
// be analysed is omitted: omitted means unknown. No program from the analysed files is run.

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// ServicePackagesBudget bounds the #service-packages analysis. Units not analysed by then are
// omitted; a run never hangs on it.
const ServicePackagesBudget = 60 * time.Second

const (
	maxServiceLines = 200
	// A unit with more packages than this is omitted (unknown) rather than truncated.
	maxLinePackages = 300
	maxELFSize      = 256 << 20
	maxELFDepth     = 32
	maxProcFile     = 16 << 20
	maxCmdline      = 1 << 20
	maxLdConfDepth  = 8
	// Paths or package names per rpm run, well below the argument size limit.
	rpmArgsPerRun = 500
)

var (
	// Same rules as the shell command (testdata/plan-commands/deb.sh).
	cgroupLine  = regexp.MustCompile(`^[0-9]+:(name=systemd)?:`)
	mapsPath    = regexp.MustCompile(`^[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +/`)
	usrPrefixed = regexp.MustCompile(`^/usr/(lib[^/]*|bin|sbin)/`)
	usrBare     = regexp.MustCompile(`^/(lib[^/]*|bin|sbin)/`)
	// Unit names passed to systemctl show (never one that looks like an option).
	showableUnit = regexp.MustCompile(`^[A-Za-z0-9:_.@\\][A-Za-z0-9:_.@\\-]*\.service$`)
	execPath     = regexp.MustCompile(`\{ path=(.*?) ; argv\[\]=`)
	// RPM package names (upper case and _ allowed: NetworkManager, python3-PyYAML).
	rpmName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,99}$`)
)

type svcUnit struct {
	name       string
	unreadable bool            // some pid's maps could not be read
	mapped     map[string]bool // file-backed mappings
	tokens     map[string]bool // absolute paths in the cmdlines
	method     string
	cands      map[string]bool // paths whose owners are the unit's packages
}

// servicePackages returns the lines of the #service-packages section for the running units.
func (c *Collector) servicePackages(ctx context.Context, mgr Manager, systemctl string, running []string) []byte {
	budget := c.ServicePackagesBudget
	if budget <= 0 {
		budget = ServicePackagesBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	// The analysis gets three quarters of the budget, the package database the rest.
	analysisEnd := time.Now().Add(budget * 3 / 4)

	want := map[string]bool{}
	for _, s := range running {
		if s != "" {
			want[s] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	units := c.scanProc(want, analysisEnd)
	if len(units) == 0 {
		return nil
	}
	names := make([]string, 0, len(units))
	for n := range units {
		names = append(names, n)
	}
	slices.Sort(names)

	execs := map[string][]string{}
	if systemctl != "" {
		args := []string{"show", "--property=Id,ExecStart"}
		for _, n := range names {
			if showableUnit.MatchString(n) {
				args = append(args, n)
			}
		}
		if len(args) > 2 {
			out, _ := c.run(ctx, systemctl, args...) // partial or no output: cmdlines still count
			execs = parseExecStart(out)
		}
	}

	r := &elfCache{c: c, objs: map[string]*elfObj{}}
	var done []*svcUnit
	need := map[string]bool{}
	for _, n := range names {
		if time.Now().After(analysisEnd) {
			break
		}
		u := units[n]
		var progs []string
		for _, p := range execs[n] {
			if r.load(p) != nil {
				progs = append(progs, p)
			}
		}
		for _, p := range sortedKeys(u.tokens) {
			if r.load(p) != nil {
				progs = append(progs, p)
			}
		}
		u.cands = map[string]bool{}
		if !u.unreadable {
			u.method = "maps"
			for p := range u.mapped {
				u.addCands(p, "")
			}
		} else {
			if len(progs) == 0 {
				continue // nothing known about this unit
			}
			u.method = "linked"
			progs = r.closure(progs)
		}
		for _, p := range progs {
			u.addCands(p, c.realpath(p))
		}
		for p := range u.cands {
			need[p] = true
		}
		done = append(done, u)
	}
	if len(done) == 0 {
		return nil
	}

	var owners map[string][]string
	switch mgr {
	case Apk:
		owners = c.apkOwners(ctx, need)
	case Rpm:
		owners = c.rpmOwners(ctx, need)
	default:
		owners = c.dpkgOwners(ctx, need)
	}
	if owners == nil {
		return nil
	}

	var b bytes.Buffer
	lines := 0
	for _, u := range done {
		pkgs := map[string]bool{}
		for p := range u.cands {
			for _, pkg := range owners[p] {
				pkgs[pkg] = true
			}
		}
		if len(pkgs) > maxLinePackages {
			continue
		}
		if lines == maxServiceLines {
			break
		}
		lines++
		b.WriteString(u.name + "\t" + u.method + "\t" + strings.Join(sortedKeys(pkgs), " ") + "\n")
	}
	return b.Bytes()
}

// addCands adds p and, when known, its symlink-resolved form, each with its usr-merge
// alternate (/usr/lib/x <-> /lib/x, likewise /lib*, /bin, /sbin).
func (u *svcUnit) addCands(p, real string) {
	for _, q := range []string{p, real} {
		if q == "" {
			continue
		}
		u.cands[q] = true
		if alt := usrAlt(q); alt != "" {
			u.cands[alt] = true
		}
	}
}

func usrAlt(p string) string {
	switch {
	case usrPrefixed.MatchString(p):
		return p[len("/usr"):]
	case usrBare.MatchString(p):
		return "/usr" + p
	}
	return ""
}

// scanProc groups the processes in /proc by the running unit their cgroup belongs to. A scan
// that does not finish in time returns nothing: a unit with missing pids would look complete.
func (c *Collector) scanProc(want map[string]bool, end time.Time) map[string]*svcUnit {
	entries, err := os.ReadDir(c.path("/proc"))
	if err != nil {
		return nil
	}
	units := map[string]*svcUnit{}
	for _, e := range entries {
		if time.Now().After(end) {
			return nil
		}
		pid := e.Name()
		if !isDigits(pid) {
			continue
		}
		dir := "/proc/" + pid
		cg, err := c.readFile(dir+"/cgroup", 64<<10)
		if err != nil {
			continue // exited
		}
		name := cgroupUnit(cg)
		if !want[name] {
			continue
		}
		u := units[name]
		if u == nil {
			u = &svcUnit{name: name, mapped: map[string]bool{}, tokens: map[string]bool{}}
			units[name] = u
		}
		if maps, err := c.readFile(dir+"/maps", maxProcFile); err != nil {
			u.unreadable = true // other users' processes without ptrace rights
		} else {
			for _, p := range mappedFiles(maps) {
				u.mapped[p] = true
			}
		}
		if cmd, err := c.readFile(dir+"/cmdline", maxCmdline); err == nil {
			for _, tok := range strings.Fields(string(bytes.ReplaceAll(cmd, []byte{0}, []byte{' '}))) {
				if strings.HasPrefix(tok, "/") {
					u.tokens[tok] = true
				}
			}
		}
	}
	return units
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cgroupUnit returns the unit of a /proc/<pid>/cgroup: on the first cgroup v2 ("0::") or v1
// name=systemd line that has one, the last path element ending in .service.
func cgroupUnit(data []byte) string {
	for _, line := range splitLines(data) {
		l := string(line)
		if !cgroupLine.MatchString(l) {
			continue
		}
		parts := strings.Split(l, "/")
		for i := len(parts) - 1; i >= 1; i-- {
			if strings.HasSuffix(parts[i], ".service") {
				return parts[i]
			}
		}
	}
	return ""
}

// mappedFiles returns the file paths of /proc/<pid>/maps (6th field onwards, starting with /),
// without a trailing " (deleted)".
func mappedFiles(maps []byte) []string {
	var paths []string
	for _, line := range splitLines(maps) {
		l := string(line)
		if loc := mapsPath.FindStringIndex(l); loc != nil {
			paths = append(paths, strings.TrimSuffix(l[loc[1]-1:], " (deleted)"))
		}
	}
	return paths
}

// parseExecStart reads `systemctl show --property=Id,ExecStart` output: records separated by
// empty lines, properties in any order, one ExecStart= line per command.
func parseExecStart(out []byte) map[string][]string {
	res := map[string][]string{}
	var id string
	var paths []string
	flush := func() {
		if id != "" {
			res[id] = append(res[id], paths...)
		}
		id, paths = "", nil
	}
	for _, line := range splitLines(out) {
		l := string(line)
		switch {
		case l == "":
			flush()
		case strings.HasPrefix(l, "Id="):
			id = l[len("Id="):]
		case strings.HasPrefix(l, "ExecStart="):
			for _, m := range execPath.FindAllStringSubmatch(l, -1) {
				if path.IsAbs(m[1]) {
					paths = append(paths, m[1])
				}
			}
		}
	}
	flush()
	return res
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// realpath resolves symlinks in p (a path inside Root); "" when that fails or leaves Root.
func (c *Collector) realpath(p string) string {
	rp, err := filepath.EvalSymlinks(c.path(p))
	if err != nil {
		return ""
	}
	root := c.Root
	if root == "" || root == "/" {
		return rp
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	rel, err := filepath.Rel(root, rp)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return "/" + filepath.ToSlash(rel)
}

// unroot turns a path under Root (as filepath.Glob returns it) back into a host path.
func (c *Collector) unroot(full string) string {
	if c.Root == "" || c.Root == "/" {
		return full
	}
	rel, err := filepath.Rel(c.Root, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return "/" + filepath.ToSlash(rel)
}

// dpkgOwners maps each needed path to the packages whose /var/lib/dpkg/info/<pkg>[:<arch>].list
// lists it (package names without :arch), like dpkg -S. nil when the database cannot be read
// in time.
func (c *Collector) dpkgOwners(ctx context.Context, need map[string]bool) map[string][]string {
	dir := c.path("/var/lib/dpkg/info")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	owners := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".list") || !e.Type().IsRegular() {
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		pkg := strings.TrimSuffix(name, ".list")
		if i := strings.IndexByte(pkg, ':'); i >= 0 {
			pkg = pkg[:i]
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if p := sc.Text(); need[p] && !slices.Contains(owners[p], pkg) {
				owners[p] = append(owners[p], pkg)
			}
		}
		f.Close()
	}
	return owners
}

// rpmOwners does the same with rpm, whose database cannot be read directly: `rpm -qf` names the
// packages that own the needed paths, then `rpm -q` lists those packages' files and a path
// counts only where a file list has it literally, as with the dpkg lists. Like the shell
// command: rpm -qf --qf '%{NAME}\n' <paths> | sort -u | rpm -q --qf '[%{FILENAMES}\t%{=NAME}\n]'.
// Lines that are not a package name ("file ... is not owned by any package") are skipped; rpm
// exits non-zero for those, which is not a failure. nil when rpm fails otherwise or runs out of
// time.
func (c *Collector) rpmOwners(ctx context.Context, need map[string]bool) map[string][]string {
	rpm, ok := c.lookPath("rpm")
	if !ok {
		return nil
	}
	// query runs rpm with the fixed options and the operands in batches, passing each output line
	// to each; false when a run failed (other than by a non-zero exit) or time ran out.
	query := func(options, operands []string, each func(line string)) bool {
		for len(operands) > 0 {
			n := min(len(operands), rpmArgsPerRun)
			args := append(slices.Clone(options), operands[:n]...)
			operands = operands[n:]
			out, err := c.run(ctx, rpm, args...)
			if (err != nil && exitCode(err) <= 0) || ctx.Err() != nil {
				return false
			}
			for _, line := range splitLines(out) {
				each(string(line))
			}
		}
		return true
	}

	names := map[string]bool{}
	if !query([]string{"-qf", "--qf", `%{NAME}\n`}, sortedKeys(need), func(line string) {
		if rpmName.MatchString(line) {
			names[line] = true
		}
	}) {
		return nil
	}
	owners := map[string][]string{}
	if !query([]string{"-q", "--qf", `[%{FILENAMES}\t%{=NAME}\n]`}, sortedKeys(names), func(line string) {
		p, pkg, ok := strings.Cut(line, "\t")
		if ok && need[p] && rpmName.MatchString(pkg) && !slices.Contains(owners[p], pkg) {
			owners[p] = append(owners[p], pkg)
		}
	}) {
		return nil
	}
	return owners
}

// apkOwners does the same with /lib/apk/db/installed (P: package, F: directory, R: file).
func (c *Collector) apkOwners(ctx context.Context, need map[string]bool) map[string][]string {
	f, err := os.Open(c.path("/lib/apk/db/installed"))
	if err != nil {
		return nil
	}
	defer f.Close()
	owners := map[string][]string{}
	var pkg, dir string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 0; sc.Scan(); n++ {
		if n%4096 == 0 && ctx.Err() != nil {
			return nil
		}
		l := sc.Text()
		switch {
		case l == "":
			pkg, dir = "", ""
		case strings.HasPrefix(l, "P:"):
			pkg, dir = l[2:], ""
		case strings.HasPrefix(l, "F:"):
			dir = l[2:]
		case strings.HasPrefix(l, "R:") && pkg != "":
			p := path.Join("/", dir, l[2:])
			if need[p] && !slices.Contains(owners[p], pkg) {
				owners[p] = append(owners[p], pkg)
			}
		}
	}
	if sc.Err() != nil {
		return nil
	}
	return owners
}

// elfObj is what the dynamic linker needs from an ELF file.
type elfObj struct {
	class          elf.Class
	machine        elf.Machine
	needed         []string
	rpath, runpath []string
	interp         string
}

// elfCache parses each file once; a nil entry is a file that is not a readable ELF.
type elfCache struct {
	c        *Collector
	objs     map[string]*elfObj
	ldDirs   []string
	ldLoaded bool
}

func (r *elfCache) load(p string) *elfObj {
	if o, ok := r.objs[p]; ok {
		return o
	}
	o := r.c.readELF(p)
	r.objs[p] = o
	return o
}

// readELF parses the dynamic section of the regular file p (at most maxELFSize). It never
// executes anything; malformed files are nil.
func (c *Collector) readELF(p string) (obj *elfObj) {
	if !path.IsAbs(p) || strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/sys/") || strings.HasPrefix(p, "/dev/") {
		return nil
	}
	defer func() {
		if recover() != nil {
			obj = nil
		}
	}()
	full := c.path(p)
	if st, err := os.Stat(full); err != nil || !st.Mode().IsRegular() || st.Size() > maxELFSize {
		return nil
	}
	// O_NONBLOCK: a FIFO swapped in after the Stat must not block the open.
	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > maxELFSize {
		return nil
	}
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil || string(magic[:]) != elf.ELFMAG {
		return nil
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil
	}
	o := &elfObj{class: ef.Class, machine: ef.Machine}
	o.needed, _ = ef.ImportedLibraries()
	o.rpath = dynPaths(ef, elf.DT_RPATH)
	o.runpath = dynPaths(ef, elf.DT_RUNPATH)
	for _, prog := range ef.Progs {
		if prog.Type == elf.PT_INTERP {
			b, _ := io.ReadAll(io.LimitReader(prog.Open(), 4096))
			o.interp = string(bytes.TrimRight(b, "\x00"))
		}
	}
	return o
}

func dynPaths(ef *elf.File, tag elf.DynTag) []string {
	vals, _ := ef.DynString(tag)
	var dirs []string
	for _, v := range vals {
		for _, d := range strings.Split(v, ":") {
			if d != "" {
				dirs = append(dirs, d)
			}
		}
	}
	return dirs
}

// closure returns progs and every shared library they load, recursively, resolved the way
// the dynamic linker does: DT_RPATH (of the object and its loaders, unless the object has
// DT_RUNPATH), DT_RUNPATH, /etc/ld.so.conf, then the default directories. A library must match
// the class and machine of the object that needs it.
func (r *elfCache) closure(progs []string) []string {
	type item struct {
		path      string
		obj       *elfObj
		depth     int
		inherited []string // DT_RPATH dirs of the loaders
	}
	seen := map[string]bool{}
	var files []string
	var stack []item
	push := func(p string, o *elfObj, depth int, inh []string) {
		if !seen[p] {
			seen[p] = true
			files = append(files, p)
			stack = append(stack, item{p, o, depth, inh})
		}
	}
	for _, p := range progs {
		if o := r.load(p); o != nil {
			push(p, o, 0, nil)
		}
	}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if it.depth >= maxELFDepth {
			continue
		}
		origin := path.Dir(it.path)
		if rp := r.c.realpath(it.path); rp != "" {
			origin = path.Dir(rp)
		}
		var rpath []string
		inherited := it.inherited
		if len(it.obj.runpath) == 0 {
			rpath = append(expandOrigin(it.obj.rpath, origin), it.inherited...)
			inherited = rpath
		}
		runpath := expandOrigin(it.obj.runpath, origin)
		if it.obj.interp != "" {
			if o := r.load(it.obj.interp); o != nil {
				push(it.obj.interp, o, it.depth+1, nil)
			}
		}
		for _, name := range it.obj.needed {
			if p, o := r.find(name, it.obj, rpath, runpath); o != nil {
				push(p, o, it.depth+1, inherited)
			}
		}
	}
	return files
}

func expandOrigin(dirs []string, origin string) []string {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		d = strings.ReplaceAll(strings.ReplaceAll(d, "${ORIGIN}", origin), "$ORIGIN", origin)
		if path.IsAbs(d) {
			out = append(out, path.Clean(d))
		}
	}
	return out
}

func (r *elfCache) find(name string, parent *elfObj, rpath, runpath []string) (string, *elfObj) {
	compatible := func(o *elfObj) bool {
		return o != nil && o.class == parent.class && o.machine == parent.machine
	}
	if strings.Contains(name, "/") {
		if o := r.load(name); path.IsAbs(name) && compatible(o) {
			return name, o
		}
		return "", nil
	}
	for _, dirs := range [][]string{rpath, runpath, r.ldConfDirs(), defaultLibDirs(parent.machine)} {
		for _, d := range dirs {
			p := path.Join(d, name)
			if o := r.load(p); compatible(o) {
				return p, o
			}
		}
	}
	return "", nil
}

var triplets = map[elf.Machine][]string{
	elf.EM_X86_64:  {"x86_64-linux-gnu"},
	elf.EM_AARCH64: {"aarch64-linux-gnu"},
	elf.EM_386:     {"i386-linux-gnu"},
	elf.EM_ARM:     {"arm-linux-gnueabihf", "arm-linux-gnueabi"},
	elf.EM_RISCV:   {"riscv64-linux-gnu"},
	elf.EM_PPC64:   {"powerpc64le-linux-gnu", "powerpc64-linux-gnu"},
	elf.EM_S390:    {"s390x-linux-gnu"},
}

func defaultLibDirs(m elf.Machine) []string {
	var dirs []string
	for _, t := range triplets[m] {
		dirs = append(dirs, "/lib/"+t, "/usr/lib/"+t)
	}
	return append(dirs, "/lib64", "/usr/lib64", "/lib", "/usr/lib")
}

// ldConfDirs returns the directories of /etc/ld.so.conf and the files it includes.
func (r *elfCache) ldConfDirs() []string {
	if !r.ldLoaded {
		r.ldLoaded = true
		r.parseLdConf("/etc/ld.so.conf", 0, map[string]bool{})
	}
	return r.ldDirs
}

func (r *elfCache) parseLdConf(p string, depth int, seen map[string]bool) {
	if depth > maxLdConfDepth || seen[p] {
		return
	}
	seen[p] = true
	data, err := r.c.readFile(p, 1<<20)
	if err != nil {
		return
	}
	for _, line := range splitLines(data) {
		l := string(line)
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		fields := strings.Fields(l)
		switch {
		case len(fields) == 0 || fields[0] == "hwcap":
		case fields[0] == "include":
			for _, pat := range fields[1:] {
				if !path.IsAbs(pat) {
					pat = path.Join(path.Dir(p), pat)
				}
				matches, _ := filepath.Glob(r.c.path(pat))
				for _, m := range matches {
					if inc := r.c.unroot(m); inc != "" {
						r.parseLdConf(inc, depth+1, seen)
					}
				}
			}
		default:
			for _, d := range fields {
				d, _, _ = strings.Cut(d, "=") // legacy dir=type
				if path.IsAbs(d) && !slices.Contains(r.ldDirs, path.Clean(d)) {
					r.ldDirs = append(r.ldDirs, path.Clean(d))
				}
			}
		}
	}
}
