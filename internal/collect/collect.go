// Package collect builds the `#smoke-host 1` host inventory (OS detection plan
// §2.1, §2.2, §2.4, §5.1). The output is byte-for-byte what the shell commands
// in the plan print on the same machine, so the backend parser needs no change.
//
// Only three external programs are run (dpkg-query or apk, and systemctl),
// directly with exec (never through a shell), found in fixed directories, with
// a timeout. Nothing else is read except /etc/os-release and whether
// /var/run/reboot-required exists.
package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Magic is the first line of the format.
const Magic = "#smoke-host 1"

// DpkgFormat is the dpkg-query format of plan §2.1 (dpkg-query expands \t and \n itself).
const DpkgFormat = `${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n`

// SearchDirs are the only directories searched for programs (no $PATH).
var SearchDirs = []string{"/usr/bin", "/bin", "/sbin", "/usr/sbin"}

// Limits.
const (
	DefaultTimeout = 2 * time.Minute
	// MaxCommandOutput caps what is read from one program (the backend accepts 5 MB in total).
	MaxCommandOutput = 32 << 20
	maxOSRelease     = 64 << 10
)

// Error is a collection failure (exit code 2).
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func errorf(format string, args ...any) error { return &Error{msg: fmt.Sprintf(format, args...)} }

// ExecFunc runs the program at path with args and returns its standard output.
// A non-nil error may come with partial output.
type ExecFunc func(ctx context.Context, path string, args ...string) ([]byte, error)

// Collector gathers the inventory. The zero value is not usable; see New.
type Collector struct {
	// Root is prepended to every file and program path ("/" in production; a fake root in tests).
	Root string
	// Dirs are the program search directories, relative to Root.
	Dirs []string
	// Exec runs a program.
	Exec ExecFunc
	// KernelRelease returns what `uname -r` prints.
	KernelRelease func() (string, error)
	// Timeout bounds each program run.
	Timeout time.Duration
}

// New returns the production collector.
func New() *Collector {
	return &Collector{
		Root:          "/",
		Dirs:          SearchDirs,
		Exec:          Run,
		KernelRelease: kernelRelease,
		Timeout:       DefaultTimeout,
	}
}

// Manager is the package manager section written.
type Manager string

const (
	Dpkg Manager = "dpkg"
	Apk  Manager = "apk"
)

// Result is the collected inventory.
type Result struct {
	Body    []byte
	Manager Manager
	// OSID is the ID from /etc/os-release (unquoted), for messages.
	OSID string
}

var (
	debOSRelease = regexp.MustCompile(`^(ID|VERSION_ID|VERSION_CODENAME)=`)
	apkOSRelease = regexp.MustCompile(`^(ID|VERSION_ID)=`)
	idLine       = regexp.MustCompile(`^ID=(.*)$`)
)

// Collect builds the `#smoke-host 1` text.
func (c *Collector) Collect(ctx context.Context) (*Result, error) {
	osRelease, err := c.readFile("/etc/os-release", maxOSRelease)
	if err != nil {
		return nil, errorf("cannot read /etc/os-release: %v", err)
	}
	id := osID(osRelease)

	dpkgQuery, hasDpkg := c.lookPath("dpkg-query")
	apk, hasApk := c.lookPath("apk")
	var mgr Manager
	switch {
	case id == "alpine" && hasApk, !hasDpkg && hasApk:
		mgr = Apk
	case id != "alpine" && hasDpkg:
		mgr = Dpkg
	case id == "alpine":
		return nil, errorf("apk not found in %s", strings.Join(c.Dirs, ", "))
	default:
		return nil, errorf("neither dpkg-query nor apk found in %s (supported: Ubuntu, Debian, Alpine)",
			strings.Join(c.Dirs, ", "))
	}

	kernel, err := c.KernelRelease()
	if err != nil {
		return nil, errorf("cannot read the kernel release: %v", err)
	}

	var b bytes.Buffer
	b.WriteString(Magic + "\n")
	b.WriteString("#os-release\n")
	// grep -E "^(ID|VERSION_ID[|VERSION_CODENAME])=" /etc/os-release
	if mgr == Dpkg {
		grepLines(&b, osRelease, debOSRelease)
	} else {
		grepLines(&b, osRelease, apkOSRelease)
	}
	b.WriteString("#kernel\n")
	b.WriteString(kernel + "\n")

	if mgr == Dpkg {
		b.WriteString("#packages dpkg\n")
		out, err := c.run(ctx, dpkgQuery, "-W", "-f="+DpkgFormat)
		if err != nil {
			return nil, errorf("dpkg-query failed: %v", err)
		}
		writeOutput(&b, out)

		b.WriteString("#services\n")
		// systemctl ... 2>/dev/null | cut -d" " -f1. Missing or failing systemctl (containers) is
		// not an error: whatever it printed is used, like the shell pipeline.
		if systemctl, ok := c.lookPath("systemctl"); ok {
			out, _ := c.run(ctx, systemctl, "list-units", "--type=service", "--state=running", "--no-legend", "--plain")
			cutFirstField(&b, out)
		}

		b.WriteString("#reboot-required\n")
		if c.isRegularFile("/var/run/reboot-required") {
			b.WriteString("yes\n")
		} else {
			b.WriteString("no\n")
		}
	} else {
		b.WriteString("#packages apk\n")
		out, err := c.run(ctx, apk, "list", "--installed")
		if err != nil {
			return nil, errorf("apk list --installed failed: %v", err)
		}
		writeOutput(&b, out)
		// §2.2 has no #services section and always says no.
		b.WriteString("#reboot-required\nno\n")
	}
	return &Result{Body: b.Bytes(), Manager: mgr, OSID: id}, nil
}

func (c *Collector) path(p string) string { return filepath.Join(c.Root, p) }

func (c *Collector) readFile(p string, limit int64) ([]byte, error) {
	f, err := os.Open(c.path(p))
	if err != nil {
		return nil, unwrapPathError(err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}

func (c *Collector) isRegularFile(p string) bool {
	st, err := os.Stat(c.path(p)) // follows symlinks, like test -f
	return err == nil && st.Mode().IsRegular()
}

// lookPath finds an executable regular file named name in c.Dirs.
func (c *Collector) lookPath(name string) (string, bool) {
	for _, d := range c.Dirs {
		p := c.path(filepath.Join(d, name))
		st, err := os.Stat(p)
		if err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

func (c *Collector) run(ctx context.Context, path string, args ...string) ([]byte, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.Exec(ctx, path, args...)
}

// osID returns the unquoted ID= value.
func osID(osRelease []byte) string {
	for _, line := range splitLines(osRelease) {
		if m := idLine.FindSubmatch(line); m != nil {
			v := strings.TrimSpace(string(m[1]))
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				v = v[1 : len(v)-1]
			}
			return v
		}
	}
	return ""
}

// splitLines splits like grep and cut do: a final line without a newline is still a line.
func splitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	lines := bytes.Split(data, []byte("\n"))
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// grepLines writes the lines that match re, each followed by a newline (grep -E).
func grepLines(b *bytes.Buffer, data []byte, re *regexp.Regexp) {
	for _, line := range splitLines(data) {
		if re.Match(line) {
			b.Write(line)
			b.WriteByte('\n')
		}
	}
}

// cutFirstField writes the text before the first space of each line, or the whole line when
// it has no space (cut -d" " -f1).
func cutFirstField(b *bytes.Buffer, data []byte) {
	for _, line := range splitLines(data) {
		if i := bytes.IndexByte(line, ' '); i >= 0 {
			line = line[:i]
		}
		b.Write(line)
		b.WriteByte('\n')
	}
}

// writeOutput copies program output verbatim. Output that does not end with a newline gets
// one, so the next section marker starts on its own line (the shell would glue them together;
// this never happens with real dpkg-query or apk output).
func writeOutput(b *bytes.Buffer, out []byte) {
	b.Write(out)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		b.WriteByte('\n')
	}
}

func unwrapPathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// Run is the production ExecFunc: no shell, a fixed environment, the working directory /,
// standard input empty, output capped at MaxCommandOutput.
func Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // path is from lookPath (fixed directories), args are constants; no shell
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 5 * time.Second
	stdout := &cappedBuffer{max: MaxCommandOutput}
	stderr := &cappedBuffer{max: 4 << 10, discard: true}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if stdout.over {
		return stdout.Bytes(), fmt.Errorf("output is larger than %d bytes", MaxCommandOutput)
	}
	if ctx.Err() != nil {
		return stdout.Bytes(), fmt.Errorf("%s did not finish in time", filepath.Base(path))
	}
	if err != nil {
		msg := strings.TrimSpace(firstLine(stderr.String()))
		if msg != "" {
			return stdout.Bytes(), fmt.Errorf("%w: %s", err, msg)
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// cappedBuffer keeps at most max bytes. Past that it either fails the write, which stops the
// copy and fails the run, or (discard) drops the rest silently.
type cappedBuffer struct {
	bytes.Buffer
	max     int
	discard bool
	over    bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.max {
		if c.discard {
			if room := c.max - c.Len(); room > 0 {
				c.Buffer.Write(p[:room])
			}
			return len(p), nil
		}
		c.over = true
		return 0, errors.New("output too large")
	}
	return c.Buffer.Write(p)
}
