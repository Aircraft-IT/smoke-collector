// Package lockfiles reads the application lockfiles at the paths configured on the host
// (OS detection plan §4b.1) and builds the body of POST /api/v1/collector/lockfiles.
//
// Each configured path is a directory (only the supported file names directly inside it are
// read, never subdirectories and never any other file) or a file whose name is supported.
// Symbolic links are followed. Files are opened read-only and non-blocking and must be regular
// files. Limits: 20 MB per file and 50 MB for the whole report (counted as sent, JSON-encoded);
// a path over a limit is reported as too_large without its files. Only the first 50 paths are
// read; the others are reported as over_limit (path only), so Smoke can show them.
package lockfiles

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

// ContentType of the report (Smoke checks the token before it parses the body).
const ContentType = "application/vnd.smoke.lockfile-report+json"

// ReportPath is the upload API, relative to the Smoke URL.
const ReportPath = "/api/v1/collector/lockfiles"

const (
	// MaxPaths is the number of paths read in one run; the lockfile= lines after it are reported
	// as over_limit without being read.
	MaxPaths = 50
	// MaxConfigPaths is the number of lockfile= lines allowed in the configuration.
	MaxConfigPaths = 200
	// MaxPathLen is the longest path Smoke accepts.
	MaxPathLen = 512
	// MaxFileBytes is the limit per file (FR-INV-01).
	MaxFileBytes = 20 << 20
	// MaxTotalBytes is the limit of the whole report as sent (before gzip).
	MaxTotalBytes = 50 << 20
	// MaxFilesPerPath is the number of files one path may report.
	MaxFilesPerPath = 20
)

// Status of one configured path.
type Status string

const (
	StatusOK         Status = "ok"
	StatusNotFound   Status = "not_found"
	StatusUnreadable Status = "unreadable"
	StatusNoLockfile Status = "no_lockfile"
	StatusTooLarge   Status = "too_large"
	// StatusOverLimit: the path comes after the first MaxPaths and was not read.
	StatusOverLimit Status = "over_limit"
)

// File is one lockfile. Size and SHA256 are those of Content (the bytes Smoke receives).
type File struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Size    int    `json:"-"`
	SHA256  string `json:"-"`
}

// Entry is one configured path. Reason explains a status other than ok, and Dir says the path
// is a directory (neither is sent).
type Entry struct {
	Path   string `json:"path"`
	Status Status `json:"status"`
	Files  []File `json:"files,omitempty"`
	Reason string `json:"-"`
	Dir    bool   `json:"-"`
}

// Report is the request body.
type Report struct {
	Lockfiles []Entry `json:"lockfiles"`
}

var exactNames = map[string]bool{
	"package-lock.json":   true,
	"npm-shrinkwrap.json": true,
	"pnpm-lock.yaml":      true,
	"yarn.lock":           true,
	"composer.lock":       true,
	"poetry.lock":         true,
	"uv.lock":             true,
	"Pipfile.lock":        true,
	"go.mod":              true,
	"Cargo.lock":          true,
	"gradle.lockfile":     true,
	"packages.lock.json":  true,
	"pubspec.lock":        true,
}

// requirementsRe is smoke-backend's REQUIREMENTS (src/inventory/parsers/detect.ts).
var requirementsRe = regexp.MustCompile(`(?i)^(?:requirements(?:[-_.][\w.-]+)?|[\w.-]+[-_.]requirements)\.txt$`)

// Supported reports whether name (a plain file name) is a lockfile name Smoke accepts.
func Supported(name string) bool {
	if name == "" || strings.Contains(name, "/") {
		return false
	}
	return exactNames[name] || requirementsRe.MatchString(name)
}

// CheckPath validates a configured path: absolute, clean (a trailing / is removed first, except
// for /), at most 512 bytes, no control characters. It returns the path to use.
func CheckPath(p string) (string, error) {
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	switch {
	case !path.IsAbs(p):
		return "", errors.New("must be an absolute path")
	case path.Clean(p) != p:
		return "", errors.New("must be a clean path (no //, . or ..)")
	case len(p) > MaxPathLen:
		return "", fmt.Errorf("is longer than %d bytes", MaxPathLen)
	case !utf8.ValidString(p):
		return "", errors.New("is not valid UTF-8")
	}
	for _, r := range p {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return "", errors.New("contains a control character")
		}
	}
	return p, nil
}

// Reader reads the configured paths. The zero value uses the limits above.
type Reader struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	// Logf reports problems (stderr in production). May be nil.
	Logf func(format string, args ...any)
}

// Read reads every path (already checked with CheckPath) and returns the report. It never fails:
// problems become the status of the path concerned.
func (r *Reader) Read(paths []string) *Report {
	maxTotal := r.MaxTotalBytes
	if maxTotal <= 0 {
		maxTotal = MaxTotalBytes
	}
	rep := &Report{Lockfiles: []Entry{}}
	total := int64(len(`{"lockfiles":[]}` + "\n"))
	if len(paths) > MaxPaths && r.Logf != nil {
		r.Logf("%d lockfile path(s) not read: only the first %d are read in one run (the others are reported as over_limit)",
			len(paths)-MaxPaths, MaxPaths)
	}
	for i, p := range paths {
		if i >= MaxPaths {
			e := Entry{Path: p, Status: StatusOverLimit,
				Reason: fmt.Sprintf("only the first %d lockfile paths are read", MaxPaths)}
			total += encodedSize(e) + 1
			rep.Lockfiles = append(rep.Lockfiles, e)
			continue
		}
		e := r.readPath(p)
		size := encodedSize(e)
		if e.Status == StatusOK && total+size+1 > maxTotal {
			e = Entry{Path: p, Status: StatusTooLarge,
				Reason: fmt.Sprintf("the report would be larger than %d MB in total", maxTotal>>20)}
			size = encodedSize(e)
		}
		if e.Status != StatusOK && r.Logf != nil {
			r.Logf("lockfile %s: %s (%s)", p, e.Status, e.Reason)
		}
		total += size + 1
		rep.Lockfiles = append(rep.Lockfiles, e)
	}
	return rep
}

func encodedSize(e Entry) int64 {
	b, err := marshal(e)
	if err != nil {
		return 0
	}
	return int64(len(b))
}

func (r *Reader) maxFile() int64 {
	if r.MaxFileBytes > 0 {
		return r.MaxFileBytes
	}
	return MaxFileBytes
}

func (r *Reader) readPath(p string) Entry {
	st, err := os.Stat(p) // follows symbolic links
	if err != nil {
		return Entry{Path: p, Status: statusOf(err), Reason: reason(err)}
	}
	switch {
	case st.IsDir():
		return r.readDir(p)
	case st.Mode().IsRegular():
		name := path.Base(p)
		if !Supported(name) {
			return Entry{Path: p, Status: StatusNoLockfile, Reason: name + " is not a supported lockfile name"}
		}
		f, status, why := r.readFile(p, name)
		if status != StatusOK {
			return Entry{Path: p, Status: status, Reason: why}
		}
		return Entry{Path: p, Status: StatusOK, Files: []File{f}}
	default:
		return Entry{Path: p, Status: StatusUnreadable, Reason: "not a regular file or directory"}
	}
}

func (r *Reader) readDir(dir string) Entry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Entry{Path: dir, Status: statusOf(err), Reason: reason(err)}
	}
	var names []string
	for _, de := range entries {
		if !Supported(de.Name()) {
			continue // never opened
		}
		st, err := os.Stat(path.Join(dir, de.Name()))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue // a dangling symbolic link
		case err != nil:
			return Entry{Path: dir, Status: StatusUnreadable, Reason: de.Name() + ": " + reason(err)}
		case st.IsDir():
			continue
		}
		names = append(names, de.Name())
	}
	if len(names) == 0 {
		return Entry{Path: dir, Status: StatusNoLockfile, Reason: "no supported lockfile name in the directory"}
	}
	if len(names) > MaxFilesPerPath {
		return Entry{Path: dir, Status: StatusTooLarge, Reason: fmt.Sprintf("more than %d lockfiles", MaxFilesPerPath)}
	}
	var files []File
	for _, name := range names {
		f, status, why := r.readFile(path.Join(dir, name), name)
		if status != StatusOK {
			return Entry{Path: dir, Status: status, Reason: name + ": " + why}
		}
		files = append(files, f)
	}
	return Entry{Path: dir, Status: StatusOK, Files: files, Dir: true}
}

// readFile reads one regular file. O_NONBLOCK keeps a FIFO swapped in after the Stat from
// blocking the open.
func (r *Reader) readFile(p, name string) (File, Status, string) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return File{}, statusOf(err), reason(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return File{}, StatusUnreadable, reason(err)
	}
	if !st.Mode().IsRegular() {
		return File{}, StatusUnreadable, "not a regular file"
	}
	limit := r.maxFile()
	if st.Size() > limit {
		return File{}, StatusTooLarge, fmt.Sprintf("larger than %d MB", limit>>20)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return File{}, StatusUnreadable, reason(err)
	}
	if int64(len(data)) > limit {
		return File{}, StatusTooLarge, fmt.Sprintf("larger than %d MB", limit>>20)
	}
	if !utf8.Valid(data) {
		// JSON carries text: invalid bytes become U+FFFD, and the size and SHA-256 are those of
		// what is sent, which is what Smoke hashes.
		data = bytes.ToValidUTF8(data, []byte("�"))
		if r.Logf != nil {
			r.Logf("lockfile %s is not valid UTF-8; invalid bytes are sent as U+FFFD", p)
		}
	}
	sum := sha256.Sum256(data)
	return File{Name: name, Content: string(data), Size: len(data), SHA256: hex.EncodeToString(sum[:])}, StatusOK, ""
}

func statusOf(err error) Status {
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return StatusNotFound
	default:
		return StatusUnreadable
	}
}

// reason is the error without the path (the caller prints the path once).
func reason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Body is the request body: the JSON report followed by a newline.
func (rep *Report) Body() ([]byte, error) {
	b, err := marshal(rep)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Digest is Smoke's lockfile_digest of an ok entry: the SHA-256 (hex) of the lines
// "<name>\t<sha256 hex of content>\n" sorted by name.
func Digest(files []File) string {
	sorted := slices.Clone(files)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	for _, f := range sorted {
		b.WriteString(f.Name + "\t" + f.SHA256 + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
