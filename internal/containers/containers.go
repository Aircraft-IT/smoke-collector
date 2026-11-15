// Package containers builds the container collector's report (OS detection plan §4a, spec
// FR-COL-09): for each distinct image of the running containers, its reference and digest and,
// read from one of its containers through the Docker API archive endpoint, the distribution and
// the package list as `#smoke-host 1` text.
//
// Only these files are read, and only through docker.Client: /etc/os-release (or
// /usr/lib/os-release), /var/lib/dpkg/status, /var/lib/dpkg/status.d/ and /lib/apk/db/installed;
// /var/lib/rpm and /usr/lib/sysimage/rpm are only checked for existence. Container names, labels,
// ports, mounts, commands and environment variables are never decoded or sent.
package containers

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"gitlab.aircraft.tw/smoke/smoke-collector/internal/collect"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/docker"
)

// Statuses of an image in the report.
const (
	StatusOK           = "ok"
	StatusNoPackages   = "no_packages"
	StatusUnsupported  = "unsupported"
	StatusUntagged     = "untagged"
	StatusSkippedLimit = "skipped_limit"
)

// Limits.
const (
	// MaxImages is the number of images whose packages are read in one run (spec FR-COL-09).
	MaxImages = 50
	// MaxFileBytes caps one file (or the files of status.d together).
	MaxFileBytes = 16 << 20
	// maxSymlinks bounds the os-release symlink chain.
	maxSymlinks = 5
	// containersPerImage is how many containers of one image are tried before giving up.
	containersPerImage = 3
	// tarOverhead allows for tar headers and padding on top of MaxFileBytes.
	tarOverhead = 1 << 20
)

// Image is one entry of the report (the backend contract of POST /api/v1/collector/containers).
type Image struct {
	Reference  *string `json:"reference"`
	ImageID    string  `json:"imageId"`
	RepoDigest *string `json:"repoDigest"`
	Containers int     `json:"containers"`
	Status     string  `json:"status"`
	Inventory  string  `json:"inventory,omitempty"`
	// Labels holds only LabelKeys, so Smoke can tell the public image it is built from (FR-COL-17).
	// Always sent (possibly empty), so Smoke can tell a collector that reads labels from one that
	// does not.
	Labels map[string]string `json:"labels"`
}

// LabelKeys are the only image labels reported: the OCI annotations naming where the image
// comes from. Other labels can hold anything (credentials, internal names, the authors' e-mail
// addresses) and are never read.
var LabelKeys = []string{
	"org.opencontainers.image.source",
	"org.opencontainers.image.title",
	"org.opencontainers.image.version",
	"org.opencontainers.image.base.name",
}

// maxLabelValue bounds each reported label value.
const maxLabelValue = 256

// Report is the request body.
type Report struct {
	Images []Image `json:"images"`
}

// API is the part of docker.Client the collector uses.
type API interface {
	Containers(ctx context.Context) ([]docker.Container, error)
	Image(ctx context.Context, id string) (*docker.Image, error)
	Archive(ctx context.Context, containerID, path string) (io.ReadCloser, error)
}

// Collector builds the report.
type Collector struct {
	API API
	// MaxImages overrides MaxImages when > 0 (tests).
	MaxImages int
	// Logf reports problems that do not stop the run (stderr in production). May be nil.
	Logf func(format string, args ...any)
}

var (
	imageIDRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// An image given by ID instead of name: sha256:<hex> or a (possibly short) hex ID.
	idLikeRe = regexp.MustCompile(`^(sha256:)?[0-9a-f]{12,64}$`)
)

type group struct {
	imageID    string
	containers []docker.Container
}

// Collect builds the report. An error means the running containers could not be listed;
// problems with single images are logged and reported in the image's status.
func (c *Collector) Collect(ctx context.Context) (*Report, error) {
	list, err := c.API.Containers(ctx)
	if err != nil {
		return nil, err
	}
	byImage := map[string]*group{}
	for _, ct := range list {
		if !imageIDRe.MatchString(ct.ImageID) {
			c.logf("skipping a container with an unexpected image ID %q", clip(ct.ImageID))
			continue
		}
		g := byImage[ct.ImageID]
		if g == nil {
			g = &group{imageID: ct.ImageID}
			byImage[ct.ImageID] = g
		}
		g.containers = append(g.containers, ct)
	}
	groups := make([]*group, 0, len(byImage))
	for _, g := range byImage {
		groups = append(groups, g)
	}
	// Most containers first, so the limit drops the least used images; then by ID for a stable order.
	sort.Slice(groups, func(i, j int) bool {
		if len(groups[i].containers) != len(groups[j].containers) {
			return len(groups[i].containers) > len(groups[j].containers)
		}
		return groups[i].imageID < groups[j].imageID
	})

	limit := c.MaxImages
	if limit <= 0 {
		limit = MaxImages
	}
	report := &Report{Images: []Image{}}
	read := 0
	for _, g := range groups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		img := Image{ImageID: g.imageID, Containers: len(g.containers)}
		var inspect *docker.Image
		if got, err := c.API.Image(ctx, g.imageID); err == nil {
			inspect = got
		} else {
			c.logf("image %s: %v", short(g.imageID), err)
		}
		img.Reference = reference(g.containers[0].Image, inspect)
		img.RepoDigest = repoDigest(img.Reference, inspect)
		img.Labels = labels(inspect)
		switch {
		case img.Reference == nil:
			img.Status = StatusUntagged
		case read >= limit:
			img.Status = StatusSkippedLimit
		default:
			read++
			img.Status, img.Inventory = c.inventory(ctx, g)
		}
		report.Images = append(report.Images, img)
	}
	return report, nil
}

// inventory reads the packages of an image from one of its containers.
func (c *Collector) inventory(ctx context.Context, g *group) (string, string) {
	var lastErr error
	for i, ct := range g.containers {
		if i >= containersPerImage {
			break
		}
		status, text, err := c.readContainer(ctx, ct.ID)
		if err == nil {
			return status, text
		}
		lastErr = err
	}
	// Unreadable (the containers stopped meanwhile, a database over the size limit, ...): the
	// image is still reported, so Smoke keeps it linked to this server.
	c.logf("image %s: cannot read its packages: %v", short(g.imageID), lastErr)
	return StatusNoPackages, ""
}

func (c *Collector) readContainer(ctx context.Context, id string) (string, string, error) {
	osRelease, err := c.readFile(ctx, id, "/etc/os-release")
	if errors.Is(err, docker.ErrNotFound) {
		osRelease, err = c.readFile(ctx, id, "/usr/lib/os-release")
	}
	if err != nil && !errors.Is(err, docker.ErrNotFound) {
		return "", "", fmt.Errorf("os-release: %w", err)
	}
	osID := collect.OSID(osRelease)

	apk, err := c.readFile(ctx, id, "/lib/apk/db/installed")
	if err != nil && !errors.Is(err, docker.ErrNotFound) {
		return "", "", fmt.Errorf("apk database: %w", err)
	}
	hasApk := err == nil
	if hasApk && osID == "alpine" {
		return StatusOK, hostText(osRelease, collect.Apk, apkLines(apk)), nil
	}

	status, err := c.readFile(ctx, id, "/var/lib/dpkg/status")
	if err != nil && !errors.Is(err, docker.ErrNotFound) {
		return "", "", fmt.Errorf("dpkg database: %w", err)
	}
	hasStatus := err == nil
	statusD, err := c.readDir(ctx, id, "/var/lib/dpkg/status.d")
	if err != nil && !errors.Is(err, docker.ErrNotFound) {
		return "", "", fmt.Errorf("dpkg status.d: %w", err)
	}
	hasDpkg := hasStatus || len(statusD) > 0
	if hasDpkg && (osID == "ubuntu" || osID == "debian") {
		return StatusOK, hostText(osRelease, collect.Dpkg, dpkgLines(append([][]byte{status}, statusD...)...)), nil
	}
	if hasApk || hasDpkg {
		return StatusUnsupported, "", nil // a distribution Smoke does not support, or no os-release
	}
	for _, p := range []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"} {
		ok, err := c.exists(ctx, id, p)
		if err != nil {
			return "", "", fmt.Errorf("rpm database: %w", err)
		}
		if ok {
			return StatusUnsupported, "", nil // RHEL family: the rpm database is SQLite (not read)
		}
	}
	return StatusNoPackages, "", nil
}

// readFile reads one regular file, following symbolic links inside the container.
func (c *Collector) readFile(ctx context.Context, id, p string) ([]byte, error) {
	for hop := 0; ; hop++ {
		target, data, err := c.readOne(ctx, id, p)
		if err != nil || target == "" {
			return data, err
		}
		if hop >= maxSymlinks {
			return nil, fmt.Errorf("%s: more than %d symbolic links", p, maxSymlinks)
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(p), target)
		}
		p = path.Clean(target)
	}
}

// readOne returns the file at p, or the target of the symbolic link at p.
func (c *Collector) readOne(ctx context.Context, id, p string) (string, []byte, error) {
	rc, err := c.API.Archive(ctx, id, p)
	if err != nil {
		return "", nil, err
	}
	defer rc.Close()
	tr := tar.NewReader(io.LimitReader(rc, MaxFileBytes+tarOverhead))
	h, err := tr.Next()
	if err != nil {
		return "", nil, fmt.Errorf("%s: reading the archive: %w", p, err)
	}
	switch h.Typeflag {
	case tar.TypeSymlink:
		return h.Linkname, nil, nil
	case tar.TypeReg:
		if h.Size > MaxFileBytes {
			return "", nil, fmt.Errorf("%s is larger than %d bytes", p, MaxFileBytes)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", p, err)
		}
		return "", data, nil
	default:
		return "", nil, fmt.Errorf("%s is not a regular file", p)
	}
}

// readDir returns the regular files directly in the directory p (status.d: one file per
// package; the *.md5sums files are skipped). A missing directory is docker.ErrNotFound.
func (c *Collector) readDir(ctx context.Context, id, p string) ([][]byte, error) {
	rc, err := c.API.Archive(ctx, id, p)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	tr := tar.NewReader(io.LimitReader(rc, MaxFileBytes+tarOverhead))
	var files [][]byte
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: reading the archive: %w", p, err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		// The archive of a directory has the directory itself first, then base/<file>.
		dir, file := path.Split(name)
		if h.Typeflag != tar.TypeReg || strings.Count(strings.Trim(dir, "/"), "/") != 0 || dir == "" ||
			strings.HasSuffix(file, ".md5sums") {
			continue
		}
		total += h.Size
		if total > MaxFileBytes {
			return nil, fmt.Errorf("%s holds more than %d bytes", p, MaxFileBytes)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		files = append(files, data)
	}
}

// exists says whether p exists in the container; the archive is closed without reading it.
func (c *Collector) exists(ctx context.Context, id, p string) (bool, error) {
	rc, err := c.API.Archive(ctx, id, p)
	if errors.Is(err, docker.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	rc.Close()
	return true, nil
}

// reference is the image name the container was started with, unless it was started by ID;
// then the image's first tag. nil when the image has no name (untagged).
func reference(containerImage string, img *docker.Image) *string {
	if containerImage != "" && !idLikeRe.MatchString(containerImage) && validRef(containerImage) {
		return &containerImage
	}
	if img != nil {
		for _, t := range img.RepoTags {
			if t != "" && t != "<none>:<none>" && validRef(t) {
				return &t
			}
		}
	}
	return nil
}

// labels keeps the LabelKeys of an image whose value is printable ASCII of at most
// maxLabelValue bytes; anything else is left out.
func labels(img *docker.Image) map[string]string {
	out := map[string]string{}
	if img == nil || img.Config == nil {
		return out
	}
	for _, k := range LabelKeys {
		v, ok := img.Config.Labels[k]
		if !ok || v == "" || len(v) > maxLabelValue {
			continue
		}
		printable := true
		for i := 0; i < len(v); i++ {
			if v[i] < ' ' || v[i] > '~' {
				printable = false
				break
			}
		}
		if printable {
			out[k] = v
		}
	}
	return out
}

// validRef rejects names that cannot be an image reference (spaces, control characters, too long).
func validRef(s string) bool {
	if len(s) > 512 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// repository is a reference without its tag or digest (nginx:1.27 → nginx,
// registry:5000/a/b:1 → registry:5000/a/b, nginx@sha256:… → nginx).
func repository(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// repoDigest is the digest of the RepoDigests entry of the reference's repository, else of the
// first entry; nil for images that were never pushed or pulled (built locally).
func repoDigest(ref *string, img *docker.Image) *string {
	if img == nil {
		return nil
	}
	var first *string
	for _, rd := range img.RepoDigests {
		repo, d, ok := strings.Cut(rd, "@")
		if !ok || !digestRe.MatchString(d) {
			continue
		}
		if ref != nil && repo == repository(*ref) {
			return &d
		}
		if first == nil {
			first = &d
		}
	}
	return first
}

func short(imageID string) string {
	if s, ok := strings.CutPrefix(imageID, "sha256:"); ok && len(s) >= 12 {
		return s[:12]
	}
	return clip(imageID)
}

func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

func (c *Collector) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}
