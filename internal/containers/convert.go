package containers

import (
	"bufio"
	"bytes"
	"sort"
	"strings"

	"github.com/aircraft-it/smoke-collector/internal/collect"
)

// stanzas splits a dpkg status or apk installed database into paragraphs of "Field: value" (dpkg)
// or "X:value" (apk) lines. Continuation lines (starting with a blank) are dropped: none of the
// fields used here spans lines.
func stanzas(data []byte, sep string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = map[string]string{}
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		k, v, ok := strings.Cut(line, sep)
		if !ok {
			continue
		}
		if _, dup := cur[k]; !dup {
			cur[k] = strings.TrimSpace(v)
		}
	}
	flush()
	return out
}

var (
	wantAbbrev   = map[string]byte{"unknown": 'u', "install": 'i', "hold": 'h', "deinstall": 'r', "purge": 'p'}
	statusAbbrev = map[string]byte{
		"not-installed": 'n', "config-files": 'c', "half-installed": 'H', "unpacked": 'U',
		"half-configured": 'F', "triggers-awaited": 'W', "triggers-pending": 't', "installed": 'i',
	}
	eflagAbbrev = map[string]byte{"ok": ' ', "reinstreq": 'R'}
)

// statusAbbrevOf is dpkg-query's ${db:Status-Abbrev} for a Status field ("install ok installed"
// → "ii "). An empty field (distroless status.d entries have none) counts as installed.
func statusAbbrevOf(status string) (string, bool) {
	if status == "" {
		return "ii ", true
	}
	f := strings.Fields(status)
	if len(f) != 3 {
		return "", false
	}
	w, ok1 := wantAbbrev[f[0]]
	e, ok2 := eflagAbbrev[f[1]]
	s, ok3 := statusAbbrev[f[2]]
	if !ok1 || !ok2 || !ok3 {
		return "", false
	}
	return string([]byte{w, s, e}), true
}

type dpkgLine struct{ pkg, arch, line string }

// dpkgLines is what `dpkg-query -W -f=<collect.DpkgFormat>` prints for the given status files:
// every package except those not-installed, sorted by package and architecture. Entries in later
// files (status.d) do not replace one already seen.
func dpkgLines(files ...[]byte) []byte {
	seen := map[string]bool{}
	var lines []dpkgLine
	for _, data := range files {
		for _, st := range stanzas(data, ":") {
			pkg := st["Package"]
			if pkg == "" {
				continue
			}
			abbrev, ok := statusAbbrevOf(st["Status"])
			if !ok || abbrev[1] == 'n' {
				continue
			}
			arch := st["Architecture"]
			key := pkg + "\x00" + arch
			if seen[key] {
				continue
			}
			seen[key] = true
			version := st["Version"]
			srcName, srcVersion := pkg, version
			if src := st["Source"]; src != "" {
				name, rest, hasVersion := strings.Cut(src, " ")
				srcName = name
				if hasVersion {
					rest = strings.TrimSpace(rest)
					if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
						srcVersion = strings.TrimSpace(rest[1 : len(rest)-1])
					}
				}
			}
			lines = append(lines, dpkgLine{pkg, arch, strings.Join(
				[]string{abbrev, pkg, version, arch, srcName, srcVersion}, "\t")})
		}
	}
	sort.Slice(lines, func(i, j int) bool {
		if lines[i].pkg != lines[j].pkg {
			return lines[i].pkg < lines[j].pkg
		}
		return lines[i].arch < lines[j].arch
	})
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l.line + "\n")
	}
	return b.Bytes()
}

// apkLines is what `apk list --installed` prints for /lib/apk/db/installed
// (`musl-1.2.5-r0 x86_64 {musl} (MIT) [installed]`), sorted by name.
func apkLines(data []byte) []byte {
	type pkg struct{ name, line string }
	var pkgs []pkg
	for _, st := range stanzas(data, ":") {
		name, version := st["P"], st["V"]
		if name == "" || version == "" {
			continue
		}
		origin := st["o"]
		if origin == "" {
			origin = name
		}
		pkgs = append(pkgs, pkg{name, name + "-" + version + " " + st["A"] + " {" + origin + "} (" + st["L"] + ") [installed]"})
	}
	sort.SliceStable(pkgs, func(i, j int) bool { return pkgs[i].name < pkgs[j].name })
	var b bytes.Buffer
	for _, p := range pkgs {
		b.WriteString(p.line + "\n")
	}
	return b.Bytes()
}

// hostText builds the `#smoke-host 1` text of a container: only #os-release and #packages (the
// kernel, services and the reboot flag belong to the host, not the image).
func hostText(osRelease []byte, mgr collect.Manager, packages []byte) string {
	var b bytes.Buffer
	b.WriteString(collect.Magic + "\n")
	b.WriteString("#os-release\n")
	b.Write(collect.OSReleaseLines(osRelease, mgr))
	b.WriteString("#packages " + string(mgr) + "\n")
	b.Write(packages)
	return b.String()
}
