// Package version holds the collector version, set at release time with
// -ldflags "-X github.com/aircraft-it/smoke-collector/internal/version.Version=<version>".
package version

import (
	"regexp"
	"runtime"
)

// Version is the collector version (semver, OS detection plan §5.1).
var Version = "0.4.1-dev"

// valid is the backend's X-Smoke-Collector-Version rule (plan §5.2).
var valid = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)

// Valid reports whether v has the form the backend accepts.
func Valid(v string) bool { return valid.MatchString(v) }

// UserAgent is the User-Agent header: smoke-collector/<version> (linux/<arch>).
func UserAgent() string { return UserAgentFor("smoke-collector") }

// UserAgentFor is UserAgent for another program of this repository
// (smoke-container-collector/<version> (linux/<arch>)).
func UserAgentFor(program string) string {
	return program + "/" + Version + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
