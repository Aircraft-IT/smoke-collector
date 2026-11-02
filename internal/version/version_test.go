package version

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for v, want := range map[string]bool{
		"0.1.0": true, "1.2.3-rc.1": true, "0.1.0-dev": true,
		"v0.1.0": false, "0.1": false, "0.1.0-": false, "0.1.0 ": false,
	} {
		if got := Valid(v); got != want {
			t.Errorf("Valid(%q) = %v, want %v", v, got, want)
		}
	}
	if !Valid(Version) {
		t.Errorf("default Version %q is not valid", Version)
	}
}

func TestUserAgent(t *testing.T) {
	if ua := UserAgent(); !strings.HasPrefix(ua, "smoke-collector/"+Version+" (") {
		t.Errorf("UserAgent() = %q", ua)
	}
}
