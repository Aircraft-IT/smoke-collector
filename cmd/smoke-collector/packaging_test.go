package main

import (
	"os"
	"strings"
	"testing"
)

// install.sh carries copies of the systemd units (it is downloaded on its own); they must stay
// identical to systemd/.
func TestInstallScriptUnitsMatchRepository(t *testing.T) {
	script, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	for marker, file := range map[string]string{
		"SERVICE": "../../systemd/smoke-collector.service",
		"TIMER":   "../../systemd/smoke-collector.timer",
	} {
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		start := strings.Index(string(script), "<<'"+marker+"'\n")
		if start < 0 {
			t.Fatalf("install.sh has no <<'%s' heredoc", marker)
		}
		body := string(script)[start+len("<<'"+marker+"'\n"):]
		end := strings.Index(body, "\n"+marker+"\n")
		if end < 0 {
			t.Fatalf("install.sh heredoc %s is not terminated", marker)
		}
		if got := body[:end+1]; got != string(want) {
			t.Errorf("install.sh %s heredoc differs from %s:\n%s", marker, file, got)
		}
	}
}

// The released install.sh gets its key from scripts/embed-pubkey.sh, which looks for this line.
func TestInstallScriptHasPlaceholder(t *testing.T) {
	script, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "\nPUBKEY=\"__SMOKE_COLLECTOR_PUBKEY__\"\n") {
		t.Error("install.sh lost the PUBKEY placeholder line")
	}
}
