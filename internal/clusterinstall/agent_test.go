package clusterinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/deploy"
	"github.com/jrsamsanchez/signalith/internal/agents"
)

func TestAgentLines(t *testing.T) {
	c, err := AgentLines(AgentLine{URL: "https://siem:7779/", Version: "0.4.0", CASHA256: caSum})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(deploy.AgentInstallSH)
	if c.ScriptSHA256 != hex.EncodeToString(sum[:]) || c.ScriptSHA256 != ScriptSHA256().Agent {
		t.Errorf("script SHA-256 %s", c.ScriptSHA256)
	}
	want := " f=$(mktemp) && curl -fsSk --proto '=https' https://siem:7779/api/agent/install.sh -o \"$f\" && echo \"" + c.ScriptSHA256 +
		"  $f\" | sha256sum -c --quiet && echo '" + agents.TokenPlaceholder + "' | sudo sh \"$f\" --from https://siem:7779 --ca-sha256 " + caSum + " --version 0.4.0 --token -"
	if c.Linux != want {
		t.Errorf("line\n%s\nwant\n%s", c.Linux, want)
	}
	if !strings.Contains(c.Note, "Ubuntu 22.04") || !strings.Contains(c.Note, "don't share it") || !strings.Contains(c.Note, "history") {
		t.Errorf("note %q", c.Note)
	}
	c, _ = AgentLines(AgentLine{URL: "https://siem:7779", Version: "dev", CASHA256: caSum, NextCASHA256: strings.Repeat("a", 64)})
	if !strings.Contains(c.Linux, "--ca-sha256 "+caSum+" --next-ca-sha256 "+strings.Repeat("a", 64)+" --version dev") {
		t.Errorf("next CA: %s", c.Linux)
	}
	c, _ = AgentLines(AgentLine{URL: "https://siem.example.com", Version: "dev"})
	if strings.Contains(c.Linux, "--ca-sha256") {
		t.Errorf("public CA: %s", c.Linux)
	}
	for name, l := range map[string]AgentLine{
		"http":        {URL: "http://siem:7779", Version: "1"},
		"quote":       {URL: "https://siem'x", Version: "1"},
		"version":     {URL: "https://siem", Version: "1;reboot"},
		"sha":         {URL: "https://siem", Version: "1", CASHA256: "abc"},
		"next alone":  {URL: "https://siem", Version: "1", NextCASHA256: caSum},
		"next not ok": {URL: "https://siem", Version: "1", CASHA256: caSum, NextCASHA256: "$(x)"},
	} {
		if _, err := AgentLines(l); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	var fe *FieldError
	if _, err := AgentLines(AgentLine{URL: "ftp://x", Version: "1"}); !errors.As(err, &fe) || fe.Field != "server" {
		t.Errorf("field error: %v", err)
	}
}

func TestAgentPrograms(t *testing.T) {
	dir := t.TempDir()
	p := &Programs{Dir: dir}
	if got := p.Available(); len(got) != 0 {
		t.Errorf("empty folder: %v", got)
	}
	if _, _, _, err := p.Open("linux", "amd64"); !errors.Is(err, ErrNoProgram) {
		t.Errorf("missing: %v", err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("signalith-agent-linux-amd64", "one")
	write("signalith-agent-windows-amd64.exe", "two")
	write("signalith-agent-plan9-386", "no")
	if err := os.Mkdir(filepath.Join(dir, "signalith-agent-linux-arm64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Available(), " "); got != "linux-amd64 windows-amd64" {
		t.Errorf("available: %s", got)
	}
	for _, c := range []struct{ goos, goarch string }{{"plan9", "386"}, {"linux", "arm64"}, {"../..", "x"}} {
		if f, _, _, err := p.Open(c.goos, c.goarch); err == nil {
			f.Close()
			t.Errorf("%s/%s opened", c.goos, c.goarch)
		}
	}
	f, size, sum, err := p.Open("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	want := sha256.Sum256([]byte("two"))
	if string(b) != "two" || size != 3 || sum != hex.EncodeToString(want[:]) {
		t.Errorf("windows: %q %d %s", b, size, sum)
	}
	// A new program (an upgrade) gets its own SHA-256.
	write("signalith-agent-windows-amd64.exe", "three")
	f, _, sum, err = p.Open("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	want = sha256.Sum256([]byte("three"))
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("after upgrade: %s", sum)
	}
}
