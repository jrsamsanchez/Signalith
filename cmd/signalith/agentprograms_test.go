package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

func TestAgentProgramsSign(t *testing.T) {
	var out bytes.Buffer
	if err := runAgentPrograms([]string{"keygen"}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(out.String())
	var priv, pub string
	for i, l := range lines {
		if l == "secret):" {
			priv = lines[i+1]
		}
		if strings.HasSuffix(l, "release.keys):") {
			pub = lines[i+1]
		}
	}
	if priv == "" || pub == "" {
		t.Fatalf("keygen said:\n%s", out.String())
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, agentproto.ProgramName("linux", "amd64")), []byte("agent"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SIGNALITH_AGENT_KEY", "")
	if err := runAgentPrograms([]string{"sign", "-version", "1.0.0", "-dir", dir}, &out); err == nil || !strings.Contains(err.Error(), "SIGNALITH_AGENT_KEY") {
		t.Fatalf("no key: %v", err)
	}
	t.Setenv("SIGNALITH_AGENT_KEY", priv)
	out.Reset()
	if err := runAgentPrograms([]string{"pubkey"}, &out); err != nil || strings.TrimSpace(out.String()) != pub {
		t.Fatalf("pubkey: %v %q, want %q", err, out.String(), pub)
	}
	out.Reset()
	if err := runAgentPrograms([]string{"sign", "-version", "1.0.0", "-dir", dir}, &out); err != nil || !strings.Contains(out.String(), "version 1.0.0") {
		t.Fatalf("sign: %v\n%s", err, out.String())
	}

	k, _ := base64.StdEncoding.DecodeString(pub)
	old := agentproto.ReleaseKeys
	agentproto.ReleaseKeys = []ed25519.PublicKey{k}
	t.Cleanup(func() { agentproto.ReleaseKeys = old })
	out.Reset()
	if err := runAgentPrograms([]string{"status", "-dir", dir}, &out); err != nil || !strings.Contains(out.String(), "Signed manifest: version 1.0.0") {
		t.Fatalf("status: %v\n%s", err, out.String())
	}
	agentproto.ReleaseKeys = nil
	out.Reset()
	if err := runAgentPrograms([]string{"status", "-dir", dir}, &out); err != nil || !strings.Contains(out.String(), "no release key") {
		t.Fatalf("status without keys: %v\n%s", err, out.String())
	}
}
