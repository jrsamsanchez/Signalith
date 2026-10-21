// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterinstall

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/deploy"
	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/keytrust"
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
	psum := sha256.Sum256(deploy.AgentInstallPS1)
	if c.WindowsSHA256 != hex.EncodeToString(psum[:]) || c.WindowsSHA256 != ScriptSHA256().AgentPS1 {
		t.Errorf("Windows script SHA-256 %s", c.WindowsSHA256)
	}
	for _, want := range []string{"$u='https://siem:7779'", "Invoke-WebRequest 'https://siem:7779/api/agent/install.ps1' -OutFile $f -SkipCertificateCheck",
		"[SignalithGet]::Save(", "-ne '" + strings.ToUpper(c.WindowsSHA256) + "'",
		"'" + agents.TokenPlaceholder + "' | & $f -From $u -CaSha256 " + caSum + " -Version 0.4.0 -Token -"} {
		if !strings.Contains(c.Windows, want) {
			t.Errorf("Windows line has no %q:\n%s", want, c.Windows)
		}
	}
	if !strings.Contains(c.WindowsNote, "Run as administrator") || !strings.Contains(c.WindowsNote, "don't share it") {
		t.Errorf("Windows note %q", c.WindowsNote)
	}
	msum := sha256.Sum256(deploy.AgentInstallMacOS)
	if c.MacOSSHA256 != hex.EncodeToString(msum[:]) || c.MacOSSHA256 != ScriptSHA256().AgentMac {
		t.Errorf("macOS script SHA-256 %s", c.MacOSSHA256)
	}
	want = " f=$(mktemp) && curl -fsSk --proto '=https' https://siem:7779/api/agent/install-macos.sh -o \"$f\" && echo \"" + c.MacOSSHA256 +
		"  $f\" | shasum -a 256 -c -s && echo '" + agents.TokenPlaceholder + "' | sudo sh \"$f\" --from https://siem:7779 --ca-sha256 " + caSum + " --version 0.4.0 --token -"
	if c.MacOS != want {
		t.Errorf("macOS line\n%s\nwant\n%s", c.MacOS, want)
	}
	if !strings.Contains(c.MacOSNote, "macOS 12") || !strings.Contains(c.MacOSNote, "Full Disk Access") || !strings.Contains(c.MacOSNote, "history") {
		t.Errorf("macOS note %q", c.MacOSNote)
	}
	c, _ = AgentLines(AgentLine{URL: "https://siem:7779", Version: "dev", CASHA256: caSum, NextCASHA256: strings.Repeat("a", 64)})
	if !strings.Contains(c.Windows, "-CaSha256 "+caSum+" -NextCaSha256 "+strings.Repeat("a", 64)+" -Version dev") {
		t.Errorf("next CA, Windows: %s", c.Windows)
	}
	if !strings.Contains(c.Linux, "--ca-sha256 "+caSum+" --next-ca-sha256 "+strings.Repeat("a", 64)+" --version dev") {
		t.Errorf("next CA: %s", c.Linux)
	}
	if !strings.Contains(c.MacOS, "--ca-sha256 "+caSum+" --next-ca-sha256 "+strings.Repeat("a", 64)+" --version dev") {
		t.Errorf("next CA, macOS: %s", c.MacOS)
	}
	c, _ = AgentLines(AgentLine{URL: "https://siem.example.com", Version: "dev"})
	if strings.Contains(c.Linux, "--ca-sha256") || strings.Contains(c.Windows, "-CaSha256") || strings.Contains(c.MacOS, "--ca-sha256") {
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

func TestSignedPrograms(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := agentproto.ReleaseKeys
	t.Cleanup(func() { agentproto.ReleaseKeys = old })
	dir := t.TempDir()
	p := &Programs{Dir: dir}
	if _, err := SignPrograms(dir, "1.0.0", priv); err == nil {
		t.Error("signed an empty folder")
	}
	if err := os.WriteFile(filepath.Join(dir, "signalith-agent-linux-amd64"), []byte("one"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"dev", "1.0", "1.0.0;x"} {
		if _, err := SignPrograms(dir, v, priv); err == nil {
			t.Errorf("signed version %q", v)
		}
	}
	m, err := SignPrograms(dir, "1.0.0", priv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("one"))
	if m.Programs["linux-amd64"] != hex.EncodeToString(sum[:]) || len(m.Programs) != 1 {
		t.Errorf("manifest: %+v", m)
	}

	// A build that trusts no key hands out no manifest and offers nothing.
	agentproto.ReleaseKeys = nil
	if _, _, _, err := p.Manifest(); !errors.Is(err, ErrNoManifest) {
		t.Errorf("no keys: %v", err)
	}
	agentproto.ReleaseKeys = []ed25519.PublicKey{pub}
	if _, _, got, err := p.Manifest(); err != nil || got.Version != "1.0.0" {
		t.Fatalf("manifest: %v %+v", err, got)
	}
	if u, err := p.Update("linux", "amd64", "0.9.0"); err != nil || u == nil || u.Version != "1.0.0" || u.SHA256 != m.Programs["linux-amd64"] {
		t.Errorf("update: %+v %v", u, err)
	}
	for _, c := range [][3]string{{"linux", "amd64", "1.0.0"}, {"linux", "amd64", "dev"}, {"windows", "amd64", "0.9.0"}} {
		if u, err := p.Update(c[0], c[1], c[2]); u != nil || err != nil {
			t.Errorf("%v: %+v %v", c, u, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "signalith-agent-linux-amd64"), []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if u, err := p.Update("linux", "amd64", "0.9.0"); u != nil || err == nil {
		t.Errorf("changed program: %+v %v", u, err)
	}
	if err := os.Remove(filepath.Join(dir, agentproto.SignatureFile)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := p.Manifest(); !errors.Is(err, ErrNoManifest) {
		t.Errorf("no signature: %v", err)
	}
}

// A kept revocation list that cannot be read could revoke the key the
// manifest is signed with, so no manifest is handed out.
func TestUnreadableRevocationListRefusesManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old, oldRoots := agentproto.ReleaseKeys, keytrust.Roots
	agentproto.ReleaseKeys, keytrust.Roots = []ed25519.PublicKey{pub}, []ed25519.PublicKey{rootPub}
	t.Cleanup(func() { agentproto.ReleaseKeys, keytrust.Roots = old, oldRoots })
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "signalith-agent-linux-amd64"), []byte("one"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := SignPrograms(dir, "1.0.0", priv); err != nil {
		t.Fatal(err)
	}
	store := &keytrust.Store{Dir: filepath.Join(t.TempDir(), "keytrust")}
	list := []byte(`{"format":1,"issued":"2026-10-20T00:00:00Z","revoked":[{"id":"` + keytrust.KeyID(pub) + `"}]}`)
	if _, err := store.Offer(list, keytrust.Sign(rootPriv, list)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(store.Dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("kept files: %v %v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, entries[0].Name()), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Programs{Dir: dir, Revocations: &keytrust.Store{Dir: store.Dir}}
	if _, _, _, err := p.Manifest(); err == nil || errors.Is(err, ErrNoManifest) || !strings.Contains(err.Error(), "revocation list") {
		t.Fatalf("manifest = %v, want refused for the unreadable list", err)
	}
	if u, err := p.Update("linux", "amd64", "0.9.0"); u != nil || err == nil {
		t.Fatalf("update = %+v %v, want none", u, err)
	}
	// The store that read the list before keeps refusing the revoked key.
	p.Revocations = store
	if _, _, _, err := p.Manifest(); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("with the list read before: %v, want revoked", err)
	}
}
