// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

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
	"time"
)

const (
	token = "SJ1.eyJ1IjoiaHR0cHM6Ly9zaWVtLWE6ODQ0MyJ9"
	bin   = "4f2a91c0e1d2c3b4a5968778695a4b3c2d1e0f1a2b3c4d5e6f708192a3b4c5d6"
)

func TestLines(t *testing.T) {
	c, err := Lines(Line{URL: "https://siem-a:8443", Token: token, Version: "1.5.0", GOOS: "linux", GOARCH: "amd64", BinarySHA256: bin})
	if err != nil {
		t.Fatal(err)
	}
	sha := ScriptSHA256()
	for _, want := range []string{"https://siem-a:8443/api/cluster/join/install.sh", sha.SH + "  $f", "sha256sum -c", "--from https://siem-a:8443",
		"--version 1.5.0", "--sha256 " + bin, "echo '" + token + "' | sudo sh", "--join -"} {
		if !strings.Contains(c.Linux, want) {
			t.Errorf("linux line has no %q:\n%s", want, c.Linux)
		}
	}
	if c.LinuxNote != "" {
		t.Errorf("linux note %q", c.LinuxNote)
	}
	// A Linux server cannot hand out the Windows program.
	for _, want := range []string{"/api/cluster/join/install.ps1", strings.ToUpper(sha.PS1), "-SkipCertificateCheck", "ServerCertificateValidationCallback=$null",
		"-From $u -Version 1.5.0 -Join '" + token + "'"} {
		if !strings.Contains(c.Windows, want) {
			t.Errorf("windows line has no %q:\n%s", want, c.Windows)
		}
	}
	if strings.Contains(c.Windows, "-Sha256") || !strings.Contains(c.WindowsNote, "1.5.0 .msi") || !strings.Contains(c.WindowsNote, "Linux") {
		t.Errorf("windows from linux: %q / %q", c.Windows, c.WindowsNote)
	}
	if !strings.Contains(c.Docker, "SIGNALITH_JOIN="+token+"\n") || !strings.Contains(c.Docker, "SIGNALITH_VERSION=1.5.0\n") || !strings.Contains(c.DockerRun, "docker-compose.server.yml") {
		t.Errorf("docker: %s / %s", c.Docker, c.DockerRun)
	}

	// A development build's image is main.
	c, err = Lines(Line{URL: "https://siem-a:8443/", Token: token, Version: "dev", GOOS: "windows", GOARCH: "amd64", BinarySHA256: bin})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Docker, "SIGNALITH_VERSION=main\n") || !strings.Contains(c.Windows, "-Sha256 "+bin) || c.LinuxNote == "" || strings.Contains(c.Linux, "--sha256") {
		t.Errorf("windows issuer: %+v", c)
	}
	if strings.Contains(c.Linux, "8443//api") {
		t.Errorf("double slash: %s", c.Linux)
	}
}

// Nothing reaches a pasted line that a shell would read as more than a
// word.
func TestLinesRefuse(t *testing.T) {
	good := Line{URL: "https://siem-a:8443", Token: token, Version: "1.5.0"}
	for name, change := range map[string]func(l *Line){
		"http":        func(l *Line) { l.URL = "http://siem-a:8443" },
		"user":        func(l *Line) { l.URL = "https://u:p@siem-a:8443" },
		"path":        func(l *Line) { l.URL = "https://siem-a:8443/x" },
		"quote":       func(l *Line) { l.URL = "https://siem-a:8443'" },
		"dollar":      func(l *Line) { l.URL = "https://$(id):8443" },
		"token":       func(l *Line) { l.Token = "SJ1.x';rm -rf /;'" },
		"not a token": func(l *Line) { l.Token = "abc" },
		"version":     func(l *Line) { l.Version = "1.5.0; id" },
		"empty":       func(l *Line) { l.Version = "" },
		"binary sha":  func(l *Line) { l.BinarySHA256 = "xyz" },
	} {
		l := good
		change(&l)
		if _, err := Lines(l); err == nil {
			t.Errorf("%s: accepted %+v", name, l)
		}
	}
	if _, err := Lines(good); err != nil {
		t.Errorf("good: %v", err)
	}
}

func TestReleased(t *testing.T) {
	for v, want := range map[string]bool{"1.5.0": true, "0.1.0-rc.1": true, "dev": false, "0.1.0-12-gabc1234-dirty": false, "1.5": false} {
		if Released(v) != want {
			t.Errorf("%s: %v", v, !want)
		}
	}
}

func TestScripts(t *testing.T) {
	for _, name := range []string{ScriptSH, ScriptPS1, ScriptSensor} {
		body, sum, ok := Script(name)
		h := sha256.Sum256(body)
		if !ok || len(body) == 0 || sum != hex.EncodeToString(h[:]) {
			t.Errorf("%s: %v %s", name, ok, sum)
		}
	}
	if _, _, ok := Script("signalith.yaml"); ok {
		t.Error("another file")
	}
}

func TestBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signalith")
	if err := os.WriteFile(path, []byte("v1"), 0o666); err != nil {
		t.Fatal(err)
	}
	f := &Files{Exe: path, GOOS: "linux", GOARCH: "arm64"}
	if _, _, _, err := f.Binary("linux", "amd64"); !errors.Is(err, ErrOtherPlatform) {
		t.Errorf("other arch: %v", err)
	}
	file, size, sum, err := f.Binary("linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(file)
	file.Close()
	h := sha256.Sum256([]byte("v1"))
	if string(body) != "v1" || size != 2 || sum != hex.EncodeToString(h[:]) || f.BinarySHA256() != sum {
		t.Errorf("%q %d %s", body, size, sum)
	}
	// An upgrade replaces the file: the SHA-256 follows.
	if err := os.WriteFile(path, []byte("v2.0"), 0o666); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	h = sha256.Sum256([]byte("v2.0"))
	if got := f.BinarySHA256(); got != hex.EncodeToString(h[:]) {
		t.Errorf("after the upgrade %s", got)
	}
}

func TestGate(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	g := &Gate{PerHour: 3, Now: func() time.Time { return now }}
	done, ok := g.Take("10.0.0.7")
	if !ok {
		t.Fatal("first download refused")
	}
	if _, ok := g.Take("10.0.0.7"); ok {
		t.Error("two at once from one address")
	}
	if d, ok := g.Take("10.0.0.8"); !ok {
		t.Error("another address refused")
	} else {
		d()
	}
	done()
	done() // twice is harmless
	for i := range 2 {
		d, ok := g.Take("10.0.0.7")
		if !ok {
			t.Fatalf("download %d refused", i+2)
		}
		d()
	}
	if _, ok := g.Take("10.0.0.7"); ok {
		t.Error("a fourth download in the hour")
	}
	now = now.Add(time.Hour)
	if d, ok := g.Take("10.0.0.7"); !ok {
		t.Error("refused an hour later")
	} else {
		d()
	}
}
