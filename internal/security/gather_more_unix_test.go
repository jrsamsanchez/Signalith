// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package security

import (
	"os"
	"path/filepath"
	"testing"
)

// fileFacts looks at the key files the configuration and the environment
// name, and lists files everyone may read before those only a group may.
func TestFileFactsNamedKeys(t *testing.T) {
	c := loadConfig(t, httpsAuto)
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tlsKey := write("https.key", 0o640)
	osKey := write("opensearch-client.key", 0o604)
	pwFile := write("admin-password", 0o644)
	c.Server.TLSCert, c.Server.TLSKey = write("https.crt", 0o644), tlsKey
	c.Server.TLS = nil
	c.OpenSearch.CertFile, c.OpenSearch.KeyFile = write("opensearch-client.crt", 0o644), osKey
	env := map[string]string{"SIGNALITH_ADMIN_PASSWORD_FILE": pwFile}
	// An account outside the files' group, so group read counts.
	h := Host{Config: c, GOOS: "linux", Docker: true, Account: Account{UID: os.Getuid(), GID: -1},
		Getenv: func(k string) string { return env[k] }}
	ff, denied := fileFacts(h)
	if denied || !ff.Known || ff.Volume != dockerVolume {
		t.Fatalf("facts %+v denied %v", ff, denied)
	}
	byPath := map[string]FileProblem{}
	for _, p := range ff.Problems {
		byPath[p.Path] = p
	}
	if p, ok := byPath[tlsKey]; !ok || !p.Read || p.Everyone {
		t.Errorf("https key %+v", p)
	}
	for _, path := range []string{osKey, pwFile} {
		if p, ok := byPath[path]; !ok || !p.Read || !p.Everyone {
			t.Errorf("%s: %+v", path, p)
		}
	}
	// Everyone-readable files come first.
	seenGroupOnly := false
	for _, p := range ff.Problems {
		if !p.Everyone {
			seenGroupOnly = true
		} else if seenGroupOnly {
			t.Errorf("an everyone-readable file after a group-only one: %+v", ff.Problems)
			break
		}
	}
}

func TestArchiveFactsCountsFiles(t *testing.T) {
	c := loadConfig(t, httpsAuto)
	dir := c.ArchiveDir()
	if err := os.MkdirAll(filepath.Join(dir, "2026"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a.ndjson.gz", "b.ndjson.gz", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, "2026", n), []byte("plain"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := Host{Config: c, GOOS: "linux", Account: Account{UID: os.Getuid(), GID: os.Getgid()}, Getenv: func(string) string { return "" }}
	a, denied := archiveFacts(h, false)
	if denied || a.Count != 2 || a.Plain != 2 || a.Bytes != 10 || a.Perm == nil {
		t.Errorf("archive %+v denied %v", a, denied)
	}
	// No folder: nothing to say, nothing denied.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	a, denied = archiveFacts(h, true)
	if denied || a.Count != 0 || a.Perm != nil {
		t.Errorf("missing archive %+v denied %v", a, denied)
	}
}
