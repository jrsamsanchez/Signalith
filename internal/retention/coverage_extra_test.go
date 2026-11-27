// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManifestMACMessage(t *testing.T) {
	m := Manifest{ID: "a", File: "a.ndjson.gz", Index: "logs-2026.01.01", Docs: 3, Created: time.Now()}
	base := m.MACMessage()
	var parsed map[string]any
	if err := json.Unmarshal(base, &parsed); err != nil || parsed["v"] != "signalith-archive-manifest/1" {
		t.Fatalf("message %s: %v", base, err)
	}
	// State is left out: it changes as the manifest is completed.
	m.State = "complete"
	if !bytes.Equal(m.MACMessage(), base) {
		t.Error("the state changes the message")
	}
	// The time is in UTC, whatever the zone it was read in.
	m.Created = m.Created.In(time.FixedZone("x", 3600))
	if !bytes.Equal(m.MACMessage(), base) {
		t.Error("the time zone changes the message")
	}
	for name, edit := range map[string]func(*Manifest){
		"docs":   func(m *Manifest) { m.Docs++ },
		"index":  func(m *Manifest) { m.Index = "logs-2026.01.02" },
		"server": func(m *Manifest) { m.Server = "b" },
		"sha":    func(m *Manifest) { m.SHA256 = "00" },
	} {
		x := m
		edit(&x)
		if bytes.Equal(x.MACMessage(), base) {
			t.Errorf("%s does not change the message", name)
		}
	}
}

func TestCheckManifest(t *testing.T) {
	good := func(msg []byte, macs []string) (bool, error) { return macs[0] == "good", nil }
	bad := func([]byte, []string) (bool, error) { return false, errors.New("mac mismatch") }
	legacy := func(Manifest) bool { return true }
	tests := []struct {
		name string
		a    Archive
		m    Manifest
		want error // nil: no error; errAny: some error
	}{
		{"plain, no keys", Archive{}, Manifest{ID: "a"}, nil},
		{"authenticated", Archive{Authenticate: good, RequireAuthenticated: true}, Manifest{ID: "a", MAC: []string{"good"}}, nil},
		{"changed", Archive{Authenticate: bad}, Manifest{ID: "a", MAC: []string{"x"}}, errAny},
		{"encrypted without mac", Archive{Authenticate: good}, Manifest{ID: "a", Encryption: "aes"}, ErrUnauthenticatedEncrypted},
		{"encrypted, wrong key", Archive{Authenticate: good}, Manifest{ID: "a", Encryption: "aes", MAC: []string{"other"}}, ErrUnauthenticatedEncrypted},
		{"encrypted legacy", Archive{Authenticate: good, Legacy: legacy}, Manifest{ID: "a", Encryption: "aes"}, nil},
		{"encrypted allowed", Archive{Authenticate: good, AllowUnauthenticated: true}, Manifest{ID: "a", Encryption: "aes"}, nil},
		{"encrypted authenticated", Archive{Authenticate: good}, Manifest{ID: "a", Encryption: "aes", MAC: []string{"good"}}, nil},
		{"plain required", Archive{Authenticate: good, RequireAuthenticated: true}, Manifest{ID: "a"}, ErrUnauthenticated},
		{"plain required, allowed", Archive{Authenticate: good, RequireAuthenticated: true, AllowUnauthenticated: true}, Manifest{ID: "a"}, nil},
	}
	for _, tc := range tests {
		err := tc.a.checkManifest(tc.m)
		switch {
		case tc.want == nil && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want == errAny && err == nil:
			t.Errorf("%s: no error", tc.name)
		case tc.want != nil && tc.want != errAny && !errors.Is(err, tc.want):
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

var errAny = errors.New("any error")

func TestWriteFileSynced(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "m.json")
	if err := writeFileSynced(name, map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(name)
	if err != nil || !bytes.HasSuffix(b, []byte("}\n")) {
		t.Fatalf("written %q %v", b, err)
	}
	if err := writeFileSynced(filepath.Join(dir, "missing", "m.json"), 1); err == nil {
		t.Error("written into a missing folder")
	}
	if err := writeFileSynced(name, func() {}); err == nil {
		t.Error("wrote a value JSON cannot hold")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("left %d files", len(entries))
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "sub", "state.json")
	for _, data := range []string{"one", "two"} {
		if err := writeAtomic(name, []byte(data)); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(name); err != nil || string(b) != data {
			t.Fatalf("read %q %v", b, err)
		}
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(file, "x", "state.json"), []byte("x")); err == nil {
		t.Error("written under a file")
	}
}

func TestSizeStringAndExisting(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KB", 1536: "1.5 KB", 1 << 20: "1.0 MB", 5 << 30: "5.0 GB", 1 << 50: "1.0 PB", 1 << 60: "1024.0 PB"} {
		if got := sizeString(n); got != want {
			t.Errorf("sizeString(%d) = %q, want %q", n, got, want)
		}
	}
	dir := t.TempDir()
	if got := existing(filepath.Join(dir, "a", "b")); got != dir {
		t.Errorf("existing = %q, want %q", got, dir)
	}
	if got := existing(dir); got != dir {
		t.Errorf("existing of an existing folder = %q", got)
	}
}
