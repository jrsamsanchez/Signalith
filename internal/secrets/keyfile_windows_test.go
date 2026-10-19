// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIRoundTrip(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, 32)
	blob, err := dpapiProtect(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, raw) {
		t.Fatal("the protected blob contains the key")
	}
	back, err := dpapiUnprotect(blob)
	if err != nil || !bytes.Equal(back, raw) {
		t.Fatalf("dpapiUnprotect = %x, %v", back, err)
	}
	// A changed blob is refused.
	blob[len(blob)-1] ^= 0xff
	if _, err := dpapiUnprotect(blob); err == nil {
		t.Error("a changed blob was accepted")
	}
}

func TestDefaultKeyIsDPAPIProtected(t *testing.T) {
	dir := t.TempDir()
	k := keyring(dir, nil)
	sealed, err := k.Seal("opensearch.password", "pw")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "keys", "master.key.dpapi")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseKey(data); err == nil {
		t.Error("the key file holds the key in the clear")
	}
	if got, err := keyring(dir, nil).Open("opensearch.password", sealed); err != nil || got != "pw" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}
