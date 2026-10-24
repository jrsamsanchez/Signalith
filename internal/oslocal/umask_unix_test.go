// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package oslocal

import (
	"archive/tar"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The release unpacks readable by all whatever root's umask, so the
// service account may run it.
func TestExtractIgnoresUmask(t *testing.T) {
	z := makeTarGz(t,
		tarEntry{name: "opensearch-3.9.0/", kind: tar.TypeDir, mode: 0o755},
		tarEntry{name: "opensearch-3.9.0/bin/opensearch", kind: tar.TypeReg, mode: 0o755, body: "run"},
		tarEntry{name: "opensearch-3.9.0/lib/a.jar", kind: tar.TypeReg, mode: 0o644, body: "jar"},
	)
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dest := filepath.Join(t.TempDir(), "3.9.0")
	if err := Extract(z, dest); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{
		dest: 0o755, filepath.Join(dest, "bin"): 0o755, filepath.Join(dest, "lib"): 0o755,
		filepath.Join(dest, "bin", "opensearch"): 0o755, filepath.Join(dest, "lib", "a.jar"): 0o644,
	} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %s", p, fi.Mode(), err, want)
		}
	}
}
