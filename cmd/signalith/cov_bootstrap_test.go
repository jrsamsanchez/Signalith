// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

// Without the CA's volume, bootstrap-docker keeps a good set of
// certificates and replaces a broken one whole.
func TestBootstrapWithoutCAKeepsAndReplaces(t *testing.T) {
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = 3072 })
	root := t.TempDir()
	o := bootstrapOptions{OSDir: filepath.Join(root, "os"), SigDir: filepath.Join(root, "sig")}
	if out, err := bootstrapWith(t, o); err != nil || !strings.Contains(out, "OpenSearch certificates: ") {
		t.Fatalf("first: %v\n%s", err, out)
	}
	if out, err := bootstrapWith(t, o); err != nil || !strings.Contains(out, "OpenSearch certificates: kept.") {
		t.Errorf("again: %v\n%s", err, out)
	}
	if err := os.Remove(filepath.Join(o.OSDir, ospki.NodeCertFile)); err != nil {
		t.Fatal(err)
	}
	if out, err := bootstrapWith(t, o); err != nil || !strings.Contains(out, "made new ones, since") {
		t.Errorf("broken set: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(o.OSDir, ospki.NodeCertFile)); err != nil {
		t.Errorf("no new node certificate: %v", err)
	}
}

// With no CA key, there is nothing to hand over and no revocation list
// to keep.
func TestBootstrapWithoutCAKey(t *testing.T) {
	root := t.TempDir()
	o := bootstrapOptions{CADir: filepath.Join(root, "ca"), CRLDir: filepath.Join(root, "crl"), StateDir: filepath.Join(root, "state")}
	var out bytes.Buffer
	if err := exportCAKey(&out, o, false); err == nil || !strings.Contains(err.Error(), "no OpenSearch CA key to hand over") {
		t.Errorf("export: %v", err)
	}
	if err := bootstrapCRL(&out, o, false); err != nil {
		t.Errorf("CRL: %v", err)
	}
	if _, err := os.Stat(o.CRLDir); err == nil {
		t.Error("a CRL folder was made without a CA")
	}
}

// -snapshots-dir makes the folder OpenSearch writes snapshots to.
func TestBootstrapSnapshotsDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bootstrap-docker prepares Linux container volumes")
	}
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = 3072 })
	root := t.TempDir()
	dir := filepath.Join(root, "snapshots")
	uid := itoa(os.Getuid())
	var err error
	out := captureStdout(t, func() {
		err = cmdBootstrapDocker([]string{"-opensearch-dir", filepath.Join(root, "os"), "-signalith-dir", filepath.Join(root, "sig"),
			"-snapshots-dir", dir, "-opensearch-uid", uid, "-signalith-uid", uid})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Errorf("snapshots folder: %v", err)
	}
	// It keeps what is there.
	if err := os.WriteFile(filepath.Join(dir, "index-0"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshotsDir(dir, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index-0")); err != nil {
		t.Errorf("a snapshot file went: %v", err)
	}
	// A file where the folder should be.
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	if err := snapshotsDir(filepath.Join(file, "sub"), os.Getuid()); err == nil {
		t.Error("made a folder under a file")
	}
}
