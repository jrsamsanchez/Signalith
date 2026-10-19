// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

// bootstrap-docker hands the OpenSearch CA to Signalith once it has
// started, makes the revocation list, replaces the CA with -new-ca, and
// refuses a CA folder that lost its key.
func TestBootstrapDockerCAHandOverAndCRL(t *testing.T) {
	root := t.TempDir()
	o := bootstrapOptions{OSDir: filepath.Join(root, "os"), SigDir: filepath.Join(root, "sig"), CADir: filepath.Join(root, "ca"),
		StateDir: filepath.Join(root, "state"), CRLDir: filepath.Join(root, "crl")}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := bootstrapWith(t, bootstrapOptions{OSDir: o.OSDir, SigDir: o.SigDir, Nodes: 2}); err == nil || !strings.Contains(err.Error(), "need -ca-dir") {
		t.Errorf("-nodes 2 without -ca-dir: %v", err)
	}

	// The state folder is still empty: Signalith has not started.
	o.ExportCAKey = true
	out, err := bootstrapWith(t, o)
	if err == nil || !strings.Contains(err.Error(), "Signalith has not started yet") {
		t.Errorf("before Signalith started: %v\n%s", err, out)
	}
	// The certificates and the revocation list are made all the same.
	if !strings.Contains(out, "Made OpenSearch's revocation list") {
		t.Errorf("no revocation list made:\n%s", out)
	}
	writeTestFile(t, filepath.Join(o.StateDir, "node.id"), "n_test\n")
	out, err = bootstrapWith(t, o)
	if err != nil || !strings.Contains(out, "Handed the OpenSearch CA's certificate and key to Signalith") {
		t.Fatalf("%v\n%s", err, out)
	}
	importDir := filepath.Join(o.StateDir, ospki.ImportDir)
	ca, err := os.ReadFile(filepath.Join(importDir, ospki.ExportCAFile))
	if err != nil {
		t.Fatal(err)
	}
	if root, _ := os.ReadFile(filepath.Join(o.OSDir, "root-ca.pem")); string(root) != string(ca) {
		t.Error("the CA handed over is not OpenSearch's")
	}
	if _, err := os.Stat(filepath.Join(importDir, ospki.ExportCAKeyFile)); err != nil {
		t.Errorf("the CA's key was not handed over: %v", err)
	}
	if _, err := os.Stat(filepath.Join(o.CRLDir, ospki.CRLFile)); err != nil {
		t.Errorf("no revocation list: %v", err)
	}
	crl, _ := os.ReadFile(filepath.Join(o.CRLDir, ospki.CRLFile))

	// Again: the CA waits already, and the list is kept.
	out, err = bootstrapWith(t, o)
	if err != nil || !strings.Contains(out, "already waiting for Signalith") || strings.Contains(out, "Made OpenSearch's revocation list") {
		t.Errorf("second run: %v\n%s", err, out)
	}
	if again, _ := os.ReadFile(filepath.Join(o.CRLDir, ospki.CRLFile)); string(again) != string(crl) {
		t.Error("the revocation list was made again")
	}

	// -new-ca replaces the CA and what it issued.
	before, _ := os.ReadFile(filepath.Join(o.OSDir, "root-ca.pem"))
	n := o
	n.ExportCAKey, n.NewCA = false, true
	out, err = bootstrapWith(t, n)
	if err != nil {
		t.Fatalf("-new-ca: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(filepath.Join(o.OSDir, "root-ca.pem")); string(after) == string(before) {
		t.Errorf("-new-ca kept the CA:\n%s", out)
	}

	// A CA folder that has the certificate but not the key.
	if err := os.Remove(filepath.Join(o.CADir, ospki.RootCAKeyFile)); err != nil {
		t.Fatal(err)
	}
	n.NewCA = false
	if _, err := bootstrapWith(t, n); err == nil || !strings.Contains(err.Error(), "has the OpenSearch CA's certificate but not its key") {
		t.Errorf("a CA without its key: %v", err)
	}
}
