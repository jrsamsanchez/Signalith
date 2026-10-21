// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestWebScriptsLoad runs .github/scripts/check-web-scripts.js, which loads
// every script of the web app's pages in page order, in one global scope
// as a browser does, and fails on a script that is missing or does not
// parse, a top-level name two scripts declare, or a name nothing defines.
// It needs Node.js, which CI's runners have; elsewhere it is skipped when
// node is not installed.
func TestWebScriptsLoad(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is not installed, so the web app's scripts cannot be checked")
		}
		t.Skip("node is not installed")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, filepath.Join(root, ".github", "scripts", "check-web-scripts.js"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the web app's scripts do not load: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
