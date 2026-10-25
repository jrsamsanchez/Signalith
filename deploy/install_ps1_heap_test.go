// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OpenSearch's Java heap reaches "signalith opensearch install -heap" from
// the .msi's OPENSEARCHHEAP property, through msi-setup.ps1 and
// install.ps1, and only when one is given: an empty one keeps the heap
// chosen before.
func TestWindowsInstallerPassesOpenSearchHeap(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.FromSlash(name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	ps1 := strings.ReplaceAll(string(InstallPS1), "\r\n", "\n")
	for _, want := range []string{`[string]$OpenSearchHeap = ""`, `if ($OpenSearchHeap) { $osArgs += @("-heap", $OpenSearchHeap) }`} {
		if !strings.Contains(ps1, want) {
			t.Errorf("install.ps1 lacks %s", want)
		}
	}
	// Both the install and the adopt command take it.
	if n := strings.Count(ps1, `@("-heap", $OpenSearchHeap)`); n != 2 {
		t.Errorf("install.ps1 passes -heap %d times, want 2 (install and adopt)", n)
	}
	setup := read("windows/msi/msi-setup.ps1")
	for _, want := range []string{`[string]$OpenSearchHeap = "heap:"`, `$OpenSearchHeap -replace '^heap:', ''`, `-OpenSearchHeap $OpenSearchHeap`} {
		if !strings.Contains(setup, want) {
			t.Errorf("msi-setup.ps1 lacks %s", want)
		}
	}
	wxs := read("windows/msi/Package.wxs")
	for _, want := range []string{`<Property Id="OPENSEARCHHEAP" Secure="yes" />`, `-OpenSearchHeap &quot;heap:[OPENSEARCHHEAP]&quot;`} {
		if !strings.Contains(wxs, want) {
			t.Errorf("Package.wxs lacks %s", want)
		}
	}
}
