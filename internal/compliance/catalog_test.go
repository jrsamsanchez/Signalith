// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateCatalog = flag.Bool("update", false, "rewrite testdata/catalog.golden from frameworks.yaml")

// catalogText is the mapping as one line per control, so a change to any
// title, capability, NIST reference or "also" text shows in review as a
// change to testdata/catalog.golden.
func catalogText() string {
	var b strings.Builder
	for _, fw := range Frameworks() {
		fmt.Fprintf(&b, "# %s %s (%d controls)\n", fw.Name, fw.Version, len(fw.Controls))
		for _, c := range fw.Controls {
			fmt.Fprintf(&b, "%s %s | %s | %s | caps %s | nist %s", fw.ID, c.ID, c.Group, c.Title,
				strings.Join(c.Caps, ","), strings.Join(c.NIST, ","))
			if c.Also != "" {
				fmt.Fprintf(&b, " | also %s", c.Also)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// The shipped mapping is the reviewed one. After changing frameworks.yaml
// on purpose, run go test ./internal/compliance -run TestCatalogGolden
// -update and review the diff of testdata/catalog.golden.
func TestCatalogGolden(t *testing.T) {
	path := filepath.Join("testdata", "catalog.golden")
	got := catalogText()
	if *updateCatalog {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < max(len(gl), len(wl)); i++ {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Fatalf("frameworks.yaml differs from testdata/catalog.golden at line %d:\n got: %s\nwant: %s\nRun with -update if the change is meant, and review the diff.", i+1, g, w)
			}
		}
	}
}

// Controls a SIEM cannot give evidence for stay out of the catalog: the
// review of the mapping dropped them (finding COMP-03).
func TestCatalogLeavesOutWhatASIEMCannotShow(t *testing.T) {
	for _, key := range []string{"pci-dss 8.3.4", "hipaa 164.308(a)(1)(ii)(A)", "soc2 CC4.1"} {
		fw, id, _ := strings.Cut(key, " ")
		f, _ := FrameworkByID(fw)
		for _, c := range f.Controls {
			if c.ID == id {
				t.Errorf("%s is mapped again; a SIEM cannot show it", key)
			}
		}
	}
}
