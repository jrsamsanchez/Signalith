// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestDocsQuoteTheBuiltinDetectionCount keeps the number of built-in
// detections the README and website quote equal to the files shipped.
func TestDocsQuoteTheBuiltinDetectionCount(t *testing.T) {
	root := filepath.Join("..", "..")
	files, err := filepath.Glob(filepath.Join(root, "internal", "detect", "builtin", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	total, off := len(files), 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`(?m)^enabled:\s*false\s*$`).Match(b) {
			off++
		}
	}
	if total == 0 {
		t.Fatal("no built-in detections found")
	}
	checks := []struct {
		file string
		re   string
		want int
	}{
		{"README.md", `ships (\d+)\s+built-in detections`, total},
		{"README.md", `\); (\d+) are on by default`, total - off},
		{"site/index.html", `next to (\d+) built-in detections`, total},
	}
	for _, c := range checks {
		b, err := os.ReadFile(filepath.Join(root, c.file))
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(c.re).FindSubmatch(b)
		if m == nil {
			t.Errorf("%s: no match for %q; update this test if the wording changed", c.file, c.re)
			continue
		}
		if got, _ := strconv.Atoi(strings.TrimSpace(string(m[1]))); got != c.want {
			t.Errorf("%s says %d, but internal/detect/builtin has %d", c.file, got, c.want)
		}
	}
}
