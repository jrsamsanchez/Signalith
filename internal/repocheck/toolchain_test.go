// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestImageBuildsWithTheGoInGoMod: CI's vulnerability check runs with the
// Go version in go.mod, so the container image (and the agent programs
// built inside it) must be built with that same Go, pinned by digest.
// Otherwise the shipped binaries can carry standard-library holes no check
// ever looks at.
func TestImageBuildsWithTheGoInGoMod(t *testing.T) {
	gomod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+\.[0-9]+)\s*$`).FindSubmatch(gomod)
	if m == nil {
		t.Fatal("go.mod has no go 1.x.y line")
	}
	want := string(m[1])
	path := filepath.Join("..", "..", "deploy", "docker", "Dockerfile")
	df, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	froms := regexp.MustCompile(`(?m)^FROM golang:(\S+)`).FindAllSubmatch(df, -1)
	if len(froms) == 0 {
		t.Fatalf("%s: no FROM golang: line", path)
	}
	pinned := regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$`)
	for _, f := range froms {
		p := pinned.FindSubmatch(f[1])
		if p == nil {
			t.Errorf("%s: golang:%s is not a version pinned by digest (golang:1.x.y@sha256:...)", path, f[1])
			continue
		}
		if string(p[1]) != want {
			t.Errorf("%s: builds with Go %s, go.mod says %s; change both together", path, p[1], want)
		}
	}
}
