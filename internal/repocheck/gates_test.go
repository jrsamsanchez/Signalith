// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// needsOf reads which jobs each job of a workflow file waits for.
func needsOf(t *testing.T, file string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", file))
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		Jobs map[string]struct {
			Needs yaml.Node `yaml:"needs"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	out := map[string][]string{}
	for name, j := range w.Jobs {
		switch j.Needs.Kind {
		case yaml.ScalarNode:
			out[name] = []string{j.Needs.Value}
		case yaml.SequenceNode:
			for _, n := range j.Needs.Content {
				out[name] = append(out[name], n.Value)
			}
		default:
			out[name] = nil
		}
	}
	return out
}

// TestReleaseWaitsForGreenCI: every release job that publishes anything
// comes after packages, and packages waits for ci-green, which refuses a
// tag on a commit that is not on main or whose CI did not pass.
func TestReleaseWaitsForGreenCI(t *testing.T) {
	needs := needsOf(t, "release.yml")
	if _, ok := needs["ci-green"]; !ok {
		t.Fatal("release.yml has no ci-green job")
	}
	if !slices.Contains(needs["packages"], "ci-green") {
		t.Errorf("release.yml: packages needs %v, want ci-green", needs["packages"])
	}
	// Every other job reaches ci-green through the jobs it needs.
	var reaches func(job string, seen map[string]bool) bool
	reaches = func(job string, seen map[string]bool) bool {
		if job == "ci-green" {
			return true
		}
		if seen[job] {
			return false
		}
		seen[job] = true
		for _, n := range needs[job] {
			if reaches(n, seen) {
				return true
			}
		}
		return false
	}
	for job := range needs {
		if job != "ci-green" && !reaches(job, map[string]bool{}) {
			t.Errorf("release.yml: job %s does not wait for ci-green", job)
		}
	}
}

// TestCIPassedCoversSkippableJobs: branch protection requires ci-passed in
// place of jobs a pull request may skip, so it must wait for them.
func TestCIPassedCoversSkippableJobs(t *testing.T) {
	needs := needsOf(t, "ci.yml")
	got, ok := needs["ci-passed"]
	if !ok {
		t.Fatal("ci.yml has no ci-passed job")
	}
	for _, want := range []string{"gofmt", "coverage", "packages"} {
		if !slices.Contains(got, want) {
			t.Errorf("ci.yml: ci-passed needs %v, missing %s", got, want)
		}
	}
}
