// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// workflow is the part of a GitHub Actions workflow file these tests read.
type workflow struct {
	Name string               `yaml:"name"`
	On   map[string]yaml.Node `yaml:"on"`
	Jobs map[string]struct {
		Environment yaml.Node `yaml:"environment"`
		Uses        string    `yaml:"uses"`
	} `yaml:"jobs"`
}

func readWorkflows(t *testing.T) map[string]workflow {
	t.Helper()
	dir := filepath.Join("..", "..", ".github", "workflows")
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows in %s: %v", dir, err)
	}
	out := map[string]workflow{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var w workflow
		if err := yaml.Unmarshal(b, &w); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[filepath.Base(f)] = w
	}
	return out
}

// TestEveryMainWorkflowRaisesAnAlert: ci-alerts.yml opens an issue when a
// workflow fails on main, so every workflow that runs on main, on a
// schedule or after another must be in its list, and every name in the
// list must be a workflow's.
func TestEveryMainWorkflowRaisesAnAlert(t *testing.T) {
	wfs := readWorkflows(t)
	alerts, ok := wfs["ci-alerts.yml"]
	if !ok {
		t.Fatal("no .github/workflows/ci-alerts.yml")
	}
	var run struct {
		Workflows []string `yaml:"workflows"`
	}
	node := alerts.On["workflow_run"]
	if err := node.Decode(&run); err != nil || len(run.Workflows) == 0 {
		t.Fatalf("ci-alerts.yml lists no workflows: %v", err)
	}
	names := map[string]string{}
	for file, w := range wfs {
		names[w.Name] = file
	}
	for _, n := range run.Workflows {
		if names[n] == "" {
			t.Errorf("ci-alerts.yml lists %q, which no workflow is named", n)
		}
	}
	// Release runs on version tags, where a failure is seen at once;
	// Packages is called by others.
	exempt := map[string]bool{"ci-alerts.yml": true, "release.yml": true, "packages.yml": true}
	var files []string
	for f := range wfs {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, file := range files {
		w := wfs[file]
		if exempt[file] {
			continue
		}
		_, sched := w.On["schedule"]
		_, after := w.On["workflow_run"]
		push := false
		if p, ok := w.On["push"]; ok {
			var on struct {
				Branches []string `yaml:"branches"`
			}
			_ = p.Decode(&on)
			push = len(on.Branches) == 0 || slices.Contains(on.Branches, "main")
		}
		if (sched || after || push) && !slices.Contains(run.Workflows, w.Name) {
			t.Errorf("%s (%q) runs on main but ci-alerts.yml does not list it, so its failures open no issue", file, w.Name)
		}
	}
}

// signingSecrets are the keys that sign what Signalith publishes. Only
// jobs in a protected environment may read them: "release" (version tags
// only) or "signing" (main only), see docs/releasing.md.
var signingSecrets = regexp.MustCompile(`secrets\.(SIGNALITH_GPG_PRIVATE_KEY|SIGNALITH_GPG_PASSPHRASE|SIGNALITH_AGENT_KEY|SIGNALITH_CONTENT_KEY|SIGNPATH_API_TOKEN)\b`)

// TestSigningSecretsOnlyInProtectedEnvironments: a job that reads a
// signing key names the release or signing environment, so the key can
// be a secret of that environment instead of the whole repository, out of
// reach of branches and pull requests. A call of a reusable workflow that
// passes the secrets on is checked in the workflow it calls.
func TestSigningSecretsOnlyInProtectedEnvironments(t *testing.T) {
	dir := filepath.Join("..", "..", ".github", "workflows")
	files, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Jobs map[string]yaml.Node `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for name, job := range doc.Jobs {
			var j struct {
				Uses        string    `yaml:"uses"`
				Environment yaml.Node `yaml:"environment"`
			}
			if err := job.Decode(&j); err != nil {
				t.Fatalf("%s: job %s: %v", f, name, err)
			}
			text, err := yaml.Marshal(&job)
			if err != nil {
				t.Fatal(err)
			}
			used := signingSecrets.FindAllString(string(text), -1)
			if len(used) == 0 || strings.HasPrefix(j.Uses, "./") {
				continue
			}
			env := j.Environment.Value
			if j.Environment.Kind == yaml.MappingNode {
				var m struct {
					Name string `yaml:"name"`
				}
				_ = j.Environment.Decode(&m)
				env = m.Name
			}
			if !strings.Contains(env, "release") && !strings.Contains(env, "signing") {
				t.Errorf("%s: job %s reads %s without the release or signing environment", filepath.Base(f), name, strings.Join(slices.Compact(used), ", "))
			}
		}
	}
}
