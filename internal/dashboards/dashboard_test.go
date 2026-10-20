// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package dashboards

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `id: soc-overview
title: SOC overview
time_range: 7d
refresh: 5m
panels:
  - title: Failed logins
    query: datamodel=Authentication action=failure | stats count
    viz: single
    compare: true
  - title: Failures over time
    query: |
      datamodel=Authentication action=failure
      | timechart count by src
  - title: Top users
    query: datamodel=Authentication | top limit=5 user
    viz: bar
    width: full
`

func TestDecodeDefaultsAndRoundTrip(t *testing.T) {
	d, err := Decode([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if d.Panels[0].Width != "third" || d.Panels[1].Viz != VizLine || d.Panels[1].Width != "full" || d.Panels[2].Width != "full" {
		t.Errorf("defaults = %+v", d.Panels)
	}
	out, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "query: |-\n      datamodel=Authentication action=failure\n      | timechart count by src") {
		t.Errorf("multi-line query not written as a block:\n%s", out)
	}
	again, err := Decode(out)
	if err != nil || again.Panels[1].Query != d.Panels[1].Query || again.Refresh != "5m" {
		t.Errorf("round trip = %+v %v", again, err)
	}
}

func TestValidateListsEveryProblem(t *testing.T) {
	d, err := Decode([]byte(`id: Bad ID
title: ""
time_range: forever
refresh: 1s
panels:
  - title: ""
    query: "a=1 | stats avg"
    viz: pie
  - title: Trend
    query: "* | stats count"
    viz: table
    width: huge
    compare: true
`))
	if err != nil {
		t.Fatal(err)
	}
	err = d.Validate()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	for _, want := range []string{"id \"Bad ID\"", "title is required", "time_range", "refresh must be at least 30s",
		"panel 1: title is required", "panel 1: query:", "viz \"pie\"", "panel 2 (Trend): width \"huge\"", "compare only applies"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
	if _, err := Decode([]byte("id: x\ntitel: typo\n")); err == nil || !strings.Contains(err.Error(), "titel") {
		t.Errorf("unknown key not rejected: %v", err)
	}
	p := &Dashboard{ID: PostureID, Title: "Mine"}
	p.Defaults()
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("posture id allowed: %v", err)
	}
}

func TestStore(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := &Dashboard{ID: "auth", Title: "Authentication", Panels: []Panel{{Title: "Failures", Query: "datamodel=Authentication action=failure | stats count"}}}
	if err := s.Put(d); err != nil {
		t.Fatal(err)
	}
	if d.Panels[0].Viz != VizSingle || d.TimeRange != "24h" {
		t.Errorf("defaults not applied on save: %+v", d)
	}
	if err := s.Put(&Dashboard{ID: "auth2", Title: "", Panels: nil}); err == nil {
		t.Error("invalid dashboard saved")
	}
	got, err := s.Get("auth")
	if err != nil || got.Title != "Authentication" || len(got.Panels) != 1 {
		t.Fatalf("get = %+v %v", got, err)
	}
	// Files dropped into the folder show up without a restart; broken ones
	// are reported, not fatal.
	os.WriteFile(filepath.Join(dir, "from-git.yaml"), []byte("id: from-git\ntitle: A from Git\npanels: []\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("id: broken\ntitle: Broken\npanels:\n  - title: x\n    query: \"| |\"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "renamed.yaml"), []byte("id: other-name\ntitle: Renamed\n"), 0o600)
	list, problems, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "from-git" || list[1].ID != "auth" {
		t.Errorf("list = %v", list)
	}
	if len(problems) != 2 || problems[0].File != "broken.yaml" || !strings.Contains(problems[1].Error, "does not match") {
		t.Errorf("problems = %+v", problems)
	}
	if _, err := s.Get("broken"); err == nil {
		t.Error("broken file loaded")
	}
	if _, err := s.Get("../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Errorf("path traversal = %v", err)
	}
	if id := s.NewID("Authentication!"); id != "authentication" {
		t.Errorf("new id = %q", id)
	}
	if id := s.NewID("auth"); id != "auth-2" {
		t.Errorf("taken id = %q", id)
	}
	if err := s.Delete("auth"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("auth"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete = %v", err)
	}
	if err := s.Delete("auth"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v", err)
	}
}

// TestDocExample keeps the example in docs/dashboards.md valid.
func TestDocExample(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "dashboards.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows checkouts may have CRLF line endings.
	text := strings.ReplaceAll(string(doc), "\r\n", "\n")
	_, rest, ok := strings.Cut(text, "## Format\n\n```yaml\n")
	example, _, ok2 := strings.Cut(rest, "```")
	if !ok || !ok2 {
		t.Fatal("no YAML example under ## Format")
	}
	d, err := Decode([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(); err != nil || len(d.Panels) != 5 {
		t.Errorf("doc example: %v (%d panels)", err, len(d.Panels))
	}
}

func TestSuggestViz(t *testing.T) {
	for q, want := range map[string]string{
		"datamodel=Authentication | timechart count by action": VizLine,
		"* | stats count":                       VizSingle,
		"* | stats count by user | sort -count": VizBar,
		"* | top user":                          VizBar,
		"datamodel=Change":                      VizTable,
		"* | stats count by user | table user":  VizTable,
		"not ( valid":                           VizTable,
	} {
		if got := SuggestViz(q); got != want {
			t.Errorf("%q -> %s, want %s", q, got, want)
		}
	}
}
