package playbooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

func testRefs() Refs {
	return Refs{
		Channels: map[string]string{"soc": "Slack #soc", "leads": "Slack #leads"},
		Actions: map[string]ActionRef{
			"block":   {Label: "Block IP on the edge firewall", Target: "ip", Disruptive: true, Enabled: true, What: "Block {target} on fw."},
			"tag":     {Label: "Tag host", Target: "any", Enabled: true},
			"disable": {Label: "Disable AD account", Target: "user", Disruptive: true, Enabled: true},
		},
	}
}

func TestSaveAndReadBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "playbooks.yaml")
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	m := &Manager{File: path, Now: func() time.Time { return now }}
	if fp := m.Fingerprint(); fp != "" {
		t.Errorf("no playbooks, fingerprint %q", fp)
	}
	in := Input{Playbooks: []Playbook{{
		Name: " Brute force response ", Enabled: true, ApprovalChannel: "leads",
		Trigger: Trigger{Detections: []string{"brute-force", "brute-force", " "}},
		Steps: []Step{
			{Kind: StepNotify, Channel: "soc", Action: "ignored"},
			{Kind: StepAction, Action: "block", Target: TargetSrc},
			{Kind: StepOpenCase, Reuse: true, Owner: "ann"},
			{Kind: StepSetFinding, Status: "in_progress"},
		},
	}}}
	list, err := m.Save(in, testRefs())
	if err != nil {
		t.Fatal(err)
	}
	p := list[0]
	if p.ID == "" || p.Name != "Brute force response" || p.Trigger.MinUrgency != "high" || len(p.Trigger.Detections) != 1 ||
		!p.Since.Equal(now) || p.Steps[0].Action != "" || !p.Steps[1].NeedsApproval {
		t.Fatalf("saved %+v", p)
	}
	if got := p.Summary(testRefs()); got != "When brute-force fires at high or above: notify Slack #soc, then block IP on the edge firewall for the source IP after approval, "+
		"then open a case (or add to the one it opened) for ann, then set the finding to In progress." {
		t.Errorf("summary %q", got)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(data), "# Playbooks set on the Playbooks page") || !strings.Contains(string(data), "needs_approval: true") {
		t.Fatalf("file %s %v", data, err)
	}
	again := &Manager{File: path}
	got, err := again.List()
	if err != nil || len(got) != 1 || got[0].ID != p.ID || len(got[0].Steps) != 4 || !got[0].Since.Equal(now) {
		t.Fatalf("read back %+v %v", got, err)
	}
	if again.Revision() != m.Revision() || again.Fingerprint() != m.Fingerprint() || m.Fingerprint() == "" {
		t.Error("revision or fingerprint differs after a round trip")
	}
	// A save over an older revision is refused.
	if _, err := m.Save(Input{Revision: "old", Playbooks: got}, testRefs()); !errors.Is(err, ErrChanged) {
		t.Errorf("stale save: %v", err)
	}
	// Turning it off and on again moves Since; a later save keeps it.
	got[0].Enabled = false
	later := now.Add(time.Hour)
	m.Now = func() time.Time { return later }
	off, _ := m.Save(Input{Revision: m.Revision(), Playbooks: got}, testRefs())
	off[0].Enabled = true
	on, _ := m.Save(Input{Playbooks: off}, testRefs())
	if !on[0].Since.Equal(later) {
		t.Errorf("since %v", on[0].Since)
	}
	// A channel deleted since the save does not block saving it again.
	refs := testRefs()
	delete(refs.Channels, "soc")
	if _, err := m.Save(Input{Playbooks: on}, refs); err != nil {
		t.Errorf("save with a deleted channel: %v", err)
	}
}

func TestSaveProblems(t *testing.T) {
	m := &Manager{}
	in := Input{Playbooks: []Playbook{
		{ID: "a", Name: "One", Enabled: true},
		{ID: "b", Name: "one", Trigger: Trigger{MinUrgency: "urgent"}, ApprovalChannel: "nope", Steps: []Step{
			{Kind: StepNotify, Channel: "gone"},
			{Kind: StepAction, Action: "disable", Target: TargetSrc},
			{Kind: StepAction, Action: "block", Target: TargetUser},
			{Kind: StepAction, Action: "block", Target: TargetFixed, Value: "not an ip"},
			{Kind: StepSetFinding},
			{Kind: StepOpenCase, Owner: "bad owner"},
			{Kind: "email"},
		}},
	}}
	_, err := m.Save(in, testRefs())
	var ie *InputError
	if !errors.As(err, &ie) {
		t.Fatalf("err %v", err)
	}
	want := []string{"a steps", "b trigger.min_urgency", "b approval_channel", "b steps[0].channel", "b steps[1].target",
		"b steps[2].target", "b steps[3].value", "b steps[4].status", "b steps[5].owner", "b steps[6].kind", "b name"}
	var got []string
	for _, p := range ie.Problems {
		got = append(got, strings.TrimPrefix(p.Where, "playbook:")+" "+p.Field)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("problems\n%v\nwant\n%v\n%v", got, want, ie)
	}
}

func TestBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "playbooks.yaml")
	if err := os.WriteFile(path, []byte("playbooks: [:"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{File: path}
	var fe *FileError
	if _, err := m.List(); !errors.As(err, &fe) {
		t.Fatalf("err %v", err)
	}
	if _, err := m.Save(Input{}, testRefs()); !errors.As(err, &fe) {
		t.Errorf("a bad file was overwritten: %v", err)
	}
	if fp := m.Fingerprint(); fp == "" {
		t.Error("a bad file fingerprints as none")
	}
	if err := os.WriteFile(path, []byte("playbooks: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.List(); err != nil {
		t.Errorf("fixed file: %v", err)
	}
}

func TestExpand(t *testing.T) {
	f := bruteForceFinding()
	if got := Expand("{detection}: {src} -> {user}\n{nope}", f); got != "brute-force: 203.0.113.7 -> jdoe {nope}" {
		t.Errorf("expand %q", got)
	}
	if got := Expand("", f); got != f.Title {
		t.Errorf("default %q", got)
	}
}

func bruteForceFinding() *findings.Finding {
	return &findings.Finding{ID: "F-1", DetectionID: "brute-force", Title: "Brute force from 203.0.113.7",
		Entities: map[string]any{"src": "203.0.113.7", "user": "jdoe"}}
}
