package compliance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func capByID(t *testing.T, id string) Capability {
	t.Helper()
	for _, c := range Capabilities() {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no capability %s", id)
	return Capability{}
}

func TestCapabilityWording(t *testing.T) {
	now := time.Now()
	base := func(mod func(*Snapshot)) *Snapshot {
		s := &Snapshot{Now: now, Assets: -1}
		mod(s)
		return s
	}
	for _, c := range []struct {
		cap    string
		snap   *Snapshot
		status Status
		text   string
	}{
		{"triage", base(func(s *Snapshot) { s.Findings = &Findings{} }), Met, "No open findings."},
		{"triage", base(func(s *Snapshot) { s.Findings = &Findings{Open: 1200, New: 3} }), Met, "1,200 open, 3 not looked at"},
		{"response", base(func(s *Snapshot) { s.Response = &Response{} }), Missing, "No response action"},
		{"response", base(func(s *Snapshot) { s.Response = &Response{Actions: 1, Playbooks: 2} }), Met, "1 response action set up, and 2 playbooks."},
		{"notify", base(func(s *Snapshot) { s.Notify = &Notify{Channels: 1} }), Partial, "1 channel is set up, but no enabled rule"},
		{"notify", base(func(s *Snapshot) { s.Notify = &Notify{} }), Missing, "No notification channel"},
		{"intel", base(func(s *Snapshot) { s.Intel = &Intel{Feeds: 2} }), Partial, "2 feeds are on, but none downloaded"},
		{"intel", base(func(s *Snapshot) { s.Intel = &Intel{} }), Missing, "No threat intel feed"},
		{"vuln-scan", base(func(s *Snapshot) { s.Vulns = &Vulns{} }), Missing, "No network is set up"},
		{"vuln-scan", base(func(s *Snapshot) { s.Vulns = &Vulns{Networks: 3} }), Missing, "3 networks are set up, but no scan"},
		{"vuln-scan", base(func(s *Snapshot) { s.Vulns = &Vulns{Networks: 1, LastScan: now.Add(-60 * 24 * time.Hour)} }), Partial, "Scan at least monthly."},
		{"vuln-scan", base(func(s *Snapshot) { s.Vulns = &Vulns{Networks: 1, LastScan: now.Add(-100 * 24 * time.Hour)} }), Missing, "100 days ago"},
		{"vuln-scan", base(func(s *Snapshot) { s.Vulns = &Vulns{Networks: 1, LastScan: now.Add(-30 * time.Minute)} }), Met, "30 minutes ago"},
		{"assets", base(func(s *Snapshot) { s.Assets = 0 }), Missing, "No assets or identities"},
		{"storage-guard", base(func(s *Snapshot) { s.Retention = &Retention{} }), Missing, "The disk guard is off"},
		{"siem-access", base(func(s *Snapshot) { s.Users = &Users{Directory: true, Named: 1} }), Met, "directory; 1 named user with roles"},
		{"siem-access", base(func(s *Snapshot) { s.Users = &Users{} }), Partial, "Only the built-in admin"},
		{"retention-90", base(func(s *Snapshot) { s.Retention = &Retention{} }), Met, "kept until it is deleted by hand"},
		{"retention-90", base(func(s *Snapshot) { s.Retention = &Retention{KeepDays: 120, Shorter: []string{"DNS"}} }), Partial, "shorter policy: DNS."},
		{"retention-90", base(func(s *Snapshot) { s.Retention = &Retention{KeepDays: 120, MaxSizeGB: 1.5} }), Partial, "size cap of 1.5 GB"},
		{"config-checks", base(func(s *Snapshot) { s.Checks = []CheckStat{} }), Missing, "No host runs osquery"},
		{"config-checks", base(func(s *Snapshot) { s.Checks = []CheckStat{}; s.Hosts = 2 }), Missing, "No configuration check covers"},
	} {
		st, text := capByID(t, c.cap).eval(c.snap, nil)
		if st != c.status || !strings.Contains(text, c.text) {
			t.Errorf("%s: %s %q, want %s %q", c.cap, st, text, c.status, c.text)
		}
	}
}

func TestWordingHelpers(t *testing.T) {
	if count(-1234) != "-1234" || count(1234567) != "1,234,567" {
		t.Errorf("count = %s %s", count(-1234), count(1234567))
	}
	if lowerFirst("") != "" || lowerFirst("Abc") != "abc" {
		t.Error("lowerFirst")
	}
	for s, want := range map[Status]string{Met: "Evidence", Missing: "Gap", NotApplicable: "Not applicable", External: "Handled outside Signalith", "odd": "odd"} {
		if got := StatusLabel(s); got != want {
			t.Errorf("StatusLabel(%s) = %s", s, got)
		}
	}
	if _, ok := FrameworkByID("no-such"); ok {
		t.Error("an unknown framework was found")
	}
	if _, ok := (&Report{}).Find("no-such"); ok {
		t.Error("an unknown report was found")
	}
}

func TestParseFrameworksProblems(t *testing.T) {
	if _, err := parseFrameworks([]byte("frameworks: [")); err == nil {
		t.Error("bad YAML parsed")
	}
	_, err := parseFrameworks([]byte(`frameworks:
- id: "Bad ID"
  name: ""
  url: http://example.com
  controls:
  - id: c1
    title: T
    group: G
    caps: [no-such-cap]
    nist: [not-nist]
  - id: c1
- id: empty
  name: Empty
  notice: N
  url: https://example.com
`))
	if err == nil {
		t.Fatal("bad frameworks parsed")
	}
	for _, want := range []string{"not valid or not unique", "an https url are required", `unknown capability "no-such-cap"`,
		`"not-nist" is not a NIST`, `control id "c1" is empty or repeated`, "title, group and caps are required", "empty: no controls"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

func TestNotesProblems(t *testing.T) {
	ctx := context.Background()
	fw := Frameworks()[0]
	ctl := fw.Controls[0].ID
	if _, err := CheckNote("no-such", ctl, External, "x"); err == nil || err.Error() != "There is no framework no-such." {
		t.Errorf("framework = %v", err)
	}
	var ie *InputError
	if _, err := CheckNote(fw.ID, ctl, External, strings.Repeat("é", MaxNote+1)); !errors.As(err, &ie) || !strings.Contains(ie.Error(), "at most") {
		t.Errorf("long note = %v", err)
	}

	dir := t.TempDir()
	bad := filepath.Join(dir, "notes.json")
	os.WriteFile(bad, []byte("{not json"), 0o600)
	n := NewNotes(bad)
	if n.Err() == nil {
		t.Error("a damaged file read")
	}
	if _, err := n.Set(ctx, fw.ID, ctl, External, "handled by IT", "admin", time.Now()); err == nil || !strings.Contains(err.Error(), "not changed") {
		t.Errorf("set on a damaged file = %v", err)
	}
	if NewNotes(dir).Err() == nil {
		t.Error("a folder read as the notes")
	}
	empty := filepath.Join(dir, "empty.json")
	os.WriteFile(empty, []byte(`{}`), 0o600)
	if n := NewNotes(empty); n.Err() != nil || len(n.All()) != 0 {
		t.Errorf("empty file = %v %v", n.Err(), n.All())
	}
	// The file cannot be written.
	blocker := filepath.Join(dir, "blocker")
	os.WriteFile(blocker, nil, 0o600)
	n = NewNotes(filepath.Join(blocker, "notes.json"))
	if _, err := n.Set(ctx, fw.ID, ctl, External, "handled by IT", "admin", time.Now()); err == nil {
		t.Error("saved under a file")
	}
	// In memory only.
	n = NewNotes("")
	if a, err := n.Set(ctx, fw.ID, ctl, NotApplicable, " no card data ", "admin", time.Now()); err != nil || a.Note != "no card data" || len(n.All()) != 1 {
		t.Errorf("memory = %+v %v", a, err)
	}
}
