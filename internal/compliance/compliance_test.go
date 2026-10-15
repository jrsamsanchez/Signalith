package compliance

import (
	"bytes"
	"encoding/csv"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint/checks"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func TestFrameworksLoad(t *testing.T) {
	fs := Frameworks()
	if len(fs) < 6 {
		t.Fatalf("only %d frameworks", len(fs))
	}
	for _, id := range []string{"nist-800-53", "cis-v8", "pci-dss", "iso-27001", "hipaa", "soc2"} {
		if _, ok := FrameworkByID(id); !ok {
			t.Errorf("no framework %s", id)
		}
	}
}

// Every control that counts configuration checks as evidence must have
// at least one check behind it, or it could never be met.
func TestEveryCheckControlHasChecks(t *testing.T) {
	all := checks.All()
	for _, f := range Frameworks() {
		for _, c := range f.Controls {
			if !slices.Contains(c.Caps, "config-checks") {
				continue
			}
			n := 0
			for _, ch := range all {
				for _, ref := range ch.References {
					if slices.ContainsFunc(c.NIST, func(ctl string) bool { return refMatches(ctl, ref) }) {
						n++
						break
					}
				}
			}
			if n == 0 {
				t.Errorf("%s %s uses config-checks, but no check references %v", f.ID, c.ID, c.NIST)
			}
		}
	}
}

func TestEveryCapabilityIsUsed(t *testing.T) {
	used := map[string]bool{}
	for _, f := range Frameworks() {
		for _, c := range f.Controls {
			for _, cp := range c.Caps {
				used[cp] = true
			}
		}
	}
	for _, c := range capabilities {
		if !used[c.ID] {
			t.Errorf("capability %s is not used by any control", c.ID)
		}
		if c.Name == "" || c.Description == "" || c.Page == "" {
			t.Errorf("capability %s needs a name, description and page", c.ID)
		}
	}
}

func TestRefMatches(t *testing.T) {
	cases := []struct {
		ctl, ref string
		want     bool
	}{
		{"CM-6", "CM-6a", true},
		{"CM-6", "CM-6", true},
		{"AC-6", "AC-6(2)", true},
		{"AC-6(9)", "AC-6(2)", false},
		{"AC-6(9)", "AC-6(9)", true},
		{"IA-5", "IA-5(1)d", true},
		{"SC-7", "SC-7(10)", true},
		{"SC-2", "SC-28", false},
		{"AU-1", "AU-12", false},
	}
	for _, c := range cases {
		if got := refMatches(c.ctl, c.ref); got != c.want {
			t.Errorf("refMatches(%q, %q) = %v", c.ctl, c.ref, got)
		}
	}
}

func empty() *Snapshot { return &Snapshot{Now: now, Data: map[string]DataSeen{}, Assets: -1} }

func full() *Snapshot {
	s := &Snapshot{
		Now: now,
		Data: map[string]DataSeen{
			"Authentication": {Count: 1200, Last: now.Add(-time.Minute)}, "Endpoint": {Count: 5000, Last: now},
			"Change": {Count: 30, Last: now}, "Network_Traffic": {Count: 9000, Last: now}, "Network_Resolution": {Count: 100, Last: now},
			"Malware": {Count: 3, Last: now.Add(-2 * time.Hour)}, "Filesystem": {Count: 40, Last: now}, "Inventory": {Count: 400, Last: now},
		},
		Detections: []Detection{
			{ID: "brute", Name: "Brute force", Enabled: true, Models: []string{"Authentication"}, Tactics: []string{"credential-access"}},
			{ID: "priv", Name: "Sudo to root", Enabled: true, Models: []string{"Authentication"}, Tactics: []string{"privilege-escalation"}},
			{ID: "mal", Name: "Malware found", Enabled: true, Models: []string{"Malware"}},
			{ID: "c2", Name: "Beaconing", Enabled: true, Models: []string{"Network_Traffic"}, Tactics: []string{"command-and-control"}},
			{ID: "acct", Name: "Account created", Enabled: true, Models: []string{"Change"}, Tactics: []string{"persistence"}},
		},
		SchedulerOn: true,
		Hosts:       2,
		Vulns:       &Vulns{Networks: 1, LastScan: now.Add(-3 * 24 * time.Hour)},
		Findings:    &Findings{Open: 4, New: 1},
		Cases:       &Cases{Total: 2, Open: 1},
		Notify:      &Notify{Channels: 1, Rules: 1},
		Response:    &Response{Actions: 2},
		Intel:       &Intel{Feeds: 2, Fresh: 2},
		Retention:   &Retention{KeepDays: 400, Guard: true},
		Users:       &Users{Named: 3},
		Assets:      10,
		HTTPS:       true,
	}
	for _, c := range checks.All() {
		s.Checks = append(s.Checks, CheckStat{ID: c.ID, Title: c.Title, Platform: c.Platform, Refs: c.References, Pass: 2})
	}
	return s
}

func TestEverythingInPlaceMeetsEveryControl(t *testing.T) {
	rep := Evaluate(full(), nil)
	for _, f := range rep.Frameworks {
		for _, c := range f.Controls {
			if c.Status != Met {
				t.Errorf("%s %s = %s: %+v", f.ID, c.ID, c.Status, c.Evidence)
			}
		}
		if f.Score != 100 {
			t.Errorf("%s score %d", f.ID, f.Score)
		}
	}
}

func TestNothingInPlace(t *testing.T) {
	rep := Evaluate(empty(), nil)
	for _, f := range rep.Frameworks {
		if f.Counts[Met] == len(f.Controls) {
			t.Errorf("%s: every control met with nothing set up", f.ID)
		}
		for _, c := range f.Controls {
			for _, e := range c.Evidence {
				if e.Status != Met && e.Fix == "" {
					t.Errorf("%s %s: %s has no fix", f.ID, c.ID, e.Capability)
				}
			}
		}
	}
	// AU-8 is built in, so it is met even here.
	f, _ := rep.Find("nist-800-53")
	for _, c := range f.Controls {
		if c.ID == "AU-8" && c.Status != Met {
			t.Errorf("AU-8 = %s", c.Status)
		}
		if c.ID == "RA-5" && c.Status != Missing {
			t.Errorf("RA-5 = %s", c.Status)
		}
	}
}

func control(t *testing.T, rep *Report, fw, id string) ControlReport {
	t.Helper()
	f, ok := rep.Find(fw)
	if !ok {
		t.Fatalf("no %s", fw)
	}
	for _, c := range f.Controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no %s %s", fw, id)
	return ControlReport{}
}

func TestPartialStates(t *testing.T) {
	s := full()
	// A failing check makes CM-6 partial and lists it.
	s.Checks[0].Fail, s.Checks[0].Pass = 1, 1
	for i := range s.Checks {
		if slices.ContainsFunc(s.Checks[i].Refs, func(r string) bool { return refMatches("CM-6", r) }) {
			s.Checks[i].Fail = 1
			break
		}
	}
	// Detections whose data stops arriving are partial.
	delete(s.Data, "Malware")
	// Old untriaged findings.
	s.Findings.Stale = 3
	// Retention under a year without archive.
	s.Retention.KeepDays = 120
	rep := Evaluate(s, nil)

	cm6 := control(t, rep, "nist-800-53", "CM-6")
	if cm6.Status != Partial || cm6.Checks == nil || cm6.Checks.Fail == 0 || len(cm6.Checks.Failing) == 0 {
		t.Errorf("CM-6 = %s %+v", cm6.Status, cm6.Checks)
	}
	if si3 := control(t, rep, "nist-800-53", "SI-3"); si3.Status != Partial || si3.Evidence[0].Status != Missing || si3.Evidence[1].Status != Partial {
		t.Errorf("SI-3 = %s %+v", si3.Status, si3.Evidence)
	}
	if au6 := control(t, rep, "nist-800-53", "AU-6"); au6.Status != Partial {
		t.Errorf("AU-6 = %s", au6.Status)
	}
	if pci := control(t, rep, "pci-dss", "10.5.1"); pci.Status != Partial {
		t.Errorf("PCI 10.5.1 = %s %+v", pci.Status, pci.Evidence)
	}
	if cis := control(t, rep, "cis-v8", "8.10"); cis.Status != Met {
		t.Errorf("CIS 8.10 = %s", cis.Status)
	}
	// Archiving makes a year met.
	s.Retention.Archive = true
	if pci := control(t, Evaluate(s, nil), "pci-dss", "10.5.1"); pci.Status != Met {
		t.Errorf("PCI 10.5.1 with archive = %s", pci.Status)
	}
}

func TestDetectionsOffOrWithoutScheduler(t *testing.T) {
	s := full()
	for i := range s.Detections {
		s.Detections[i].Enabled = false
	}
	c := control(t, Evaluate(s, nil), "nist-800-53", "AC-7")
	if c.Status != Partial || c.Evidence[1].Status != Missing || !strings.Contains(c.Evidence[1].Detail, "none is on") {
		t.Errorf("AC-7 = %s %+v", c.Status, c.Evidence)
	}
	s = full()
	s.SchedulerOn = false
	c = control(t, Evaluate(s, nil), "nist-800-53", "AC-7")
	if c.Evidence[1].Status != Partial || len(c.Detections) == 0 {
		t.Errorf("AC-7 without scheduler = %+v", c)
	}
}

func TestTaggedDetections(t *testing.T) {
	s := empty()
	s.SchedulerOn = true
	s.Data["Other"] = DataSeen{Count: 5}
	s.Detections = []Detection{{ID: "custom", Name: "Card data export", Enabled: true, Tags: []string{"PCI-DSS:10.2.1.4"}}}
	c := control(t, Evaluate(s, nil), "pci-dss", "10.2.1.4")
	if len(c.Detections) != 1 || !c.Detections[0].Tagged {
		t.Errorf("tagged detection not listed: %+v", c.Detections)
	}
	// A control without detection capabilities gets its own line.
	s.Detections[0].Tags = []string{"pci-dss:10.6.1"}
	c = control(t, Evaluate(s, nil), "pci-dss", "10.6.1")
	if len(c.Evidence) != 2 || c.Evidence[1].Capability != "tagged" || c.Evidence[1].Status != Met {
		t.Errorf("tagged line = %+v", c.Evidence)
	}
}

func TestNotes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compliance.json")
	n := NewNotes(path)
	if _, err := n.Set("pci-dss", "10.6.1", External, "  ", "ann", now); err == nil {
		t.Error("an empty note was accepted")
	}
	if _, err := n.Set("pci-dss", "99.9", External, "x", "ann", now); err == nil {
		t.Error("an unknown control was accepted")
	}
	if _, err := n.Set("pci-dss", "10.6.1", "maybe", "x", "ann", now); err == nil {
		t.Error("an unknown status was accepted")
	}
	if _, err := n.Set("pci-dss", "10.6.1", External, "Chrony on every host, checked by the platform team.", "ann", now); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Set("pci-dss", "11.3.1", NotApplicable, "No cardholder network.", "ann", now); err != nil {
		t.Fatal(err)
	}
	// Read back from the file.
	n = NewNotes(path)
	if n.Err() != nil || len(n.All()) != 2 {
		t.Fatalf("reread: %v %+v", n.Err(), n.All())
	}
	rep := Evaluate(empty(), n.All())
	f, _ := rep.Find("pci-dss")
	if f.Counts[External] != 1 || f.Counts[NotApplicable] != 1 {
		t.Errorf("counts = %+v", f.Counts)
	}
	c := control(t, rep, "pci-dss", "10.6.1")
	if c.Status != External || c.Computed != Met || c.Attestation == nil || c.Attestation.By != "ann" {
		t.Errorf("10.6.1 = %+v", c)
	}
	if _, err := n.Set("pci-dss", "11.3.1", "", "", "ann", now); err != nil {
		t.Fatal(err)
	}
	if len(NewNotes(path).All()) != 1 {
		t.Error("removing a note did not stick")
	}
}

func TestScore(t *testing.T) {
	s := full()
	rep := Evaluate(s, map[string]Attestation{Key("hipaa", "164.312(b)"): {Status: NotApplicable, Note: "x"}})
	f, _ := rep.Find("hipaa")
	if f.Score != 100 || f.Counts[NotApplicable] != 1 {
		t.Errorf("score %d counts %+v", f.Score, f.Counts)
	}
	rep = Evaluate(empty(), nil)
	f, _ = rep.Find("hipaa")
	if f.Score < 0 || f.Score >= 100 {
		t.Errorf("empty score %d", f.Score)
	}
}

func TestExports(t *testing.T) {
	s := full()
	s.Checks[0].Fail = 1
	rep := Evaluate(s, map[string]Attestation{Key("pci-dss", "10.6.1"): {Status: External, Note: "=HYPERLINK(\"x\")", By: "ann", At: now}})
	f, _ := rep.Find("pci-dss")
	var b bytes.Buffer
	if err := WriteCSV(&b, rep, f, "siem-1"); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&b).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) < len(f.Controls)+1 || recs[0][1] != "control" {
		t.Fatalf("csv rows = %d", len(recs))
	}
	for _, r := range recs {
		for _, v := range r {
			if strings.HasPrefix(v, "=") {
				t.Errorf("formula left in the CSV: %q", v)
			}
		}
	}
	b.Reset()
	if err := WriteHTML(&b, rep, f, "siem-1", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	for _, want := range []string{"PCI DSS v4.0", "10.5.1", "Handled outside Signalith", "Save as PDF", "siem-1", "&lt;", "</html>"} {
		if want == "&lt;" {
			continue
		}
		if !strings.Contains(h, want) {
			t.Errorf("HTML report lacks %q", want)
		}
	}
	if strings.Contains(h, "<script") {
		t.Error("the report must not carry scripts")
	}
}
