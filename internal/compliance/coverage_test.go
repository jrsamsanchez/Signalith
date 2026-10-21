// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

// Sign-in and process logs count for every computer Signalith knows, not
// for one that sends them (COMP-08).
func TestDataCoverageByComputer(t *testing.T) {
	auth := capByID(t, "data-auth")
	change := capByID(t, "data-change")
	snap := func(mod func(*Snapshot)) *Snapshot {
		s := &Snapshot{Now: now, Assets: -1, Data: map[string]DataSeen{
			"Authentication": {Count: 50, Last: now}, "Change": {Count: 5, Last: now}}}
		mod(s)
		return s
	}
	for _, c := range []struct {
		name   string
		snap   *Snapshot
		status Status
		text   string
	}{
		{"one of three", snap(func(s *Snapshot) {
			s.Computers = []string{"db-01", "web-01", "web-02"}
			s.DataHosts = map[string]map[string]bool{"Authentication": {"web-01": true}}
		}), Partial, "from 1 of the 3 computers that run the agent or osquery; none from db-01, web-02."},
		{"all", snap(func(s *Snapshot) {
			s.Computers = []string{"db-01", "web-01"}
			s.DataHosts = map[string]map[string]bool{"Authentication": {"web-01": true, "db-01": true, "fw-1": true}}
		}), Met, "from all 2 computers that run the agent or osquery."},
		{"unknown computers", snap(func(*Snapshot) {}), Met, "cannot tell whether every computer sends them"},
		{"unread", snap(func(s *Snapshot) { s.Computers, s.HostsErr = []string{"db-01"}, "search is not available" }), Partial, "could not be read: search is not available."},
	} {
		st, d := auth.eval(c.snap, nil)
		if st != c.status || !strings.Contains(d, c.text) {
			t.Errorf("%s: %s %q", c.name, st, d)
		}
	}
	// Account changes are rarer, so one host is enough there.
	s := snap(func(s *Snapshot) {
		s.Computers = []string{"db-01", "web-01"}
		s.DataHosts = map[string]map[string]bool{}
	})
	if st, d := change.eval(s, nil); st != Met {
		t.Errorf("change: %s %q", st, d)
	}
	// Process logs from either of their models count.
	s.Data["Script"] = DataSeen{Count: 3, Last: now}
	s.DataHosts = map[string]map[string]bool{"Endpoint": {"db-01": true}, "Script": {"web-01": true}}
	if st, d := capByID(t, "data-process").eval(s, nil); st != Met {
		t.Errorf("process: %s %q", st, d)
	}
}

func TestShortHost(t *testing.T) {
	for in, want := range map[string]string{"WEB-01.corp.example": "web-01", " db-01 ": "db-01", "10.0.0.5": "10.0.0.5", "fe80::1": "fe80::1"} {
		if got := ShortHost(in); got != want {
			t.Errorf("ShortHost(%q) = %q", in, got)
		}
	}
}

// A check for one platform shows nothing about hosts on another, and
// checks that error everywhere are not "waiting" (COMP-09).
func TestChecksFollowPlatforms(t *testing.T) {
	win := []CheckStat{{ID: "w1", Title: "TLS 1.2 only", Platform: "windows", Refs: []string{"SC-8"}}}
	snap := func(cs []CheckStat, platforms map[string]int) *Snapshot {
		n := 0
		for _, v := range platforms {
			n += v
		}
		return &Snapshot{Now: now, Assets: -1, Checks: cs, Hosts: n, Platforms: platforms,
			HostsSeen: [2]time.Time{now.Add(-3 * time.Hour), now.Add(-time.Minute)}}
	}
	ctl := &controlCtx{control: Control{ID: "x", NIST: []string{"SC-8"}}}
	for _, c := range []struct {
		name   string
		snap   *Snapshot
		status Status
		text   string
	}{
		{"linux only", snap(win, map[string]int{"linux": 3}), Missing, "The checks for this run only on Windows, and none of your hosts does."},
		{"mixed", snap([]CheckStat{{ID: "w1", Title: "TLS", Platform: "windows", Refs: []string{"SC-8"}, Pass: 1}}, map[string]int{"windows": 1, "linux": 2}),
			Partial, "No check covers your 2 Linux hosts."},
		{"errors", snap([]CheckStat{{ID: "w1", Title: "TLS", Platform: "windows", Refs: []string{"SC-8"}, Error: 2}}, map[string]int{"windows": 2}),
			Missing, "but no host could run it. 2 results could not be read on the host."},
		{"reported", snap([]CheckStat{{ID: "w1", Title: "TLS", Platform: "windows", Refs: []string{"SC-8"}, Pass: 2}}, map[string]int{"windows": 2}),
			Met, "Hosts last reported between 3 hours ago and just now."},
	} {
		st, d := evalChecks(c.snap, ctl)
		if st != c.status || !strings.Contains(d, c.text) {
			t.Errorf("%s: %s %q", c.name, st, d)
		}
	}
}

// The report says which mapping it used, how it measured and who
// exported it (COMP-11).
func TestExportProvenance(t *testing.T) {
	rep := Evaluate(full(), nil)
	f, _ := rep.Find("pci-dss")
	x := Export{Server: "siem-1", Version: "0.3.2", By: "alice"}
	var b bytes.Buffer
	if err := WriteCSV(&b, rep, f, x); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&b).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	head, row := recs[0], recs[1]
	got := map[string]string{}
	for i, h := range head {
		got[h] = row[i]
	}
	if got["mapping"] != MappingVersion() || got["exported_by"] != "alice" || got["signalith_version"] != "0.3.2" || len(MappingVersion()) != 12 {
		t.Errorf("csv provenance %v", got)
	}
	b.Reset()
	if err := WriteHTML(&b, rep, f, x); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Mapping " + MappingVersion(), "Exported by alice", "How it was measured:", "in the last 7 days"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q", want)
		}
	}
}
