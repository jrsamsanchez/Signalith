// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// searchFails is a backend whose searches fail.
type searchFails struct{ *fakeOS }

func (searchFails) Search(context.Context, string, map[string]any) (map[string]any, error) {
	return nil, errors.New("search down")
}

// The compliance snapshot reads the evidence each part keeps: plain
// syslog listeners, notification rules and what they delivered, response
// runs that worked, retention kept longer than the default and the
// oldest day held, rated assets and the computers agents report.
func TestComplianceSnapshotEvidence(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	ctx := context.Background()
	now := time.Now().UTC()

	notes := &notify.Manager{}
	on := true
	if _, err := notes.Save(notify.Input{
		Channels: []notify.ChannelInput{{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T/B/x"}},
		Rules:    []notify.RuleInput{{ID: "all", Name: "All", Enabled: &on, Channels: []string{"soc"}, MinUrgency: "low"}},
	}); err != nil {
		t.Fatal(err)
	}
	deliveries := notify.NewMemory()
	for i, st := range []string{notify.StatusSent, notify.StatusSent, notify.StatusFailed} {
		d := &notify.Delivery{ID: "d" + string(rune('0'+i)), Kind: "finding", FindingID: "f" + string(rune('0'+i)), Channel: "soc",
			Status: st, Created: now.Add(-time.Duration(3-i) * time.Minute), Updated: now.Add(-time.Duration(3-i) * time.Minute)}
		if _, err := deliveries.Claim(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	runs := &respond.Memory{}
	if err := runs.Put(ctx, &respond.Run{ID: "r1", Action: "block", Status: respond.StatusSucceeded, Started: now.Add(-time.Hour)}, false); err != nil {
		t.Fatal(err)
	}
	if err := runs.Put(ctx, &respond.Run{ID: "r2", Action: "block", Status: respond.StatusFailed, Started: now.Add(-time.Hour)}, false); err != nil {
		t.Fatal(err)
	}
	mem := retention.NewMemory()
	mem.DiskTotal, mem.DiskBase = 100*retention.GB, 30*retention.GB
	oldest := now.AddDate(0, 0, -20)
	for d := oldest; !d.After(now); d = d.AddDate(0, 0, 1) {
		mem.AddIndex(retention.IndexName("signalith", "endpoint", d), retention.GB/10)
	}
	dir := t.TempDir()
	lists, err := assets.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lists.SetAssets(assets.MarshalAssets([]assets.Asset{{Host: []string{"web1"}, Owner: "web team"}, {Host: []string{"db1"}}})); err != nil {
		t.Fatal(err)
	}
	if _, err := lists.SetIdentities(assets.MarshalIdentities([]assets.Identity{{Identity: []string{"ceo"}, Priority: "critical"}, {Identity: []string{"intern"}}})); err != nil {
		t.Fatal(err)
	}
	inv := &agentinv.Inventory{Server: func() string { return "siem-a" }}
	inv.Note(agentinv.Contact{Name: "web1.corp.example.com", Address: "192.0.2.10", Events: 5})
	inv.Note(agentinv.Contact{Name: "db1", Address: "192.0.2.11", Events: 5})

	var srv *Server
	newTestServerWith(t, func(s *Server) {
		srv = s
		s.Config.Syslog.UDP = "0.0.0.0:514"
		s.Config.Syslog.TCP = "0.0.0.0:601"
		s.Notify = &Notify{Settings: notes, Deliveries: deliveries, Sender: &notify.Senders{}}
		s.Respond = &respond.Runner{Actions: &respond.Actions{File: filepath.Join(dir, "response.yaml"), Log: s.Log}, Store: runs, Log: s.Log}
		s.Retention = &retention.Manager{
			Cluster: mem, Prefix: "signalith",
			Config: retention.Config{Default: &retention.Policy{KeepDays: 30},
				Policies: map[string]retention.Policy{"network_traffic": {KeepDays: 400}, "authentication": {KeepDays: 0}, "endpoint": {KeepDays: 7}}},
			Store:       retention.NewStore(filepath.Join(dir, "retention.yaml")),
			Archive:     &retention.Archive{Dir: filepath.Join(dir, "archive")},
			HistoryFile: filepath.Join(dir, "retention_history.json"),
		}
		s.Assets = lists
		s.Engine.Assets = lists
		s.Agents = inv
	})
	snap := srv.complianceSnapshot(ctx, httptest.NewRequest("GET", "/api/compliance", nil))

	if strings.Join(snap.PlainSyslog, ",") != "UDP 0.0.0.0:514,TCP 0.0.0.0:601" {
		t.Errorf("plain syslog %v", snap.PlainSyslog)
	}
	if n := snap.Notify; n == nil || n.Channels != 1 || n.Rules != 1 || n.Unread || n.Sent != 2 || n.Failing != 1 {
		t.Errorf("notify %+v", snap.Notify)
	}
	if rs := snap.Response; rs == nil || rs.Ran != 1 {
		t.Errorf("response %+v", snap.Response)
	}
	rt := snap.Retention
	if rt == nil {
		t.Fatal("no retention")
	}
	if !slices.ContainsFunc(rt.Longer, func(s string) bool { return strings.Contains(s, "(400 days)") }) ||
		!slices.ContainsFunc(rt.Longer, func(s string) bool { return strings.Contains(s, "kept forever") }) {
		t.Errorf("longer %v", rt.Longer)
	}
	if !slices.ContainsFunc(rt.Shorter, func(s string) bool { return strings.Contains(s, "(7 days)") }) {
		t.Errorf("shorter %v", rt.Shorter)
	}
	if !rt.OldestRead || rt.Oldest.IsZero() || rt.Oldest.After(oldest.Add(24*time.Hour)) {
		t.Errorf("oldest %v read %v", rt.Oldest, rt.OldestRead)
	}
	if snap.Assets != 4 || snap.AssetsRated != 2 {
		t.Errorf("assets %d rated %d", snap.Assets, snap.AssetsRated)
	}
	if strings.Join(snap.Computers, ",") != "db1,web1" {
		t.Errorf("computers %v", snap.Computers)
	}
}

// When the searches fail, the snapshot says so instead of showing no
// data, and the computers agents report are kept.
func TestComplianceSnapshotSearchFails(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	inv := &agentinv.Inventory{Server: func() string { return "siem-a" }}
	inv.Note(agentinv.Contact{Name: "web1", Address: "192.0.2.10", Events: 1})
	var srv *Server
	newTestServerWith(t, func(s *Server) {
		srv = s
		bad := searchFails{&fakeOS{}}
		s.Engine = &search.Engine{Store: bad, Assets: s.Assets}
		s.Agents = inv
	})
	snap := srv.complianceSnapshot(context.Background(), httptest.NewRequest("GET", "/api/compliance", nil))
	if snap.DataErr == "" || snap.HostsErr != "the search failed" || len(snap.Computers) != 1 {
		t.Errorf("data %q hosts %q computers %v", snap.DataErr, snap.HostsErr, snap.Computers)
	}
	// Without search at all, both say it is not available.
	srv.Engine = nil
	snap = srv.complianceSnapshot(context.Background(), nil)
	if snap.DataErr != "search is not available" || snap.HostsErr != "search is not available" {
		t.Errorf("no engine: data %q hosts %q", snap.DataErr, snap.HostsErr)
	}
}
