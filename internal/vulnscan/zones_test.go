package vulnscan

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// countingDocs counts searches, to show what an idle server asks.
type countingDocs struct {
	*endpoint.MemoryDocs
	searches atomic.Int32
}

func (c *countingDocs) SearchDocs(ctx context.Context, index string, q map[string]any) ([]store.Doc, error) {
	c.searches.Add(1)
	return c.MemoryDocs.SearchDocs(ctx, index, q)
}

// zoneScanners are two servers sharing one OpenSearch: a runs the
// background jobs, b is a scanner in another network zone.
func zoneScanners(t *testing.T) (a, b *Scanner, aArgs, bArgs *[]string, docs *countingDocs) {
	t.Helper()
	docs = &countingDocs{MemoryDocs: endpoint.NewMemoryDocs()}
	aArgs, bArgs = new([]string), new([]string)
	mk := func(name, node string, leader bool, args *[]string) *Scanner {
		return &Scanner{Store: NewStore(docs, "signalith"), NVD: &NVD{URL: "http://127.0.0.1:1", Gap: time.Millisecond}, Events: &events{},
			Server: name, NodeID: node, Leader: func() bool { return leader }, Runner: fakeNmap(nmapXML, args), Loc: time.UTC,
			Checker: &Checker{FindNmap: func() string { return "/usr/bin/nmap" }}}
	}
	return mk("siem-a", "n_aaaa", true, aArgs), mk("siem-b", "n_bbbb", false, bArgs), aArgs, bArgs, docs
}

func TestZoneScannerRunsItsNetworks(t *testing.T) {
	a, b, aArgs, bArgs, _ := zoneScanners(t)
	ctx := context.Background()
	plant := target("10.20.0.0/24")
	plant.ID, plant.Name, plant.Scanner, plant.Schedule = "plant", "Plant floor", "n_bbbb", Schedule{Every: Manual}
	office := target("192.0.2.0/24")
	office.Schedule = Schedule{Every: Manual}
	set, err := a.Store.SaveSettings(ctx, Settings{Targets: []Target{office, plant}}, store.Version{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := a.Store.NewScan(ctx, set.Targets[1], TriggerManual, "alice")
	// The server running the jobs leaves the plant network to its scanner.
	if err := a.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if *aArgs != nil {
		t.Fatalf("the job server scanned the plant: %q", *aArgs)
	}
	if err := b.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ := a.Store.Scan(ctx, sc.ID)
	if got.State != StateDone || got.Scanner != "siem-b" || got.ScannerID != "n_bbbb" || (*bArgs)[len(*bArgs)-1] != "10.20.0.0/24" {
		t.Fatalf("plant scan = %+v, args %q", got, *bArgs)
	}
	hosts, _ := a.Store.Hosts(ctx)
	if len(hosts) != 2 || hosts[0].TargetID != "plant" {
		t.Errorf("hosts = %+v", hosts)
	}
	// A network with no scanner of its own is the job server's.
	*bArgs = nil
	sc2, _ := a.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err := b.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if *bArgs != nil {
		t.Fatalf("the zone scanner scanned the office: %q", *bArgs)
	}
	if err := a.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ = a.Store.Scan(ctx, sc2.ID)
	if got.State != StateDone || got.ScannerID != "n_aaaa" {
		t.Errorf("office scan = %+v", got)
	}
}

func TestZoneScannerSchedulesItsOwn(t *testing.T) {
	a, b, aArgs, _, _ := zoneScanners(t)
	ctx := context.Background()
	now := time.Now().UTC()
	plant := target("10.20.0.0/24")
	plant.Scanner, plant.Schedule = "n_bbbb", Schedule{Every: Daily, Hour: now.Hour()}
	if _, err := a.Store.SaveSettings(ctx, Settings{Targets: []Target{plant}}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	set, v, _ := a.Store.Settings(ctx)
	set.Targets[0].CreatedAt = now.Add(-25 * time.Hour)
	if _, err := a.Store.Docs.PutIf(ctx, a.Store.Index, kindSettings, settingsDoc{Kind: kindSettings, Settings: set}, v, true); err != nil {
		t.Fatal(err)
	}
	if err := a.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if scans, _ := a.Store.Scans(ctx); len(scans) != 0 || *aArgs != nil {
		t.Fatalf("the job server queued the zone's scan: %+v", scans)
	}
	b.Store.settings = nil // past the cache
	for range 2 {
		if err := b.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	scans, _ := a.Store.Scans(ctx)
	if len(scans) != 1 || scans[0].Trigger != TriggerSchedule || scans[0].State != StateDone || scans[0].ScannerID != "n_bbbb" {
		t.Fatalf("scans = %+v", scans)
	}
}

func TestIdleScannerAsksLittle(t *testing.T) {
	a, b, _, _, docs := zoneScanners(t)
	ctx := context.Background()
	if _, err := a.Store.SaveSettings(ctx, Settings{Targets: []Target{target("192.0.2.0/24")}}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	before := docs.searches.Load()
	for range 3 {
		if err := b.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := docs.searches.Load() - before; n != 0 {
		t.Errorf("a server scanning no network searched %d times", n)
	}
}

func TestUnclaimedScanFails(t *testing.T) {
	a, _, _, _, _ := zoneScanners(t)
	ctx := context.Background()
	plant := target("10.20.0.0/24")
	plant.Scanner = "n_gone"
	set, _ := a.Store.SaveSettings(ctx, Settings{Targets: []Target{plant}}, store.Version{}, "alice")
	old := &Scan{ID: "old", TargetID: plant.ID, TargetName: plant.Name, State: StateQueued, Trigger: TriggerManual, CreatedAt: time.Now().Add(-OfflineAfter - time.Minute)}
	if _, err := a.Store.Docs.Create(ctx, a.Store.Index, scanDocID(old.ID), scanDoc{kindScan, old}, true); err != nil {
		t.Fatal(err)
	}
	fresh, _ := a.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	// The scanner checked itself lately: its scans wait for it.
	if err := a.Store.PutReport(ctx, &Report{Server: "siem-gone", NodeID: "n_gone", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := a.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := a.Store.Scan(ctx, "old"); got.State != StateQueued {
		t.Fatalf("waiting scan of a live scanner = %+v", got)
	}
	// It went quiet: the old scan fails, the new one still waits.
	if err := a.Store.PutReport(ctx, &Report{Server: "siem-gone", NodeID: "n_gone", At: time.Now().Add(-time.Hour).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := a.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ := a.Store.Scan(ctx, "old")
	if got.State != StateFailed || !strings.Contains(got.Error, "siem-gone") {
		t.Errorf("old scan = %+v", got)
	}
	if got, _, _ := a.Store.Scan(ctx, fresh.ID); got.State != StateQueued {
		t.Errorf("fresh scan = %+v", got)
	}
}

func TestClaimOnce(t *testing.T) {
	a, b, _, _, _ := zoneScanners(t)
	ctx := context.Background()
	sc, _ := a.Store.NewScan(ctx, target("192.0.2.1"), TriggerManual, "alice")
	if !a.claim(ctx, sc) {
		t.Fatal("first claim refused")
	}
	again, _, _ := b.Store.Scan(ctx, sc.ID)
	if b.claim(ctx, again) {
		t.Fatal("a running scan was claimed again")
	}
	if got, _, _ := a.Store.Scan(ctx, sc.ID); got.State != StateRunning || got.ScannerID != "n_aaaa" {
		t.Errorf("scan = %+v", got)
	}
}

func TestScannerReportsByNode(t *testing.T) {
	a, b, _, _, _ := zoneScanners(t)
	ctx := context.Background()
	plant := target("10.20.0.0/24")
	plant.Scanner = "n_bbbb"
	if _, err := a.Store.SaveSettings(ctx, Settings{Targets: []Target{target("192.0.2.0/24"), {ID: "plant", Name: "Plant", Networks: plant.Networks, Scanner: "n_bbbb", Enabled: true}}}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Scanner{a, b} {
		s.Checker.Version = func(context.Context, string) (string, error) { return "7.94", nil }
		s.Checker.SelfTest = func(context.Context, string) error { return nil }
		s.Checker.Reach = func(_ context.Context, e string) Route {
			return Route{Entry: e, From: netip.MustParseAddr("10.0.0.5")}
		}
	}
	a.CheckNow(ctx)
	rb := b.CheckNow(ctx)
	reports, _ := a.Store.Reports(ctx)
	if len(reports) != 2 {
		t.Fatalf("reports = %+v", reports)
	}
	var reach *Check
	for i, c := range rb.Checks {
		if c.ID == "reach:plant" {
			reach = &rb.Checks[i]
		}
		if c.ID == "reach:office" {
			t.Errorf("b checks a network it does not scan")
		}
	}
	if rb.NodeID != "n_bbbb" || reach == nil || reach.State != CheckInfo || !strings.Contains(reach.Detail, "from 10.0.0.5: 10.20.0.0/24") ||
		!strings.Contains(strings.Join(reach.Fix, " "), "Scanned by") {
		t.Errorf("b report = %+v", rb)
	}
}

func TestProbeAddr(t *testing.T) {
	for _, c := range []struct{ in, addr, pfx string }{
		{"192.0.2.7", "192.0.2.7", "192.0.2.7/32"},
		{"192.0.2.0/24", "192.0.2.1", "192.0.2.0/24"},
		{"192.0.2.10-20", "192.0.2.10", "192.0.2.0/27"},
		{"192.0.2.0-255", "192.0.2.1", "192.0.2.0/24"},
		{"2001:db8::/120", "2001:db8::1", "2001:db8::/120"},
	} {
		a, p, ok := probeAddr(c.in)
		if !ok || a.String() != c.addr || p.String() != c.pfx {
			t.Errorf("%s: %v %v %v", c.in, a, p, ok)
		}
	}
	if _, _, ok := probeAddr("fileserver.corp.example"); ok {
		t.Error("a host name has an address")
	}
	if r := LocalRoute(context.Background(), "127.0.0.1"); !r.Direct {
		t.Errorf("loopback = %+v", r)
	}
}

// A scan cut short because its server restarts in place, or stops, goes
// back in the queue and runs again on the server's next scanner.
func TestRestartRequeuesScan(t *testing.T) {
	a, b, _, bArgs, _ := zoneScanners(t)
	ctx := context.Background()
	plant := target("10.20.0.0/24")
	plant.ID, plant.Name, plant.Scanner, plant.Schedule = "plant", "Plant floor", "n_bbbb", Schedule{Every: Manual}
	set, err := a.Store.SaveSettings(ctx, Settings{Targets: []Target{plant}}, store.Version{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := a.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	started := make(chan struct{})
	b.Runner = &Runner{Path: "/usr/bin/nmap", Exec: func(ctx context.Context, path string, a []string) (io.ReadCloser, func() ([]byte, error), error) {
		close(started)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}}
	runCtx, restart := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- b.Step(runCtx) }()
	<-started
	restart()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, _, _ := a.Store.Scan(ctx, sc.ID)
	if got.State != StateQueued || got.ScannerID != "" || got.Scanner != "" || !got.StartedAt.IsZero() {
		t.Fatalf("scan after the restart = %+v", got)
	}
	// The scanner that comes back runs it.
	again := &Scanner{Store: b.Store, NVD: b.NVD, Events: b.Events, Server: "siem-b", NodeID: "n_bbbb", Leader: b.Leader,
		Runner: fakeNmap(nmapXML, bArgs), Loc: time.UTC, Checker: b.Checker}
	if err := again.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _, _ = a.Store.Scan(ctx, sc.ID); got.State != StateDone || got.ScannerID != "n_bbbb" {
		t.Errorf("scan after it ran again = %+v", got)
	}
}

func TestRequeueOnlyOwnRunningScan(t *testing.T) {
	a, b, _, _, _ := zoneScanners(t)
	ctx := context.Background()
	sc, _ := a.Store.NewScan(ctx, target("192.0.2.1"), TriggerManual, "alice")
	if ok, _ := a.Store.RequeueScan(ctx, sc.ID, "n_aaaa"); ok {
		t.Fatal("a queued scan was requeued")
	}
	if !a.claim(ctx, sc) {
		t.Fatal("claim refused")
	}
	if ok, _ := b.Store.RequeueScan(ctx, sc.ID, "n_bbbb"); ok {
		t.Fatal("another server's scan was requeued")
	}
	if err := a.Store.UpdateScan(ctx, sc.ID, map[string]any{"stop": true}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := a.Store.RequeueScan(ctx, sc.ID, "n_aaaa"); ok {
		t.Fatal("a stopped scan was requeued")
	}
}
