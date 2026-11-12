// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

// failCases refuses every new case.
type failCases struct{ cases.Store }

func (failCases) Create(context.Context, *cases.Case) error {
	return errors.New("cases index read-only")
}

func TestBuildCaseLinksTheStorysFindings(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	d := &Data{ID: "sample-1", CaseFocus: []string{"ws-fin-07"}}
	base := fixedNow.Add(-time.Hour)
	mk := func(id, sample, host string, at time.Time) {
		t.Helper()
		f := &findings.Finding{ID: id, Title: "t-" + id, Severity: "high", Status: findings.StatusNew,
			Entities: map[string]any{"host": host}, Sample: sample, Created: at, Updated: at}
		if err := l.Findings.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	mk("late", "sample-1", "ws-fin-07", base.Add(10*time.Minute))
	mk("early", "sample-1", "ws-fin-07", base)
	mk("other-host", "sample-1", "srv-01", base)
	mk("real", "", "ws-fin-07", base)

	ids := l.buildCase(ctx, d)
	if len(ids) != 1 {
		t.Fatalf("cases %v", ids)
	}
	c, err := l.Cases.Get(ctx, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if c.Title != CaseTitle || c.Sample != "sample-1" || c.Status != findings.StatusInProgress {
		t.Errorf("case %+v", c)
	}
	if len(c.Findings) != 2 || c.Findings[0] != "early" || c.Findings[1] != "late" {
		t.Errorf("findings %v, want early then late", c.Findings)
	}
	for id, want := range map[string]string{"early": c.ID, "late": c.ID, "other-host": "", "real": ""} {
		f, err := l.Findings.Get(ctx, id)
		if err != nil || f.CaseID != want {
			t.Errorf("%s case %q, want %q (%v)", id, f.CaseID, want, err)
		}
	}

	// Nothing to do without a focus, a store or matching findings.
	if got := l.buildCase(ctx, &Data{ID: "sample-1"}); got != nil {
		t.Errorf("no focus: %v", got)
	}
	if got := l.buildCase(ctx, &Data{ID: "sample-2", CaseFocus: []string{"ws-fin-07"}}); got != nil {
		t.Errorf("no findings: %v", got)
	}
	noCases := &Loader{Findings: l.Findings, Now: l.Now}
	if got := noCases.buildCase(ctx, d); got != nil {
		t.Errorf("no case store: %v", got)
	}

	// A case that cannot be written is logged and left out.
	var logs bytes.Buffer
	l2, _, _, _, _ := newTestLoader(t, t.TempDir())
	l2.Findings = l.Findings
	l2.Cases = failCases{cases.NewMemory()}
	l2.Log = slog.New(slog.NewTextHandler(&logs, nil))
	if got := l2.buildCase(ctx, d); got != nil || !strings.Contains(logs.String(), "could not create the investigation") {
		t.Errorf("failed create: %v, logs %s", got, logs.String())
	}
}

// freshScript answers KeepFresh's calls with set errors.
type freshScript struct {
	st        *State
	removeErr error
	loadErr   error
	loads     int
}

func (f *freshScript) Status(context.Context) (*State, error) { return f.st, nil }

func (f *freshScript) Load(context.Context, Size, ProgressFn) (*State, error) {
	f.loads++
	return nil, f.loadErr
}

func (f *freshScript) Remove(context.Context, ProgressFn) (*State, error) { return nil, f.removeErr }

func TestKeepFreshRetriesAndStops(t *testing.T) {
	ctx := context.Background()
	now := time.Now
	f := &freshScript{st: &State{ID: "s", Partial: true}, removeErr: ErrAlreadyLoaded}
	if wait, err := freshRound(ctx, f, FreshEvery, now); !errors.Is(err, ErrAlreadyLoaded) || wait != freshBusyWait || f.loads != 0 {
		t.Errorf("remove refused: wait %v err %v loads %d", wait, err, f.loads)
	}
	f = &freshScript{st: &State{ID: "s", Partial: true}, removeErr: errors.New("boom")}
	if wait, _ := freshRound(ctx, f, FreshEvery, now); wait != freshErrorWait {
		t.Errorf("remove error wait %v", wait)
	}

	// A failed round is logged, and the loop ends with its context.
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	f = &freshScript{loadErr: errors.New("disk full")}
	rctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { keepFresh(rctx, f, FreshEvery, now, log); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("keepFresh did not stop")
	}
	if !strings.Contains(logs.String(), "could not be loaded again") || f.loads != 1 {
		t.Errorf("loads %d logs %s", f.loads, logs.String())
	}

	// KeepFresh on a real loader whose context has ended returns at once
	// without logging.
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	logs.Reset()
	cctx, ccancel := context.WithCancel(ctx)
	ccancel()
	KeepFresh(cctx, l, FreshEvery, log)
	if strings.Contains(logs.String(), "could not") {
		t.Errorf("logged after the context ended: %s", logs.String())
	}
}

func TestCheckJobsServerEdgeCases(t *testing.T) {
	ctx := context.Background()
	if err := (&Loader{}).CheckJobsServer(ctx); err != nil {
		t.Errorf("no docs: %v", err)
	}
	for _, c := range []struct {
		name     string
		lease    any
		hb       any
		wantName string
	}{
		{"no lease", nil, nil, ""},
		{"unreadable lease", "not a lease", nil, ""},
		{"lease without holder", cluster.LeaseDoc{Kind: "lease", Job: "jobs"}, nil, ""},
		{"holder without heartbeat", cluster.LeaseDoc{Kind: "lease", Job: "jobs", Holder: "n_b"}, nil, ""},
		{"unreadable heartbeat", cluster.LeaseDoc{Kind: "lease", Job: "jobs", Holder: "n_b"}, "not a heartbeat", ""},
		{"name from the lease", cluster.LeaseDoc{Kind: "lease", Job: "jobs", Holder: "n_b", HolderName: "siem-b"},
			cluster.Heartbeat{Kind: "node", NodeID: "n_b", Version: "1.3.0", State: cluster.StateReady}, "siem-b"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, _, _, _, _ := newTestLoader(t, t.TempDir())
			docs := l.Docs.(*memDocs)
			if c.lease != nil {
				docs.set(t, cluster.LeaseDocID, c.lease)
			}
			if c.hb != nil {
				docs.set(t, cluster.NodeDocID("n_b"), c.hb)
			}
			err := l.CheckJobsServer(ctx)
			var old *OldJobsServerError
			switch {
			case c.wantName == "" && err != nil:
				t.Errorf("err %v", err)
			case c.wantName != "" && (!errors.As(err, &old) || old.Name != c.wantName || old.Version != "1.3.0"):
				t.Errorf("err %v", err)
			}
		})
	}
}

// badFindings is a findings store whose searches or deletes fail.
type badFindings struct {
	*findings.Memory
	search, del error
}

func (b *badFindings) Search(ctx context.Context, f findings.Filter) ([]*findings.Finding, int, error) {
	if b.search != nil {
		return nil, 0, b.search
	}
	return b.Memory.Search(ctx, f)
}

func (b *badFindings) Delete(ctx context.Context, id string) error {
	if b.del != nil {
		return b.del
	}
	return b.Memory.Delete(ctx, id)
}

// badCases is a cases store whose calls fail while their error is set.
type badCases struct {
	*cases.Memory
	search, findingSearch, del, modify error
}

func (b *badCases) Search(ctx context.Context, f cases.Filter) ([]*cases.Case, int, error) {
	if b.search != nil && f.Sample != nil {
		return nil, 0, b.search
	}
	if b.findingSearch != nil && f.FindingID != "" {
		return nil, 0, b.findingSearch
	}
	return b.Memory.Search(ctx, f)
}

func (b *badCases) Delete(ctx context.Context, id string) error {
	if b.del != nil {
		return b.del
	}
	return b.Memory.Delete(ctx, id)
}

func (b *badCases) Modify(ctx context.Context, id string, change func(*cases.Case) (bool, error)) (*cases.Case, error) {
	if b.modify != nil {
		return nil, b.modify
	}
	return b.Memory.Modify(ctx, id, change)
}

// syncFails is an intel store whose sync or delete fails.
type syncFails struct {
	fakeIntel
	sync, del error
}

func (s *syncFails) Sync(context.Context) (bool, error) { return false, s.sync }

func (s *syncFails) DeleteSource(ctx context.Context, source string) (int, error) {
	if s.del != nil {
		return 0, s.del
	}
	return s.fakeIntel.DeleteSource(ctx, source)
}

func TestRemoveHelpersReportFailures(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	boom := errors.New("index unavailable")

	// Findings.
	if _, err := l.sampleFindingIDs(ctx, ""); err == nil {
		t.Error("no load id accepted")
	}
	mem := findings.NewMemory()
	f := &findings.Finding{ID: "f1", Title: "t", Severity: "high", Status: findings.StatusNew, Sample: "s1", Created: fixedNow, Updated: fixedNow}
	if err := mem.Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	bf := &badFindings{Memory: mem, del: boom}
	l.Findings = bf
	if err := l.removeFindings(ctx, "s1", map[string]bool{"f1": true}); err == nil || !strings.Contains(err.Error(), "deleting sample finding") {
		t.Errorf("delete failure: %v", err)
	}
	bf.del, bf.search = nil, boom
	if err := l.removeFindings(ctx, "s1", map[string]bool{"f1": true}); !errors.Is(err, boom) {
		t.Errorf("search failure: %v", err)
	}
	bf.search = nil
	if err := l.removeFindings(ctx, "s1", nil); err != nil {
		t.Errorf("remove: %v", err)
	}
	if _, err := mem.Get(ctx, "f1"); err == nil {
		t.Error("the marked finding was left")
	}
	noFindings := &Loader{Cases: l.Cases}
	if err := noFindings.removeFindings(ctx, "s1", nil); err != nil {
		t.Errorf("no store: %v", err)
	}
	if ids, err := noFindings.sampleFindingIDs(ctx, "s1"); err != nil || len(ids) != 0 {
		t.Errorf("no store ids: %v %v", ids, err)
	}

	// Cases.
	cm := cases.NewMemory()
	own := &cases.Case{ID: "c-own", Title: "sample", Severity: "high", Status: "new", Sample: "s1", Created: fixedNow, Updated: fixedNow}
	user := &cases.Case{ID: "c-user", Title: "mine", Severity: "high", Status: "new", Created: fixedNow, Updated: fixedNow}
	if _, err := user.AddFinding(f, "ann", fixedNow); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*cases.Case{own, user} {
		if err := cm.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	bc := &badCases{Memory: cm}
	l.Cases = bc
	if err := l.removeCases(ctx, "", nil); err == nil {
		t.Error("no load id accepted")
	}
	for _, c := range []struct {
		name string
		set  func()
	}{
		{"search", func() { bc.search = boom }},
		{"delete", func() { bc.del = boom }},
		{"finding search", func() { bc.findingSearch = boom }},
		{"modify", func() { bc.modify = boom }},
	} {
		bc.search, bc.del, bc.findingSearch, bc.modify = nil, nil, nil, nil
		c.set()
		if err := l.removeCases(ctx, "s1", map[string]bool{"f1": true}); !errors.Is(err, boom) {
			t.Errorf("%s failure: %v", c.name, err)
		}
	}
	bc.search, bc.del, bc.findingSearch, bc.modify = nil, nil, nil, nil
	if err := l.removeCases(ctx, "s1", map[string]bool{"f1": true}); err != nil {
		t.Fatal(err)
	}
	if got, err := cm.Get(ctx, "c-user"); err != nil || len(got.Findings) != 0 {
		t.Errorf("user's case kept its sample finding: %+v %v", got, err)
	}
	if _, err := cm.Get(ctx, "c-own"); err == nil {
		t.Error("the sample's case was left")
	}
	noCases := &Loader{Findings: l.Findings}
	if err := noCases.removeCases(ctx, "s1", nil); err != nil {
		t.Errorf("no store: %v", err)
	}

	// Threat intel.
	r := &reporter{op: "remove"}
	si := &syncFails{sync: boom}
	l.Intel = si
	if err := l.removeOwn(ctx, r); err == nil || !strings.Contains(err.Error(), "reading threat intel") {
		t.Errorf("sync failure: %v", err)
	}
	si.sync, si.del = nil, boom
	if err := l.removeOwn(ctx, r); err == nil || !strings.Contains(err.Error(), "removing sample threat intel") {
		t.Errorf("delete failure: %v", err)
	}
	bare := Loader{}
	if err := bare.removeOwn(ctx, r); err != nil {
		t.Errorf("nothing to remove: %v", err)
	}
}

func TestPause(t *testing.T) {
	l := &Loader{}
	if err := l.pause(context.Background(), 20*time.Millisecond); err != nil {
		t.Errorf("pause: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.pause(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled pause: %v", err)
	}
}
