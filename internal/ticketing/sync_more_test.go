// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// dueLinks is a Memory whose Due, ForCases and Update fail while their
// error is set.
type dueLinks struct {
	*Memory
	due, forCases, update error
}

func (d *dueLinks) Due(ctx context.Context) ([]Stored, error) {
	if d.due != nil {
		return nil, d.due
	}
	return d.Memory.Due(ctx)
}

func (d *dueLinks) ForCases(ctx context.Context, ids []string) ([]Stored, error) {
	if d.forCases != nil {
		return nil, d.forCases
	}
	return d.Memory.ForCases(ctx, ids)
}

func (d *dueLinks) Update(ctx context.Context, l *Link, v store.Version) (store.Version, error) {
	if d.update != nil {
		return store.Version{}, d.update
	}
	return d.Memory.Update(ctx, l, v)
}

// searchFails is a cases store whose searches fail while fail is set.
type searchFails struct {
	*cases.Memory
	fail error
	get  error
}

func (s *searchFails) Search(ctx context.Context, f cases.Filter) ([]*cases.Case, int, error) {
	if s.fail != nil {
		return nil, 0, s.fail
	}
	return s.Memory.Search(ctx, f)
}

func (s *searchFails) Get(ctx context.Context, id string) (*cases.Case, error) {
	if s.get != nil {
		return nil, s.get
	}
	return s.Memory.Get(ctx, id)
}

func (e *env) captureLog() *logBuf {
	logs := &logBuf{}
	e.svc.Log = slog.New(slog.NewTextHandler(logs, nil))
	return logs
}

func TestPassUnreadableFile(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	logs := e.captureLog()
	good := e.svc.Settings
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("connections: [::"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.svc.Settings = &Manager{File: bad}
	e.pass()
	e.pass()
	if n := strings.Count(logs.String(), "ticketing does not sync until the ticketing file is fixed"); n != 1 {
		t.Errorf("logged %d times: %s", n, logs.String())
	}
	e.svc.Settings = good
	e.pass()
	if !strings.Contains(logs.String(), "ticketing works again") {
		t.Errorf("recovery not logged: %s", logs.String())
	}
	// Not allowed: nothing happens.
	e.svc.Allowed = func() bool { return false }
	e.svc.Settings = &Manager{File: bad}
	before := logs.String()
	e.pass()
	if logs.String() != before {
		t.Error("a pass ran while not allowed")
	}
}

func TestPassLinksUnreadable(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	logs := e.captureLog()
	e.svc.Links = &dueLinks{Memory: e.links, due: errors.New("links index unavailable")}
	e.pass()
	if !strings.Contains(logs.String(), "ticketing could not read its links from OpenSearch") {
		t.Errorf("logs %s", logs.String())
	}
}

func TestPendingLinkOfRemovedConnectionFails(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	c := e.newCase("case-1", "Brute force", "high")
	gone := Connection{ID: "gone", Name: "Old Jira", Type: TypeJira}
	ctx := context.Background()
	if _, err := e.links.Create(ctx, newLink(gone, c, "ann", false, StatePending, e.clk.Now())); err != nil {
		t.Fatal(err)
	}
	// A creating link of the removed connection is left alone.
	c2 := e.newCase("case-2", "Other", "high")
	if _, err := e.links.Create(ctx, newLink(gone, c2, "ann", true, StateCreating, e.clk.Now())); err != nil {
		t.Fatal(err)
	}
	e.pass()
	st := e.link("gone", "case-1")
	if st.State != StateFailed || !strings.Contains(st.Error, "connection was removed") {
		t.Errorf("pending: %+v", st.Link)
	}
	if st := e.link("gone", "case-2"); st.State != StateCreating {
		t.Errorf("creating: %+v", st.Link)
	}
}

func TestAutoCreateCaseSearchFails(t *testing.T) {
	e, f := autoEnv(t)
	logs := e.captureLog()
	sf := &searchFails{Memory: e.cases, fail: errors.New("cases index unavailable")}
	e.svc.Cases = sf
	e.newCase("c1", "Brute force", "critical")
	e.pass()
	if n := f.count("POST /api/now/table/incident"); n != 0 {
		t.Errorf("%d tickets opened", n)
	}
	if !strings.Contains(logs.String(), "ticketing could not search the cases") {
		t.Errorf("logs %s", logs.String())
	}
	// Once the search works, the ticket is opened.
	sf.fail = nil
	e.pass()
	if st := e.link("sn", "c1"); st.State != StateLinked {
		t.Errorf("after recovery: %+v", st.Link)
	}
	// A failed link write means no ticket either.
	e.newCase("c2", "Second", "critical")
	e.svc.Links = &failLinks{Memory: e.links, create: errors.New("links write refused")}
	e.pass()
	if n := f.count("POST /api/now/table/incident"); n != 1 {
		t.Errorf("%d tickets opened, want 1", n)
	}
}

func TestSyncDeletedCaseAndMissingConnection(t *testing.T) {
	e, f := autoEnv(t)
	logs := e.captureLog()
	e.newCase("c1", "Brute force", "critical")
	e.pass()
	if st := e.link("sn", "c1"); st.State != StateLinked || f.count("POST /api/now/table/incident") != 1 {
		t.Fatalf("not linked: %+v", st.Link)
	}
	// The case is deleted: the next full pass stops keeping the ticket
	// in step.
	if err := e.cases.Delete(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	e.clk.add(fullEvery)
	e.pass()
	st := e.link("sn", "c1")
	if st.Active || !strings.Contains(st.Error, "case was deleted") {
		t.Errorf("deleted case: %+v", st.Link)
	}

	// A linked ticket of a connection this server does not have.
	other := Connection{ID: "elsewhere", Name: "Other desk", Type: TypeServiceNow}
	c2 := e.newCase("c2", "Other", "low")
	l := newLink(other, c2, "ann", false, StateLinked, e.clk.Now())
	l.Active, l.Key = true, "INC9"
	if _, err := e.links.Create(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	e.pass()
	if !strings.Contains(logs.String(), "some tickets belong to a connection that is not on this server's Ticketing page") {
		t.Errorf("logs %s", logs.String())
	}
}

func TestSyncCaseReadAndLinkWriteFailures(t *testing.T) {
	e, _ := autoEnv(t)
	logs := e.captureLog()
	e.newCase("c1", "Brute force", "critical")
	e.pass()
	sf := &searchFails{Memory: e.cases, get: errors.New("cases index unavailable")}
	e.svc.Cases = sf
	e.clk.add(fullEvery)
	e.pass()
	if !strings.Contains(logs.String(), "ticketing could not read a case") {
		t.Errorf("logs %s", logs.String())
	}
	// A deleted case whose link cannot be written is logged.
	sf.get = cases.ErrNotFound
	e.svc.Links = &dueLinks{Memory: e.links, update: errors.New("links write refused")}
	e.clk.add(fullEvery)
	e.pass()
	if !strings.Contains(logs.String(), "could not record what was synced") {
		t.Errorf("logs %s", logs.String())
	}
	// Changed cases whose links cannot be read are logged.
	sf.get = nil
	e.svc.Links = &dueLinks{Memory: e.links, forCases: errors.New("links search refused")}
	e.change("c1", cases.Update{Comment: "more"})
	e.pass()
	if !strings.Contains(logs.String(), "ticketing could not read its links from OpenSearch") {
		t.Errorf("logs %s", logs.String())
	}
	// Changed cases that cannot be searched are logged.
	sf.fail = errors.New("cases search refused")
	e.svc.Links = e.links
	e.pass()
	if !strings.Contains(logs.String(), "ticketing could not search the cases") {
		t.Errorf("logs %s", logs.String())
	}
}

func TestRunStopsWithContext(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { e.svc.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
