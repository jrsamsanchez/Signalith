// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// failLinks is a Memory whose writes fail when their error is set.
type failLinks struct {
	*Memory
	mu               sync.Mutex
	create, get, upd error
}

func (f *failLinks) errs() (c, g, u error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.create, f.get, f.upd
}

func (f *failLinks) Create(ctx context.Context, l *Link) (store.Version, error) {
	if c, _, _ := f.errs(); c != nil {
		return store.Version{}, c
	}
	return f.Memory.Create(ctx, l)
}

func (f *failLinks) Get(ctx context.Context, id string) (Stored, error) {
	if _, g, _ := f.errs(); g != nil {
		return Stored{}, g
	}
	return f.Memory.Get(ctx, id)
}

func (f *failLinks) Update(ctx context.Context, l *Link, v store.Version) (store.Version, error) {
	if _, _, u := f.errs(); u != nil {
		return store.Version{}, u
	}
	return f.Memory.Update(ctx, l, v)
}

// mappedCases is a cases store that maps its tickets field on demand.
type mappedCases struct {
	*cases.Memory
	mu    sync.Mutex
	fail  error
	calls int
}

func (m *mappedCases) EnsureTicketsField(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.fail
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestRequestAndClaim(t *testing.T) {
	ctx := context.Background()
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t, jiraCloudConn(f))
	logs := &logBuf{}
	e.svc.Log = slog.New(slog.NewTextHandler(logs, nil))
	e.newCase("case-1", "Brute force", "high")

	if _, err := e.svc.Request(ctx, "case-1", "nope", "ann"); !errors.Is(err, ErrNoConnection) {
		t.Errorf("no connection = %v", err)
	}
	if _, err := e.svc.Request(ctx, "missing", "jc", "ann"); !errors.Is(err, cases.ErrNotFound) {
		t.Errorf("no case = %v", err)
	}
	l, err := e.svc.Request(ctx, "case-1", "jc", "ann")
	if err != nil || l.State != StatePending || !strings.Contains(logs.String(), "asked for a ticket") {
		t.Fatalf("request = %+v %v", l, err)
	}
	if _, err := e.svc.Request(ctx, "case-1", "jc", "bob"); !errors.Is(err, ErrInProgress) {
		t.Errorf("second request = %v", err)
	}
	// One left pending too long may be asked for again.
	e.clk.add(staleAfter + time.Minute)
	l, err = e.svc.Request(ctx, "case-1", "jc", "bob")
	if err != nil || l.CreatedBy != "bob" || l.MayExist {
		t.Fatalf("stale request = %+v %v", l, err)
	}
	links, err := e.svc.LinksOf(ctx, "case-1")
	if err != nil || len(links) != 1 || links[0].CreatedBy != "bob" {
		t.Errorf("links = %+v %v", links, err)
	}

	// A linked link whose case lost its ticket is still linked.
	st := e.link("jc", "case-1")
	st.State, st.Key, st.System = StateLinked, "SEC-9", TypeJira
	if _, err := e.links.Update(ctx, &st.Link, st.Version); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.Create(ctx, "case-1", "jc", "ann")
	var le *LinkedError
	if !errors.As(err, &le) || err.Error() != "this case already has a ticket in Jira: SEC-9" {
		t.Errorf("linked = %v", err)
	}

	// The store fails.
	fl := &failLinks{Memory: NewMemory()}
	e.svc.Links = fl
	boom := errors.New("opensearch down")
	fl.create = boom
	if _, err := e.svc.Request(ctx, "case-1", "jc", "ann"); !errors.Is(err, boom) {
		t.Errorf("create = %v", err)
	}
	fl.create = nil
	if _, err := e.svc.Request(ctx, "case-1", "jc", "ann"); err != nil {
		t.Fatal(err)
	}
	e.clk.add(staleAfter + time.Minute)
	fl.get = boom
	if _, err := e.svc.Create(ctx, "case-1", "jc", "ann"); !errors.Is(err, boom) {
		t.Errorf("get = %v", err)
	}
	fl.get, fl.upd = nil, store.ErrConflict
	if _, err := e.svc.Create(ctx, "case-1", "jc", "ann"); !errors.Is(err, ErrInProgress) {
		t.Errorf("conflict = %v", err)
	}
	fl.upd = boom
	if _, err := e.svc.Create(ctx, "case-1", "jc", "ann"); !errors.Is(err, boom) {
		t.Errorf("update = %v", err)
	}
}

func TestOpenRecordsProblems(t *testing.T) {
	ctx := context.Background()
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t, jiraCloudConn(f))
	logs := &logBuf{}
	e.svc.Log = slog.New(slog.NewTextHandler(logs, nil))
	set, err := e.svc.Settings.Settings()
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := set.Connection("jc")

	// The case is deleted while its ticket is being opened.
	c := e.newCase("case-1", "Brute force", "high")
	st, err := e.svc.claim(ctx, newLink(conn, c, "ann", false, StateCreating, e.clk.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.cases.Delete(ctx, "case-1"); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.open(ctx, conn, st)
	var te *Error
	if !errors.As(err, &te) || te.Msg != "The case was deleted." {
		t.Errorf("deleted case = %v", err)
	}
	if got := e.link("jc", "case-1"); got.State != StateFailed || !got.MayExist || got.Error != "The case was deleted." {
		t.Errorf("link = %+v", got)
	}

	// The link cannot be written: the ticket is still opened and added to
	// the case, and the problem logged.
	mc := &mappedCases{Memory: e.cases, fail: errors.New("mapping refused")}
	e.svc.Cases = mc
	c = e.newCase("case-2", "Malware", "medium")
	fl := &failLinks{Memory: e.links}
	e.svc.Links = fl
	st, err = e.svc.claim(ctx, newLink(conn, c, "", false, StateCreating, e.clk.Now()))
	if err != nil {
		t.Fatal(err)
	}
	fl.upd = errors.New("opensearch down")
	l, err := e.svc.open(ctx, conn, st)
	if err != nil || l.Key == "" {
		t.Fatalf("open = %+v %v", l, err)
	}
	for _, want := range []string{"opened a ticket but could not record it", "could not add it to the case"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs lack %q: %s", want, logs)
		}
	}
	if mc.calls != 1 {
		t.Errorf("mapping asked %d times", mc.calls)
	}

	// Once mapped, a ticket is added once, and a new one of the same
	// connection replaces the old.
	mc.fail = nil
	now := e.clk.Now()
	if err := e.svc.linkCase(ctx, *l, now); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.linkCase(ctx, *l, now); err != nil {
		t.Fatal(err)
	}
	next := *l
	next.Key = "SEC-99"
	if err := e.svc.linkCase(ctx, next, now); err != nil {
		t.Fatal(err)
	}
	got := e.getCase("case-2")
	if len(got.Tickets) != 1 || got.Tickets[0].Key != "SEC-99" || mc.calls != 2 {
		t.Errorf("tickets = %+v, mapped %d times", got.Tickets, mc.calls)
	}
	h := got.History[len(got.History)-1]
	if h.Author != "Signalith" || h.From != "Jira "+l.Key || h.To != "Jira SEC-99" {
		t.Errorf("history = %+v", h)
	}

	// A failed try whose record cannot be written is logged.
	c = e.newCase("case-3", "Gone soon", "low")
	fl.upd = nil
	st, err = e.svc.claim(ctx, newLink(conn, c, "ann", false, StateCreating, e.clk.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.cases.Delete(ctx, "case-3"); err != nil {
		t.Fatal(err)
	}
	fl.upd = errors.New("opensearch down")
	if _, err := e.svc.open(ctx, conn, st); err == nil {
		t.Error("open of a deleted case worked")
	}
	if !strings.Contains(logs.String(), "could not record that a ticket could not be opened") {
		t.Errorf("logs = %s", logs)
	}
}

func TestServiceDefaults(t *testing.T) {
	s := &Service{}
	if s.log() == nil || s.now().IsZero() || s.caseLink("c1") != "" {
		t.Error("defaults")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.sleepFunc()(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleep = %v", err)
	}
	if err := s.sleepFunc()(context.Background(), time.Millisecond); err != nil {
		t.Errorf("short sleep = %v", err)
	}
	s.quirks.Store("gone:field", true)
	s.quirks.Store("kept:field", true)
	s.Forget(Settings{Connections: []Connection{{ID: "kept"}}})
	if _, ok := s.quirks.Load("gone:field"); ok {
		t.Error("a removed connection's quirk was kept")
	}
	if _, ok := s.quirks.Load("kept:field"); !ok {
		t.Error("a kept connection's quirk was dropped")
	}
}
