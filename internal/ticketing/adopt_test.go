package ticketing

import (
	"context"
	"strings"
	"testing"
	"time"
)

// crashAfterCreate opens a ticket for a case as a server would, and stops
// before recording it: the link is left being created, and the ticket
// exists only in the system.
func (e *env) crashAfterCreate(connID, caseID string) {
	e.t.Helper()
	e.crash(connID, caseID, false, true)
}

// crash leaves a case's link being created, as a server that stopped
// while opening its ticket does: auto when the connection was opening it
// by itself, made when the system had made the ticket.
func (e *env) crash(connID, caseID string, auto, made bool) {
	e.t.Helper()
	ctx := context.Background()
	set, err := e.svc.Settings.Settings()
	if err != nil {
		e.t.Fatal(err)
	}
	conn, _ := set.Connection(connID)
	c := e.getCase(caseID)
	by := "ann"
	if auto {
		by = "Signalith"
	}
	if _, err := e.links.Create(ctx, newLink(conn, c, by, auto, StateCreating, e.clk.Now())); err != nil {
		e.t.Fatal(err)
	}
	if !made {
		return
	}
	rem, err := e.svc.remote(conn)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := rem.create(ctx, contentOf(c, e.svc.caseLink(caseID))); err != nil {
		e.t.Fatal(err)
	}
}

func TestRetryAfterCrashAdoptsTheTicket(t *testing.T) {
	for _, tc := range []struct {
		name    string
		conn    func(t *testing.T) (Connection, func() int, func() []string)
		wantKey string
	}{
		{"jira cloud", func(t *testing.T) (Connection, func() int, func() []string) {
			f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
			return jiraCloudConn(f), func() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.issues) }, func() []string { f.mu.Lock(); defer f.mu.Unlock(); return f.lastJQL }
		}, "SEC-1"},
		{"jira data center", func(t *testing.T) (Connection, func() int, func() []string) {
			f := newFakeJira(t, false, "Bearer dc-personal-access-token")
			return jiraDCConn(f), func() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.issues) }, func() []string { f.mu.Lock(); defer f.mu.Unlock(); return f.lastJQL }
		}, "SEC-1"},
		{"servicenow", func(t *testing.T) (Connection, func() int, func() []string) {
			f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
			return snConn(f), func() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.records) }, func() []string {
				var out []string
				for _, r := range f.requests() {
					if strings.Contains(r, "correlation_id%3D") {
						out = append(out, r)
					}
				}
				return out
			}
		}, "INC0010001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, tickets, finds := tc.conn(t)
			e := newEnv(t, conn)
			ctx := context.Background()
			e.newCase("CASE-20261016-0001", "Brute force", "high")
			e.crashAfterCreate(conn.ID, "CASE-20261016-0001")
			if tickets() != 1 {
				t.Fatalf("%d tickets after the crash", tickets())
			}
			// Until it is stale, the half-opened ticket blocks another.
			if _, err := e.svc.Create(ctx, "CASE-20261016-0001", conn.ID, "bob"); err != ErrInProgress {
				t.Fatalf("retry before stale: %v", err)
			}
			e.clk.add(staleAfter + 1)
			l, err := e.svc.Create(ctx, "CASE-20261016-0001", conn.ID, "bob")
			if err != nil {
				t.Fatal(err)
			}
			if l.Key != tc.wantKey || l.State != StateLinked || l.MayExist || l.URL == "" {
				t.Errorf("link %+v", l)
			}
			if n := tickets(); n != 1 {
				t.Errorf("%d tickets after the retry, want the one found", n)
			}
			if len(finds()) == 0 {
				t.Error("the retry did not look for the ticket")
			}
			if c := e.getCase("CASE-20261016-0001"); len(c.Tickets) != 1 || c.Tickets[0].Key != tc.wantKey {
				t.Errorf("case tickets %+v", c.Tickets)
			}
			// It is then kept in step like any other.
			e.pass()
			if st := e.link(conn.ID, "CASE-20261016-0001"); st.Error != "" || st.CaseStatus != "new" {
				t.Errorf("after a pass %+v", st.Link)
			}
		})
	}
}

// A case without a crash opens its ticket without looking first.
func TestFirstOpenDoesNotLook(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	e.newCase("case-1", "x", "high")
	if _, err := e.svc.Create(context.Background(), "case-1", "sn", "ann"); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.requests() {
		if strings.Contains(r, "correlation_id") {
			t.Errorf("looked for a ticket on a first open: %s", r)
		}
	}
	if r := f.record("INC0010001"); r.correlationID != "signalith:case-1" || r.correlationDisplay != "Signalith" {
		t.Errorf("record %+v", r)
	}
}

// A failed open may have made the ticket: trying again looks first, and
// opens one when there is none.
func TestRetryAfterFailureLooksFirst(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	ctx := context.Background()
	e.newCase("case-1", "x", "high")
	f.inject(fault{match: "POST /api/now/table/incident", status: 504, body: "gateway timeout"})
	if _, err := e.svc.Create(ctx, "case-1", "sn", "ann"); err == nil {
		t.Fatal("a 504 opened the ticket")
	}
	if st := e.link("sn", "case-1"); !st.MayExist {
		t.Errorf("failed link %+v", st.Link)
	}
	if _, err := e.svc.Create(ctx, "case-1", "sn", "ann"); err != nil {
		t.Fatal(err)
	}
	var seq []string
	for _, r := range f.requests() {
		switch {
		case strings.HasPrefix(r, "POST /api/now/table/incident"):
			seq = append(seq, "create")
		case strings.Contains(r, "correlation_id%3D"):
			seq = append(seq, "find")
		}
	}
	if strings.Join(seq, ",") != "create,find,create" {
		t.Errorf("requests %v", seq)
	}
	if len(f.records) != 1 {
		t.Errorf("%d records", len(f.records))
	}
}

// Without the labels field on the create screen the issue is still made,
// and the next one does not send labels.
func TestJiraLabelsRefused(t *testing.T) {
	f := newFakeJira(t, false, "Bearer dc-personal-access-token")
	f.noLabels = true
	e := newEnv(t, jiraDCConn(f))
	e.newCase("case-1", "x", "high")
	e.newCase("case-2", "y", "high")
	for _, id := range []string{"case-1", "case-2"} {
		if _, err := e.svc.Create(context.Background(), id, "dc", "ann"); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count("POST /rest/api/2/issue"); n != 3 {
		t.Errorf("%d creates, want 3", n)
	}
	if is := f.issue("SEC-1"); len(is.labels) != 0 {
		t.Errorf("labels %v", is.labels)
	}
}

func TestMarkers(t *testing.T) {
	if got := jiraLabel("CASE-20261012-3fa9c1d27b40e865"); got != "signalith-CASE-20261012-3fa9c1d27b40e865" {
		t.Errorf("label %s", got)
	}
	for _, odd := range []string{"a b", `x"y`, "é", strings.Repeat("a", 81), "a^b,c"} {
		m := markerID(odd)
		if !strings.HasPrefix(m, "h") || len(m) != 17 || m == markerID(odd+"x") {
			t.Errorf("marker of %q: %s", odd, m)
		}
		if l := len(correlationID(odd)); l > 100 {
			t.Errorf("correlation ID of %q is %d long", odd, l)
		}
	}
	if len(correlationID(strings.Repeat("a", 80))) > 100 {
		t.Error("correlation ID too long for ServiceNow's 100")
	}
}

func autoEnv(t *testing.T) (*env, *fakeSN) {
	t.Helper()
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	conn := snConn(f)
	conn.AutoCreate, conn.AutoMinSeverity = true, "high"
	clk := newClock()
	conn.AutoSince = clk.Now().Add(-time.Hour)
	e := newEnv(t, conn)
	e.clk = clk
	e.svc.Now = clk.Now
	return e, f
}

// A ticket the connection was opening by itself when the server stopped
// is opened again by the sync once stale: it looks first, and adopts the
// ticket when the system made it.
func TestSyncRetriesStaleAutoOpen(t *testing.T) {
	e, f := autoEnv(t)
	e.newCase("made", "made before the crash", "high")
	e.newCase("lost", "lost in the crash", "critical")
	e.crash("sn", "made", true, true)
	e.crash("sn", "lost", true, false)

	e.pass()
	for _, id := range []string{"made", "lost"} {
		if st := e.link("sn", id); st.State != StateCreating {
			t.Fatalf("%s before stale: %+v", id, st.Link)
		}
	}
	if n := f.count("POST /api/now/table/incident"); n != 1 {
		t.Fatalf("%d creates before stale", n)
	}

	e.clk.add(staleAfter)
	e.pass()
	if st := e.link("sn", "made"); st.State != StateLinked || st.Key != "INC0010001" || st.MayExist {
		t.Errorf("made: %+v", st.Link)
	}
	if st := e.link("sn", "lost"); st.State != StateLinked || st.Key != "INC0010002" {
		t.Errorf("lost: %+v", st.Link)
	}
	if n := f.count("POST /api/now/table/incident"); n != 2 {
		t.Errorf("%d creates, want 2: %v", n, f.requests())
	}
	finds := 0
	for _, r := range f.requests() {
		if strings.Contains(r, "correlation_id%3D") {
			finds++
		}
	}
	if finds != 2 {
		t.Errorf("%d finds, want one for each retry", finds)
	}
	if c := e.getCase("made"); len(c.Tickets) != 1 || c.Tickets[0].Key != "INC0010001" {
		t.Errorf("made tickets %+v", c.Tickets)
	}
}

// The sync gives up on a stale automatic open after the auto-create
// tries, and leaves it failed for a person to retry, still looking first.
func TestSyncStaleAutoOpenIsBounded(t *testing.T) {
	e, f := autoEnv(t)
	ctx := context.Background()
	e.newCase("made", "made before the crash", "high")
	e.crash("sn", "made", true, true)
	st := e.link("sn", "made")
	l := st.Link
	l.Attempts = maxAutoAttempts - 1
	if _, err := e.links.Update(ctx, &l, st.Version); err != nil {
		t.Fatal(err)
	}

	e.clk.add(staleAfter)
	e.pass()
	st = e.link("sn", "made")
	if st.State != StateFailed || !st.MayExist || st.Error == "" {
		t.Fatalf("after the last try: %+v", st.Link)
	}
	if n := f.count("GET /api/now/table/incident?"); n != 0 {
		t.Errorf("%d lookups after giving up", n)
	}
	e.clk.add(retryEvery)
	e.pass()
	if n := f.count("POST /api/now/table/incident"); n != 1 {
		t.Errorf("%d creates after giving up", n)
	}

	got, err := e.svc.Create(ctx, "made", "sn", "ann")
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != "INC0010001" || f.count("POST /api/now/table/incident") != 1 {
		t.Errorf("manual retry %+v, %d creates", got, f.count("POST /api/now/table/incident"))
	}
}
