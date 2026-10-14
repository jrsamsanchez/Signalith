package agentinv

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newInv(c *store.Client, node string, clk *clock, pin string) *Inventory {
	return &Inventory{Client: c, Prefix: "s", Now: clk.now,
		Node: func() string { return node }, Server: func() string { return "siem-" + node },
		ServerCA: func() string { return pin }}
}

const pinA, pinB = "0123456789abcdef", "fedcba9876543210"

func list(t *testing.T, v *Inventory) []Agent {
	t.Helper()
	agents, _, err := v.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return agents
}

func TestAnAgentThatSendsToTwoServersIsOneRow(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	n1, n2 := newInv(c, "n1", clk, pinA), newInv(c, "n2", clk, pinA)
	ctx := context.Background()
	contact := Contact{Name: "  WEB-01 ", Address: "192.0.2.10", Tag: "win.security", Intake: "agent", TLS: true,
		TokenID: "abcdef012345", TokenName: "Windows servers", Config: "ca=" + pinA + ";v=1.4.0", Events: 40}
	n1.Note(contact)
	clk.add(time.Minute)
	contact.Events = 2
	n2.Note(contact)
	n1.FlushNow(ctx)
	n2.FlushNow(ctx)
	// A third server that heard from nobody still lists it, once.
	agents := list(t, newInv(c, "n3", clk, pinA))
	if len(agents) != 1 {
		t.Fatalf("agents: %+v", agents)
	}
	a := agents[0]
	if a.Name != "web-01" || a.Events1h != 42 || len(a.Servers) != 2 || a.Servers[0] != "siem-n1" || a.Servers[1] != "siem-n2" ||
		a.Transport != TransportTLS || a.TokenName != "Windows servers" || a.ConfigVersion != "1.4.0" || len(a.CA) != 1 || a.CA[0] != pinA || a.CAMismatch {
		t.Errorf("row: %+v", a)
	}
	if !a.FirstSeen.Equal(time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)) || !a.LastSeen.Equal(clk.now()) {
		t.Errorf("seen: %v %v", a.FirstSeen, a.LastSeen)
	}
	// Unwritten counts of the server asked count too.
	n1.Note(contact)
	if got := list(t, n1)[0].Events1h; got != 44 {
		t.Errorf("with unwritten counts: %d", got)
	}
	// An hour later its events no longer count.
	clk.add(2 * time.Hour)
	if got := list(t, newInv(c, "n3", clk, pinA))[0].Events1h; got != 0 {
		t.Errorf("an hour later: %d", got)
	}
}

func TestAnAgentPinnedToAnotherCAIsFlaggedAfterItsHandshakesFail(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	n1, n2 := newInv(c, "n1", clk, pinA), newInv(c, "n2", clk, pinB)
	ctx := context.Background()
	// It sent to n1, which still uses the CA it pins.
	n1.Note(Contact{Name: "db-01", Address: "192.0.2.20", TLS: true, Config: "ca=" + pinA + ";v=1.4.0", Events: 5})
	n1.FlushNow(ctx)
	// n2 uses another CA: the agent refuses its certificate, every few
	// seconds. So does a computer that never sent anything.
	for range 3 {
		n2.NoteRefusedCA("192.0.2.20:51234")
		n2.NoteRefusedCA("[2001:db8::7]:40000")
		clk.add(time.Minute)
	}
	// A browser that refused once is not listed.
	n2.NoteRefusedCA("198.51.100.4:1234")
	n2.FlushNow(ctx)
	agents := list(t, newInv(c, "n3", clk, pinA))
	if len(agents) != 2 {
		t.Fatalf("agents: %+v", agents)
	}
	var agent, alone *Agent
	for i := range agents {
		if agents[i].Refusing {
			alone = &agents[i]
		} else {
			agent = &agents[i]
		}
	}
	if agent == nil || agent.Name != "db-01" || agent.Refused1h != 3 {
		t.Errorf("agent: %+v", agent)
	}
	if alone == nil || alone.Name != "" || len(alone.Addresses) != 1 || alone.Addresses[0] != "2001:db8::7" || alone.Refused1h != 3 ||
		len(alone.Servers) != 1 || alone.Servers[0] != "siem-n2" {
		t.Errorf("address alone: %+v", alone)
	}
	// An agent whose pin differs from the server it sent to is told
	// apart even without refusals.
	n2.Note(Contact{Name: "app-01", Address: "192.0.2.30", TLS: true, Config: "ca=" + pinA + ";v=1.4.0", Events: 1})
	for _, a := range list(t, n2) {
		if a.Name == "app-01" && !a.CAMismatch {
			t.Errorf("mismatch not seen: %+v", a)
		}
		if a.Name == "db-01" && a.CAMismatch {
			t.Errorf("db-01 matched its server: %+v", a)
		}
	}
}

func TestAgentsWithoutANameAreToldApartByAddressAndToken(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	v := newInv(nil, "n1", clk, "")
	v.Note(Contact{Address: "203.0.113.5", TokenID: "aaaaaaaaaaaa", Events: 1})
	v.Note(Contact{Address: "203.0.113.5", TokenID: "bbbbbbbbbbbb", Events: 1})
	if got := list(t, v); len(got) != 2 {
		t.Fatalf("two tokens: %+v", got)
	}
	w := newInv(nil, "n1", clk, "")
	w.Note(Contact{Address: "203.0.113.5", TokenID: "aaaaaaaaaaaa", Events: 1})
	w.Note(Contact{Address: "203.0.113.5", TokenID: "aaaaaaaaaaaa", Events: 2})
	got := list(t, w)
	if len(got) != 1 || got[0].Events1h != 3 || got[0].Name != "" {
		t.Fatalf("one token: %+v", got)
	}
}

func TestBadHeaderValuesAreIgnored(t *testing.T) {
	for _, bad := range []string{"", "-web", "web 01", "web/01", "wéb", string(make([]byte, 300)), "web<script>"} {
		if CleanName(bad) != "" {
			t.Errorf("name %q kept", bad)
		}
	}
	if CleanName(" Web-01.corp.example ") != "web-01.corp.example" {
		t.Error("good name refused")
	}
	for _, bad := range []string{"ca=xyz;v=1", "ca=0123456789ABCDEF;v=1", "v=1;v=2", "v=1 2", "x=1", "ca=" + pinA, "v=", "v=" + string(make([]byte, 65))} {
		if _, _, ok := ParseConfig(bad); ok && bad != "ca="+pinA {
			t.Errorf("config %q accepted", bad)
		}
	}
	// A pin alone is a valid header, with no version.
	if ca, v, ok := ParseConfig("ca=" + pinA); !ok || ca != pinA || v != "" {
		t.Errorf("pin alone: %q %q %v", ca, v, ok)
	}
	if ca, v, ok := ParseConfig("ca=" + pinA + ";v=1.4.0-rc.1"); !ok || ca != pinA || v != "1.4.0-rc.1" {
		t.Errorf("good config: %q %q %v", ca, v, ok)
	}
	clk := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	v := newInv(nil, "n1", clk, "")
	v.Note(Contact{Name: "bad name!", Address: "203.0.113.5", Config: "ca=nothex;v=1", Events: 1})
	got := list(t, v)
	if len(got) != 1 || got[0].Name != "" || len(got[0].CA) != 0 || got[0].ConfigVersion != "" {
		t.Errorf("bad headers kept: %+v", got)
	}
	if Pin("AB:CD:EF:01:23:45:67:89:AA:BB") != "abcdef0123456789" || Pin("") != "" || Pin("zz") != "" {
		t.Error("Pin")
	}
}

func TestTidyRemovesOldAgentsOnlyOnTheJobsServer(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)}
	v := newInv(c, "n1", clk, "")
	ctx := context.Background()
	v.Note(Contact{Name: "old-01", Address: "192.0.2.1", Events: 1})
	v.FlushNow(ctx)
	clk.add(31 * 24 * time.Hour)
	w := newInv(c, "n2", clk, "")
	w.Note(Contact{Name: "new-01", Address: "192.0.2.2", Events: 1})
	w.FlushNow(ctx)
	if n, err := w.TidyNow(ctx); err != nil || n != 0 {
		t.Fatalf("not the jobs server: %d %v", n, err)
	}
	w.Leader = func() bool { return true }
	if n, err := w.TidyNow(ctx); err != nil || n != 1 {
		t.Fatalf("tidy: %d %v", n, err)
	}
	if fos.Source("s_runtime", docID(Key("old-01", "", ""), "n1")) != nil || fos.Source("s_runtime", docID(Key("new-01", "", ""), "n2")) == nil {
		t.Error("wrong documents removed")
	}
}

func TestFirstSeenSurvivesARestart(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)}
	first := clk.now()
	v := newInv(c, "n1", clk, "")
	ctx := context.Background()
	v.Note(Contact{Name: "web-01", Address: "192.0.2.1", Events: 1})
	v.FlushNow(ctx)
	clk.add(48 * time.Hour)
	// The same server, started again.
	again := newInv(c, "n1", clk, "")
	again.loadFirstSeen(ctx)
	again.Note(Contact{Name: "web-01", Address: "192.0.2.1", Events: 1})
	again.FlushNow(ctx)
	got := list(t, again)
	if len(got) != 1 || !got[0].FirstSeen.Equal(first) || !got[0].LastSeen.Equal(clk.now()) {
		t.Errorf("after restart: %+v", got)
	}
}

func TestFlushFailureIsWrittenNextTime(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)}
	v := newInv(c, "n1", clk, "")
	ctx := context.Background()
	v.Note(Contact{Name: "web-01", Address: "192.0.2.1", Events: 1})
	fos.FailN(1, "POST", "_bulk", 503, "unavailable_shards_exception")
	v.FlushNow(ctx)
	if fos.Source("s_runtime", docID(Key("web-01", "", ""), "n1")) != nil {
		t.Fatal("written despite the failure")
	}
	v.FlushNow(ctx)
	if fos.Source("s_runtime", docID(Key("web-01", "", ""), "n1")) == nil {
		t.Error("not written the next time")
	}
}

// A configuration made while a new certificate authority was prepared
// trusts both, so it matches a server on either.
func TestAConfigurationMayTrustTwoCAs(t *testing.T) {
	both := pinA + "," + pinB
	if ca, _, ok := ParseConfig("ca=" + both + ";v=1.4.0"); !ok || ca != both {
		t.Fatalf("two pins: %q %v", ca, ok)
	}
	for _, bad := range []string{"ca=" + pinA + ",", "ca=," + pinA, "ca=" + pinA + ",xyz"} {
		if _, _, ok := ParseConfig(bad); ok {
			t.Errorf("config %q accepted", bad)
		}
	}
	if !TrustsCA(both, pinB) || TrustsCA(pinA, pinB) || TrustsCA(both, "") {
		t.Error("TrustsCA")
	}
	clk := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	v := newInv(nil, "n1", clk, pinB)
	v.Note(Contact{Name: "web-01", Address: "192.0.2.10", TLS: true, Config: "ca=" + both + ";v=1.4.0", Events: 1})
	if a := list(t, v)[0]; a.CAMismatch || len(a.CA) != 1 || a.CA[0] != both {
		t.Errorf("row: %+v", a)
	}
}

// A configuration replaced since, which another server still has a
// document of, does not count: only those of around the last batch do.
func TestAnOlderConfigurationOnAnotherServerDoesNotCount(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	docs := []Doc{
		{Kind: Kind, Agent: "k", Name: "web-01", Node: "n1", Server: "siem-n1", CA: pinA, ServerCA: pinA, LastSeen: now.Add(-5 * 24 * time.Hour)},
		{Kind: Kind, Agent: "k", Name: "web-01", Node: "n2", Server: "siem-n2", CA: pinB, ServerCA: pinB, LastSeen: now},
	}
	a := Merge(docs, now)
	if len(a) != 1 || len(a[0].CA) != 1 || a[0].CA[0] != pinB || len(a[0].Servers) != 2 {
		t.Errorf("rows: %+v", a)
	}
}

// Another server's hourly count keeps being written as it drops, so it is
// not frozen at its value of the last batch.
func TestAnHourlyCountIsWrittenAsItDrops(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	n1 := newInv(c, "n1", clk, pinA)
	ctx := context.Background()
	n1.Note(Contact{Name: "web-01", Address: "192.0.2.10", TLS: true, Events: 7})
	n1.FlushNow(ctx)
	clk.add(30 * time.Minute)
	n1.Note(Contact{Name: "web-01", Address: "192.0.2.10", TLS: true, Events: 1})
	n1.FlushNow(ctx)
	// 31 minutes later the first batch is over an hour old, the second
	// is not: the hour's count is 1, not the 8 written with the batch.
	clk.add(31 * time.Minute)
	n1.FlushNow(ctx)
	got := list(t, newInv(c, "n2", clk, pinA))
	if len(got) != 1 || got[0].Events1h != 1 {
		t.Errorf("frozen count: %+v", got)
	}
}

// Old entries are forgotten on every server, and a full list makes room
// by forgetting the one heard from longest ago rather than refusing the
// new one.
func TestOldEntriesAreForgottenAndAFullListMakesRoom(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	v := newInv(c, "n1", clk, pinA)
	ctx := context.Background()
	for i := range maxRefusing {
		v.NoteRefusedCA("10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256))
	}
	v.FlushNow(ctx)
	clk.add(time.Minute)
	v.NoteRefusedCA("192.0.2.20")
	v.mu.Lock()
	_, kept := v.refused["192.0.2.20"]
	n := len(v.refused)
	v.mu.Unlock()
	if !kept || n != maxRefusing {
		t.Errorf("full list: kept %v, %d entries", kept, n)
	}
	v.Note(Contact{Name: "web-01", Address: "192.0.2.10", Events: 1})
	clk.add(2 * time.Hour)
	v.FlushNow(ctx)
	v.mu.Lock()
	refusing := len(v.refused)
	v.mu.Unlock()
	if refusing != 0 {
		t.Errorf("refusals over an hour old kept: %d", refusing)
	}
	clk.add(keepFor)
	v.FlushNow(ctx)
	v.mu.Lock()
	agents := len(v.agents)
	v.mu.Unlock()
	if agents != 0 {
		t.Errorf("agents not heard from for 30 days kept: %d", agents)
	}
}
