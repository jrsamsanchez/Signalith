package clusterauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// A session made on A works on B at once, without a refresh; a sign-out
// on B ends it on A within one poll; a new password ends every session of
// the user on both.
func TestSessionsAcrossServers(t *testing.T) {
	_, a, b, _ := pair(t)
	a.addUser("jlee", users.Analyst)
	b.cycle()
	c1 := a.signIn("jlee", false)
	if !a.valid(c1) || !b.valid(c1) {
		t.Fatal("a session made on A does not work on both servers")
	}
	s, ok := b.sessions.Lookup(context.Background(), c1, false)
	if !ok || s.User != "jlee" || s.Method != users.SourceLocal || s.Epoch != 1 {
		t.Fatalf("B's view of the session: %+v %v", s, ok)
	}

	b.sessions.Delete(context.Background(), c1)
	if b.valid(c1) {
		t.Error("B still accepts the session it signed out")
	}
	a.cycle()
	if a.valid(c1) {
		t.Error("A accepts a session signed out on B after one poll")
	}

	c2 := a.signIn("jlee", true)
	c3 := b.signIn("jlee", false)
	if !a.valid(c2) || !a.valid(c3) {
		t.Fatal("new sessions do not work")
	}
	if _, err := b.store.SetPassword(context.Background(), "jlee", "another-password", true); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	for _, c := range []string{c2, c3} {
		if a.valid(c) || b.valid(c) {
			t.Error("a session from before a password reset still works")
		}
	}
}

// V6: made-up cookies, and cookies of the right form with a wrong tag,
// are refused without a single request to OpenSearch.
func TestCookiesRefusedWithoutRequests(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	kid := a.key().ID()
	o.fake.Requests()
	for i := range 10000 {
		raw := make([]byte, 1+i%80)
		_, _ = rand.Read(raw)
		v := base64.RawURLEncoding.EncodeToString(raw)
		if i%3 == 0 {
			v = "s1." + v
		}
		if _, ok := a.sessions.Lookup(ctx, v, true); ok {
			t.Fatalf("random cookie %q accepted", v)
		}
	}
	for range 1000 {
		random, tag := make([]byte, 32), make([]byte, tagSize)
		_, _ = rand.Read(random)
		_, _ = rand.Read(tag)
		v := "s1." + kid + "." + b64.EncodeToString(random) + "." + b64.EncodeToString(tag)
		if _, ok := a.sessions.Lookup(ctx, v, true); ok {
			t.Fatal("a cookie with a wrong tag was accepted")
		}
		a.sessions.Delete(ctx, v)
	}
	if reqs := o.fake.Requests(); len(reqs) != 0 {
		t.Fatalf("%d requests for made-up cookies, such as %s", len(reqs), reqs[0])
	}
	// A cookie made for another cluster is refused too.
	other := NewCookie(a.key(), "c_other")
	if err := ParseCookie(a.rt.Hub().Keys(), a.docs.ClusterID(), other); err == nil {
		t.Error("a cookie of another cluster parses")
	}
	if err := ParseCookie(a.rt.Hub().Keys(), a.docs.ClusterID(), NewCookie(a.key(), a.docs.ClusterID())); err != nil {
		t.Errorf("a good cookie: %v", err)
	}
}

// V12, sessions: a session document changed in OpenSearch, or made up
// there, is refused and audited.
func TestForgedSessionRefused(t *testing.T) {
	o, a, b, _ := pair(t)
	a.addUser("jlee", users.Viewer)
	b.cycle()
	cookie := a.signIn("jlee", false)
	id := SessionID(cookie)
	index := shared.SessionsIndex(testPrefix)
	src := o.fake.Source(index, id)
	src["user"] = "admin"
	o.fake.Put(index, id, src)
	if b.valid(cookie) {
		t.Fatal("a session changed to another user is accepted")
	}
	if !strings.Contains(b.logs.String(), "session.tamper") {
		t.Error("the changed session was not audited")
	}
	// A made-up session for a good cookie the forger chose: without the
	// cluster key its MAC cannot be right.
	forged := NewCookie(a.key(), a.docs.ClusterID())
	o.fake.Put(index, SessionID(forged), map[string]any{"user": "admin", "epoch": 1, "created": time.Now().UTC().Format(time.RFC3339Nano),
		"last_seen": time.Now().UTC().Format(time.RFC3339Nano), "remember": true, "method": "builtin", "mac": "m1:" + a.key().ID() + ":AAAA"})
	if a.valid(forged) {
		t.Fatal("a made-up session is accepted")
	}
	if got := a.sessions.Users(context.Background()); len(got) != 0 {
		t.Errorf("users with a session: %v", got)
	}
}

// V18: while OpenSearch cannot be read, a session read before keeps
// working for 5 minutes past its last confirmation, not 6.
func TestStaleSessionsWhileDegraded(t *testing.T) {
	o, a, _, clk := pair(t)
	a.addUser("jlee", users.Viewer)
	cookie := a.signIn("jlee", false)
	if !a.valid(cookie) {
		t.Fatal("the session does not work")
	}
	o.fake.SetFault(func(_, path string) *ostest.Fault {
		if strings.Contains(path, "_sessions") {
			return &ostest.Fault{Status: 503, Type: "unavailable_shards_exception"}
		}
		return nil
	})
	clk.Advance(4*time.Minute + 59*time.Second)
	if !a.valid(cookie) {
		t.Fatal("the session ended within 5 minutes of its confirmation")
	}
	clk.Advance(61 * time.Second)
	if a.valid(cookie) {
		t.Fatal("the session still works 6 minutes after its confirmation")
	}

	// The same while the server knows it is degraded: no request at all.
	o2, c, _, clk2 := pair(t)
	c.addUser("ann", users.Viewer)
	cookie = c.signIn("ann", false)
	c.valid(cookie)
	c.degraded.Store(true)
	o2.fake.Requests()
	clk2.Advance(4 * time.Minute)
	if !c.valid(cookie) {
		t.Fatal("degraded: the session ended within 5 minutes")
	}
	if reqs := requestsTo(o2.fake.Requests(), "_sessions"); len(reqs) != 0 {
		t.Errorf("degraded, yet asked OpenSearch: %v", reqs)
	}
	clk2.Advance(2 * time.Minute)
	if c.valid(cookie) {
		t.Fatal("degraded: the session works 6 minutes after its confirmation")
	}
}

// Idle sessions end unless remembered; a peek does not count as use; the
// stored last_seen is written at most once a minute.
func TestIdleAndLastSeen(t *testing.T) {
	o, a, b, clk := pair(t)
	a.addUser("jlee", users.Viewer)
	b.cycle()
	a.sessions.SetIdle(10 * time.Minute)
	b.sessions.SetIdle(10 * time.Minute)
	keep := a.signIn("jlee", true)
	idle := a.signIn("jlee", false)
	o.fake.Requests()
	for range 5 {
		clk.Advance(20 * time.Second)
		a.valid(idle)
	}
	if n := len(requestsTo(o.fake.Requests(), "_update")); n != 1 {
		t.Errorf("%d last_seen writes in 100 seconds of use, want 1", n)
	}
	// Used on A, so B sees the stored last_seen and keeps it.
	clk.Advance(9 * time.Minute)
	if !b.valid(idle) {
		t.Fatal("B ended a session used on A 9 minutes ago")
	}
	clk.Advance(9 * time.Minute)
	if _, ok := a.sessions.Lookup(context.Background(), idle, false); !ok {
		t.Fatal("A ended a session used on B 9 minutes ago")
	}
	clk.Advance(9 * time.Minute)
	if a.valid(idle) {
		t.Error("a session only peeked at for 18 minutes is still alive")
	}
	if !a.valid(keep) {
		t.Error("a remembered session ended for being idle")
	}
	clk.Advance(MaxAge)
	if a.valid(keep) {
		t.Error("a remembered session outlived MaxAge")
	}
}

// V27: a user deleted and made again under the same name does not get
// the old sessions; tombstones go after 30 days.
func TestRecreatedUserKeepsNoSessions(t *testing.T) {
	o, a, b, clk := pair(t)
	ctx := context.Background()
	a.addUser("zed", users.Analyst)
	b.cycle()
	old := b.signIn("zed", true)
	if _, err := a.store.Delete(ctx, "zed"); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if b.valid(old) {
		t.Fatal("a deleted user's session works")
	}
	clk.Advance(time.Second)
	a.addUser("zed", users.Analyst)
	b.cycle()
	if u, _ := b.store.Get("zed"); u.SessionEpoch != 1 {
		t.Fatalf("the new zed's epoch is %d", u.SessionEpoch)
	}
	if a.valid(old) || b.valid(old) {
		t.Fatal("the old zed's session works for the new zed")
	}
	fresh := a.signIn("zed", false)
	if !b.valid(fresh) {
		t.Fatal("the new zed cannot sign in")
	}

	// A user made on a server whose clock is ahead signs in at once on
	// another: the servers' clocks are never compared.
	a.addUser("amy", users.Analyst)
	if _, err := a.docs.Users().Mutate(ctx, "x", "amy", func(v *UserBody) error {
		v.Created = v.Created.Add(5 * time.Second)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	early := b.signIn("amy", false)
	if !a.valid(early) || !b.valid(early) {
		t.Fatal("a session made just after a user was, by a clock behind, is refused")
	}

	a.addUser("gone", users.Viewer)
	if _, err := a.store.Delete(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	cfg := shared.ConfigIndex(testPrefix)
	if o.fake.Source(cfg, "user:gone") == nil {
		t.Fatal("no tombstone")
	}
	if n, _ := a.rt.Hub().Housekeep(ctx, time.Now().Add(29*24*time.Hour)); n != 0 {
		t.Errorf("%d tombstones removed before 30 days", n)
	}
	if n, _ := a.rt.Hub().Housekeep(ctx, time.Now().Add(31*24*time.Hour)); n != 1 || o.fake.Source(cfg, "user:gone") != nil {
		t.Errorf("%d tombstones removed after 31 days", n)
	}
}

// V28: the 51st session of a user removes the oldest; housekeeping
// deletes old sessions and those of an older session epoch.
func TestSessionLimitAndHousekeeping(t *testing.T) {
	o, a, b, clk := pair(t)
	ctx := context.Background()
	a.addUser("ann", users.Viewer)
	a.addUser("bob", users.Viewer)
	a.addUser("cat", users.Viewer)
	b.cycle()
	var cookies []string
	for range MaxPerUser + 1 {
		cookies = append(cookies, a.signIn("ann", true))
		clk.Advance(time.Millisecond)
	}
	if n := o.sessionDocs(t, "ann"); n != MaxPerUser {
		t.Fatalf("%d sessions of ann, want %d", n, MaxPerUser)
	}
	if b.valid(cookies[0]) {
		t.Error("the oldest session still works")
	}
	if !b.valid(cookies[1]) || !b.valid(cookies[MaxPerUser]) {
		t.Error("newer sessions were removed")
	}

	oldBob := a.signIn("bob", true)
	clk.Advance(8 * 24 * time.Hour)
	newBob := a.signIn("bob", true)
	cat := a.signIn("cat", true)
	if _, err := a.store.SetPassword(ctx, "cat", "a-new-password", false); err != nil {
		t.Fatal(err)
	}
	newCat := a.signIn("cat", true)
	n, err := a.sessions.Housekeep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Every session of ann is 8 days old now, as is bob's first.
	if want := MaxPerUser + 2; n != want {
		t.Errorf("housekeeping deleted %d sessions, want %d", n, want)
	}
	for _, gone := range []string{oldBob, cat} {
		if o.fake.Source(shared.SessionsIndex(testPrefix), SessionID(gone)) != nil {
			t.Error("an ended session is still stored")
		}
	}
	b.cycle()
	for _, kept := range []string{newBob, newCat} {
		if !b.valid(kept) {
			t.Error("housekeeping ended a live session")
		}
	}
}

// An in-process restart keeps the cache: a server made again over the
// same SessionCache knows the sessions it read, and the sign-outs it saw.
func TestSessionCacheKept(t *testing.T) {
	o, a, _, _ := pair(t)
	a.addUser("jlee", users.Viewer)
	cookie := a.signIn("jlee", false)
	a.valid(cookie)
	again := &Sessions{Docs: a.docs, Client: o.client, Node: "n_siem-a", Cache: a.sessions.Cache, DirectoryOn: a.dirOn.Load, Now: a.sessions.Now}
	again.SetIdle(time.Hour)
	o.fake.Requests()
	if _, ok := again.Lookup(context.Background(), cookie, false); !ok {
		t.Fatal("the session is not known after a restart")
	}
	if reqs := requestsTo(o.fake.Requests(), "_sessions"); len(reqs) != 0 {
		t.Errorf("read again after a restart: %v", reqs)
	}
}
