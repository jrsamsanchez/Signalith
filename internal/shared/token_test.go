package shared

import (
	"context"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

func TestTokenFollowsWrites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "settings", "settings", 1)
	NewDoc[testBody](b, "settings", "settings", 1)
	if a.Token() != "" {
		t.Errorf("token before reading: %q", a.Token())
	}
	cycle(t, a)
	cycle(t, b)
	before := b.Token()
	seq, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "x"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	tok := a.TokenAfter(seq)
	if !strings.HasSuffix(tok, "."+strconv.FormatInt(seq, 10)) {
		t.Errorf("token after %q", tok)
	}
	// The writer's own token reaches it at its next cycle.
	if stale := a.Wait(ctx, tok); stale || a.Token() != tok {
		t.Errorf("a %q, stale %v, after %q", a.Token(), stale, tok)
	}
	if !b.behind(tok) {
		t.Fatalf("b at %q is not behind %q", before, tok)
	}
	if stale := b.Wait(ctx, tok); stale {
		t.Error("stale after one cycle")
	}
	if b.Token() != tok {
		t.Errorf("b %q a %q", b.Token(), tok)
	}
	// A token ahead of anything any server has: stale, at most Timing.Wait.
	uuid, _, _ := ParseToken(tok)
	start := time.Now()
	if stale := b.Wait(ctx, uuid+".99999"); !stale {
		t.Error("not stale")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("waited %v", time.Since(start))
	}
	// Tokens that cannot be read are not waited for.
	for _, bad := range []string{"", "nonsense", "x.-2", ".5", uuid + ".-1"} {
		if b.Wait(ctx, bad) {
			t.Errorf("stale for %q", bad)
		}
	}
}

// U7: a token from a housekeeping delete never makes a page wait.
func TestTokenAfterHousekeeping(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "jointoken", "tokens", 1)
	NewCollection[testBody](b, "jointoken", "tokens", 1)
	if _, err := ca.Create(ctx, "sam", "t1", &testBody{Name: "t1"}); err != nil {
		t.Fatal(err)
	}
	_, etag, _ := ca.Get("t1")
	if _, err := ca.Delete(ctx, "sam", "t1", etag); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	cycle(t, b)
	e.clock.Advance(TombstoneAge + time.Hour)
	_, seq, err := ca.Housekeep(ctx, e.clock.Now())
	if err != nil || seq == 0 {
		t.Fatalf("housekeeping: %d %v", seq, err)
	}
	tok := a.TokenAfter(seq)
	if !b.behind(tok) {
		t.Fatalf("b %q is not behind %q", b.Token(), tok)
	}
	start := time.Now()
	if stale := b.Wait(ctx, tok); stale {
		t.Errorf("stale: b %q, token %q", b.Token(), tok)
	}
	if time.Since(start) > time.Second {
		t.Errorf("waited %v", time.Since(start))
	}
}

// U9: a token of a config index that was deleted and made again is
// ignored.
func TestTokenOfAnotherIndexIsIgnored(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "settings", "settings", 1)
	NewDoc[testBody](b, "settings", "settings", 1)
	cycle(t, a)
	for range 3 {
		if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name += "x"; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	cycle(t, a)
	old := a.Token()
	oldUUID, oldSeq, _ := ParseToken(old)
	if err := e.c.Do(ctx, http.MethodDelete, "/"+testIndex, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := EnsureConfig(ctx, e.c, testPrefix); err != nil {
		t.Fatal(err)
	}
	e.putSigned(e.key, "settings", "settings", 1, 3, `{"name":"xxx"}`, nil)
	cycle(t, b)
	newUUID, newSeq, ok := ParseToken(b.Token())
	if !ok || newUUID == oldUUID || newSeq >= oldSeq {
		t.Fatalf("old %q new %q", old, b.Token())
	}
	start := time.Now()
	if stale := b.Wait(ctx, old); stale {
		t.Error("stale for a token of the old index")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Errorf("waited %v", time.Since(start))
	}
	// The writer finds the new index too.
	cycle(t, a)
	if u, _, _ := ParseToken(a.Token()); u != newUUID {
		t.Errorf("a %q", a.Token())
	}
}

// A server's own write does not make its token claim the writes of other
// servers it has not read yet.
func TestTokenOnlyCountsWhatWasRead(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ax := NewDoc[testBody](a, "x", "x", 1)
	ay := NewDoc[testBody](a, "y", "y", 1)
	NewDoc[testBody](b, "x", "x", 1)
	by := NewDoc[testBody](b, "y", "y", 1)
	cycle(t, a)
	cycle(t, b)
	seqY, err := by.Mutate(ctx, "bob", func(v *testBody) error { v.Name = "from b"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	tokY := b.TokenAfter(seqY)
	if _, err := ax.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "from a"; return nil }); err != nil {
		t.Fatal(err)
	}
	if !a.behind(tokY) {
		t.Fatalf("a %q claims %q before reading y", a.Token(), tokY)
	}
	if stale := a.Wait(ctx, tokY); stale {
		t.Error("stale after one cycle")
	}
	if v, _ := ay.Get(); v.Name != "from b" {
		t.Errorf("a serves y %+v at token %q", v, a.Token())
	}
}

// A collection that fails to reload holds the token back, even when
// other documents moved in the same cycle.
func TestTokenWaitsForAFailedReload(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "user", "users", 1)
	NewCollection[testBody](b, "user", "users", 1)
	da := NewDoc[testBody](a, "settings", "settings", 1)
	NewDoc[testBody](b, "settings", "settings", 1)
	cycle(t, a)
	cycle(t, b)
	seq, err := ca.Create(ctx, "sam", "jlee", &testBody{Name: "J. Lee"})
	if err != nil {
		t.Fatal(err)
	}
	tok := a.TokenAfter(seq)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "later"; return nil }); err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	fail.Store(true)
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if fail.Load() && strings.Contains(path, "/_search") {
			return &ostest.Fault{Status: http.StatusServiceUnavailable, Type: "unavailable"}
		}
		return nil
	})
	if err := b.Cycle(ctx); err == nil {
		t.Fatal("no error from the failed reload")
	}
	if !b.behind(tok) {
		t.Errorf("b %q is not behind %q after a failed reload", b.Token(), tok)
	}
	fail.Store(false)
	cycle(t, b)
	if b.behind(tok) {
		t.Errorf("b %q is behind %q", b.Token(), tok)
	}
}

// A request waiting for a cycle while another runs gives up at
// Timing.Wait, and leaves nothing behind.
func TestWaitGivesUpOnASlowCycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	a.opts.Timing.Wait = 50 * time.Millisecond
	da := NewDoc[testBody](a, "settings", "settings", 1)
	cycle(t, a)
	seq, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "x"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	tok := a.TokenAfter(seq)
	// A cycle stuck on OpenSearch.
	a.cycling <- struct{}{}
	before := runtime.NumGoroutine()
	for range 5 {
		if stale := a.Wait(ctx, tok); !stale {
			t.Fatal("not stale while the cycle is stuck")
		}
	}
	waitFor(t, func() bool { return runtime.NumGoroutine() <= before })
	<-a.cycling
	if stale := a.Wait(ctx, tok); stale {
		t.Error("stale once the cycle is free")
	}
}

// Written follows this server's own writes of tracked documents and
// watch documents, for the token of the answer to a change.
func TestWrittenFollowsOwnWrites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "settings", "settings", 1)
	NewDoc[testBody](b, "settings", "settings", 1)
	cycle(t, a)
	cycle(t, b)
	if a.Written() != -1 {
		t.Errorf("written before any write: %d", a.Written())
	}
	seq, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "x"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if a.Written() != seq {
		t.Errorf("written %d, want %d", a.Written(), seq)
	}
	bump, err := a.Bump(ctx, "intel")
	if err != nil || bump <= seq || a.Written() != bump {
		t.Errorf("bump %d %v, written %d", bump, err, a.Written())
	}
	// Another server's writes are not this one's.
	if b.Written() != -1 {
		t.Errorf("b written %d", b.Written())
	}
	// A document only this server tracks (its nodecfg) does not count:
	// no other server would ever reach its token.
	local := NewDoc[testBody](a, "nodecfg:n_a", "nodecfg", 1)
	local.Local = true
	if _, err := local.Mutate(ctx, "signalith", func(v *testBody) error { v.Name = "y"; return nil }); err != nil {
		t.Fatal(err)
	}
	if a.Written() != bump {
		t.Errorf("written %d after a local write, want %d", a.Written(), bump)
	}
	cycle(t, a)
	if _, applied, _ := ParseToken(a.Token()); applied != seq {
		t.Errorf("token %s after a local write, want seq %d", a.Token(), seq)
	}
}
