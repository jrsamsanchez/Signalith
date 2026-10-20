// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// restarted is s's sessions as after a restart of its process: the same
// documents, an empty cache.
func restarted(o *testOS, s *server) *Sessions {
	again := &Sessions{Docs: s.docs, Client: o.client, Node: s.sessions.Node, Cache: NewSessionCache(), DirectoryOn: s.dirOn.Load,
		Degraded: s.degraded.Load, Log: s.log, Now: s.sessions.Now}
	again.SetIdle(12 * time.Hour)
	return again
}

// fastRetries makes the session read retries quick for one test.
func fastRetries(t *testing.T) {
	old := readRetry
	readRetry = time.Millisecond
	t.Cleanup(func() { readRetry = old })
}

// sessionsDown makes every request to the sessions index fail as an
// overloaded OpenSearch does, until the returned func is called.
func sessionsDown(o *testOS) func() {
	o.fake.SetFault(func(_, path string) *ostest.Fault {
		if strings.Contains(path, "_sessions") {
			return &ostest.Fault{Status: 503, Type: "unavailable_shards_exception"}
		}
		return nil
	})
	return func() { o.fake.SetFault(nil) }
}

// A server that just restarted has no copy of a session. When OpenSearch
// does not answer its read, the session is not refused (which signs the
// browser out) but cannot be checked; it works again once OpenSearch
// answers.
func TestUncheckedAfterRestart(t *testing.T) {
	fastRetries(t)
	o, a, _, _ := pair(t)
	a.addUser("jlee", users.Viewer)
	cookie := a.signIn("jlee", false)
	again := restarted(o, a)
	up := sessionsDown(o)
	o.fake.Requests()
	if _, err := again.Check(context.Background(), cookie, true); !errors.Is(err, ErrSessionUnchecked) {
		t.Fatalf("OpenSearch does not answer: %v, want ErrSessionUnchecked", err)
	}
	if reqs := requestsTo(o.fake.Requests(), "_sessions/_doc"); len(reqs) != readTries {
		t.Errorf("read %d times, want %d: %v", len(reqs), readTries, reqs)
	}
	if !strings.Contains(a.logs.String(), "could not read a sign-in session") {
		t.Error("the failed read was not logged")
	}
	up()
	s, err := again.Check(context.Background(), cookie, true)
	if err != nil || s.User != "jlee" {
		t.Fatalf("OpenSearch answers again: %+v, %v", s, err)
	}
}

// One read that fails is tried again at once: the request does not wait
// for the browser to send it again.
func TestUncheckedReadRetried(t *testing.T) {
	fastRetries(t)
	o, a, _, _ := pair(t)
	a.addUser("jlee", users.Viewer)
	cookie := a.signIn("jlee", false)
	again := restarted(o, a)
	o.fake.FailN(readTries-1, "GET", "_sessions/_doc", 503, "unavailable_shards_exception")
	if _, err := again.Check(context.Background(), cookie, false); err != nil {
		t.Fatalf("failed %d times, then answered: %v", readTries-1, err)
	}
}

// While the server cannot use OpenSearch, a session it has no copy of
// cannot be checked, and OpenSearch is not asked.
func TestUncheckedWhileDegraded(t *testing.T) {
	o, a, _, _ := pair(t)
	a.addUser("jlee", users.Viewer)
	cookie := a.signIn("jlee", false)
	a.degraded.Store(true)
	again := restarted(o, a)
	o.fake.Requests()
	if _, err := again.Check(context.Background(), cookie, true); !errors.Is(err, ErrSessionUnchecked) {
		t.Fatalf("degraded: %v, want ErrSessionUnchecked", err)
	}
	if reqs := requestsTo(o.fake.Requests(), "_sessions"); len(reqs) != 0 {
		t.Errorf("degraded, yet asked OpenSearch: %v", reqs)
	}
	a.degraded.Store(false)
	if _, err := again.Check(context.Background(), cookie, true); err != nil {
		t.Fatalf("no longer degraded: %v", err)
	}
}

// A copy past StaleFor is not used, but the session is not refused for
// that either.
func TestUncheckedStaleCopy(t *testing.T) {
	fastRetries(t)
	o, a, _, clk := pair(t)
	a.addUser("jlee", users.Viewer)
	cookie := a.signIn("jlee", false)
	defer sessionsDown(o)()
	clk.Advance(StaleFor - time.Second)
	if _, err := a.sessions.Check(context.Background(), cookie, false); err != nil {
		t.Fatalf("a copy within StaleFor: %v", err)
	}
	clk.Advance(2 * time.Second)
	if _, err := a.sessions.Check(context.Background(), cookie, false); !errors.Is(err, ErrSessionUnchecked) {
		t.Fatalf("a copy past StaleFor: %v, want ErrSessionUnchecked", err)
	}
}

// What OpenSearch or the user says still refuses a session on a server
// that just restarted, never as "cannot be checked": no document, a MAC
// that does not verify, a user that is gone or disabled, an epoch moved
// on, a cookie of no cluster.
func TestUncheckedStillRefuses(t *testing.T) {
	fastRetries(t)
	ctx := context.Background()
	o, a, _, _ := pair(t)
	index := shared.SessionsIndex(testPrefix)
	for _, name := range []string{"del", "mac", "gone", "off", "renew"} {
		a.addUser(name, users.Viewer)
	}
	cookies := map[string]string{}
	for _, name := range []string{"del", "mac", "gone", "off", "renew"} {
		cookies[name] = a.signIn(name, false)
	}
	o.fake.Delete(index, SessionID(cookies["del"]))
	src := o.fake.Source(index, SessionID(cookies["mac"]))
	src["user"] = "admin"
	o.fake.Put(index, SessionID(cookies["mac"]), src)
	if _, err := a.store.Delete(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := a.store.Update(ctx, "off", users.Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.SetPassword(ctx, "renew", "another-password", false); err != nil {
		t.Fatal(err)
	}
	cookies["foreign"] = "not-a-cookie-of-this-cluster"
	again := restarted(o, a)
	for name, cookie := range cookies {
		_, err := again.Check(ctx, cookie, true)
		if err == nil || errors.Is(err, ErrSessionUnchecked) {
			t.Errorf("%s: %v, want refused", name, err)
		}
		if _, ok := again.Lookup(ctx, cookie, true); ok {
			t.Errorf("%s: Lookup accepts it", name)
		}
	}
	// A refused cookie stays refused while OpenSearch does not answer.
	defer sessionsDown(o)()
	if _, err := again.Check(ctx, cookies["del"], true); err == nil || errors.Is(err, ErrSessionUnchecked) {
		t.Errorf("a signed-out session while OpenSearch does not answer: %v", err)
	}
}
