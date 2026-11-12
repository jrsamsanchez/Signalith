// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
)

// auditTap is a server log whose audit records are kept, as the audit
// alerts' tap sees them.
type auditTap struct {
	mu   sync.Mutex
	list []audit.Event
}

func (l *auditTap) logger(t *testing.T) *slog.Logger {
	sink := audit.NewSink(audit.SinkOptions{Dir: t.TempDir(), Server: "s1", NodeID: "n1"})
	sink.SetEnabled(false)
	sink.SetTap(func(ev audit.Event) {
		l.mu.Lock()
		l.list = append(l.list, ev)
		l.mu.Unlock()
	})
	return slog.New(audit.Handler(slog.NewTextHandler(io.Discard, nil), sink))
}

// count returns how many records have the message, and the records.
func (l *auditTap) count(msg string) (int, []audit.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []audit.Event
	for _, ev := range l.list {
		if ev.Message == msg {
			out = append(out, ev)
		}
	}
	return len(out), out
}

// RT-01: a name or password far longer than any account's is refused
// before the sign-in limits, so they keep nothing of it, and before the
// audit log; a sign-in request is read only up to maxLoginBody.
func TestOversizedSignInsAreRefusedFirst(t *testing.T) {
	var tap auditTap
	s, base, cl, _ := newLockoutServer(t, nil)
	s.Log = tap.logger(t)
	long := strings.Repeat("n", maxSignInName+1)
	for range 40 {
		if r := signInWith(t, cl, base, attempt{user: long, pass: "guess"}); r.code != http.StatusUnauthorized {
			t.Fatalf("long name: %d %v", r.code, r.body)
		}
		if r := signInWith(t, cl, base, attempt{user: "vera", pass: strings.Repeat("p", maxSignInPassword+1)}); r.code != http.StatusUnauthorized {
			t.Fatalf("long password: %d %v", r.code, r.body)
		}
	}
	// Basic credentials go the same way.
	req, _ := http.NewRequest("GET", base+"/api/me", nil)
	req.SetBasicAuth(long, "guess")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Basic with a long name: %d", resp.StatusCode)
	}
	if n, _ := tap.count("sign-in failed"); n != 0 {
		t.Errorf("%d audit records of oversized sign-ins", n)
	}
	// Eighty refusals counted toward nothing: the right password still
	// works from here.
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "the-v-password"}); r.code != http.StatusOK {
		t.Errorf("vera after the oversized tries: %d %v", r.code, r.body)
	}
	// A body past maxLoginBody is not read.
	big := `{"username":"vera","password":"the-v-password","x":"` + strings.Repeat("x", maxLoginBody) + `"}`
	resp, err = cl.Post(base+"/api/login", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a %d byte sign-in: %d", len(big), resp.StatusCode)
	}
}

// AUTHRT-02: failed sign-ins with made-up names from one client behind a
// trusted proxy that names no client (so it is shared, with no
// per-address limit) write signInFailsPerClient records a minute, not one
// each; a lockout is always written.
func TestFailedSignInsHaveAnAuditBudget(t *testing.T) {
	var tap auditTap
	s, base, cl, _ := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
	})
	s.Log = tap.logger(t)
	for i := range 60 {
		if r := signInWith(t, cl, base, attempt{user: fmt.Sprint("made-up", i), pass: "guess"}); r.code != http.StatusUnauthorized {
			t.Fatalf("sign-in %d: %d %v", i, r.code, r.body)
		}
	}
	n, got := tap.count("sign-in failed")
	if n != signInFailsPerClient {
		t.Fatalf("60 failed sign-ins wrote %d records, want %d", n, signInFailsPerClient)
	}
	if got[0].User != "made-up0" {
		t.Errorf("first record %+v", got[0])
	}
}

func TestSignInFailureBudget(t *testing.T) {
	var f ssoRefusals
	now := time.Now()
	logged := 0
	for i := range 1000 {
		// Two hundred clients (IPv6 /64s), five failures each.
		if n, _ := f.noteUpTo(fmt.Sprintf("2001:db8:%x::/64", i%200), now.Add(time.Duration(i)*10*time.Millisecond), signInFailsPerClient, signInFailsAMinute); n > 0 {
			logged++
		}
	}
	if logged != signInFailsAMinute {
		t.Errorf("1000 failures from 200 clients in ten seconds wrote %d records, want %d", logged, signInFailsAMinute)
	}
	// The minute after, the first record says what was left out, once.
	_, skipped := f.noteUpTo("192.0.2.1", now.Add(2*time.Minute), signInFailsPerClient, signInFailsAMinute)
	if skipped != 1000-signInFailsAMinute {
		t.Errorf("left out: %d, want %d", skipped, 1000-signInFailsAMinute)
	}
	if _, skipped = f.noteUpTo("192.0.2.1", now.Add(2*time.Minute), signInFailsPerClient, signInFailsAMinute); skipped != 0 {
		t.Errorf("left out said twice: %d", skipped)
	}
}

// AUTHRT-04: refusals from one IPv6 /64 count as one client's, however
// many addresses in it they come from, and what the total leaves out is
// said in one record.
func TestSSORefusalsCountAnIPv6NetworkAsOne(t *testing.T) {
	var tap auditTap
	srv := &Server{}
	srv.Log = tap.logger(t)
	now := time.Now()
	for i := range 500 {
		c := clientInfo{Addr: netip.MustParseAddr(fmt.Sprintf("2001:db8:1:2::%x", i+1))}
		if n, _ := srv.ssoRefused.noteAll(c.key(), now); n > 0 && i > 0 {
			t.Fatalf("address %d of the same /64 wrote a record", i)
		}
	}
	for i := range 200 {
		c := clientInfo{Addr: netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::1", i+10))}
		srv.ssoRefused.noteAll(c.key(), now)
	}
	_, skipped := srv.ssoRefused.noteAll("192.0.2.1", now.Add(time.Minute))
	if skipped != 200-(ssoFailsAMinute-1) {
		t.Errorf("left out %d, want %d", skipped, 200-(ssoFailsAMinute-1))
	}
	srv.logSkipped("failed single sign-ons", skipped)
	if n, got := tap.count("audit records left out"); n != 1 || got[0].Fields["count"] != fmt.Sprint(skipped) {
		t.Errorf("summary records %+v", got)
	}
}
