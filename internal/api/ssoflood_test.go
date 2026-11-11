// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/oidc/oidctest"
)

// ssoAuditLog is a server log whose audit records of failed single
// sign-ons are counted, as the audit alerts' tap would see them.
type ssoAuditLog struct {
	mu   sync.Mutex
	list []audit.Event
}

func (l *ssoAuditLog) logger(t *testing.T) *slog.Logger {
	sink := audit.NewSink(audit.SinkOptions{Dir: t.TempDir(), Server: "s1", NodeID: "n1"})
	sink.SetEnabled(false)
	sink.SetTap(func(ev audit.Event) {
		if ev.Message == "single sign-on failed" {
			l.mu.Lock()
			l.list = append(l.list, ev)
			l.mu.Unlock()
		}
	})
	return slog.New(audit.Handler(slog.NewTextHandler(io.Discard, nil), sink))
}

func (l *ssoAuditLog) records() []audit.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]audit.Event(nil), l.list...)
}

// ssoFlooder sends what anyone, not signed in, can send to the single
// sign-on routes, n times each.
func ssoFlooder(t *testing.T, base string, n int) {
	t.Helper()
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i := range n {
		text := url.QueryEscape(fmt.Sprintf("URGENT %d:\r\nyour session expired\u202e, sign in again at https://evil.example/login %s", i, strings.Repeat("é", 600)))
		for _, target := range []string{
			ssoStartPath + "?agreed=0",
			ssoCallbackPath + "?error=x&error_description=" + text,
			ssoCallbackPath + "?code=abc&state=nothing-under-way",
			samlStartPath,
		} {
			resp, err := cl.Get(base + target)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if strings.HasPrefix(target, ssoCallbackPath) && (resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login?sso_error=")) {
				t.Fatalf("%s: status %d to %q, want the sign-in page with its code as before", target, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
		resp, err := cl.PostForm(base+samlACSPath, url.Values{"SAMLResponse": {"x"}, "RelayState": {"y"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
}

// With single sign-on off, as on a new install, every such request used
// to write one audit record.
func TestSSOFailuresWriteNoAuditRecordWhileSingleSignOnIsOff(t *testing.T) {
	var log ssoAuditLog
	ts, _ := newTestServerWith(t, func(s *Server) { s.Log = log.logger(t) })
	ssoFlooder(t, ts.URL, 60)
	if got := log.records(); len(got) != 0 {
		t.Fatalf("300 requests from nobody wrote %d audit records, the first %+v", len(got), got[0])
	}
}

// With it on they are written once a minute for an address, and what the
// sender put in the callback is cut short and cleaned.
func TestSSOFailuresThatNameNobodyAreLimitedInTheAuditLog(t *testing.T) {
	var log ssoAuditLog
	ts, s := newSSOServer(t, oidctest.New(t), nil)
	s.Log = log.logger(t)
	ssoFlooder(t, ts.URL, 60)
	got := log.records()
	if len(got) != 1 {
		t.Fatalf("300 requests from one address wrote %d audit records, want 1", len(got))
	}
	if got[0].Fields["failures"] != "1" || got[0].SourceIP == "" {
		t.Errorf("record %+v", got[0])
	}
	// The callback's own text, whichever request came first.
	s.ssoRefused = ssoRefusals{}
	log.list = nil
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Get(ts.URL + ssoCallbackPath + "?error=" + strings.Repeat("e", 5000) + "&error_description=" +
		url.QueryEscape("line one\r\nline two\x00\u202e\u2028 "+strings.Repeat("é", 5000)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got = log.records()
	if len(got) != 1 {
		t.Fatalf("%d records", len(got))
	}
	reason := got[0].Fields["reason"]
	if n := len([]rune(reason)); n > 450 {
		t.Errorf("the reason is %d characters long", n)
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' {
			t.Fatalf("the reason holds %U: %q", r, reason)
		}
	}
	if !strings.Contains(reason, "line one  line two") {
		t.Errorf("reason %q", reason)
	}
}

func TestSSORefusalsLimit(t *testing.T) {
	var f ssoRefusals
	now := time.Now()
	if n := f.note("203.0.113.7", now); n != 1 {
		t.Fatalf("the first failure: %d to log", n)
	}
	for i := range 500 {
		if n := f.note("203.0.113.7", now.Add(time.Duration(i)*50*time.Millisecond)); n != 0 {
			t.Fatalf("failure %d within the minute: %d to log", i, n)
		}
	}
	if n := f.note("203.0.113.7", now.Add(61*time.Second)); n != 501 {
		t.Errorf("a minute later: %d to log, want the 501 since", n)
	}
	// Many addresses together stay under the total for a minute.
	f = ssoRefusals{}
	logged := 0
	for i := range 5000 {
		if f.note(fmt.Sprintf("2001:db8::%x", i), now.Add(time.Duration(i)*time.Millisecond)) > 0 {
			logged++
		}
	}
	if logged != ssoFailsAMinute {
		t.Errorf("5000 addresses in five seconds wrote %d records, want %d", logged, ssoFailsAMinute)
	}
	if n := f.note("2001:db8::ffff:1", now.Add(2*time.Minute)); n != 1 {
		t.Errorf("after the minute: %d to log", n)
	}
}
