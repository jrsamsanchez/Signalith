// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// recorded runs write against a recorder and returns the status and the
// JSON body.
func recorded(t *testing.T, write func(w http.ResponseWriter)) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	write(rec)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %q", rec.Body.String())
	}
	return rec.Code, out
}

// Each kind of error a store gives maps to the status the page acts on.
func TestErrorStatuses(t *testing.T) {
	s := &Server{}
	for _, c := range []struct {
		name   string
		write  func(w http.ResponseWriter)
		status int
	}{
		{"user stale", func(w http.ResponseWriter) { writeUserError(w, users.ErrStale) }, http.StatusPreconditionFailed},
		{"user busy", func(w http.ResponseWriter) { writeUserError(w, users.ErrBusy) }, http.StatusServiceUnavailable},
		{"user missing", func(w http.ResponseWriter) { writeUserError(w, users.ErrNotFound) }, http.StatusNotFound},
		{"user exists", func(w http.ResponseWriter) { writeUserError(w, users.ErrExists) }, http.StatusConflict},
		{"user other", func(w http.ResponseWriter) { writeUserError(w, errors.New("bad")) }, http.StatusBadRequest},
		{"mfa wrong", func(w http.ResponseWriter) { s.writeMFAError(w, users.ErrWrongCode) }, http.StatusBadRequest},
		{"mfa no setup", func(w http.ResponseWriter) { s.writeMFAError(w, users.ErrNoSetup) }, http.StatusConflict},
		{"mfa on", func(w http.ResponseWriter) { s.writeMFAError(w, users.ErrMFAOn) }, http.StatusConflict},
		{"mfa builtin", func(w http.ResponseWriter) { s.writeMFAError(w, users.ErrNoBuiltinMFA) }, http.StatusConflict},
		{"mfa other", func(w http.ResponseWriter) { s.writeMFAError(w, users.ErrNotFound) }, http.StatusNotFound},
		{"notebook bad", func(w http.ResponseWriter) { writeNotebookError(w, badRequest{errors.New("bad")}) }, http.StatusBadRequest},
		{"notebook forbidden", func(w http.ResponseWriter) { writeNotebookError(w, forbidden{errors.New("no")}) }, http.StatusForbidden},
		{"notebook invalid", func(w http.ResponseWriter) {
			writeNotebookError(w, &notebooks.ValidationError{Problems: []string{"title is required"}})
		}, http.StatusBadRequest},
		{"notebook busy", func(w http.ResponseWriter) { writeNotebookError(w, notebooks.ErrBusy) }, http.StatusConflict},
		{"notebook case gone", func(w http.ResponseWriter) { writeNotebookError(w, cases.ErrNotFound) }, http.StatusNotFound},
		{"notebook other", func(w http.ResponseWriter) { writeNotebookError(w, errors.New("down")) }, http.StatusBadGateway},
		{"feed input", func(w http.ResponseWriter) { writeFeedError(w, &intel.InputError{}) }, http.StatusBadRequest},
		{"feed unknown", func(w http.ResponseWriter) { writeFeedError(w, intel.ErrUnknownFeed) }, http.StatusNotFound},
		{"feed read only", func(w http.ResponseWriter) { writeFeedError(w, intel.ErrReadOnly) }, http.StatusConflict},
		{"feed file", func(w http.ResponseWriter) {
			writeFeedError(w, &intel.FileError{Path: "intel_feeds.yaml", Err: fs.ErrPermission})
		}, http.StatusServiceUnavailable},
		{"feed busy", func(w http.ResponseWriter) { writeFeedError(w, intel.ErrBusy) }, http.StatusTooManyRequests},
		{"feed other", func(w http.ResponseWriter) { writeFeedError(w, errors.New("x")) }, http.StatusInternalServerError},
		{"retention confirm", func(w http.ResponseWriter) {
			writeRetentionError(w, &retention.ConfirmError{Check: &retention.RestoreCheck{Message: "it restores 3 days"}})
		}, http.StatusConflict},
		{"retention policy", func(w http.ResponseWriter) {
			writeRetentionError(w, &retention.PolicyError{Problems: []string{"keep_days must be at least 1"}})
		}, http.StatusBadRequest},
		{"retention unknown", func(w http.ResponseWriter) { writeRetentionError(w, retention.ErrUnknownCategory) }, http.StatusNotFound},
		{"retention managed", func(w http.ResponseWriter) { writeRetentionError(w, retention.ErrManaged) }, http.StatusBadRequest},
		{"retention busy", func(w http.ResponseWriter) { writeRetentionError(w, retention.ErrBusy) }, http.StatusConflict},
		{"retention opensearch", func(w http.ResponseWriter) { writeRetentionError(w, retention.ErrOpenSearch) }, http.StatusServiceUnavailable},
		{"retention other", func(w http.ResponseWriter) { writeRetentionError(w, errors.New("x")) }, http.StatusInternalServerError},
		{"sign-in other", func(w http.ResponseWriter) { writeSignInError(w, errors.New("x")) }, http.StatusInternalServerError},
		{"sign-in", func(w http.ResponseWriter) { writeSignInError(w, errMFAUnavailable) }, http.StatusServiceUnavailable},
	} {
		code, out := recorded(t, c.write)
		if code != c.status || out["error"] == "" || out["error"] == nil {
			t.Errorf("%s: %d %v, want %d", c.name, code, out, c.status)
		}
	}
	// A policy error names the fields it is about and reads as a sentence.
	_, out := recorded(t, func(w http.ResponseWriter) {
		writeRetentionError(w, &retention.PolicyError{Problems: []string{"keep_days must be at least 1"}})
	})
	if out["error"] != "Keep_days must be at least 1" {
		t.Errorf("policy error %v", out)
	}
	// A refused sign-in that can be tried again says when.
	rec := httptest.NewRecorder()
	writeSignInError(rec, errMFAUnavailable)
	if rec.Header().Get("Retry-After") != "30" {
		t.Errorf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
}

func TestQueryAndSearchErrorText(t *testing.T) {
	if got := queryErrText(&query.Error{Pos: 4, Msg: "unexpected |"}); got != "unexpected | (at character 5)" {
		t.Errorf("query error %q", got)
	}
	if got := queryErrText(errors.New("plain")); got != "plain" {
		t.Errorf("other error %q", got)
	}
	_, err := query.Parse("user=bob | stats")
	if err == nil || !strings.Contains(queryErrText(err), "(at character") {
		t.Errorf("parse error text %v", err)
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{&search.QueryError{Msg: "no such field"}, "no such field"},
		{search.ErrBusy, "Too many searches"},
		{fmt.Errorf("x: %w", search.ErrUserBusy), "Too many searches"},
		{context.DeadlineExceeded, "took too long"},
		{errors.New("boom"), "The search failed: boom"},
	} {
		if got := searchErrText(c.err); !strings.Contains(got, c.want) {
			t.Errorf("%v: %q", c.err, got)
		}
	}
}

func TestSmallTextHelpers(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{webURL("http", "siem.example.com", "80"), "http://siem.example.com"},
		{webURL("https", "2001:db8::1", "443"), "https://[2001:db8::1]"},
		{webURL("https", "siem.example.com", "8443"), "https://siem.example.com:8443"},
		{webURL("http", "2001:db8::1", "8080"), "http://[2001:db8::1]:8080"},
		{sentence(""), ""},
		{sentence("it broke"), "It broke."},
		{sentence("Done."), "Done."},
		{plainFileError(errors.New("open signalith.yaml: permission denied")), "Open signalith.yaml: permission denied."},
		{plainFileError(errors.New("yaml: line 3: did not find expected key")), "It is not valid YAML (line 3: did not find expected key)."},
		{plainFileError(errors.New("yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str into int\n  line 9: x")), "It is not laid out as Signalith writes it (line 4, line 9)."},
		{plainFileError(errors.New("yaml: unmarshal errors:\n  something")), "It is not laid out as Signalith writes it."},
		{scopeText("pack:windows"), "every detection of the windows pack"},
		{scopeText("tag:phish"), "every detection tagged phish"},
		{scopeText(""), "every detection"},
		{joinAnd(nil), ""},
		{joinAnd([]string{"a"}), "a"},
		{joinAnd([]string{"a", "b", "c"}), "a, b and c"},
		{ticketingHost("https://acme.service-now.com/x"), "acme.service-now.com"},
		{ticketingHost("::bad"), ""},
		{sampleWhere(&sample.Activity{Command: true, Server: "siem-a"}), "Started with the signalith sample-data command on siem-a."},
		{sampleWhere(&sample.Activity{Command: true}), "Started with the signalith sample-data command."},
		{sampleWhere(&sample.Activity{Server: "siem-b"}), "Started on the server siem-b."},
		{sampleWhere(&sample.Activity{}), ""},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "no-port"
	if clientHost(r) != "no-port" {
		t.Errorf("clientHost %q", clientHost(r))
	}
	r.RemoteAddr = "192.0.2.4:5555"
	if clientHost(r) != "192.0.2.4" {
		t.Errorf("clientHost %q", clientHost(r))
	}
	for host, want := range map[string]bool{"LOCALHOST": true, "127.0.0.2": true, "::1": true, "192.0.2.1": false, "siem": false} {
		if isLoopback(host) != want {
			t.Errorf("isLoopback(%q)", host)
		}
	}
	hosts := passkeyHosts(users.MFA{Passkeys: []users.Passkey{{RPID: "siem.example.com"}, {RPID: "localhost"}, {RPID: "siem.example.com"}}})
	if strings.Join(hosts, ",") != "siem.example.com,localhost" {
		t.Errorf("passkeyHosts %v", hosts)
	}
	if passkeyHosts(users.MFA{}) != nil {
		t.Error("no passkeys, no hosts")
	}
}

func TestGRPCCodes(t *testing.T) {
	for status, want := range map[int]int{400: 3, 415: 3, 401: 16, 403: 7, 408: 4, 413: 8, 503: 14, 500: 2, 200: 2} {
		if got := grpcCode(status); got != want {
			t.Errorf("grpcCode(%d) = %d, want %d", status, got, want)
		}
	}
}

func TestHostAndAddressParsing(t *testing.T) {
	for h, want := range map[string]bool{
		"":                       false,
		strings.Repeat("a", 301): false,
		"siem.example.com":       true,
		"siem.example.com:8443":  true,
		"siem.example.com:":      false,
		"[2001:db8::1]:443":      true,
		"2001:db8::1":            false,
		"bad host":               false,
		"evil/x":                 false,
		"[::1]":                  false,
	} {
		if got := validHostHeader(h); got != want {
			t.Errorf("validHostHeader(%q) = %v", h, got)
		}
	}
	for raw, want := range map[string]bool{
		"http://localhost:11434/v1": true, "http://ollama.localhost": true, "http://host.docker.internal:1234": true,
		"http://10.1.2.3": true, "http://169.254.1.1": true, "http://127.0.0.1": true,
		"https://api.example.com": false, "http://203.0.113.9": false, "::nope": false, "": false,
	} {
		if got := isLocalModel(raw); got != want {
			t.Errorf("isLocalModel(%q) = %v", raw, got)
		}
	}
	for raw, want := range map[string]string{
		"192.0.2.7": "192.0.2.7", " 192.0.2.7:443 ": "192.0.2.7", "[2001:db8::5]": "2001:db8::5",
		"[2001:db8::5]:80": "2001:db8::5", "::ffff:192.0.2.9": "192.0.2.9",
	} {
		a, ok := parseForwardedAddr(raw)
		if !ok || a != netip.MustParseAddr(want) {
			t.Errorf("parseForwardedAddr(%q) = %v %v", raw, a, ok)
		}
	}
	for _, raw := range []string{"", "unknown", "[nope]", "_hidden"} {
		if _, ok := parseForwardedAddr(raw); ok {
			t.Errorf("parseForwardedAddr(%q) parsed", raw)
		}
	}
}

// Errors that carry addresses, paths or OpenSearch's own words are kept
// out of answers to the browser.
func TestInternalDetail(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&store.Error{Status: 500, Body: "x"}, true},
		{&url.Error{Op: "Get", URL: "http://os:9200", Err: errors.New("refused")}, true},
		{&fs.PathError{Op: "open", Path: "/etc/x", Err: fs.ErrPermission}, true},
		{errors.New("opensearch returned 500"), true},
		{errors.New("could not reach https://os:9200"), true},
		{errors.New("title is required"), false},
	} {
		if got := internalDetail(c.err); got != c.want {
			t.Errorf("internalDetail(%v) = %v", c.err, got)
		}
	}
}

func TestFeedChanges(t *testing.T) {
	a := intel.Feed{Name: "x", URL: "https://feeds.example.com/a.txt", Format: "lines", Interval: time.Hour, Weight: 1, Enabled: true,
		Password: "one", Headers: map[string]string{"A": "1"}}
	b := a
	if got := feedChanges(a, b); got != "" {
		t.Errorf("no change: %q", got)
	}
	b.URL, b.Weight, b.Enabled, b.Password, b.Headers = "https://feeds.example.com/b.txt", 2, false, "two", map[string]string{"A": "2"}
	got := feedChanges(a, b)
	for _, want := range []string{"url: https://feeds.example.com/a.txt -> https://feeds.example.com/b.txt", "weight: 1 -> 2", "enabled: true -> false", "password changed", "headers changed"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "one") || strings.Contains(got, "two") {
		t.Errorf("a password in the change: %q", got)
	}
}

func TestTaskChanges(t *testing.T) {
	if taskChanges(nil, &cases.Task{}) != nil {
		t.Error("nil before")
	}
	got := taskChanges(&cases.Task{Title: "a", Owner: "andy"}, &cases.Task{Title: "b", Owner: "bea", Done: true})
	if strings.Join(got, "; ") != "title: a -> b; owner: andy -> bea; done: false -> true" {
		t.Errorf("changes %v", got)
	}
}

func TestSampleErrorTextCases(t *testing.T) {
	for _, c := range []struct {
		op   string
		err  error
		st   *sample.State
		want string
	}{
		{"load", sample.ErrBusy, nil, "Another sample-data load"},
		{"load", sample.ErrAlreadyLoaded, nil, "already loaded"},
		{"load", sample.ErrPartial, nil, "did not finish"},
		{"load", sample.ErrUnnamedLoad, nil, "did not say which load"},
		{"remove", sample.ErrTakenOver, nil, "took the job over"},
		{"load", context.Canceled, nil, "stopped before it could load the sample data"},
		{"remove", &url.Error{Op: "Post", URL: "https://os:9200", Err: errors.New("reset")}, nil, "lost its connection"},
		{"load", &store.Error{Status: 429}, nil, "too busy"},
		{"load", sample.ErrNothingWritten, nil, "did not accept any"},
		{"load", errors.New("odd"), &sample.State{Partial: true}, "Remove what was loaded"},
		{"remove", errors.New("odd"), &sample.State{Partial: true, Removing: true}, "Finish removing"},
		{"remove", errors.New("odd"), nil, "could not remove the sample data. Try again."},
	} {
		if got, _ := sampleErrorText(c.op, c.err, c.st); !strings.Contains(got, c.want) {
			t.Errorf("%s %v: %q", c.op, c.err, got)
		}
	}
}
