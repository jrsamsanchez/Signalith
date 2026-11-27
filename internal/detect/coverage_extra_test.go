// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jrsamsanchez/signalith/internal/splcheck"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestTransformEncodings(t *testing.T) {
	tests := []struct {
		mod  string
		in   string
		want []string
	}{
		{"base64", "ab", []string{base64.StdEncoding.EncodeToString([]byte("ab"))}},
		{"utf16le", "ab", []string{"a\x00b\x00"}},
		{"wide", "ab", []string{"a\x00b\x00"}},
		{"utf16be", "ab", []string{"\x00a\x00b"}},
		{"utf16", "ab", []string{"\xff\xfea\x00b\x00"}},
		{"unknown", "ab", nil},
	}
	for _, tc := range tests {
		got := transform(tc.mod, []string{tc.in})
		if len(got) != len(tc.want) {
			t.Errorf("%s: %q, want %q", tc.mod, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: %q, want %q", tc.mod, got[i], tc.want[i])
			}
		}
	}
	// A rune outside the BMP is a surrogate pair.
	if got := encodeUTF16("\U0001F600", false, false); len(got) != 4 {
		t.Errorf("surrogate pair encodes to %d bytes", len(got))
	}
	if got := transform("windash", []string{"-a"}); len(got) < 2 {
		t.Errorf("windash gives %q", got)
	}
	if got := transform("base64offset", []string{"abc"}); len(got) != 3 {
		t.Errorf("base64offset gives %q", got)
	}
}

func TestSigmaLiteral(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"plain", "plain", true},
		{`a\*b`, "a*b", true},
		{`a\?b`, "a?b", true},
		{`a\\b`, `a\b`, true},
		{`trailing\`, `trailing\`, true},
		{`a\nb`, `a\nb`, true},
		{"a*b", "", false},
		{"a?b", "", false},
	}
	for _, tc := range tests {
		got, err := sigmaLiteral(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("sigmaLiteral(%q) = %q, %v", tc.in, got, err)
		}
	}
	if sigmaString(nil) != "" || sigmaString(3) != "3" || sigmaString("x") != "x" {
		t.Error("sigmaString")
	}
}

func TestSigmaFieldsOfNamedLogs(t *testing.T) {
	for _, strict := range []bool{false, true} {
		c := &sigmaConv{strict: strict}
		for in, want := range map[string]string{"Provider_Name": "provider", "EventID": "signature_id", "Computer": "host", "ComputerName": "host", "Data": "event_data"} {
			if got := c.eventDataField(in); got != want {
				t.Errorf("eventDataField(%s) = %s, want %s", in, got, want)
			}
		}
		for in, want := range map[string]string{"Provider_Name": "provider", "EventID": "signature_id", "computer": "host"} {
			if got := c.channelField("Some-Channel", in); got != want {
				t.Errorf("channelField(%s) = %s, want %s", in, got, want)
			}
		}
		if c.err != nil || len(c.warnings) != 0 {
			t.Errorf("known fields warn: %v %v", c.err, c.warnings)
		}
		if got := c.eventDataField("Nonsense"); got != "Nonsense" {
			t.Errorf("unknown event data field = %s", got)
		}
		if got := c.channelField("No-Such-Channel/Operational", "Nonsense"); got != "Nonsense" {
			t.Errorf("unknown channel field = %s", got)
		}
		if got := c.auditdField("Mixed_Case"); got != "Mixed_Case" {
			t.Errorf("mixed-case audit field = %s", got)
		}
		if got := c.auditdField("exe"); got != "auditd_exe" {
			t.Errorf("audit field exe = %s", got)
		}
		if len(c.warnings) != 3 {
			t.Errorf("warnings %v", c.warnings)
		}
		if strict != (c.err != nil) {
			t.Errorf("strict %v: err %v", strict, c.err)
		}
		if strict && !strings.Contains(c.err.Error(), "Nonsense") {
			t.Errorf("strict mode keeps the first approximation: %v", c.err)
		}
	}
}

func TestNeedsGeoIP(t *testing.T) {
	tests := []struct {
		d    Detection
		want bool
	}{
		{Detection{Tags: []string{"geoip"}, Query: "x=1"}, true},
		{Detection{Query: `src=* | iplocation src`}, true},
		{Detection{Query: `src=* | stats count by src`}, false},
		{Detection{Query: `(((`}, false},
	}
	for _, tc := range tests {
		if got := NeedsGeoIP(&tc.d); got != tc.want {
			t.Errorf("NeedsGeoIP(%+v) = %v", tc.d, got)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{2 * time.Hour: "2h", 5 * time.Minute: "5m", 90 * time.Second: "90s"} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%v) = %s, want %s", d, got, want)
		}
	}
}

func TestUseMacrosAndLookups(t *testing.T) {
	p := &Pack{}
	m := map[string]*splcheck.Macro{"m": {Name: "m"}}
	p.UseMacros(m)
	if p.macros["m"] == nil {
		t.Error("UseMacros")
	}
	l := map[string]*splcheck.Lookup{"t": {Name: "t"}}
	p.UseLookups(l)
	if p.Lookups()["t"] == nil {
		t.Error("UseLookups")
	}
}

func TestLoadMacrosAndLookupsErrors(t *testing.T) {
	macro := "name: m\ndefinition: sourcetype=x\n"
	lookupMeta := "name: t\nlookup_type: csv\ndescription: d\nmatch_type:\n    - WILDCARD(domain)\nmin_matches: 1\ncase_sensitive_match: false\n"
	csv := "domain,isIOC\nexample.com,TRUE\n"

	good := fstest.MapFS{
		"p/macros/m.yml":  {Data: []byte(macro)},
		"p/lookups/t.yml": {Data: []byte(lookupMeta)},
		"p/lookups/t.csv": {Data: []byte(csv)},
	}
	ms, err := loadMacros(good, "p")
	if err != nil || ms["m"] == nil {
		t.Fatalf("macros %v %v", ms, err)
	}
	ls, err := loadLookups(good, "p")
	if err != nil || ls["t"] == nil {
		t.Fatalf("lookups %v %v", ls, err)
	}

	if _, err := loadMacros(fstest.MapFS{"p/macros/bad.yml": {Data: []byte("definition: [")}}, "p"); err == nil {
		t.Error("a broken macro loaded")
	}
	if _, err := loadMacros(fstest.MapFS{}, "["); err == nil {
		t.Error("a bad pattern globbed")
	}
	if _, err := loadLookups(fstest.MapFS{}, "["); err == nil {
		t.Error("a bad pattern globbed")
	}
	for name, fsys := range map[string]fstest.MapFS{
		"no csv": {"p/lookups/t.yml": {Data: []byte(lookupMeta)}},
		"bad yml": {
			"p/lookups/t.yml": {Data: []byte("name: [")},
			"p/lookups/t.csv": {Data: []byte(csv)},
		},
		"misnamed": {
			"p/lookups/other.yml": {Data: []byte(lookupMeta)},
			"p/lookups/other.csv": {Data: []byte(csv)},
		},
	} {
		if _, err := loadLookups(fsys, "p"); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestExceptionValidate(t *testing.T) {
	until := time.Now().Add(time.Hour)
	from := until.Add(time.Hour)
	many := map[string]string{}
	for i := range maxExceptionMatch + 1 {
		many["f"+strings.Repeat("x", i)] = "v"
	}
	tests := []struct {
		name string
		e    Exception
		want string
	}{
		{"good", Exception{ID: "e", Match: map[string]string{"host": "a"}}, ""},
		{"no id", Exception{Match: map[string]string{"host": "a"}}, "id is required"},
		{"too many fields", Exception{ID: "e", Match: many}, "at most"},
		{"bad field", Exception{ID: "e", Match: map[string]string{"a b": "x"}}, "not a field name"},
		{"empty value", Exception{ID: "e", Match: map[string]string{"host": " "}}, "needs a value"},
		{"long value", Exception{ID: "e", Match: map[string]string{"host": strings.Repeat("v", maxExceptionValue+1)}}, "longer than"},
		{"everything forever", Exception{ID: "e"}, "needs an end time"},
		{"until before from", Exception{ID: "e", Match: map[string]string{"host": "a"}, From: &from, Until: &until}, "until must be after from"},
		{"bad scope", Exception{ID: "e", Match: map[string]string{"host": "a"}, Scope: "everything"}, "scope"},
		{"good scope", Exception{ID: "e", Match: map[string]string{"host": "a"}, Scope: ScopeAll}, ""},
		{"long comment", Exception{ID: "e", Match: map[string]string{"host": "a"}, Comment: strings.Repeat("c", maxCommentLen+1)}, "comment"},
	}
	for _, tc := range tests {
		err := tc.e.Validate()
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// failingRunStore fails every read, counting them.
type failingRunStore struct {
	RunStore
	reads atomic.Int32
}

func (f *failingRunStore) Get(context.Context, string, string) (json.RawMessage, store.Version, bool, error) {
	f.reads.Add(1)
	return nil, store.Version{}, false, errors.New("down")
}

func TestFollowerRunLogsAndStops(t *testing.T) {
	rs := &failingRunStore{RunStore: NewMemoryRunStore()}
	var buf syncBuffer
	f := &Follower{Tenant: "acme", Self: "b", Runtime: rs, RuntimeIndex: "rt", Log: slog.New(slog.NewTextHandler(&buf, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.Run(ctx, 20*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for rs.reads.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	if rs.reads.Load() < 2 {
		t.Errorf("read %d times", rs.reads.Load())
	}
	if !strings.Contains(buf.String(), "could not read which detections this server runs") {
		t.Errorf("log %q", buf.String())
	}

	// Without a logger the failure is dropped, not a panic.
	f = &Follower{Tenant: "acme", Self: "b", Runtime: rs, RuntimeIndex: "rt"}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		f.Run(ctx, 20*time.Millisecond)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done
}

func TestSchedulerForget(t *testing.T) {
	s := &Scheduler{}
	s.det = map[string]*detEntry{}
	s.taken = map[string]time.Time{}
	s.Forget()
	if s.det != nil || s.taken != nil {
		t.Error("Forget kept the run state")
	}
}

// syncBuffer is a log the follower's goroutine writes while the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
