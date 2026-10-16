package search

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// sessionEvents are sign-ins and sign-outs, newest first as OpenSearch
// returns them.
const sessionEvents = `{"hits":{"total":{"value":8},"hits":[
	{"_source":{"@timestamp":"2026-10-15T11:00:00Z","host":"h1","user":"amy","action":"logoff","message":"amy logged off"}},
	{"_source":{"@timestamp":"2026-10-15T10:30:00Z","host":"h1","user":"amy","action":"read","message":"amy read b"}},
	{"_source":{"@timestamp":"2026-10-15T10:20:00Z","host":"h2","user":"bob","action":"logon","message":"Accepted bob"}},
	{"_source":{"@timestamp":"2026-10-15T10:10:00Z","host":"h1","user":"amy","action":"read","message":"amy read a"}},
	{"_source":{"@timestamp":"2026-10-15T10:00:00Z","host":"h1","user":"amy","action":"logon","message":"Accepted amy"}},
	{"_source":{"@timestamp":"2026-10-15T09:00:00Z","host":"h1","user":"amy","action":"read","message":"amy read early"}},
	{"_source":{"@timestamp":"2026-10-15T08:00:00Z","host":"h1","message":"no user"}},
	{"_source":{"host":"h1","user":"amy","message":"no time"}}]}}`

func runTransaction(t *testing.T, src string) *Result {
	t.Helper()
	e := &Engine{Store: &fakeStore{responses: []string{sessionEvents}}}
	res, err := e.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("Run(%q): %v", src, err)
	}
	return res
}

func summary(rows []Row) []string {
	var out []string
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%v %v n=%v d=%v", r["_time"], r["user"], r["eventcount"], r["duration"]))
	}
	return out
}

func TestTransactionGroupsByFields(t *testing.T) {
	res := runTransaction(t, `* | transaction user`)
	want := []string{
		"2026-10-15T10:20:00Z bob n=1 d=0",
		"2026-10-15T09:00:00Z amy n=5 d=7200",
	}
	if got := summary(res.Rows); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	amy := res.Rows[1]
	if amy["host"] != "h1" || !reflect.DeepEqual(amy["action"], []any{"read", "logon", "logoff"}) {
		t.Errorf("amy = %v", amy)
	}
	if amy[RawField] != "amy read early\nAccepted amy\namy read a\namy read b\namy logged off" {
		t.Errorf("_raw = %q", amy[RawField])
	}
	if !strings.Contains(strings.Join(res.Columns, ","), "duration,eventcount") {
		t.Errorf("columns = %v", res.Columns)
	}
}

func TestTransactionLimits(t *testing.T) {
	for src, want := range map[string][]string{
		`* | transaction user maxpause=30m`: {
			"2026-10-15T10:20:00Z bob n=1 d=0", "2026-10-15T10:00:00Z amy n=4 d=3600", "2026-10-15T09:00:00Z amy n=1 d=0"},
		`* | transaction user maxspan=1h`: {
			"2026-10-15T10:20:00Z bob n=1 d=0", "2026-10-15T10:10:00Z amy n=3 d=3000", "2026-10-15T09:00:00Z amy n=2 d=3600"},
		`* | transaction user maxevents=2`: {
			"2026-10-15T11:00:00Z amy n=1 d=0", "2026-10-15T10:20:00Z bob n=1 d=0",
			"2026-10-15T10:10:00Z amy n=2 d=1200", "2026-10-15T09:00:00Z amy n=2 d=3600"},
		`* | transaction user startswith="accepted"`: {
			"2026-10-15T10:20:00Z bob n=1 d=0", "2026-10-15T10:00:00Z amy n=4 d=3600"},
		`* | transaction user startswith=(action=logon) endswith=(action=logoff)`: {
			"2026-10-15T10:00:00Z amy n=4 d=3600"},
		`* | transaction host, user endswith=logged | where eventcount > 1`: {
			"2026-10-15T09:00:00Z amy n=5 d=7200"},
		`* | transaction startswith=(action=logon)`: {
			"2026-10-15T10:20:00Z [bob amy] n=3 d=2400", "2026-10-15T10:00:00Z amy n=2 d=600"},
	} {
		if got := summary(runTransaction(t, src).Rows); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\ngot  %v\nwant %v", src, got, want)
		}
	}
}

func TestTransactionAsksForAllEvents(t *testing.T) {
	p := compile(t, `* | transaction user`)
	if p.Body["size"] == 100 {
		t.Errorf("size = %v", p.Body["size"])
	}
}

// FuzzTransaction runs transaction with any options over a few events: it
// must finish without panicking, and every row it gives must count at
// least one event.
func FuzzTransaction(f *testing.F) {
	for _, s := range []string{`user`, `host, user maxspan=1h maxpause=10m maxevents=2`,
		`user startswith="Accepted" endswith=(action=logoff)`, `startswith=(NOT action=read OR user IN (amy))`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, args string) {
		e := &Engine{Store: &fakeStore{responses: []string{sessionEvents}}}
		res, err := e.Run(context.Background(), `* | transaction `+args)
		if err != nil {
			return
		}
		for _, r := range res.Rows {
			if n, _ := r["eventcount"].(int64); n < 1 {
				t.Fatalf("%q: row %v", args, r)
			}
		}
	})
}
