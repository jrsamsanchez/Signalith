// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// namesDays reports whether an index list names only days of the indices
// starting with stem, today among them, plus any exclusions.
func namesDays(index, stem string) bool {
	today := stem + time.Now().UTC().Format("2006.01.02") + "*"
	found := false
	for _, p := range strings.Split(index, ",") {
		switch {
		case strings.HasPrefix(p, "-"):
		case !strings.HasPrefix(p, stem):
			return false
		case p == today:
			found = true
		}
	}
	return found
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestNarrowToDays(t *testing.T) {
	for _, c := range []struct {
		index, from, to, want string
	}{
		// All data and one data model, within a day.
		{"signalith-*,-signalith-risk-*", "2026-10-17T10:00:00Z", "2026-10-17T12:00:00Z",
			"signalith-*-2026.10.17*,-signalith-risk-*"},
		{"signalith-network-*", "2026-10-17T10:00:00Z", "2026-10-17T12:00:00Z", "signalith-network-2026.10.17*"},
		// An hour either side reaches the day before and after.
		{"signalith-network-*", "2026-10-17T00:30:00Z", "2026-10-17T23:30:00Z",
			"signalith-network-2026.10.16*,signalith-network-2026.10.17*,signalith-network-2026.10.18*"},
		// Whole months and years are one pattern each.
		{"signalith-network-*", "2026-09-30T12:00:00Z", "2026-11-02T12:00:00Z",
			"signalith-network-2026.09.30*,signalith-network-2026.10.*,signalith-network-2026.11.01*,signalith-network-2026.11.02*"},
		{"signalith-network-*", "2024-12-31T12:00:00Z", "2026-01-01T12:00:00Z",
			"signalith-network-2024.12.31*,signalith-network-2025.*,signalith-network-2026.01.01*"},
		// Patterns it does not know stay as they are.
		{"signalith-network-2026.10.*", "2026-10-17T10:00:00Z", "2026-10-17T12:00:00Z", "signalith-network-2026.10.*"},
		{"signalith-net*", "2026-10-17T10:00:00Z", "2026-10-17T12:00:00Z", "signalith-net*"},
		{"signalith-a-b-*", "2026-10-17T10:00:00Z", "2026-10-17T12:00:00Z", "signalith-a-b-*"},
		{"signalith-*,signalith_summary-*", "2026-10-17T10:00:00Z", "2026-10-17T12:00:00Z", "signalith-*,signalith_summary-*"},
		{"other-*", "2026-10-17T10:00:00Z", "2026-10-17T12:00:00Z", "other-*"},
		// So do ranges that end before they start.
		{"signalith-network-*", "2026-10-17T10:00:00Z", "2026-10-14T12:00:00Z", "signalith-network-*"},
	} {
		if got := narrowToDays(c.index, "signalith", at(c.from), at(c.to)); got != c.want {
			t.Errorf("%s %s..%s:\n got %s\nwant %s", c.index, c.from, c.to, got, c.want)
		}
	}
	// A list too long for the request line keeps the whole pattern.
	long := strings.Repeat("x", 200)
	if got := narrowToDays(long+"-*", long, at("2026-10-02T12:00:00Z"), at("2026-10-29T12:00:00Z")); got != long+"-*" {
		t.Errorf("long list = %d bytes", len(got))
	}
	for _, d := range []string{"2026-10-02T12:00:00Z", "2001-03-02T12:00:00Z"} {
		got := narrowToDays("signalith-*", "signalith", at("2000-01-02T12:00:00Z"), at(d))
		if n := len(url.PathEscape(got)); n > maxIndexList {
			t.Errorf("index list of %d bytes", n)
		}
	}
}

func TestNarrowedPatternsMatchDayParts(t *testing.T) {
	got := narrowToDays("signalith-*,-signalith-risk-*", "signalith", at("2026-10-17T10:00:00Z"), at("2026-10-17T12:00:00Z"))
	matches := func(name string) bool {
		for _, p := range strings.Split(got, ",") {
			if ok, _ := path.Match(p, name); ok {
				return true
			}
		}
		return false
	}
	for _, name := range []string{"signalith-network-2026.10.17", "signalith-network-2026.10.17-2", "signalith-network-2026.10.17-999"} {
		if !matches(name) {
			t.Errorf("%s is not searched", name)
		}
	}
	for _, name := range []string{"signalith-network-2026.10.16", "signalith-network-2026.10.18-2", "signalith_cases"} {
		if matches(name) {
			t.Errorf("%s is searched", name)
		}
	}
}

func TestSearchSpan(t *testing.T) {
	now := at("2026-10-17T12:00:00Z")
	from, to, ok := searchSpan("-24h", "", now)
	if !ok || !from.Equal(at("2026-10-16T12:00:00Z")) || !to.Equal(now.Add(ingest.MaxEventAhead)) {
		t.Errorf("-24h = %v %v %v", from, to, ok)
	}
	from, to, ok = searchSpan("2026-10-01T00:00:00Z", "-7d@d", now)
	if !ok || !from.Equal(at("2026-10-01T00:00:00Z")) || !to.Equal(at("2026-10-10T00:00:00Z")) {
		t.Errorf("absolute = %v %v %v", from, to, ok)
	}
	for _, earliest := range []string{"", "0", "yesterday"} {
		if _, _, ok := searchSpan(earliest, "", now); ok {
			t.Errorf("%q has a span", earliest)
		}
	}
	if _, _, ok := searchSpan("-24h", "tomorrow", now); ok {
		t.Error("latest=tomorrow has a span")
	}
}

// A search finds the events of every part of a busy day and asks only
// for that day's indices.
func TestSearchReadsOnlyItsDays(t *testing.T) {
	fake := ostest.New(t)
	fake.Put("signalith-network_traffic-2026.10.17", "a", map[string]any{"@timestamp": "2026-10-17T05:00:00Z", "src": "10.0.0.1"})
	fake.Put("signalith-network_traffic-2026.10.17-2", "b", map[string]any{"@timestamp": "2026-10-17T06:00:00Z", "src": "10.0.0.2"})
	fake.Put("signalith-network_traffic-2026.09.01", "c", map[string]any{"@timestamp": "2026-10-17T05:30:00Z", "src": "10.0.0.3"})
	e := &Engine{Store: store.New(store.Config{URL: fake.URL}), Opt: Options{IndexPrefix: "signalith"}}
	res, err := e.Run(context.Background(), `datamodel=Network_Traffic earliest=2026-10-17T04:00:00Z latest=2026-10-17T08:00:00Z`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range res.Rows {
		got = append(got, r["src"].(string))
	}
	if strings.Join(got, ",") != "10.0.0.2,10.0.0.1" && strings.Join(got, ",") != "10.0.0.1,10.0.0.2" {
		t.Errorf("rows = %v", got)
	}
	for _, r := range fake.Requests() {
		if strings.Contains(r, "_search") && !strings.Contains(r, "2026.10.17") {
			t.Errorf("request %s", r)
		}
	}
}
