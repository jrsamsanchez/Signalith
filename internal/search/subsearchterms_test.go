// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestSubsearchTerms(t *testing.T) {
	e := lookupEngine(t)
	if _, err := e.Run(context.Background(), `datamodel=Web [| inputlookup hosts | fields host, site] | head 5`); err != nil {
		t.Fatal(err)
	}
	body := asJSON(e.Store.(*fakeStore).bodies[0])
	for _, want := range []string{`"h1"`, `"Dallas"`, `"h2"`, `"Austin"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s: %s", want, body)
		}
	}
	if strings.Contains(body, `"bob"`) {
		t.Errorf("fields dropped by the subsearch searched: %s", body)
	}

	// In | search, with NOT; after a command it filters in memory.
	e = lookupEngine(t)
	if _, err := e.Run(context.Background(), `* | search NOT [inputlookup owners | where team="Data" | fields user] | table user`); err != nil {
		t.Fatal(err)
	}
	if body := asJSON(e.Store.(*fakeStore).bodies[0]); !strings.Contains(body, `"must_not"`) || !strings.Contains(body, `"amy"`) || strings.Contains(body, `"bob"`) {
		t.Errorf("body = %s", body)
	}
	res := runLookup(t, `* | head 10 | search NOT [inputlookup owners | where team="Data" | fields user] | table user`)
	for _, r := range res.Rows {
		if r["user"] == "amy" {
			t.Errorf("rows = %v", res.Rows)
		}
	}

	// No rows match nothing, and NOT of them everything.
	e = lookupEngine(t)
	if _, err := e.Run(context.Background(), `* [| inputlookup owners | where team="none"]`); err != nil {
		t.Fatal(err)
	}
	if body := asJSON(e.Store.(*fakeStore).bodies[0]); !strings.Contains(body, "match_none") {
		t.Errorf("empty subsearch: %s", body)
	}

	// tstats names a subsearch's fields with the node.
	e = lookupEngine(t)
	e.Store = &fakeStore{responses: []string{`{"hits":{"total":{"value":0}},"aggregations":{"groups":{"buckets":[]}}}`}}
	if _, err := e.Run(context.Background(), `| tstats count from datamodel=Endpoint.Processes where [| inputlookup hosts | rename host as Processes.process_name | fields Processes.process_name] by Processes.dest`); err != nil {
		t.Fatal(err)
	}
	if body := asJSON(e.Store.(*fakeStore).bodies[0]); !strings.Contains(body, `"process_name"`) || strings.Contains(body, "Processes.") {
		t.Errorf("tstats subsearch: %s", body)
	}

	// Explain and the plan compile without running the subsearch.
	e = lookupEngine(t)
	q := mustParse(t, `datamodel=Web [| inputlookup hosts | fields host]`)
	if _, err := e.Compile(q); err != nil {
		t.Fatal(err)
	}
	if n := len(e.Store.(*fakeStore).bodies); n != 0 {
		t.Errorf("Compile searched %d times", n)
	}
	// A tenant's subsearch reads only the tenant's indexes.
	e.Opt.IndexPrefix = "signalith.t.acme"
	if _, err := e.Compile(mustParse(t, `datamodel=Web [search index=signalith-* | fields host]`)); err == nil {
		t.Error("a tenant's subsearch of another index compiled")
	}
}

func TestSubsearchTermsLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("v\n")
	for i := range maxSubsearchTerms + 1 {
		b.WriteString("x" + strings.Repeat("y", i%5) + string(rune('a'+i%26)) + "\n")
	}
	e := lookupEngine(t)
	if _, err := e.Lookups.Put("big", []byte(b.String())); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), `* [| inputlookup big]`); err == nil || !strings.Contains(err.Error(), "narrow it") {
		t.Errorf("err = %v", err)
	}
}

func mustParse(t *testing.T, src string) *query.Query {
	t.Helper()
	q, err := query.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
