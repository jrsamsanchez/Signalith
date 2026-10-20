// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestEventCount(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":1234,"relation":"eq"}}}`}}
	e := &Engine{Store: fs}
	if got := runRows(t, e, `| eventcount | eval n=count*2`, "count", "n"); !reflect.DeepEqual(got, []string{"1234 2468"}) {
		t.Errorf("eventcount = %v", got)
	}
	if fs.indexes[0] != "signalith-*,-signalith-risk-*" || fs.bodies[0]["track_total_hits"] != true || fs.bodies[0]["aggs"] != nil {
		t.Errorf("searched %s with %v", fs.indexes[0], fs.bodies[0])
	}
	if strings.Contains(asJSON(fs.bodies[0]), "range") {
		t.Errorf("eventcount reads a time range: %v", fs.bodies[0])
	}

	// One row per index, by name, from the indexes asked for.
	fs = &fakeStore{responses: []string{`{"hits":{"total":{"value":30}},"aggregations":{"indexes":{"sum_other_doc_count":0,"buckets":[
		{"key":"signalith-network-2026.10.17","doc_count":20},
		{"key":"signalith-authentication-2026.10.17","doc_count":10}]}}}`}}
	e = &Engine{Store: fs, Opt: Options{DefaultEarliest: "-24h"}}
	if got := runRows(t, e, `| eventcount summarize=false index=Signalith-Authentication-* index=signalith-network-*`, "index", "count"); !reflect.DeepEqual(got, []string{"signalith-authentication-2026.10.17 10", "signalith-network-2026.10.17 20"}) {
		t.Errorf("eventcount summarize=false = %v", got)
	}
	if fs.indexes[0] != "signalith-authentication-*,signalith-network-*" || strings.Contains(asJSON(fs.bodies[0]), "now-24h") {
		t.Errorf("searched %s with %v", fs.indexes[0], fs.bodies[0])
	}

	// A tenant's engine counts only the tenant's own indexes.
	fs = &fakeStore{responses: []string{`{"hits":{"total":{"value":5}}}`}}
	e = &Engine{Store: fs, Opt: Options{IndexPrefix: "signalith.t.acme"}}
	runRows(t, e, `| eventcount`, "count")
	if fs.indexes[0] != "signalith.t.acme-*,-signalith.t.acme-risk-*" {
		t.Errorf("tenant searched %s", fs.indexes[0])
	}
	for _, bad := range []string{"| eventcount index=signalith-*", "| eventcount index=signalith_findings", "| eventcount index=.security", "| eventcount index=other-*"} {
		if _, err := (&Engine{Store: &fakeStore{}, Opt: Options{IndexPrefix: "signalith.t.acme"}}).Run(context.Background(), bad); err == nil {
			t.Errorf("tenant ran %s", bad)
		}
	}
}

func TestEventCountParse(t *testing.T) {
	for _, bad := range []string{"user=x | eventcount", "index=x | eventcount", "| eventcount summarize=maybe", "| eventcount report_size=true", "| eventcount list_vix=t", "| eventcount foo=1", "| eventcount main", "| eventcount index=a,b", "| eventcount index=other:x", "| eventcount index=-x", "| stats count | appendpipe [eventcount]"} {
		if _, err := query.Parse(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
	q, err := query.Parse("| eventcount index=Signalith-* summarize=f report_size=false")
	if err != nil {
		t.Fatal(err)
	}
	if got := q.String(); got != "*\n| eventcount index=signalith-* summarize=false" {
		t.Errorf("String = %q", got)
	}
}
