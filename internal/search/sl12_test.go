// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Functions and forms an SPL user reaches for (SL-12).
func TestMoreSPLFunctions(t *testing.T) {
	five := `| makeresults count=5 | streamstats count as n`
	for q, want := range map[string]string{
		`| makeresults | eval h=sha512("abc") | table h`: "[map[h:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f]]",
		`| makeresults | eval p=round(pi(), 4), s=round(sin(pi()/2), 3), c=round(cos(0), 3), a=round(atan2(1, 1)*4, 4), h=hypot(3, 4) | table p s c a h`: "[map[a:3.1416 c:1 h:5 p:3.1416 s:1]]",
		`| makeresults | eval b=isbool(true()), n=isbool(1), e=exact(0.1+0.2) | table b n e`:                                                             "[map[b:true e:0.30000000000000004 n:false]]",
		`| makeresults | eval m=ipmask("255.255.255.0", "10.20.30.40") | table m`:                                                                        "[map[m:10.20.30.0]]",
		five + ` | head limit=2 | table n`:                                            "[map[n:1] map[n:2]]",
		five + ` | stats sumsq(n) as sq, varp(n) as vp, stdevp(n) as sp, var(n) as v`: "[map[sp:1.4142135623730951 sq:55 v:2.5 vp:2]]",
	} {
		res, err := (&Engine{}).Run(context.Background(), q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if got := fmt.Sprint(res.Rows); got != want {
			t.Errorf("%s = %s, want %s", q, got, want)
		}
	}
	res, err := (&Engine{}).Run(context.Background(), `| makeresults count=50 | eval r=random() | stats dc(r) as d, min(r) as lo, max(r) as hi`)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	if d, _ := asFloat(r["d"]); d < 45 {
		t.Errorf("random() gave %v distinct values of 50", r["d"])
	}
	if lo, _ := asFloat(r["lo"]); lo < 0 {
		t.Errorf("random() below 0: %v", lo)
	}
	if hi, _ := asFloat(r["hi"]); hi >= 1<<31 {
		t.Errorf("random() past 2^31-1: %v", hi)
	}
}

// stats over a * pattern expands to every matching field, as Splunk
// does, instead of reading the pattern as one field's name (SL-12).
func TestStatsWildcardFields(t *testing.T) {
	src := `| makeresults count=3 | streamstats count as n | eval bytes_in=n*10, bytes_out=n, user=if(n<3, "a", "b")`
	for q, want := range map[string]string{
		src + ` | stats sum(bytes*) by user`:                   "[map[sum(bytes_in):30 sum(bytes_out):3 user:a] map[sum(bytes_in):30 sum(bytes_out):3 user:b]]",
		src + ` | stats max(bytes_*) as max_* | table max_*`:   "[map[max_in:30 max_out:3]]",
		src + ` | stats values(*) as * by user | table user n`: "[map[n:[1 2] user:a] map[n:3 user:b]]",
	} {
		res, err := (&Engine{}).Run(context.Background(), q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if got := fmt.Sprint(res.Rows); got != want {
			t.Errorf("%s = %s, want %s", q, got, want)
		}
	}

	// Run against OpenSearch, the events are read and stats runs on them.
	one := `{"hits":{"total":{"value":1},"hits":[{"_source":{"@timestamp":"2026-10-11T10:00:00Z","user":"a","bytes_in":5}}]}}`
	fs := &fakeStore{responses: []string{one}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), `* | stats sum(bytes*) by user`)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(res.Rows); got != "[map[sum(bytes_in):5 user:a]]" {
		t.Errorf("pushed down wildcard stats = %s", got)
	}

	for _, q := range []string{
		`* | stats count by *`,
		`* | timechart sum(bytes*)`,
		`* | streamstats sum(bytes*)`,
		`* | chart sum(bytes*) by user`,
	} {
		_, err := (&Engine{}).Run(context.Background(), q)
		if err == nil || !strings.Contains(err.Error(), "wildcard") {
			t.Errorf("%s: err %v, want a wildcard refusal", q, err)
		}
	}
}
