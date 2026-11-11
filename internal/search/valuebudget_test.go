// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// TestManyValuesOnManyRowsAreRefused covers RT-203: a short search that
// puts a 10,000-value field on each of 10,000 rows held gigabytes, since
// the budget counted a one-letter value as two bytes. Every way to make
// such a field counts each value's real cost, so the search is refused
// after a bounded amount of work.
func TestManyValuesOnManyRowsAreRefused(t *testing.T) {
	list := strings.Repeat("a,", maxMultiValues-1) + "a"
	spaced := strings.ReplaceAll(list, ",", " ")
	for _, c := range []struct{ name, q string }{
		{"split", `| makeresults count=10000 | eval a=split("` + list + `", ",") | stats count`},
		{"split kept under another name", `| makeresults count=10000 | eval a=split("` + list + `", ","), b=mvindex(a, 0, -1), a=null() | stats count`},
		{"mvappend", `| makeresults count=10000 | eval s=split("` + list[:1999] + `", ",") | eval a=mvappend(s, s, s, s, s, s, s, s, s, s) | stats count`},
		{"mvrange", `| makeresults count=10000 | eval a=mvrange(0, 10000) | stats count`},
		{"mvsort", `| makeresults count=10000 | eval s=mvsort(split("` + list + `", ",")) | stats count`},
		{"makemv", `| makeresults count=10000 | eval a="` + spaced + `" | makemv a | stats count`},
		{"rex max_match=0", `| makeresults count=10000 | eval a="` + spaced + `" | rex field=a max_match=0 "(?<v>a)" | stats count`},
		{"eventstats values", `| makeresults count=10000 | streamstats count as n | eventstats values(n) as all | stats count`},
		{"filldown", `| makeresults count=10000 | streamstats count as n | eval a=if(n=1, split("` + list + `", ","), null()) | filldown a`},
	} {
		t.Run(c.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := (&Engine{}).Run(context.Background(), c.q)
			runtime.ReadMemStats(&after)
			var qe *QueryError
			if !errors.As(err, &qe) {
				t.Fatalf("err = %v, want a query error naming the limit", err)
			}
			if !strings.Contains(qe.Msg, "MB") {
				t.Errorf("error %q does not name the limit", qe.Msg)
			}
			// Everything the search allocated, kept or not: a few times
			// the budget at most, where it used to be several GB.
			if mb := (after.TotalAlloc - before.TotalAlloc) >> 20; mb > 6*(maxEvalTotal>>20) {
				t.Errorf("the search allocated %d MB before it was refused", mb)
			}
			t.Logf("%v (allocated %d MB)", err, (after.TotalAlloc-before.TotalAlloc)>>20)
		})
	}
}

// TestMultivalueErrorNamesTheLimit: when the number of values is what
// fills the budget, the error says so and how to get under it.
func TestMultivalueErrorNamesTheLimit(t *testing.T) {
	list := strings.Repeat("a,", maxMultiValues-1) + "a"
	_, err := (&Engine{}).Run(context.Background(), `| makeresults count=10000 | eval a=split("`+list+`", ",") | stats count`)
	if err == nil || !strings.Contains(err.Error(), "multivalue fields hold more than a search may build") || !strings.Contains(err.Error(), "fewer rows or fewer values") {
		t.Errorf("err = %v, want the multivalue budget", err)
	}
	// One field past the per-field cap names that cap instead.
	_, err = (&Engine{}).Run(context.Background(), `| makeresults | eval a=split("`+list+`,a", ",")`)
	if err == nil || !strings.Contains(err.Error(), "10000") {
		t.Errorf("err = %v, want the cap on one field's values", err)
	}
}

// TestRealisticMultivalueSearchesFit: the budget leaves room for what
// real searches do, such as a few hundred values on each of 10,000 rows.
func TestRealisticMultivalueSearchesFit(t *testing.T) {
	list := strings.Repeat("10.20.30.40,", 299) + "10.20.30.40"
	for _, q := range []string{
		`| makeresults count=10000 | eval a=split("` + list + `", ",") | stats count`,
		`| makeresults count=400 | eval a=mvrange(0, 10000) | stats count`,
		`| makeresults count=2000 | streamstats count as n | eventstats values(n) as all | stats count`,
	} {
		res, err := (&Engine{}).Run(context.Background(), q)
		if err != nil {
			t.Errorf("%.60s...: %v", q, err)
			continue
		}
		if len(res.Rows) != 1 {
			t.Errorf("%.60s...: %d rows, want 1", q, len(res.Rows))
		}
	}
}
