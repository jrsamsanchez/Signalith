// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// maxWildcardFields bounds the fields one wildcard aggregation such as
// values(*) expands to.
const maxWildcardFields = 1000

// hasWildcardAgg reports whether an aggregation names fields with a *,
// as sum(bytes*) or values(*) do.
func hasWildcardAgg(aggs []query.Agg) bool {
	for _, a := range aggs {
		if strings.Contains(a.Field, "*") {
			return true
		}
	}
	return false
}

// expandWildcardAggs replaces each aggregation over a * pattern with one
// for every field of rows the pattern matches, as Splunk does: values(*)
// becomes values(dest), values(user) and so on. An AS name with one *
// takes the part of the field the pattern's one * matched, so values(*)
// AS * names each column after its field. The by fields, and fields
// starting with _ unless the pattern does, are left out. clipped is set
// when a pattern matched more than maxWildcardFields fields.
func expandWildcardAggs(aggs []query.Agg, by []string, rows []Row, clipped *bool) []query.Agg {
	if !hasWildcardAgg(aggs) {
		return aggs
	}
	skip := map[string]bool{}
	for _, f := range by {
		skip[f] = true
	}
	seen := map[string]bool{}
	var names []string
	for _, r := range rows {
		for f := range r {
			if !seen[f] {
				seen[f] = true
				names = append(names, f)
			}
		}
	}
	sort.Strings(names)
	var out []query.Agg
	for _, a := range aggs {
		if !strings.Contains(a.Field, "*") {
			out = append(out, a)
			continue
		}
		g := compileGlob(a.Field, false)
		pre, post, oneStar := strings.Cut(a.Field, "*")
		oneStar = oneStar && !strings.Contains(post, "*")
		n := 0
		for _, f := range names {
			if skip[f] || strings.HasPrefix(f, "_") && !strings.HasPrefix(a.Field, "_") || !g.match(f) {
				continue
			}
			if n == maxWildcardFields {
				if clipped != nil {
					*clipped = true
				}
				break
			}
			n++
			e := a
			e.Field = f
			e.Alias = ""
			if a.Alias != "" && oneStar && strings.Count(a.Alias, "*") == 1 {
				e.Alias = strings.Replace(a.Alias, "*", f[len(pre):len(f)-len(post)], 1)
			}
			out = append(out, e)
		}
	}
	return out
}
