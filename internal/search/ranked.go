// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// A composite aggregation returns groups in the order of their keys, so
// when a search has more groups than MaxBuckets the rows it keeps are the
// alphabetically first ones, and top 10 or sort -count | head 10 would
// rank the wrong groups. A ranking asks OpenSearch again for the groups
// in the order the search ranks them, so the groups it keeps are the
// largest (or, for rare, the smallest).
type ranking struct {
	order    map[string]any // the terms aggregation's order
	size     int            // groups to ask for
	complete bool           // size is every row the pipeline keeps
}

// maxRankedGroups bounds the groups a ranking asks for when the
// pipeline keeps them all.
const maxRankedGroups = 10000

// rankable reports whether OpenSearch can order groups by the result of
// agg, and the name to order by.
func rankable(a query.Agg, i int) (string, bool) {
	switch a.Func {
	case "count":
		if a.Field == "" {
			return "_count", true
		}
		return fmt.Sprintf("m%d", i), true
	case "dc", "sum", "avg", "min", "max":
		return fmt.Sprintf("m%d", i), true
	}
	return "", false
}

// statsRanking is how to rank stats groups for the commands after it: by
// the column a following sort orders by, keeping only head's rows when
// head comes next; otherwise by event count. ok is false when neither
// can be ranked in OpenSearch.
func statsRanking(st *query.Stats, post []query.Command, maxBuckets int) (r ranking, ok bool) {
	r.size = min(maxBuckets, maxRankedGroups)
	if len(post) > 0 {
		if s, isSort := post[0].(*query.Sort); isSort && len(s.Keys) > 0 {
			for i, a := range st.Aggs {
				if a.Column() != s.Keys[0].Field {
					continue
				}
				name, can := rankable(a, i)
				if !can {
					return r, false
				}
				dir := "asc"
				if s.Keys[0].Desc {
					dir = "desc"
				}
				r.order = map[string]any{name: dir}
				if len(post) > 1 {
					if h, isHead := post[1].(*query.Head); isHead && h.N > 0 && h.N <= r.size {
						r.size, r.complete = h.N, true
					}
				}
				return r, true
			}
		}
	}
	for _, a := range st.Aggs {
		if a.Func == "count" && a.Field == "" {
			r.order = map[string]any{"_count": "desc"}
			return r, true
		}
	}
	return r, false
}

// topRanking is how to rank the groups of top or rare: by count, keeping
// only limit rows when there are no by fields.
func topRanking(t *query.Top, maxBuckets int) ranking {
	dir := "desc"
	if t.Rare {
		dir = "asc"
	}
	r := ranking{order: map[string]any{"_count": dir}, size: min(maxBuckets, maxRankedGroups)}
	if len(t.By) == 0 && t.Limit > 0 && t.Limit <= r.size {
		r.size, r.complete = t.Limit, true
	}
	return r
}

// rankedBuckets asks OpenSearch for the groups of keys in r's order, as
// composite buckets (key k0, k1, ...), with the events in groups it did
// not return.
func (e *Engine) rankedBuckets(ctx context.Context, p *Plan, keys []string, r ranking) ([]map[string]any, int64, error) {
	aggs, _ := p.Body["aggs"].(map[string]any)
	groups, _ := aggs["groups"].(map[string]any)
	if groups == nil {
		return nil, 0, fmt.Errorf("no groups to rank")
	}
	shardSize := min(max(r.size*10, 1000), 20000)
	shardSize = max(shardSize, r.size)
	var agg map[string]any
	if len(keys) == 1 {
		agg = map[string]any{"terms": map[string]any{"field": storedField(keys[0]), "size": r.size, "shard_size": shardSize, "order": r.order}}
	} else {
		var terms []any
		for _, k := range keys {
			terms = append(terms, map[string]any{"field": storedField(k)})
		}
		agg = map[string]any{"multi_terms": map[string]any{"terms": terms, "size": r.size, "shard_size": shardSize, "order": r.order}}
	}
	if sub, ok := groups["aggs"]; ok {
		agg["aggs"] = sub
	}
	body := cloneMap(p.Body)
	nextAggs := cloneMap(aggs)
	nextAggs["groups"] = agg
	body["aggs"] = nextAggs
	body["track_total_hits"] = false
	resp, err := e.Store.Search(ctx, p.Index, body)
	if err != nil {
		return nil, 0, err
	}
	ra, _ := resp["aggregations"].(map[string]any)
	rg, _ := ra["groups"].(map[string]any)
	bs, _ := rg["buckets"].([]any)
	var out []map[string]any
	for _, b := range bs {
		m, ok := b.(map[string]any)
		if !ok {
			continue
		}
		key := map[string]any{}
		if len(keys) == 1 {
			key["k0"] = m["key"]
		} else {
			parts, _ := m["key"].([]any)
			for i, v := range parts {
				key[fmt.Sprintf("k%d", i)] = v
			}
		}
		c := cloneMap(m)
		c["key"] = key
		out = append(out, c)
	}
	other, _ := asFloat(toNumber(rg["sum_other_doc_count"]))
	return out, int64(other), nil
}
