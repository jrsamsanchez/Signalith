// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// The series of a timechart split by a field, OTHER and NULL as Splunk
// names them.
const (
	otherSeries = "OTHER"
	nullSeries  = "NULL"
)

// timechartSplit runs a timechart by a field once resp, the answer to its
// Body, has named the series: the by field's largest values over the
// whole time range (SL-04). Each time bucket then counts each series, the
// events with any other value (OTHER) and those without the field
// (NULL), so a series is never missing from a bucket only because other
// values were larger there. It returns the histogram's answer, with the
// series names under seriesKey.
func (e *Engine) timechartSplit(ctx context.Context, p *Plan, tc *query.Timechart, resp map[string]any) (map[string]any, error) {
	aggs, _ := resp["aggregations"].(map[string]any)
	series, _ := aggs["series"].(map[string]any)
	bs, _ := series["buckets"].([]any)
	field := storedField(tc.By)
	filters := map[string]any{}
	var names []string
	var keys []any
	for i, b := range bs {
		bm, _ := b.(map[string]any)
		key := bm["key"]
		keys = append(keys, key)
		names = append(names, fmt.Sprint(normalize(key)))
		filters[fmt.Sprintf("s%d", i)] = map[string]any{"term": map[string]any{field: key}}
	}
	exists := map[string]any{"exists": map[string]any{"field": field}}
	if field == indexMeta {
		// Every event has an index, and OpenSearch asks no exists of it.
		exists = map[string]any{"match_all": map[string]any{}}
	}
	if other, _ := asFloat(toNumber(series["sum_other_doc_count"])); other > 0 && !tc.NoOther {
		filters[otherSeries] = map[string]any{"bool": map[string]any{
			"filter":   []any{exists},
			"must_not": []any{map[string]any{"terms": map[string]any{field: keys}}},
		}}
	}
	if !tc.NoNull && field != indexMeta {
		filters[nullSeries] = map[string]any{"bool": map[string]any{"must_not": []any{exists}}}
	}
	ts := cloneMap(p.split)
	by := map[string]any{"filters": map[string]any{"filters": filters}}
	if sub, ok := ts["aggs"]; ok {
		by["aggs"] = sub
	}
	ts["aggs"] = map[string]any{"by": by}
	body := cloneMap(p.Body)
	nextAggs := map[string]any{"time": ts}
	if first, _ := p.Body["aggs"].(map[string]any); first[eventsAgg] != nil {
		nextAggs[eventsAgg] = first[eventsAgg]
	}
	body["aggs"] = nextAggs
	body["track_total_hits"] = false
	out, err := e.Store.Search(ctx, p.Index, body)
	if err != nil {
		return nil, err
	}
	out[seriesKey] = names
	return out, nil
}

// seriesKey holds, in a timechart's answer, the names of its series.
const seriesKey = "\x00series"
