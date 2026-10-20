// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// maxEventCountRows bounds the indexes eventcount summarize=false lists.
const maxEventCountRows = 10000

// eventCountPlan counts the events of c's indexes. Each index= goes
// through IndexPattern, as a search's would, so eventcount reaches no
// index the same user's searches cannot: only Signalith's event indexes
// under this engine's prefix, which for a tenant is the tenant's own.
// Like Splunk's, the count ignores the time range.
func (e *Engine) eventCountPlan(c *query.EventCount, post []query.Command) (*Plan, error) {
	var patterns []string
	if len(c.Indexes) == 0 {
		p, err := e.IndexPattern(&query.Query{})
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, p)
	}
	for _, ix := range c.Indexes {
		p, err := e.IndexPattern(&query.Query{Index: ix})
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, p)
	}
	body := map[string]any{"size": 0, "track_total_hits": true}
	if !c.Summarize {
		body["aggs"] = map[string]any{"indexes": map[string]any{"terms": map[string]any{"field": indexMeta, "size": maxEventCountRows}}}
	}
	return &Plan{Mode: "eventcount", Index: strings.Join(patterns, ","), Body: body, transform: c, post: post}, nil
}

// eventCount runs an eventcount plan: one row with count, or with
// summarize=false a row with count and index for each index holding
// events, by index name.
func (e *Engine) eventCount(ctx context.Context, p *Plan) (*Result, error) {
	resp, err := e.Store.Search(ctx, p.Index, p.Body)
	if err != nil {
		return nil, err
	}
	total := totalHits(resp)
	res := &Result{Kind: "table", Matched: total}
	if p.transform.(*query.EventCount).Summarize {
		res.Columns = []string{"count"}
		res.Rows = []Row{{"count": total}}
		return res, nil
	}
	res.Columns = []string{"count", IndexField}
	aggs, _ := resp["aggregations"].(map[string]any)
	idx, _ := aggs["indexes"].(map[string]any)
	buckets, _ := idx["buckets"].([]any)
	for _, b := range buckets {
		m, _ := b.(map[string]any)
		name, ok := m["key"].(string)
		if !ok {
			continue
		}
		res.Rows = append(res.Rows, Row{"count": toNumber(m["doc_count"]), IndexField: name})
	}
	if n, _ := toNumber(idx["sum_other_doc_count"]).(int64); n > 0 {
		res.Truncated = true
	}
	sort.Slice(res.Rows, func(i, j int) bool { return res.Rows[i][IndexField].(string) < res.Rows[j][IndexField].(string) })
	return res, nil
}
