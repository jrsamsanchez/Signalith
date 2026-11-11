// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Match selects the audit events a reader of new records wants, such as
// the audit alerts of package notify: those at or after Since whose
// message is one of Messages or starts with one of MessagePrefixes, or
// whose action is one of Actions or starts with one of ActionPrefixes.
// With none of these set it selects nothing.
type Match struct {
	Since           time.Time
	Messages        []string
	MessagePrefixes []string
	Actions         []string
	ActionPrefixes  []string
}

func (m Match) empty() bool {
	return len(m.Messages)+len(m.MessagePrefixes)+len(m.Actions)+len(m.ActionPrefixes) == 0
}

// matchPage is how many events one request of Matching reads.
const matchPage = 500

// Matching returns the events m selects, oldest first, at most limit of
// them; truncated is true when there were more (the newest are then left
// out, for the next read). With no audit index yet, there are none.
func Matching(ctx context.Context, c Searcher, prefix string, m Match, limit int) (hits []Hit, truncated bool, err error) {
	if m.empty() || limit <= 0 {
		return nil, false, nil
	}
	var should []any
	if len(m.Messages) > 0 {
		should = append(should, map[string]any{"terms": map[string]any{"message.keyword": m.Messages}})
	}
	for _, p := range m.MessagePrefixes {
		should = append(should, map[string]any{"prefix": map[string]any{"message.keyword": p}})
	}
	if len(m.Actions) > 0 {
		should = append(should, map[string]any{"terms": map[string]any{"action": m.Actions}})
	}
	for _, p := range m.ActionPrefixes {
		should = append(should, map[string]any{"prefix": map[string]any{"action": p}})
	}
	filter := []any{map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}}
	if !m.Since.IsZero() {
		filter = append(filter, map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": m.Since.UTC().Format(time.RFC3339Nano)}}})
	}
	var after []any
	for len(hits) < limit {
		size := min(matchPage, limit-len(hits)+1)
		body := map[string]any{
			"query": map[string]any{"bool": map[string]any{"filter": filter}},
			"size":  size,
			"sort":  []any{map[string]any{"@timestamp": "asc"}, map[string]any{"node_id": "asc"}, map[string]any{"seq": "asc"}},
		}
		if after != nil {
			body["search_after"] = after
		}
		res, err := search(ctx, c, Pattern(prefix), body)
		if missing(err) {
			return hits, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		var out struct {
			Hits struct {
				Hits []struct {
					Index  string          `json:"_index"`
					ID     string          `json:"_id"`
					Source json.RawMessage `json:"_source"`
					Sort   []any           `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := remarshal(res, &out); err != nil {
			return nil, false, fmt.Errorf("audit search: %w", err)
		}
		for _, h := range out.Hits.Hits {
			if len(hits) == limit {
				return hits, true, nil
			}
			var ev Event
			if err := json.Unmarshal(h.Source, &ev); err != nil {
				return nil, false, fmt.Errorf("audit search: event %s: %w", h.ID, err)
			}
			hits = append(hits, Hit{Event: ev, ID: h.ID, Index: h.Index})
		}
		if len(out.Hits.Hits) < size {
			return hits, false, nil
		}
		after = out.Hits.Hits[len(out.Hits.Hits)-1].Sort
	}
	return hits, false, nil
}
