// Package risk stores risk events in OpenSearch under the Risk data model,
// in daily indices "<prefix>-risk-YYYY.MM.DD", so retention ages them out
// like any other events and analysts can search them with datamodel=Risk.
package risk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Client is what the store needs from OpenSearch.
type Client interface {
	Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error)
	Do(ctx context.Context, method, path string, body any, out any) error
}

// Store writes and queries risk events.
type Store struct {
	Client Client
	Prefix string
}

func (s *Store) pattern() string {
	return s.Prefix + "-" + strings.ToLower(datamodel.RiskModel) + "-*"
}

// Write indexes risk events, in the daily index of each event's time. An
// event with an ID that is already stored was written before (by an
// earlier run of the same slot), so that counts as written.
func (s *Store) Write(ctx context.Context, events []detect.RiskEvent) error {
	if len(events) == 0 {
		return nil
	}
	docs := make([]store.IndexedDoc, 0, len(events))
	for _, e := range events {
		docs = append(docs, store.IndexedDoc{
			Index: datamodel.IndexName(s.Prefix, datamodel.RiskModel, e.Time.UTC().Format("2006.01.02")),
			ID:    e.ID,
			Doc:   e.Doc(),
		})
	}
	errs, err := s.Client.Bulk(ctx, docs)
	if err != nil {
		return err
	}
	// A risk event with an ID that is already stored was written before.
	errs, _ = store.WithoutConflicts(errs, docs)
	if len(errs) > 0 {
		return fmt.Errorf("%d risk events were rejected: %s", len(errs), errs[0].Reason)
	}
	return nil
}

// Exists reports whether a detection recorded risk with this group key
// since a time.
func (s *Store) Exists(ctx context.Context, detectionID, groupKey string, since time.Time) (bool, error) {
	body := map[string]any{"query": map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"detection_id": detectionID}},
		map[string]any{"term": map[string]any{"group_key": groupKey}},
		map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339Nano)}}},
	}}}}
	var out struct {
		Count int `json:"count"`
	}
	path := "/" + url.PathEscape(s.pattern()) + "/_count?ignore_unavailable=true&allow_no_indices=true"
	if err := s.Client.Do(ctx, http.MethodPost, path, body, &out); err != nil {
		return false, err
	}
	return out.Count > 0, nil
}
