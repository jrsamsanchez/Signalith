// Package clusterarchive keeps what retention records in OpenSearch
// rather than in each server's files, once servers that share one
// OpenSearch reach shared.LevelSharedAudit: the archive manifests
// (<prefix>_runtime/archive:<id>, created once, so two servers never
// write the same archive), the claims that fence each step that changes
// an index (op:<index>), the progress of restores (retention:job), the
// last run (retention:lastrun) and the history, kept as audit records.
// It also has the importers that move the founder's history file and
// manifest files into OpenSearch, and the archive_restore request.
package clusterarchive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Kinds of the documents in the runtime index.
const (
	KindArchive = "archive"
	KindOp      = "op"
	KindJob     = "retention_job"
	KindLastRun = "retention_lastrun"
)

// Document ids.
const (
	JobID     = "retention:job"
	LastRunID = "retention:lastrun"
)

// ArchiveDocID is the id of an archive's manifest document.
func ArchiveDocID(id string) string { return KindArchive + ":" + id }

// OpDocID is the id of an index's claim document.
func OpDocID(index string) string { return KindOp + ":" + index }

// doc is a document of this package in the runtime index: the mapped
// fields the runtime index has (kind, name, node, state, epoch, at) and
// the rest in body, which is kept but not indexed.
type doc struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name,omitempty"`
	Node   string          `json:"node,omitempty"`
	NodeID string          `json:"node_id,omitempty"`
	State  string          `json:"state,omitempty"`
	Epoch  int64           `json:"epoch,omitempty"`
	At     time.Time       `json:"at"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// Client is what this package needs of OpenSearch. *store.Client has it.
type Client interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
	Do(ctx context.Context, method, path string, body any, out any) error
	Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error)
	Search(ctx context.Context, index string, body map[string]any) (map[string]any, error)
}

// read reads a document of this package, false when there is none.
func read(ctx context.Context, c Client, prefix, id string) (*doc, store.Version, bool, error) {
	src, v, found, err := c.Get(ctx, cluster.RuntimeIndex(prefix), id)
	if err != nil || !found {
		return nil, v, false, err
	}
	var d doc
	if err := json.Unmarshal(src, &d); err != nil {
		return nil, v, false, err
	}
	return &d, v, true, nil
}

// put writes a document whatever its version, for documents only the
// server that runs the background jobs writes.
func put(ctx context.Context, c Client, prefix, id string, d doc) error {
	return c.Do(ctx, http.MethodPut, "/"+url.PathEscape(cluster.RuntimeIndex(prefix))+"/_doc/"+url.PathEscape(id), d, nil)
}

func now(f func() time.Time) time.Time {
	if f != nil {
		return f().UTC()
	}
	return time.Now().UTC()
}
