// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// An Exporter writes one part of the shared settings as the files a
// server of an earlier version, which keeps them in its own folders, reads
// (signalith cluster export --to-files): the inverse of the Importer of
// the same name.
type Exporter struct {
	// Name is the name of the importer it inverts.
	Name string
	// Run writes the files under the export folder and lists them.
	Run func(ctx context.Context, out ExportTarget) ([]ExportedFile, error)
}

// ExportTarget is where an exporter writes.
type ExportTarget struct {
	// Under returns where, in the export folder, the file a server keeps
	// at path (this server's own path for it) is written.
	Under func(path string) string
	// Master is this server's master key: the files of an earlier version
	// keep their passwords and keys sealed with it (enc: values), as the
	// file stores seal them (secrets.Default is the same keyring).
	Master *secrets.Keyring
	// Server is the node id of the server whose own settings are written
	// (signalith cluster export -server), this server's by default.
	Server string
	// Log takes what could not be exported, such as a password sealed
	// with a cluster key this server does not have.
	Log *slog.Logger
}

// Logger returns Log, or one that discards.
func (t ExportTarget) Logger() *slog.Logger {
	if t.Log != nil {
		return t.Log
	}
	return slog.New(slog.DiscardHandler)
}

// ExportedFile is one file an exporter wrote.
type ExportedFile struct {
	// Path is where it was written, in the export folder.
	Path string `json:"path"`
	// Dest is where it goes on the server: this server's path for it.
	Dest string `json:"dest"`
	// Secret is set when it holds passwords or keys.
	Secret bool `json:"secret,omitempty"`
}

// RetiredConfigIndex is the copy of the config index that
// signalith cluster export -retire keeps, made at stamp (UTC
// yyyymmddThhmmss).
func RetiredConfigIndex(prefix, stamp string) string {
	return ConfigIndex(prefix) + "_retired_" + stamp
}

// RetiredConfigPattern matches every retired copy of the config index.
func RetiredConfigPattern(prefix string) string { return ConfigIndex(prefix) + "_retired_*" }

// RetireConfig copies the config index into RetiredConfigIndex(prefix,
// stamp), with the same settings and mappings, checks that the copy holds
// as many documents, and then deletes the config index. It returns the
// number of documents copied. The config index is blocked for writes
// first, so a server still running cannot write into it a change that the
// copy misses; when the copy fails, the block is lifted and the partial
// copy deleted. The copy is kept so the cluster can go forward again (copy
// it back into <prefix>_config).
func RetireConfig(ctx context.Context, cl *store.Client, prefix, stamp string) (n int, err error) {
	from, to := ConfigIndex(prefix), RetiredConfigIndex(prefix, stamp)
	if err := cl.Do(ctx, http.MethodGet, "/"+url.PathEscape(from), nil, nil); err != nil {
		return 0, fmt.Errorf("could not read %s: %w", from, err)
	}
	if err := setWriteBlock(ctx, cl, from, true); err != nil {
		return 0, fmt.Errorf("could not stop writes to %s before copying it: %w", from, err)
	}
	made := false
	defer func() {
		if err == nil {
			return
		}
		// Undo with a context of its own: ctx may be what ended.
		undo, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if made {
			_ = cl.DeleteIndex(undo, to)
		}
		_ = setWriteBlock(undo, cl, from, false)
	}()
	docs, err := cl.SearchDocs(ctx, from, map[string]any{"match_all": map[string]any{}})
	if err != nil {
		return 0, fmt.Errorf("could not read %s: %w", from, err)
	}
	if err := cl.Do(ctx, http.MethodPut, "/"+url.PathEscape(to), map[string]any{"settings": configSettings(), "mappings": configMappings()}, nil); err != nil {
		return 0, fmt.Errorf("could not make %s: %w", to, err)
	}
	made = true
	batch := make([]store.IndexedDoc, 0, len(docs))
	for _, d := range docs {
		var src map[string]any
		if err := json.Unmarshal(d.Source, &src); err != nil {
			return 0, fmt.Errorf("%s/%s cannot be read: %w", from, d.ID, err)
		}
		batch = append(batch, store.IndexedDoc{Index: to, ID: d.ID, Doc: src})
	}
	for start := 0; start < len(batch); start += 500 {
		part := batch[start:min(start+500, len(batch))]
		errs, err := cl.Bulk(ctx, part)
		if err != nil {
			return 0, fmt.Errorf("could not copy %s into %s: %w", from, to, err)
		}
		if errs, _ = store.WithoutConflicts(errs, part); len(errs) > 0 {
			return 0, fmt.Errorf("could not copy %s into %s: %s", from, to, errs[0].Reason)
		}
	}
	// A refresh makes the copies countable at once; the fake OpenSearch of
	// the tests counts them without one.
	_ = cl.Do(ctx, http.MethodPost, "/"+url.PathEscape(to)+"/_refresh", nil, nil)
	n, err = countDocs(ctx, cl, to, len(docs))
	if err != nil {
		return 0, err
	}
	if n != len(docs) {
		return 0, fmt.Errorf("%s holds %d documents, not the %d of %s, so %s was not deleted", to, n, len(docs), from, from)
	}
	// The source too: a write that got in before the block was in place
	// but after the read would otherwise be lost with it.
	_ = cl.Do(ctx, http.MethodPost, "/"+url.PathEscape(from)+"/_refresh", nil, nil)
	src, err := countDocs(ctx, cl, from, len(docs))
	if err != nil {
		return 0, err
	}
	if src != len(docs) {
		return 0, fmt.Errorf("%s changed while it was copied (%d documents, %d copied), so it was not deleted; try again", from, src, len(docs))
	}
	if err := cl.DeleteIndex(ctx, from); err != nil {
		return 0, fmt.Errorf("copied %s into %s, but could not delete it: %w", from, to, err)
	}
	return n, nil
}

// setWriteBlock turns index.blocks.write on index on or off.
func setWriteBlock(ctx context.Context, cl *store.Client, index string, on bool) error {
	return cl.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_settings",
		map[string]any{"index": map[string]any{"blocks": map[string]any{"write": on}}}, nil)
}

// countDocs counts the documents of index, trying again for a few
// seconds while OpenSearch has not made all want of them visible yet.
func countDocs(ctx context.Context, cl *store.Client, index string, want int) (int, error) {
	n := 0
	for try := 0; ; try++ {
		var out struct {
			Count int `json:"count"`
		}
		if err := cl.Do(ctx, http.MethodGet, "/"+url.PathEscape(index)+"/_count", nil, &out); err != nil {
			return 0, fmt.Errorf("could not count the documents of %s: %w", index, err)
		}
		if n = out.Count; n == want || try == 9 {
			return n, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
