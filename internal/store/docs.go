// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Documents that several Signalith servers may change at once are read
// with their version and written back only if nobody changed them since
// (OpenSearch's if_seq_no and if_primary_term), so no change is lost. Every
// write carries a random write_id: when the answer to a write is lost, the
// document is read again, and finding that write_id there means the write
// went through.

// Version is a document's place in its history. A write that names it
// succeeds only when nothing changed the document since it was read.
type Version struct {
	SeqNo       int64 `json:"seq_no"`
	PrimaryTerm int64 `json:"primary_term"`
	Version     int64 `json:"version"`
}

// IsZero reports whether v names no version: the document was not found.
func (v Version) IsZero() bool { return v.PrimaryTerm == 0 }

// Same reports whether v and o are the same version of a document.
func (v Version) Same(o Version) bool { return v.SeqNo == o.SeqNo && v.PrimaryTerm == o.PrimaryTerm }

func (v Version) String() string { return fmt.Sprintf("%d.%d", v.SeqNo, v.PrimaryTerm) }

// Ref names a document.
type Ref struct {
	Index string `json:"_index"`
	ID    string `json:"_id"`
}

// Doc is a document as read: its version and, when asked for, its source.
type Doc struct {
	Ref
	Version
	Found  bool
	Source json.RawMessage
}

var (
	// ErrExists is a Create of a document that is already there.
	ErrExists = errors.New("the document already exists")
	// ErrConflict is a write to a document that changed since it was read.
	ErrConflict = errors.New("the document was changed since it was read")
	// ErrNotFound is a change to a document that is not there.
	ErrNotFound = errors.New("the document does not exist")
)

// recheckTimeout bounds the read that finds out whether a write whose
// answer was lost went through.
const recheckTimeout = 10 * time.Second

type recheckKey struct{}

// WithRecheckLimit returns ctx with a limit on that read: a write that is
// worthless after a moment (a lease renewal after the lease ran out) is
// not checked for longer.
func WithRecheckLimit(ctx context.Context, until time.Time) context.Context {
	return context.WithValue(ctx, recheckKey{}, until)
}

// docPath is /<index>/<op>/<id>.
func docPath(index, op, id string) string {
	return "/" + url.PathEscape(index) + "/" + op + "/" + url.PathEscape(id)
}

// Get reads a document in real time, so a write is seen at once. A
// missing document, or a missing index, is found == false.
func (c *Client) Get(ctx context.Context, index, id string) (json.RawMessage, Version, bool, error) {
	var out struct {
		Found       bool            `json:"found"`
		SeqNo       *int64          `json:"_seq_no"`
		PrimaryTerm int64           `json:"_primary_term"`
		Version     int64           `json:"_version"`
		Source      json.RawMessage `json:"_source"`
	}
	err := c.Do(ctx, http.MethodGet, docPath(index, "_doc", id), nil, &out)
	if notFound(err) {
		return nil, Version{}, false, nil
	}
	if err != nil {
		return nil, Version{}, false, err
	}
	if !out.Found || out.SeqNo == nil {
		return nil, Version{}, false, nil
	}
	return out.Source, Version{SeqNo: *out.SeqNo, PrimaryTerm: out.PrimaryTerm, Version: out.Version}, true, nil
}

// MGetVersions reads the versions of documents in real time, without
// their sources. Missing ones are left out of the map.
func (c *Client) MGetVersions(ctx context.Context, refs []Ref) (map[Ref]Version, error) {
	docs, err := c.mget(ctx, refs, false)
	if err != nil {
		return nil, err
	}
	out := make(map[Ref]Version, len(docs))
	for _, d := range docs {
		if d.Found {
			out[d.Ref] = d.Version
		}
	}
	return out, nil
}

// MGet reads documents in real time, in the order asked for; a missing
// one has Found false.
func (c *Client) MGet(ctx context.Context, refs []Ref) ([]Doc, error) {
	return c.mget(ctx, refs, true)
}

func (c *Client) mget(ctx context.Context, refs []Ref, source bool) ([]Doc, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	var out struct {
		Docs []struct {
			Index       string          `json:"_index"`
			ID          string          `json:"_id"`
			Found       bool            `json:"found"`
			SeqNo       *int64          `json:"_seq_no"`
			PrimaryTerm int64           `json:"_primary_term"`
			Version     int64           `json:"_version"`
			Source      json.RawMessage `json:"_source"`
			// Error, when set, is why this document could not be read;
			// the answer is 200 even then.
			Error *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"docs"`
	}
	path := "/_mget?realtime=true&_source=" + strconv.FormatBool(source)
	if err := c.Do(ctx, http.MethodPost, path, map[string]any{"docs": refs}, &out); err != nil {
		return nil, err
	}
	docs := make([]Doc, len(refs))
	for i, r := range refs {
		docs[i].Ref = r
		if i >= len(out.Docs) {
			continue
		}
		d := out.Docs[i]
		if d.Error != nil {
			// A document in a missing index comes back with an error
			// instead: not found. Any other error, such as no shard
			// available while OpenSearch starts, is a read that failed,
			// as a get of that one document would with 503: the document
			// may well be there.
			if d.Error.Type == "index_not_found_exception" {
				continue
			}
			body, _ := json.Marshal(map[string]any{"error": d.Error, "status": http.StatusServiceUnavailable})
			return nil, &Error{Status: http.StatusServiceUnavailable, Body: string(body)}
		}
		if d.Found && d.SeqNo != nil {
			docs[i].Found = true
			docs[i].Version = Version{SeqNo: *d.SeqNo, PrimaryTerm: d.PrimaryTerm, Version: d.Version}
			docs[i].Source = d.Source
		}
	}
	return docs, nil
}

// Create writes a document that must not exist yet: ErrExists when it
// does. refresh makes it searchable before Create returns.
func (c *Client) Create(ctx context.Context, index, id string, body any, refresh bool) (Version, error) {
	raw, wid, err := withWriteID(body)
	if err != nil {
		return Version{}, err
	}
	v, err := c.write(ctx, http.MethodPut, docPath(index, "_create", id)+refreshQuery("?", refresh), raw)
	switch {
	case err == nil:
		return v, nil
	case conflict(err):
		return Version{}, ErrExists
	case !ambiguous(err):
		return Version{}, err
	}
	// The answer was lost: the document tells whether this write made it.
	src, now, found, rerr := c.recheck(ctx, index, id)
	switch {
	case rerr != nil || !found:
		return Version{}, err
	case writeIDOf(src) == wid:
		return now, nil
	}
	return Version{}, ErrExists
}

// PutIf replaces a document, only if it is still at version v:
// ErrConflict when it changed or was deleted since.
func (c *Client) PutIf(ctx context.Context, index, id string, body any, v Version, refresh bool) (Version, error) {
	raw, wid, err := withWriteID(body)
	if err != nil {
		return Version{}, err
	}
	nv, err := c.write(ctx, http.MethodPut, docPath(index, "_doc", id)+ifQuery(v)+refreshQuery("&", refresh), raw)
	return c.settle(ctx, index, id, v, wid, nv, err)
}

// UpdateIf changes some fields of a document, only if it is still at
// version v: ErrConflict when it changed since, ErrNotFound when it is
// gone. Documents in the shared configuration index (<prefix>_config)
// are only ever written whole, so it refuses them.
func (c *Client) UpdateIf(ctx context.Context, index, id string, fields map[string]any, v Version, refresh bool) (Version, error) {
	if err := partialAllowed(index); err != nil {
		return Version{}, err
	}
	raw, wid, err := withWriteID(fields)
	if err != nil {
		return Version{}, err
	}
	body := json.RawMessage(`{"doc":` + string(raw) + `}`)
	nv, err := c.write(ctx, http.MethodPost, docPath(index, "_update", id)+ifQuery(v)+refreshQuery("&", refresh), body)
	return c.settle(ctx, index, id, v, wid, nv, err)
}

// Update changes some fields of a document whatever its version, for
// fields only ever moved forward, such as when a session was last used.
// Like UpdateIf it refuses the shared configuration index.
func (c *Client) Update(ctx context.Context, index, id string, fields map[string]any, refresh bool) (Version, error) {
	if err := partialAllowed(index); err != nil {
		return Version{}, err
	}
	raw, _, err := withWriteID(fields)
	if err != nil {
		return Version{}, err
	}
	body := json.RawMessage(`{"doc":` + string(raw) + `}`)
	v, err := c.write(ctx, http.MethodPost, docPath(index, "_update", id)+"?retry_on_conflict=3"+refreshQuery("&", refresh), body)
	if notFound(err) {
		return Version{}, ErrNotFound
	}
	return v, err
}

// DeleteIf deletes a document, only if it is still at version v:
// ErrConflict when it changed since, ErrNotFound when it is gone (or its
// index is).
func (c *Client) DeleteIf(ctx context.Context, index, id string, v Version, refresh bool) error {
	_, err := c.write(ctx, http.MethodDelete, docPath(index, "_doc", id)+ifQuery(v)+refreshQuery("&", refresh), nil)
	switch {
	case err == nil:
		return nil
	case conflict(err):
		// OpenSearch answers a conditional delete of a document that is
		// gone with a version conflict too: a read tells them apart.
		if _, _, found, rerr := c.recheck(ctx, index, id); rerr == nil && !found {
			return ErrNotFound
		}
		return ErrConflict
	case notFound(err):
		return ErrNotFound
	case !ambiguous(err):
		return err
	}
	_, now, found, rerr := c.recheck(ctx, index, id)
	switch {
	case rerr != nil:
		return err
	case !found:
		// Gone, which is what was asked for.
		return nil
	case now.Same(v):
		return err
	}
	return ErrConflict
}

// settle turns the answer to a conditional write into its result. When
// the answer was lost, the document is read again: this write's write_id
// in it means success; the version it was written over means the write
// never arrived, so the original error stands; anything else means
// someone else changed it.
func (c *Client) settle(ctx context.Context, index, id string, v Version, wid string, nv Version, err error) (Version, error) {
	switch {
	case err == nil:
		return nv, nil
	case conflict(err):
		return Version{}, ErrConflict
	case notFound(err):
		return Version{}, ErrNotFound
	case !ambiguous(err):
		return Version{}, err
	}
	src, now, found, rerr := c.recheck(ctx, index, id)
	switch {
	case rerr != nil:
		return Version{}, err
	case !found:
		return Version{}, ErrConflict
	case writeIDOf(src) == wid:
		return now, nil
	case now.Same(v):
		return Version{}, err
	}
	return Version{}, ErrConflict
}

// recheck reads a document after a write whose answer was lost, even
// when the write's own context has ended, for at most recheckTimeout or
// until the limit set with WithRecheckLimit.
func (c *Client) recheck(ctx context.Context, index, id string) (json.RawMessage, Version, bool, error) {
	until := time.Now().Add(recheckTimeout)
	if t, ok := ctx.Value(recheckKey{}).(time.Time); ok && t.Before(until) {
		until = t
	}
	rctx, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
	defer cancel()
	return c.Get(rctx, index, id)
}

// write sends a document write and returns the version it made.
func (c *Client) write(ctx context.Context, method, path string, body json.RawMessage) (Version, error) {
	var out struct {
		SeqNo       int64 `json:"_seq_no"`
		PrimaryTerm int64 `json:"_primary_term"`
		Version     int64 `json:"_version"`
	}
	var b any
	if body != nil {
		b = body
	}
	if err := c.Do(ctx, method, path, b, &out); err != nil {
		return Version{}, err
	}
	return Version{SeqNo: out.SeqNo, PrimaryTerm: out.PrimaryTerm, Version: out.Version}, nil
}

// searchPage is how many documents one search request returns.
const searchPage = 1000

// SearchVersions lists the documents in index that match query (an
// OpenSearch query, such as {"term":{"kind":"node"}}), with their
// versions and no sources.
func (c *Client) SearchVersions(ctx context.Context, index string, query map[string]any) ([]Doc, error) {
	return c.searchAll(ctx, index, query, false)
}

// SearchDocs is SearchVersions with each document's source.
func (c *Client) SearchDocs(ctx context.Context, index string, query map[string]any) ([]Doc, error) {
	return c.searchAll(ctx, index, query, true)
}

// searchAll pages through every match. Usually they fit in one page; only
// when they do not are they read again in _id order with search_after,
// since sorting by _id costs OpenSearch memory.
func (c *Client) searchAll(ctx context.Context, index string, query map[string]any, source bool) ([]Doc, error) {
	if query == nil {
		query = map[string]any{"match_all": map[string]any{}}
	}
	body := map[string]any{"query": query, "size": searchPage, "seq_no_primary_term": true,
		"_source": source, "track_total_hits": true}
	docs, total, last, err := c.searchPage(ctx, index, body)
	if err != nil || total <= len(docs) {
		return docs, err
	}
	body["sort"] = []any{map[string]any{"_id": "asc"}}
	body["track_total_hits"] = false
	docs = docs[:0]
	for {
		page, _, after, err := c.searchPage(ctx, index, body)
		if err != nil {
			return nil, err
		}
		docs = append(docs, page...)
		if len(page) < searchPage {
			return docs, nil
		}
		last = after
		body["search_after"] = last
	}
}

func (c *Client) searchPage(ctx context.Context, index string, body map[string]any) ([]Doc, int, []any, error) {
	var out struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Index       string          `json:"_index"`
				ID          string          `json:"_id"`
				SeqNo       int64           `json:"_seq_no"`
				PrimaryTerm int64           `json:"_primary_term"`
				Version     int64           `json:"_version"`
				Source      json.RawMessage `json:"_source"`
				Sort        []any           `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
	}
	path := "/" + url.PathEscape(index) + "/_search?ignore_unavailable=true&allow_no_indices=true&version=true"
	if err := c.Do(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, 0, nil, err
	}
	docs := make([]Doc, 0, len(out.Hits.Hits))
	var last []any
	for _, h := range out.Hits.Hits {
		docs = append(docs, Doc{Ref: Ref{Index: h.Index, ID: h.ID}, Found: true, Source: h.Source,
			Version: Version{SeqNo: h.SeqNo, PrimaryTerm: h.PrimaryTerm, Version: h.Version}})
		last = h.Sort
	}
	return docs, out.Hits.Total.Value, last, nil
}

// NewWriteID returns a random id for one write.
func NewWriteID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "w_" + hex.EncodeToString(b)
}

// withWriteID returns body as a JSON object with a new write_id in it,
// and that id.
func withWriteID(body any) (json.RawMessage, string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return nil, "", fmt.Errorf("a document must be a JSON object, not %.40s", raw)
	}
	wid := NewWriteID()
	fields["write_id"], _ = json.Marshal(wid)
	raw, err = json.Marshal(fields)
	return raw, wid, err
}

// writeIDOf returns the write_id in a document's source.
func writeIDOf(src json.RawMessage) string {
	var d struct {
		WriteID string `json:"write_id"`
	}
	_ = json.Unmarshal(src, &d)
	return d.WriteID
}

func partialAllowed(index string) error {
	if strings.HasSuffix(index, "_config") {
		return fmt.Errorf("documents in %s are only written whole", index)
	}
	return nil
}

func ifQuery(v Version) string {
	return "?if_seq_no=" + strconv.FormatInt(v.SeqNo, 10) + "&if_primary_term=" + strconv.FormatInt(v.PrimaryTerm, 10)
}

func refreshQuery(sep string, refresh bool) string {
	if !refresh {
		return ""
	}
	return sep + "refresh=wait_for"
}

// conflict reports whether OpenSearch refused a write as a version
// conflict.
func conflict(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusConflict
}

// notFound reports whether OpenSearch answered that the document or its
// index does not exist.
func notFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// ambiguous reports whether a write may have gone through although no
// answer says so: the connection failed or timed out after sending, or a
// proxy in front of OpenSearch gave up waiting.
func ambiguous(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Status == http.StatusBadGateway || e.Status == http.StatusServiceUnavailable || e.Status == http.StatusGatewayTimeout
	}
	return !errors.Is(err, ErrResponseTooLarge)
}

// IsClusterBlock reports whether OpenSearch refused a write because of a
// block, as it does for every index once its disk passes the flood-stage
// watermark (HTTP 429 in OpenSearch 2, 403 before). Deleting a whole
// index still works then.
func IsClusterBlock(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Status == http.StatusTooManyRequests || e.Status == http.StatusForbidden) &&
		strings.Contains(e.Body, "cluster_block_exception")
}

// IsConflict reports whether err is a version conflict or an existing
// document, from any of the writes above.
func IsConflict(err error) bool { return errors.Is(err, ErrConflict) || errors.Is(err, ErrExists) }
