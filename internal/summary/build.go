// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package summary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Tunables of the builder.
const (
	// Settle is how long after a slot ends it is first summarized, for
	// events still on their way.
	Settle = 2 * time.Minute
	// chunk is the time range one aggregation summarizes.
	chunk = time.Hour
	// chunksPerTick caps the chunks one model builds per tick, so a
	// backfill of 30 days spreads over a few minutes.
	chunksPerTick = 24
	// DefaultMaxRows is the most rows one chunk may produce. A chunk
	// with more (dimensions almost unique per event) is not stored:
	// those slots are a gap that searches read from the events.
	DefaultMaxRows = 100000
	// The composite aggregation's first page has firstPage rows; later
	// pages hold about pageBytes of values, between minPage and maxPage
	// rows, so long values (up to 8 KB each) never make a huge response.
	firstPage = 200
	minPage   = 100
	maxPage   = 5000
	pageBytes = 4 << 20
	// maxChunkBytes caps the values one chunk's rows hold; a chunk with
	// more is a gap, as one with too many rows is.
	maxChunkBytes = 64 << 20
	// maxPageResponse caps one page's answer, read before it is decoded:
	// a page sized on short values that comes back full of long ones
	// makes its chunk a gap instead of a huge answer to decode.
	maxPageResponse = 16 << 20
	// A bulk request carries at most bulkSize rows or bulkBytes of
	// values.
	bulkSize  = 5000
	bulkBytes = 8 << 20
	// recentEvery and fullEvery are how often the summaries of the last
	// recentSpan, and of the whole covered range, are checked against
	// the events.
	recentEvery = 10 * time.Minute
	recentSpan  = 48 * time.Hour
	fullEvery   = 6 * time.Hour
	// maxRebuilds caps the ranges one check rebuilds; the rest wait for
	// the next one.
	maxRebuilds = 48
)

// IndexPattern is the pattern of a prefix's summary indices.
func IndexPattern(prefix string) string { return prefix + "_summary-*" }

// indexName is the monthly summary index of a slot.
func indexName(prefix string, t time.Time) string {
	return prefix + "_summary-" + t.UTC().Format("2006.01")
}

// rawPattern is the pattern of a model's daily event indices.
func rawPattern(prefix, model string) string { return prefix + "-" + strings.ToLower(model) + "-*" }

// Client is what the builder needs from OpenSearch; *store.Client has it.
type Client interface {
	Search(ctx context.Context, index string, body map[string]any) (map[string]any, error)
	Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error)
	Do(ctx context.Context, method, path string, body any, out any) error
	ListIndices(ctx context.Context, pattern string) ([]string, error)
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// Builder keeps the summaries of one index prefix. Only the server that
// runs the background jobs runs it; its writes carry the job lease's
// epoch, and a state written under a newer epoch is never overwritten.
type Builder struct {
	Client Client
	Prefix string
	// Runtime is the runtime index (<prefix>_runtime) that holds the
	// state documents.
	Runtime string
	// Days is how far back summaries reach; 0 builds none.
	Days func() int
	// KeepDays is how long a data model's events are kept (0: forever),
	// with ok false when that cannot be read: the model's summaries then
	// wait. Summaries never reach further back, so they never outlive the
	// events retention deleted.
	KeepDays func(model string) (days int, ok bool)
	// Now is the cluster's clock.
	Now func() time.Time
	// Allowed reports whether this server still runs the jobs; Epoch
	// and Node identify its lease.
	Allowed func() bool
	Epoch   func() int64
	Node    string
	// IndexSettings are the replica (and shard) settings of new
	// summary indices.
	IndexSettings func() map[string]any
	// FieldType gives the event template's type of a field
	// (ingest.FieldType), which summary rows map it to as well.
	FieldType func(string) (string, bool)
	MaxRows   int
	Log       *slog.Logger

	mu      sync.Mutex
	states  map[string]*held
	epoch   int64
	created map[string]bool
	gen     int64
	fails   map[string]failure
}

// held is a state document and its stored version.
type held struct {
	st State
	v  store.Version
	ok bool
}

var errStaleEpoch = errors.New("the summaries were taken over by a newer jobs server")

func (b *Builder) log() *slog.Logger {
	if b.Log != nil {
		return b.Log
	}
	return slog.Default()
}

func (b *Builder) allowed() bool { return b.Allowed == nil || b.Allowed() }

// fenced reports whether this server still holds the lease the tick
// started under, which every write checks first.
func (b *Builder) fenced() bool { return b.allowed() && b.epochNow() == b.epoch }

func (b *Builder) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

func (b *Builder) epochNow() int64 {
	if b.Epoch != nil {
		return b.Epoch()
	}
	return 0
}

// Run builds and checks summaries every minute until ctx ends.
func (b *Builder) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if err := b.Tick(ctx); err != nil && ctx.Err() == nil {
			b.log().Warn("summaries: could not update", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick brings every model's summaries up to date once.
func (b *Builder) Tick(ctx context.Context) error {
	days := 0
	if b.Days != nil {
		days = b.Days()
	}
	if days <= 0 || !b.allowed() {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.epochNow(); b.states == nil || e != b.epoch {
		// A new lease: read the states again, someone else may have
		// moved them on.
		b.states, b.epoch = map[string]*held{}, e
	}
	// Where each model's summaries started as of the last tick, which
	// every server's Coverage has seen by now.
	starts := map[string]time.Time{}
	for m, h := range b.states {
		starts[m] = h.st.From
	}
	var errs []error
	for _, m := range Models() {
		if ctx.Err() != nil || !b.allowed() {
			return ctx.Err()
		}
		d := days
		if b.KeepDays != nil {
			k, ok := b.KeepDays(m)
			if !ok {
				continue
			}
			if k > 0 && k < d {
				d = k
			}
		}
		if err := b.model(ctx, m, d); err != nil {
			if errors.Is(err, errStaleEpoch) {
				return nil
			}
			errs = append(errs, fmt.Errorf("%s: %w", m, err))
			delete(b.states, m) // read it again next time
		}
	}
	if err := b.dropMonths(ctx, starts); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// dropMonths deletes the summary indices of months that end before every
// model's summaries start.
func (b *Builder) dropMonths(ctx context.Context, starts map[string]time.Time) error {
	var from time.Time
	for _, m := range Models() {
		t, ok := starts[m]
		if !ok || t.IsZero() {
			return nil // not every model's start is known yet
		}
		if from.IsZero() || t.Before(from) {
			from = t
		}
	}
	names, err := b.Client.ListIndices(ctx, IndexPattern(b.Prefix))
	if err != nil {
		return err
	}
	for _, n := range names {
		month, err := time.Parse("2006.01", strings.TrimPrefix(n, b.Prefix+"_summary-"))
		if err != nil || month.AddDate(0, 1, 0).After(from) {
			continue
		}
		if !b.fenced() {
			return errStaleEpoch
		}
		if err := b.Client.Do(ctx, http.MethodDelete, "/"+url.PathEscape(n), nil, nil); err != nil && !isNotFound(err) {
			return fmt.Errorf("could not delete %s: %w", n, err)
		}
		delete(b.created, n)
		b.log().Info("summaries: deleted a month older than every data model's summaries", "index", n)
	}
	return nil
}

// model brings one model's summaries up to date.
func (b *Builder) model(ctx context.Context, model string, days int) error {
	h, err := b.state(ctx, model)
	if err != nil {
		return err
	}
	now := b.now()
	target := now.Add(-Settle).Truncate(Slot)
	start := now.Add(-time.Duration(days) * 24 * time.Hour).Truncate(Slot)
	st := &h.st
	if st.Layout != layout(model) || st.From.IsZero() || st.Through.Before(st.From) {
		// New, or the dimensions changed: drop what an older layout
		// wrote and start again.
		if err := b.deleteRows(ctx, model, time.Time{}, time.Time{}, ""); err != nil {
			return err
		}
		*st = State{Kind: kindState, Model: model, Layout: layout(model), From: start, Through: start}
		if err := b.save(ctx, h); err != nil {
			return err
		}
	}
	if start.Sub(st.From) >= chunk {
		// The range moved on, or retention or summary_days shortened
		// it: older rows go. Only those the state stopped covering a
		// move ago, so even a server whose Coverage is not up to date
		// yet never reads a range whose rows are going.
		prev := st.From
		st.From = start.Truncate(chunk)
		if st.Through.Before(st.From) {
			st.Through = st.From
		}
		var gaps []Gap
		for _, g := range st.Gaps {
			if g.To.After(st.From) {
				gaps = append(gaps, g)
			}
		}
		st.Gaps = gaps
		if err := b.save(ctx, h); err != nil {
			return err
		}
		if err := b.deleteRows(ctx, model, time.Time{}, prev, ""); err != nil {
			return err
		}
	}
	if start.Before(st.From) {
		// summary_days was raised: build the older days too, as a
		// fresh start would. The rows already stored stay right; until
		// the state covers them again searches ignore them, and their
		// rebuild writes over them.
		st.From, st.Through, st.Gaps = start, start, nil
		if err := b.save(ctx, h); err != nil {
			return err
		}
	}
	built := false
	var busy map[int64]bool
	if st.Through.Before(target) {
		// Hours with neither events nor rows need no build: most data
		// models have nothing in most hours.
		upto := minTime(st.Through.Add(chunksPerTick*chunk), target)
		if busy, err = b.busyHours(ctx, model, st.Through, upto); err != nil {
			return err
		}
	}
	for n := 0; n < chunksPerTick && st.Through.Before(target); n++ {
		if !b.allowed() {
			break
		}
		end := minTime(st.Through.Add(chunk).Truncate(chunk), target)
		if !end.After(st.Through) {
			end = target
		}
		rows, err := 0, error(nil)
		if busy[st.Through.Truncate(chunk).UnixMilli()] {
			rows, err = b.build(ctx, model, st.Through, end)
		}
		switch {
		case errors.Is(err, errTooMany):
			st.Gaps = addGap(st.Gaps, Gap{From: st.Through, To: end})
			b.log().Info("summaries: too many distinct values to summarize; searches read these events directly", "datamodel", model, "from", st.Through, "to", end)
		case errors.Is(err, errStaleEpoch):
			return err
		case err != nil && b.failed(model, st.Through) < maxFailures:
			st.LastError = err.Error()
			_ = b.save(ctx, h)
			return err
		case err != nil:
			// It keeps failing (rows OpenSearch refuses, say): its
			// events are read directly instead of building it forever.
			st.Gaps = addGap(st.Gaps, Gap{From: st.Through, To: end})
			b.log().Warn("summaries: could not summarize; searches read these events directly", "datamodel", model, "from", st.Through, "to", end, "error", err)
		}
		st.Through, st.Rows, st.LastBuild, st.LastError = end, st.Rows+int64(rows), now, ""
		built = true
	}
	if built {
		// Saved once a tick: after a crash, the chunks built since are
		// built again, writing over the same rows.
		if err := b.save(ctx, h); err != nil {
			return err
		}
	}
	if err := b.orphans(ctx, h); err != nil {
		return err
	}
	return b.verify(ctx, h, now)
}

var errTooMany = errors.New("too many rows")

// maxFailures is how many times in a row a chunk may fail to build
// before it becomes a gap.
const maxFailures = 3

// failed counts a failure to build model's chunk at from, and returns
// how many times in a row it failed.
func (b *Builder) failed(model string, from time.Time) int {
	if b.fails == nil {
		b.fails = map[string]failure{}
	}
	f := b.fails[model]
	if !f.at.Equal(from) {
		f = failure{at: from}
	}
	f.n++
	b.fails[model] = f
	return f.n
}

type failure struct {
	at time.Time
	n  int
}

// busyHours returns the hours in [from, to) where model has events or
// summary rows.
func (b *Builder) busyHours(ctx context.Context, model string, from, to time.Time) (map[int64]bool, error) {
	out := map[int64]bool{}
	for _, summed := range []bool{false, true} {
		index, filter := rawPattern(b.Prefix, model), map[string]any(nil)
		if summed {
			index, filter = IndexPattern(b.Prefix), map[string]any{"term": map[string]any{ModelField: model}}
		}
		h, err := b.histogram(ctx, index, filter, from, to, "1h", summed)
		if err != nil {
			return nil, err
		}
		for k := range h {
			out[k] = true
		}
	}
	return out, nil
}

// newGen names one build, written on its rows.
func (b *Builder) newGen() string {
	b.gen++
	return fmt.Sprintf("%d-%s-%d-%d", b.epoch, b.Node, b.now().UnixNano(), b.gen)
}

// build summarizes model's events in [from, to) and replaces the rows
// stored for that range. It returns the rows written, or errTooMany when
// the range has more than MaxRows (its rows are removed).
func (b *Builder) build(ctx context.Context, model string, from, to time.Time) (int, error) {
	gen := b.newGen()
	rows, err := b.aggregate(ctx, model, from, to)
	if errors.Is(err, errTooMany) {
		if derr := b.deleteRows(ctx, model, from, to, gen); derr != nil {
			return 0, derr
		}
		return 0, err
	}
	if err != nil {
		return 0, err
	}
	docs := make([]store.IndexedDoc, 0, len(rows))
	sizes := make([]int, 0, len(rows))
	for _, r := range rows {
		t := r.slot
		doc := r.fields
		doc["@timestamp"] = t.Format(time.RFC3339)
		doc["datamodel"] = model
		doc[ModelField] = model
		doc[CountField] = r.count
		doc[GenField] = gen
		docs = append(docs, store.IndexedDoc{Index: indexName(b.Prefix, t), ID: rowID(model, t, r.key), Doc: doc, Replace: true})
		sizes = append(sizes, r.size)
	}
	for _, ix := range uniqueIndices(docs) {
		if err := b.ensureIndex(ctx, ix); err != nil {
			return 0, err
		}
	}
	for len(docs) > 0 {
		if !b.fenced() {
			return 0, errStaleEpoch
		}
		n, bytes := 0, 0
		for n < len(docs) && n < bulkSize && (n == 0 || bytes+sizes[n] <= bulkBytes) {
			bytes += sizes[n]
			n++
		}
		errs, err := b.Client.Bulk(ctx, docs[:n])
		if err != nil {
			return 0, err
		}
		if len(errs) > 0 {
			return 0, fmt.Errorf("could not store %d summary rows: %s", len(errs), errs[0].Reason)
		}
		docs, sizes = docs[n:], sizes[n:]
	}
	if len(rows) > 0 {
		if err := b.refresh(ctx); err != nil {
			return 0, err
		}
	}
	// Rows of an earlier build of this range that this one did not
	// write again (values that are gone) go.
	return len(rows), b.deleteRows(ctx, model, from, to, gen)
}

func uniqueIndices(docs []store.IndexedDoc) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range docs {
		if !seen[d.Index] {
			seen[d.Index] = true
			out = append(out, d.Index)
		}
	}
	return out
}

// row is one summary row before it is written.
type row struct {
	slot   time.Time
	key    string
	fields map[string]any
	count  int64
	size   int // about the bytes of its values
}

// rowID is a row's document ID: the same slot and values get the same
// ID, so a rebuild writes over the row.
func rowID(model string, slot time.Time, key string) string {
	h := sha256.Sum256([]byte(model + "\x00" + slot.UTC().Format(time.RFC3339) + "\x00" + key))
	return hex.EncodeToString(h[:16])
}

// aggregate reads the rows of model's events in [from, to).
func (b *Builder) aggregate(ctx context.Context, model string, from, to time.Time) ([]row, error) {
	dims := Dims(model)
	sources := []any{map[string]any{"t": map[string]any{"date_histogram": map[string]any{"field": "@timestamp", "fixed_interval": "5m"}}}}
	for i, d := range dims {
		sources = append(sources, map[string]any{fmt.Sprintf("d%d", i): map[string]any{"terms": map[string]any{"field": d, "missing_bucket": true}}})
	}
	comp := map[string]any{"size": firstPage, "sources": sources}
	body := map[string]any{
		"size":             0,
		"track_total_hits": false,
		"query":            map[string]any{"bool": map[string]any{"filter": []any{timeRange(from, to)}}},
		"aggs":             map[string]any{"g": map[string]any{"composite": comp}},
	}
	if ms := Measures(model); len(ms) > 0 {
		sub := map[string]any{}
		for i, m := range ms {
			sub[fmt.Sprintf("s%d", i)] = map[string]any{"sum": map[string]any{"field": m}}
		}
		body["aggs"].(map[string]any)["g"].(map[string]any)["aggs"] = sub
	}
	maxRows := b.MaxRows
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}
	var out []row
	total := 0
	pctx := store.WithMaxResponse(ctx, maxPageResponse)
	for {
		resp, err := b.Client.Search(pctx, rawPattern(b.Prefix, model), body)
		if err != nil {
			if isNotFound(err) {
				return out, nil
			}
			if errors.Is(err, store.ErrResponseTooLarge) {
				return nil, errTooMany
			}
			return nil, err
		}
		g, _ := dig(resp, "aggregations", "g").(map[string]any)
		buckets, _ := g["buckets"].([]any)
		page := 0
		for _, x := range buckets {
			bk, _ := x.(map[string]any)
			key, _ := bk["key"].(map[string]any)
			ms, ok := toFloat(key["t"])
			if !ok {
				continue
			}
			r := row{slot: time.UnixMilli(int64(ms)).UTC(), fields: map[string]any{}}
			n, _ := toFloat(bk["doc_count"])
			r.count = int64(n)
			vals := make([]any, len(dims))
			for i, d := range dims {
				v := key[fmt.Sprintf("d%d", i)]
				vals[i] = v
				if v != nil {
					r.fields[d] = v
				}
			}
			for i, m := range Measures(model) {
				if s, ok := toFloat(dig(bk, fmt.Sprintf("s%d", i), "value")); ok && s != 0 {
					r.fields[m] = s
				}
			}
			k, _ := json.Marshal(vals)
			r.key = string(k)
			r.size = len(k) + 256 // the field names and the row's own fields
			out = append(out, r)
			page += r.size
			if total += r.size; len(out) > maxRows || total > maxChunkBytes {
				return nil, errTooMany
			}
		}
		after, _ := g["after_key"].(map[string]any)
		if after == nil || len(buckets) == 0 {
			return out, nil
		}
		comp["after"] = after
		comp["size"] = max(minPage, min(maxPage, pageBytes*len(buckets)/max(page, 1)))
	}
}

// timeRange filters @timestamp to [from, to).
func timeRange(from, to time.Time) map[string]any {
	r := map[string]any{"format": "epoch_millis"}
	if !from.IsZero() {
		r["gte"] = from.UnixMilli()
	}
	if !to.IsZero() {
		r["lt"] = to.UnixMilli()
	}
	return map[string]any{"range": map[string]any{"@timestamp": r}}
}

// deleteRows deletes model's rows in [from, to) (all of them when both
// are zero), except those written by keepGen.
func (b *Builder) deleteRows(ctx context.Context, model string, from, to time.Time, keepGen string) error {
	if !b.fenced() {
		return errStaleEpoch
	}
	filter := []any{map[string]any{"term": map[string]any{ModelField: model}}}
	if !from.IsZero() || !to.IsZero() {
		filter = append(filter, timeRange(from, to))
	}
	q := map[string]any{"bool": map[string]any{"filter": filter}}
	if keepGen != "" {
		q["bool"].(map[string]any)["must_not"] = []any{map[string]any{"term": map[string]any{GenField: keepGen}}}
	}
	path := "/" + url.PathEscape(IndexPattern(b.Prefix)) + "/_delete_by_query?conflicts=proceed&allow_no_indices=true&ignore_unavailable=true"
	var out struct {
		Deleted int64 `json:"deleted"`
	}
	err := b.Client.Do(ctx, http.MethodPost, path, map[string]any{"query": q}, &out)
	if isNotFound(err) {
		return nil
	}
	if err != nil || out.Deleted == 0 {
		return err
	}
	// Searches must stop seeing the deleted rows before the state says
	// the range is built.
	return b.refresh(ctx)
}

func (b *Builder) refresh(ctx context.Context) error {
	err := b.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(IndexPattern(b.Prefix))+"/_refresh?allow_no_indices=true&ignore_unavailable=true", nil, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

// ensureIndex creates a summary index with the mapping its rows need,
// unless it exists.
func (b *Builder) ensureIndex(ctx context.Context, name string) error {
	if b.created == nil {
		b.created = map[string]bool{}
	}
	if b.created[name] {
		return nil
	}
	settings := map[string]any{"number_of_shards": 1, "refresh_interval": "5s"}
	if b.IndexSettings != nil {
		maps.Copy(settings, b.IndexSettings())
	}
	body := map[string]any{"settings": settings, "mappings": Mapping(b.FieldType)}
	err := b.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(name), body, nil)
	if err != nil && !strings.Contains(err.Error(), "resource_already_exists_exception") {
		return fmt.Errorf("could not create %s: %w", name, err)
	}
	b.created[name] = true
	return nil
}

// Mapping is the mapping of summary indices: each dimension and measure
// as the event template maps it (fieldType), so one search can aggregate
// events and rows together, and nothing else (dynamic false).
func Mapping(fieldType func(string) (string, bool)) map[string]any {
	props := map[string]any{
		"@timestamp": map[string]any{"type": "date"},
		"datamodel":  map[string]any{"type": "keyword"},
		ModelField:   map[string]any{"type": "keyword"},
		GenField:     map[string]any{"type": "keyword"},
		CountField:   map[string]any{"type": "long"},
	}
	for _, m := range Models() {
		for _, f := range append(Dims(m), Measures(m)...) {
			if _, ok := props[f]; ok {
				continue
			}
			t, ok := "", false
			if fieldType != nil {
				t, ok = fieldType(f)
			}
			switch {
			case !ok, t == "wildcard", t == "text":
				props[f] = map[string]any{"type": "keyword", "ignore_above": 8191}
			case t == "keyword":
				props[f] = map[string]any{"type": "keyword", "ignore_above": 8191}
			default:
				props[f] = map[string]any{"type": t}
			}
		}
	}
	return map[string]any{"dynamic": false, "properties": props}
}

// dig walks nested maps.
func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// dayIndices returns the days (YYYY.MM.DD) that have an event index of
// model, or a part of one (see datamodel.SplitPart).
func (b *Builder) dayIndices(ctx context.Context, model string) (map[string]bool, error) {
	names, err := b.Client.ListIndices(ctx, rawPattern(b.Prefix, model))
	if err != nil {
		if isNotFound(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	out := map[string]bool{}
	pre := datamodel.IndexName(b.Prefix, model, "")
	for _, n := range names {
		day, _, ok := datamodel.SplitPart(n)
		if d, cut := strings.CutPrefix(day, pre); ok && cut && len(d) == len("2006.01.02") {
			out[d] = true
		}
	}
	return out, nil
}

// sortedKeys is the keys of m in order.
func sortedKeys[V any](m map[int64]V) []int64 {
	return slices.Sorted(maps.Keys(m))
}

// isNotFound reports an OpenSearch 404: no index matches.
func isNotFound(err error) bool {
	var e *store.Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}
