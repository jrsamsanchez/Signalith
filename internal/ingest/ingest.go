// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package ingest turns raw records from agents (Fluent Bit) into normalized
// events and writes them to OpenSearch. Each source type has a parser that
// maps the record onto a data model; unrecognized events land in "Other"
// and stay searchable by text.
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Event is a normalized event before it is indexed.
type Event struct {
	Time   time.Time
	Model  string
	Fields map[string]any
	// DeviceTime is the event's own time when it could not be the event
	// time (too old, or too far ahead); the event is then filed under the
	// time it arrived and this is stored as device_time.
	DeviceTime time.Time
	// Origin is where the event came from, when it differs from the
	// origin of the request (see WithOrigin), as for syslog messages,
	// whose batches mix devices. It is recorded in the event's
	// signalith_* fields.
	Origin Origin
	// ID is the event's document ID, "" to let the request's position
	// (IngestBody) or OpenSearch pick one. Parsers set it when the raw
	// line identifies the event (network sensors, see sensorDocID), so the
	// same line sent again, even in another batch, is stored once.
	ID string
	// Sensor is what a sensor's status line says (tag sensor.status), for
	// the agent inventory; it is not stored with the event.
	Sensor *SensorStatus
}

// DefaultMaxEventAge is how old an event's own time may be and still be
// its event time, when ingest.max_event_age is not set (or the retention
// period, when that is shorter). Events go to one index per day, so
// without a bound a sender could create an index for every day it names
// and use up the cluster's shards, which stops all ingestion; older events
// are filed under the time they arrived instead.
const DefaultMaxEventAge = 7 * 24 * time.Hour

// MaxEventAhead is how far ahead of this server's clock an event's own
// time may be (clock skew) and still be its event time.
const MaxEventAhead = time.Hour

// TimeUsable reports whether t can be the event time of an event received
// at recv: set, no older than maxAge (zero: DefaultMaxEventAge) and at most
// MaxEventAhead ahead. Keeping event times in this window bounds the daily
// indices senders can make Signalith create.
func TimeUsable(t, recv time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		maxAge = DefaultMaxEventAge
	}
	return !t.IsZero() && !t.Before(recv.Add(-maxAge)) && !t.After(recv.Add(MaxEventAhead))
}

// Bulker writes documents in bulk.
type Bulker interface {
	Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error)
}

// Pipeline parses records and writes them.
type Pipeline struct {
	Store  Bulker
	Prefix string
	Now    func() time.Time
	// MaxEventAge is how old an event's own time may be and still be its
	// event time (zero: DefaultMaxEventAge); see TimeUsable.
	MaxEventAge time.Duration
	// Limits, when set, are the ingest slots and receive budget this
	// pipeline shares with others, such as every tenant's pipeline; then
	// MaxConcurrent and MaxReceiving are not used. nil gives the pipeline
	// Limits of its own.
	Limits *Limits
	// Tenant is the tenant whose events this pipeline takes, "" for the
	// default tenant: what its requests are counted under in Limits.
	Tenant string
	// MaxConcurrent caps the ingest requests Admit lets in at once
	// (default DefaultMaxConcurrent) when Limits is nil. Memory is capped
	// by MaxReceiving; this bounds how many bulk writes run against
	// OpenSearch together.
	MaxConcurrent int
	// MaxReceiving caps the memory request bodies hold, from their first
	// byte until they have been written (default DefaultMaxReceiving),
	// when Limits is nil; one sender may hold a quarter of it. See
	// ReadBody.
	MaxReceiving int64
	// Custom parses the records sent under a custom parser's tag
	// (CustomTagPrefix); nil leaves them to the built-in parsers. Set it
	// before the pipeline takes records.
	Custom CustomParsers
	// Log, when set, gets a warning (at most once a minute per kind) when
	// events are refiled under their arrival time or lose fields.
	Log *slog.Logger
	// SampleMark marks every event this pipeline writes as sample data
	// with this load ID (datamodel.SampleField). Only the sample-data
	// loader sets it, on a pipeline of its own: every other pipeline
	// removes the marker from what senders send (see Reserved).
	SampleMark string
	// Rollover, when set, picks the part of a busy day's index events go
	// to (see Rollover); nil writes every event to its day's index.
	Rollover *Rollover
	// Servers returns how many servers share each day's field-name
	// budgets: those that stored events in the last 10 minutes (see
	// cluster.Node.IndexingServers). nil is this server alone.
	Servers func() int
	// FieldCount returns how many fields an index's mapping has (see
	// MappingFieldCount); nil does not look.
	FieldCount func(ctx context.Context, index string) (int, error)
	// liveMaxAge, when set (SetMaxEventAge), replaces MaxEventAge: the
	// retention policies it follows can change while the pipeline runs.
	liveMaxAge atomic.Int64
	// urlQuery is ingest.url_query (SetURLQuery): 0 keeps the query
	// strings of web addresses, 1 hides their values, 2 drops them.
	urlQuery atomic.Int32

	stats   Stats
	names   fieldBudget
	procs   ProcessTracker
	counter fieldCounter
	// ownLimits are the pipeline's own Limits, when Limits is nil.
	ownLimitsOnce sync.Once
	ownLimits     *Limits
	warnMu        sync.Mutex
	warned        map[string]time.Time

	// plaintext lists the agents that sent over plain HTTP, and refused
	// the ones whose batches were turned away.
	plaintext, refused senderLog
}

// Stats counts what the pipeline has processed since start, for the health page.
type Stats struct {
	Received atomic.Int64
	Indexed  atomic.Int64
	Failed   atomic.Int64
	LastSeen atomic.Int64 // unix seconds
	// LastIndexed is when an event was last stored (unix seconds).
	LastIndexed atomic.Int64
	// Retimed counts events whose own time was too old or too far ahead,
	// so they were filed under the time they arrived.
	Retimed atomic.Int64
	// FieldsDropped counts fields left out of events: invalid names, too
	// many fields, names over an index's budget, or names Signalith sets
	// itself (Reserved).
	FieldsDropped atomic.Int64
}

// Snapshot is a JSON-friendly copy of Stats.
type Snapshot struct {
	Received      int64     `json:"received"`
	Indexed       int64     `json:"indexed"`
	Failed        int64     `json:"failed"`
	Retimed       int64     `json:"retimed"`
	FieldsDropped int64     `json:"fields_dropped"`
	LastSeen      time.Time `json:"last_seen,omitzero"`
	LastIndexed   time.Time `json:"last_indexed,omitzero"`
}

// Stats returns current counters.
func (p *Pipeline) Stats() Snapshot {
	s := Snapshot{
		Received:      p.stats.Received.Load(),
		Indexed:       p.stats.Indexed.Load(),
		Failed:        p.stats.Failed.Load(),
		Retimed:       p.stats.Retimed.Load(),
		FieldsDropped: p.stats.FieldsDropped.Load(),
	}
	if ls := p.stats.LastSeen.Load(); ls > 0 {
		s.LastSeen = time.Unix(ls, 0).UTC()
	}
	s.LastIndexed = p.LastIndexed()
	return s
}

// LastIndexed returns when this pipeline last stored an event, zero
// before the first.
func (p *Pipeline) LastIndexed() time.Time {
	if t := p.stats.LastIndexed.Load(); t > 0 {
		return time.Unix(t, 0).UTC()
	}
	return time.Time{}
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// SetMaxEventAge changes MaxEventAge while the pipeline runs, as when
// the shared retention policies change; zero or less is ignored.
func (p *Pipeline) SetMaxEventAge(d time.Duration) {
	if d > 0 {
		p.liveMaxAge.Store(int64(d))
	}
}

func (p *Pipeline) maxAge() time.Duration {
	if d := p.liveMaxAge.Load(); d > 0 {
		return time.Duration(d)
	}
	if p.MaxEventAge > 0 {
		return p.MaxEventAge
	}
	return DefaultMaxEventAge
}

// maxErrors caps the rejected documents a Result lists; Rejected has the
// full count.
const maxErrors = 10

// Result reports one ingest call.
type Result struct {
	Received int `json:"received"`
	Indexed  int `json:"indexed"`
	Rejected int `json:"rejected,omitempty"`
	// Duplicates were stored by an earlier send of the same request (a
	// resend after an error); they count as indexed.
	Duplicates int `json:"duplicates,omitempty"`
	// Temporary counts rejected events OpenSearch may take if sent again
	// later, such as while its disk is full or it is too busy.
	Temporary int                   `json:"temporary,omitempty"`
	Errors    []store.BulkItemError `json:"errors,omitempty"`
	// Retimed and FieldsDropped are as in Stats, for this call.
	Retimed       int `json:"retimed,omitempty"`
	FieldsDropped int `json:"fields_dropped,omitempty"`
	// Hosts are the first few host names in the events, to tell agents
	// apart in Health page warnings (see NotePlaintext).
	Hosts []string `json:"-"`
	// Sensor is the last sensor status line among the events that were
	// stored (in the order they came), nil when there is none.
	Sensor *SensorStatus `json:"-"`
}

// maxResultHosts caps Result.Hosts, and maxHostName the length of a name
// kept there: they come from the sender.
const (
	maxResultHosts = 4
	maxHostName    = 64
)

// noteHost adds an event's host name to r.Hosts, when it looks like one.
func (r *Result) noteHost(ev *Event) {
	h, _ := ev.Fields["host"].(string)
	if h == "" || len(h) > maxHostName || len(r.Hosts) >= maxResultHosts || slices.Contains(r.Hosts, h) ||
		strings.ContainsFunc(h, func(c rune) bool { return c <= ' ' || c == 0x7f }) {
		return
	}
	r.Hosts = append(r.Hosts, h)
}

func (r *Result) add(o *Result) {
	// Batches are written in the order they came: a later one's status
	// line is the newer.
	if o.Sensor != nil {
		r.Sensor = o.Sensor
	}
	r.Indexed += o.Indexed
	r.Rejected += o.Rejected
	r.Duplicates += o.Duplicates
	r.Temporary += o.Temporary
	r.Retimed += o.Retimed
	r.FieldsDropped += o.FieldsDropped
	for _, e := range o.Errors {
		if len(r.Errors) < maxErrors {
			r.Errors = append(r.Errors, e)
		}
	}
}

// Ingest normalizes records sent with a Fluent Bit tag and writes them.
func (p *Pipeline) Ingest(ctx context.Context, tag string, records []map[string]any) (*Result, error) {
	p.stats.Received.Add(int64(len(records)))
	p.stats.LastSeen.Store(p.now().Unix())
	total := &Result{Received: len(records)}
	for start := 0; start < len(records); start += batchEvents {
		end := min(start+batchEvents, len(records))
		events := make([]Event, 0, end-start)
		for _, r := range records[start:end] {
			if ev, drop := p.normalize(tag, r, p.now()); !drop {
				events = append(events, ev)
			}
		}
		if len(events) == 0 {
			continue
		}
		res, err := p.write(ctx, events, nil)
		if err != nil {
			p.stats.Failed.Add(int64(len(records) - end))
			return nil, err
		}
		total.add(res)
	}
	return total, nil
}

// IngestEvents writes events that are already normalized, such as syslog
// messages, to the same daily data model indices as Ingest, and counts them
// in the same stats. An event with no time gets the current time, and one
// with no model goes to Other.
func (p *Pipeline) IngestEvents(ctx context.Context, events []Event) (*Result, error) {
	p.stats.Received.Add(int64(len(events)))
	p.stats.LastSeen.Store(p.now().Unix())
	res, err := p.write(ctx, events, nil)
	if err != nil {
		return nil, err
	}
	res.Received = len(events)
	return res, nil
}

// write files events under their index and writes them. An event whose own
// time is outside TimeUsable's window is filed under the time it arrived,
// with its own time kept as device_time, and sender-chosen field names go
// through the field budget. When OpenSearch turns an event away because of
// one of its fields (a clash with how the index maps it, or a full
// mapping), the event is written again with only its known fields, so junk
// fields cannot cost a legitimate event. ids, when given, are the events'
// document IDs, so a resent event already stored counts as a duplicate
// instead of being stored twice.
func (p *Pipeline) write(ctx context.Context, events []Event, ids []string) (*Result, error) {
	prefix := p.Prefix
	if prefix == "" {
		prefix = "signalith"
	}
	recv := p.now()
	oldest := dayOf(recv.Add(-p.maxAge() - 24*time.Hour))
	res := &Result{Received: len(events)}
	docs := make([]store.IndexedDoc, 0, len(events))
	var reserved []string
	ctxOrigin := OriginFrom(ctx)
	// Linux program starts, joined from their audit records, are stored
	// too. Each takes its ID from its EXECVE record's.
	for i := range min(len(ids), len(events)) {
		if events[i].ID == "" && isAuditRecord(&events[i], "EXECVE") {
			events[i].ID = ids[i]
		}
	}
	if starts := p.procs.Starts(events); len(starts) > 0 {
		events = append(events, starts...)
	}
	// Each server's share of the day's new field names, and the indices
	// whose mapping is near OpenSearch's limit, asked once per index.
	budget := namesBudget(p.servers())
	full := map[string]bool{}
	urlQuery := p.URLQuery()
	for i := range events {
		ev := &events[i]
		if ev.Fields == nil {
			ev.Fields = map[string]any{}
		}
		nReserved := p.dropReserved(ev.Fields, &reserved)
		ApplyURLQuery(ev.Fields, urlQuery)
		// After the drop, so only Signalith sets these. The sample data
		// carries its own marker instead, and the origin an event of it
		// names (as a sensor's token would send it), so detections that
		// believe only such events fire on the sample too.
		if p.SampleMark == "" {
			o := ev.Origin
			if o.IsZero() {
				o = ctxOrigin
			}
			o.stamp(ev.Fields)
			setSource(ev.Fields, o.Intake)
		} else {
			ev.Origin.stamp(ev.Fields)
		}
		if ev.Time.IsZero() {
			ev.Time = recv
		} else if !TimeUsable(ev.Time, recv, p.maxAge()) {
			ev.DeviceTime = ev.Time
			ev.Time = recv
		}
		if !ev.DeviceTime.IsZero() {
			res.Retimed++
		}
		if ev.Model == "" {
			ev.Model = "Other"
		}
		day := dayOf(ev.Time)
		index := p.Rollover.Index(datamodel.IndexName(prefix, ev.Model, day))
		isFull, asked := full[index]
		if !asked && hasUnknown(ev.Fields) {
			isFull = p.mappingFull(ctx, index)
			full[index] = isFull
		}
		if n := nReserved + p.names.limitTo(index, day, oldest, ev.Fields, budget, isFull); n > 0 {
			ev.Fields["dropped_fields"] = int64(n)
			res.FieldsDropped += n
		}
		doc := store.IndexedDoc{Index: index, Doc: ev.Document(), ID: ev.ID}
		if doc.ID == "" && i < len(ids) {
			doc.ID = ids[i]
		}
		docs = append(docs, doc)
	}
	errs, err := p.Store.Bulk(ctx, docs)
	if err != nil {
		p.stats.Failed.Add(int64(len(docs)))
		return nil, err
	}
	if retry, pos, removed := retryable(errs, events, docs); len(retry) > 0 {
		errs = keepOthers(errs, pos)
		again, err := p.Store.Bulk(ctx, retry)
		if err != nil {
			again = make([]store.BulkItemError, len(retry))
			for i, d := range retry {
				again[i] = store.BulkItemError{Index: d.Index, Reason: err.Error(), Pos: i, Status: http.StatusServiceUnavailable}
			}
		}
		for i := range again {
			// Positions in the retry are positions in events here.
			again[i].Pos = pos[min(max(again[i].Pos, 0), len(pos)-1)]
		}
		errs = append(errs, again...)
		res.FieldsDropped += removed
	}
	errs, res.Duplicates = store.WithoutConflicts(errs, docs)
	res.Rejected = len(errs)
	res.Indexed = len(docs) - len(errs)
	res.Sensor = storedSensor(events, errs, recv)
	limited := 0
	for _, e := range errs {
		if temporary(e) {
			res.Temporary++
		}
		if shardLimit(e) {
			limited++
		}
	}
	if limited > 0 {
		p.warn("shards", "OpenSearch refused to create a new index: the cluster holds the most shards it allows (cluster.max_shards_per_node times the data nodes). "+
			"The events were refused for now and senders that retry send them again; keep fewer days, send fewer data models, add a data node, "+
			"or raise cluster.max_shards_per_node (a soft limit)",
			"events", limited, "first", firstShardLimit(errs))
	}
	if len(errs) > maxErrors {
		errs = errs[:maxErrors]
	}
	res.Errors = errs
	p.stats.Indexed.Add(int64(res.Indexed))
	if res.Indexed > 0 {
		p.stats.LastIndexed.Store(p.now().Unix())
	}
	p.stats.Failed.Add(int64(res.Rejected))
	p.stats.Retimed.Add(int64(res.Retimed))
	p.stats.FieldsDropped.Add(int64(res.FieldsDropped))
	if res.Retimed > 0 {
		p.warn("retimed", "some events had a time too old or too far ahead; they were filed under the time they arrived, with their own time in device_time",
			"events", res.Retimed, "max_event_age", p.maxAge().String(), "max_ahead", MaxEventAhead.String())
	}
	if res.FieldsDropped > 0 {
		p.warn("fields", "some event fields were not indexed (invalid names, too many fields, or too many new field names for one day); their values stay in the raw event",
			"fields", res.FieldsDropped)
	}
	if len(reserved) > 0 {
		p.warn("reserved", "some events carried fields that only Signalith sets, such as the sample-data marker; the events were stored without those fields",
			"fields", strings.Join(reserved, ", "))
	}
	return res, nil
}

// storedSensor returns the last sensor status line among the events that
// were stored (errs are the ones that were not). Which line is newest
// goes by the order they came, never by the time a line gives itself: a
// sensor whose clock ran ahead, or a sender writing a time far ahead,
// would otherwise keep its status forever. That time is kept for the
// page, but never later than when the line arrived (recv).
func storedSensor(events []Event, errs []store.BulkItemError, recv time.Time) *SensorStatus {
	var out *SensorStatus
	for i := len(events) - 1; i >= 0 && out == nil; i-- {
		s := events[i].Sensor
		if s == nil || slices.ContainsFunc(errs, func(e store.BulkItemError) bool { return e.Pos == i }) {
			continue
		}
		out = s
	}
	if out != nil && (out.At.IsZero() || out.At.After(recv)) {
		out.At = recv
	}
	return out
}

// dropReserved removes the fields a sender may not set (see Reserved)
// from an event's fields, adds the names it found to seen, and returns how
// many it removed. Ingest drops them rather than refuse the event: the
// event is real activity that must stay visible, and an agent that is
// refused sends the same batch again forever. An event that could carry
// the sample-data marker would hide from live detections and be deleted
// with the sample data. On the sample-data loader's pipeline it then
// marks the event with the load's ID; the marker the generator already
// put there is not counted.
func (p *Pipeline) dropReserved(f map[string]any, seen *[]string) int {
	n := 0
	for k := range f {
		if !Reserved(k) {
			continue
		}
		delete(f, k)
		if k == datamodel.SampleField && p.SampleMark != "" {
			continue
		}
		n++
		if !slices.Contains(*seen, k) && len(*seen) < 20 {
			*seen = append(*seen, k)
		}
	}
	if p.SampleMark != "" {
		f[datamodel.SampleField] = p.SampleMark
	}
	return n
}

// retryable returns, for events OpenSearch rejected because of a field,
// their documents with only known fields, their positions in events, and
// how many fields that left out (also added to each event's
// dropped_fields).
func retryable(errs []store.BulkItemError, events []Event, docs []store.IndexedDoc) ([]store.IndexedDoc, []int, int) {
	var retry []store.IndexedDoc
	var pos []int
	removed := 0
	for _, e := range errs {
		if !fieldRejection(e.Type) || e.Pos < 0 || e.Pos >= len(events) || containsInt(pos, e.Pos) {
			continue
		}
		ev := &events[e.Pos]
		n := onlyKnown(ev.Fields)
		if n == 0 {
			continue // nothing to leave out; the rejection stands
		}
		prev, _ := ev.Fields["dropped_fields"].(int64)
		ev.Fields["dropped_fields"] = prev + int64(n)
		removed += n
		retry = append(retry, store.IndexedDoc{Index: docs[e.Pos].Index, ID: docs[e.Pos].ID, Doc: ev.Document()})
		pos = append(pos, e.Pos)
	}
	return retry, pos, removed
}

// temporary reports whether OpenSearch turned an event away for a reason
// that may pass, so the sender should send it again later: too busy
// (429, es_rejected_execution_exception), a write block such as a full
// disk (cluster_block_exception), no room for the day's new index under
// the shard limit (see shardLimit), or a failure on its side (5xx).
func temporary(e store.BulkItemError) bool {
	if shardLimit(e) {
		return true
	}
	switch e.Type {
	case "cluster_block_exception", "es_rejected_execution_exception", "circuit_breaking_exception",
		"unavailable_shards_exception", "process_cluster_event_timeout_exception", "timeout_exception":
		return true
	}
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// shardLimit reports whether OpenSearch refused to create the event's
// index because the cluster holds the most shards it allows
// (cluster.max_shards_per_node times the data nodes). Like a full disk,
// it passes once room is made, so the event is sent again rather than
// dropped.
func shardLimit(e store.BulkItemError) bool {
	return e.Type == "validation_exception" && strings.Contains(e.Reason, "maximum") && strings.Contains(e.Reason, "shards open")
}

// firstShardLimit returns the reason of the first shard-limit refusal.
func firstShardLimit(errs []store.BulkItemError) string {
	for _, e := range errs {
		if shardLimit(e) {
			return e.Reason
		}
	}
	return ""
}

// fieldRejection reports whether OpenSearch turned a document away because
// of one of its fields: a value the mapping cannot take, or a full mapping.
func fieldRejection(errType string) bool {
	switch errType {
	case "mapper_parsing_exception", "illegal_argument_exception", "document_parsing_exception", "strict_dynamic_mapping_exception":
		return true
	}
	return false
}

// keepOthers returns the errors not about the documents at pos.
func keepOthers(errs []store.BulkItemError, pos []int) []store.BulkItemError {
	var out []store.BulkItemError
	for _, e := range errs {
		if !containsInt(pos, e.Pos) || !fieldRejection(e.Type) {
			out = append(out, e)
		}
	}
	return out
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// warn logs at most once a minute per kind.
func (p *Pipeline) warn(kind, msg string, args ...any) {
	if p.Log == nil {
		return
	}
	now := time.Now()
	p.warnMu.Lock()
	if p.warned == nil {
		p.warned = map[string]time.Time{}
	}
	last, seen := p.warned[kind]
	if seen && now.Sub(last) < time.Minute {
		p.warnMu.Unlock()
		return
	}
	p.warned[kind] = now
	p.warnMu.Unlock()
	p.Log.Warn(msg, args...)
}

// ErrBusy means too many ingest requests are being written already; the
// sender should retry shortly (Fluent Bit does on a 503).
var ErrBusy = errors.New("Signalith is busy writing other events; send again in a few seconds")

// DefaultMaxConcurrent is how many ingest requests are decoded and written
// at once when Pipeline.MaxConcurrent is not set. Each request waits on its
// bulk write to OpenSearch, so too few slots leave both the server's CPU
// and OpenSearch idle: in the lab load test 8 slots held one 2-core server
// to about 11,000 events a second with OpenSearch mostly idle. The bodies
// those requests hold stay capped by MaxReceiving whatever this is.
const DefaultMaxConcurrent = 32

// Document returns the OpenSearch document for an event, dropping empty
// values so searches like user=* only match real values. The event time,
// data model and device time always come from the event itself, never
// from a field of the same name.
func (e Event) Document() map[string]any {
	doc := map[string]any{}
	for k, v := range e.Fields {
		switch k {
		case "@timestamp", "datamodel", "device_time":
			continue
		}
		if s, ok := v.(string); ok {
			s = strings.TrimSpace(s)
			if s == "" || s == "-" {
				continue
			}
			v = s
		}
		if v == nil {
			continue
		}
		doc[k] = v
	}
	doc["@timestamp"] = e.Time.UTC().Format(time.RFC3339Nano)
	doc["datamodel"] = e.Model
	if !e.DeviceTime.IsZero() {
		doc["device_time"] = e.DeviceTime.UTC().Format(time.RFC3339Nano)
	}
	return doc
}

// Normalize maps one record to an event. tag is the Fluent Bit tag, which
// says what kind of source the record came from.
func Normalize(tag string, r map[string]any, now time.Time) Event {
	ev := parseRecord(tag, r, now)
	if ev.Time.IsZero() {
		ev.Time = recordTime(r, now)
	}
	if ev.Model == "" {
		ev.Model = "Other"
	}
	if ev.Fields == nil {
		ev.Fields = map[string]any{}
	}
	if _, ok := ev.Fields["message"]; !ok {
		raw, _ := json.Marshal(r)
		ev.Fields["message"] = string(raw)
	}
	if !hasSource(ev.Fields) {
		// Where the agent read it: the file (the tail inputs' Path_Key),
		// or the journal.
		if f := str(r, "file"); f != "" {
			ev.Fields["source"] = truncateUTF8(CapValue(f), maxSourceLen)
		} else if strings.HasPrefix(tag, "linux.journal") {
			ev.Fields["source"] = "journald"
		}
	}
	return ev
}

// maxSourceLen caps a source taken from a file path.
const maxSourceLen = 1024

func hasSource(f map[string]any) bool {
	s, ok := f["source"].(string)
	return ok && s != ""
}

// setSource gives an event without a source one, as Splunk's source field
// reads: a Windows event's log (WinEventLog:Security), else how it arrived.
func setSource(f map[string]any, intake string) {
	if hasSource(f) {
		return
	}
	if st, _ := f["sourcetype"].(string); strings.HasPrefix(st, "WinEventLog:") {
		f["source"] = st
	} else if intake != "" {
		f["source"] = intake
	}
}

func sourcetypeForTag(tag string) string {
	switch {
	case strings.HasPrefix(tag, "linux.auth"):
		return "linux:auth"
	case strings.HasPrefix(tag, "syslog"):
		return "syslog"
	case strings.HasPrefix(tag, "linux."):
		return "linux:" + strings.TrimPrefix(tag, "linux.")
	}
	return "syslog"
}

func parseGeneric(r map[string]any) Event {
	fields := map[string]any{"sourcetype": "json"}
	for k, v := range r {
		if k == "date" || k == "@timestamp" {
			continue // the record's time; see recordTime
		}
		switch v.(type) {
		case map[string]any, []any:
			b, _ := json.Marshal(v)
			fields[k] = string(b)
		default:
			fields[k] = v
		}
	}
	return Event{Model: "Other", Fields: fields}
}

// recordTime reads Fluent Bit's "date" key, or "@timestamp" when a record
// has no usable date (JSON sent by a script or another shipper), as epoch
// seconds or an ISO string, falling back to now. Like every event time, it
// is then kept within ingest's window (see TimeUsable).
func recordTime(r map[string]any, now time.Time) time.Time {
	for _, k := range []string{"date", "@timestamp"} {
		if t, ok := timeValue(r[k]); ok {
			return t
		}
	}
	return now.UTC()
}

// timeValue reads a record's time: epoch seconds as a number, or a string
// in one of timeLayouts.
func timeValue(v any) (time.Time, bool) {
	switch d := v.(type) {
	case float64:
		sec := int64(d)
		return time.Unix(sec, int64((d-float64(sec))*1e9)).UTC(), true
	case json.Number:
		if f, err := d.Float64(); err == nil {
			sec := int64(f)
			return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), true
		}
	case string:
		return parseTime(d)
	}
	return time.Time{}, false
}

var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05.000000000 -0700",
	"2006-01-02 15:04:05 MST",
	"2006-01-02T15:04:05.000000000Z",
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05",
}

func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range timeLayouts {
		t, err := time.Parse(l, s)
		if err != nil {
			continue
		}
		if strings.HasSuffix(l, "MST") && !knownZone(t) {
			// Go reads a zone name it doesn't know (one that isn't this
			// server's, or "XYZ") as UTC, which could be hours off: the
			// time isn't used, and the receive time is.
			return time.Time{}, false
		}
		return t.UTC(), true
	}
	return time.Time{}, false
}

// knownZone reports whether a time parsed with a zone name has the offset
// that name stands for: UTC and GMT, or this server's own zone names. Go
// gives any other name an offset of zero.
func knownZone(t time.Time) bool {
	name, off := t.Zone()
	if off != 0 || name == "UTC" || name == "GMT" {
		return true
	}
	local, _ := t.In(time.Local).Zone()
	return name == local
}

func has(r map[string]any, k string) bool {
	_, ok := r[k]
	return ok
}

// str returns the first present key as a string.
func str(r map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := r[k]; ok && v != nil {
			switch x := v.(type) {
			case string:
				return x
			case json.Number:
				return x.String()
			case float64:
				return strconv.FormatFloat(x, 'f', -1, 64)
			default:
				return fmt.Sprint(x)
			}
		}
	}
	return ""
}

// atoi returns a number for numeric strings, or nil.
func atoi(s string) any {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if n, err := strconv.ParseInt(s[2:], 16, 64); err == nil {
			return n
		}
	}
	return nil
}

// baseName returns the file name of a Windows or Unix path.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// parseRecord runs the parser for a record's kind of source. A parser that
// panics on a crafted record stores the record as a generic event instead,
// so one bad record cannot fail the batch it came in or stop the server.
func parseRecord(tag string, r map[string]any, now time.Time) (ev Event) {
	defer func() {
		if p := recover(); p != nil {
			parserPanics.Add(1)
			if last := lastParserPanicLog.Load(); now.Unix()-last >= 60 && lastParserPanicLog.CompareAndSwap(last, now.Unix()) {
				slog.Warn("a record stopped its parser; stored it as a generic event (logged once a minute)", "tag", tag, "panic", fmt.Sprint(p))
			}
			ev = parseGeneric(r)
		}
	}()
	switch {
	case tag == SensorStatusTag:
		ev = parseSensorStatus(r)
	case isWazuhTag(tag) || IsWazuhAlert(r):
		ev = parseWazuhRecord(r)
	case isZeekTag(tag) || (!isSuricataTag(tag) && IsZeekRecord(r)):
		ev = parseZeekRecord(tag, r)
	case isSuricataTag(tag) || IsSuricataEVE(r):
		ev = parseSuricataRecord(r)
	case tag == CloudTrailTag || strings.HasPrefix(tag, CloudTrailTag+".") || IsCloudTrailRecord(r):
		ev = ParseCloudTrail(r)
	case tag == AzureTag || strings.HasPrefix(tag, AzureTag+".") || IsAzureRecord(r):
		ev = ParseAzure(r)
	case tag == O365Tag || strings.HasPrefix(tag, O365Tag+".") || IsO365Record(r):
		ev = ParseO365(r)
	case tag == GCPTag || strings.HasPrefix(tag, GCPTag+".") || IsGCPRecord(r):
		ev = ParseGCP(r)
	case tag == OktaTag || strings.HasPrefix(tag, OktaTag+".") || IsOktaRecord(r):
		ev = ParseOkta(r)
	case isKubernetesTag(tag) || IsKubernetesRecord(r):
		ev = ParseKubernetes(kubeLine(r))
	case tag == GitHubTag || strings.HasPrefix(tag, GitHubTag+".") || githubSniffTag(tag) && IsGitHubRecord(r):
		ev = ParseGitHub(r)
	case isWindowsRecord(tag, r):
		ev = parseWindows(r)
	case strings.HasPrefix(tag, "linux.clamav"):
		ev = parseClamAVRecord(r)
	case strings.HasPrefix(tag, WebTag):
		ev = parseWebRecord(r)
	case strings.HasPrefix(tag, "linux.audit"):
		ev = parseAuditdRecord(r)
	case strings.HasPrefix(tag, "linux.journal") || has(r, "MESSAGE"):
		ev = parseJournal(r)
	case strings.HasPrefix(tag, "linux.") || strings.HasPrefix(tag, "syslog") || has(r, "log"):
		ev = parseSyslogLine(str(r, "log", "message"), sourcetypeForTag(tag), now)
	default:
		ev = parseGeneric(r)
	}
	return ev
}

var (
	// parserPanics counts records whose parser panicked.
	parserPanics atomic.Int64
	// lastParserPanicLog is when a parser panic was last logged, in Unix
	// seconds.
	lastParserPanicLog atomic.Int64
)
