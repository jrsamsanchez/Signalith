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
	"net/netip"
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
	// MaxConcurrent caps the ingest requests Admit lets in at once
	// (default 8), which bounds the memory decoding and writing use.
	MaxConcurrent int
	// MaxReceiving caps the memory request bodies hold, from their first
	// byte until they have been written (default DefaultMaxReceiving); one
	// sender may hold a quarter of it. See ReadBody.
	MaxReceiving int64
	// Log, when set, gets a warning (at most once a minute per kind) when
	// events are refiled under their arrival time or lose fields.
	Log *slog.Logger
	// SampleMark marks every event this pipeline writes as sample data
	// with this load ID (datamodel.SampleField). Only the sample-data
	// loader sets it, on a pipeline of its own: every other pipeline
	// removes the marker from what senders send (see reservedFields).
	SampleMark string

	stats   Stats
	names   fieldBudget
	slots   chan struct{}
	slotsMu sync.Mutex
	warnMu  sync.Mutex
	warned  map[string]time.Time

	// plaintext lists the agents that sent over plain HTTP, and refused
	// the ones whose batches were turned away.
	plaintext, refused senderLog

	// recvUsed is the receive budget in use, and recvBy each sender's
	// part of it (see ReadBody).
	recvMu   sync.Mutex
	recvUsed int64
	recvBy   map[netip.Addr]int64
}

// Stats counts what the pipeline has processed since start, for the health page.
type Stats struct {
	Received atomic.Int64
	Indexed  atomic.Int64
	Failed   atomic.Int64
	LastSeen atomic.Int64 // unix seconds
	// Retimed counts events whose own time was too old or too far ahead,
	// so they were filed under the time they arrived.
	Retimed atomic.Int64
	// FieldsDropped counts fields left out of events: invalid names, too
	// many fields, names over an index's budget, or names Signalith sets
	// itself (reservedFields).
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
	return s
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Pipeline) maxAge() time.Duration {
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
			events = append(events, Normalize(tag, r, p.now()))
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
	for i := range events {
		ev := &events[i]
		if ev.Fields == nil {
			ev.Fields = map[string]any{}
		}
		nReserved := p.dropReserved(ev.Fields, &reserved)
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
		index := datamodel.IndexName(prefix, ev.Model, day)
		if n := nReserved + p.names.limit(index, day, oldest, ev.Fields); n > 0 {
			ev.Fields["dropped_fields"] = int64(n)
			res.FieldsDropped += n
		}
		doc := store.IndexedDoc{Index: index, Doc: ev.Document()}
		if i < len(ids) {
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
	errs, res.Duplicates = withoutDuplicates(errs, docs)
	res.Rejected = len(errs)
	res.Indexed = len(docs) - len(errs)
	for _, e := range errs {
		if temporary(e) {
			res.Temporary++
		}
	}
	if len(errs) > maxErrors {
		errs = errs[:maxErrors]
	}
	res.Errors = errs
	p.stats.Indexed.Add(int64(res.Indexed))
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

// reservedFields are the fields Signalith sets on events itself, which a
// sender must not choose: the event time and data model (from where the
// event is filed), device_time and dropped_fields (what ingest did to the
// event), and the sample-data marker. Live detections leave out every
// event with the marker, and removing the sample data deletes them, so an
// event that could carry one would hide from detections and then be
// deleted. Ingest drops these from what senders send rather than refuse
// the event: the event is real activity that must stay visible, and an
// agent that is refused sends the same batch again forever.
var reservedFields = []string{"@timestamp", "datamodel", "device_time", "dropped_fields", datamodel.SampleField}

// dropReserved removes reservedFields from an event's fields, adds the
// names it found to seen, and returns how many it removed. On the
// sample-data loader's pipeline it then marks the event with the load's
// ID; the marker the generator already put there is not counted.
func (p *Pipeline) dropReserved(f map[string]any, seen *[]string) int {
	n := 0
	for _, k := range reservedFields {
		if _, ok := f[k]; !ok {
			continue
		}
		delete(f, k)
		if k == datamodel.SampleField && p.SampleMark != "" {
			continue
		}
		n++
		if !slices.Contains(*seen, k) {
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

// withoutDuplicates drops the errors saying a document with the same ID is
// already stored (an earlier send of the same request got it in), and
// reports how many there were.
func withoutDuplicates(errs []store.BulkItemError, docs []store.IndexedDoc) ([]store.BulkItemError, int) {
	out := errs[:0]
	n := 0
	for _, e := range errs {
		if e.Type == "version_conflict_engine_exception" && e.Pos >= 0 && e.Pos < len(docs) && docs[e.Pos].ID != "" {
			n++
			continue
		}
		out = append(out, e)
	}
	return out, n
}

// temporary reports whether OpenSearch turned an event away for a reason
// that may pass, so the sender should send it again later: too busy
// (429, es_rejected_execution_exception), a write block such as a full
// disk (cluster_block_exception), or a failure on its side (5xx).
func temporary(e store.BulkItemError) bool {
	switch e.Type {
	case "cluster_block_exception", "es_rejected_execution_exception", "circuit_breaking_exception",
		"unavailable_shards_exception", "process_cluster_event_timeout_exception", "timeout_exception":
		return true
	}
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
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

// Admit waits up to wait for one of MaxConcurrent ingest slots and returns
// the function that frees it, or ErrBusy. Take a slot once the request
// body has arrived (see ReadBody) and hold it while the body is decoded
// and written: that bounds the memory and OpenSearch writes ingest uses
// however many agents send at once, and a slow sender cannot hold a slot.
func (p *Pipeline) Admit(ctx context.Context, wait time.Duration) (func(), error) {
	p.slotsMu.Lock()
	if p.slots == nil {
		n := p.MaxConcurrent
		if n <= 0 {
			n = 8
		}
		p.slots = make(chan struct{}, n)
	}
	slots := p.slots
	p.slotsMu.Unlock()
	release := func() { <-slots }
	select {
	case slots <- struct{}{}:
		return release, nil
	default:
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case slots <- struct{}{}:
		return release, nil
	case <-t.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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
	var ev Event
	switch {
	case isWindowsRecord(tag, r):
		ev = parseWindows(r)
	case strings.HasPrefix(tag, "linux.journal") || has(r, "MESSAGE"):
		ev = parseJournal(r)
	case strings.HasPrefix(tag, "linux.") || strings.HasPrefix(tag, "syslog") || has(r, "log"):
		ev = parseSyslogLine(str(r, "log", "message"), sourcetypeForTag(tag), now)
	default:
		ev = parseGeneric(r)
	}
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
	return ev
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
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
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
