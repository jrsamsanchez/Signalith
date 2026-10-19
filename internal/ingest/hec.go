// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Senders built for Splunk's HTTP Event Collector (HEC) send to
// /services/collector/event, a stream of JSON objects, each with the
// event and its metadata:
//
//	{"time": 1700000000.5, "host": "web1", "source": "app", "sourcetype": "linux_secure",
//	 "index": "main", "event": "Accepted password for ...", "fields": {"env": "prod"}}
//
// and to /services/collector/raw, lines of text whose metadata is in the
// query string. Signalith files every event under its data model, as
// events from agents are: the sourcetype picks the parser where Signalith
// has one (syslog, linux_secure, web access logs, and the JSON of the
// cloud sources it already reads), and anything else is an Other event
// with the sender's sourcetype. The sender's index is kept in orig_index
// (searches choose data models with index= and datamodel=), and a
// sourcetype a parser replaced in orig_sourcetype.

// HECMeta is an event's metadata: from each /event object, or for /raw
// from the query string.
type HECMeta struct {
	Host, Source, Sourcetype, Index string
	// Time is the event's time, zero when the sender gave none.
	Time time.Time
}

// HECError is a HEC request refused as a whole, before anything was
// written: Status is the HTTP status and Code the HEC status code senders
// expect, and Event is the 0-based number of the event at fault (Splunk's
// invalid-event-number), -1 for none.
type HECError struct {
	Status int
	Code   int
	Text   string
	Event  int
}

func (e *HECError) Error() string { return e.Text }

// HEC status codes, as senders expect them.
const (
	HECSuccess       = 0
	HECTokenDisabled = 1
	HECTokenRequired = 2
	HECInvalidAuth   = 3
	HECInvalidToken  = 4
	HECNoData        = 5
	HECInvalidFormat = 6
	HECServerBusy    = 9
	HECEventRequired = 12
	HECEventBlank    = 13
	HECAckDisabled   = 14
	HECBadFields     = 15
	HECQueryAuth     = 16
	HECHealthy       = 17
)

// Limits of a HEC event beyond the ingest request's own.
const (
	// hecMaxFields caps the indexed fields of one event.
	hecMaxFields = 100
	// hecMaxMeta caps a sourcetype and an index name.
	hecMaxMeta = 256
)

func hecBad(code, event int, format string, args ...any) *HECError {
	return &HECError{Status: http.StatusBadRequest, Code: code, Text: fmt.Sprintf(format, args...), Event: event}
}

// hecItem is one event of a request.
type hecItem struct {
	meta   HECMeta
	line   string         // the event as text, or
	record map[string]any // the event as a JSON object
	fields map[string]any // indexed fields
	size   int
}

// IngestHEC writes the events of a /services/collector/event request
// body. The whole body is checked first, so a refused request (a
// *HECError) writes nothing. Each event's document ID comes from the body
// and its place in it, so a sender that sends the same request again after
// an error does not store its events twice.
func (p *Pipeline) IngestHEC(ctx context.Context, body []byte) (*Result, error) {
	n := 0
	if err := walkHEC(body, false, func(*hecItem) error { n++; return nil }); err != nil {
		return nil, err
	}
	return p.writeHEC(ctx, "hec", body, n, func(fn func(*hecItem) error) error { return walkHEC(body, true, fn) })
}

// IngestHECRaw writes the lines of a /services/collector/raw request body,
// one event each, with meta for all of them. Empty lines are skipped.
func (p *Pipeline) IngestHECRaw(ctx context.Context, body []byte, meta HECMeta) (*Result, error) {
	meta = cleanHECMeta(meta)
	n := 0
	if err := walkHECRaw(body, meta, func(*hecItem) error { n++; return nil }); err != nil {
		return nil, err
	}
	seed := "hec.raw\x00" + meta.Host + "\x00" + meta.Source + "\x00" + meta.Sourcetype + "\x00" + meta.Index
	return p.writeHEC(ctx, seed, body, n, func(fn func(*hecItem) error) error { return walkHECRaw(body, meta, fn) })
}

func (p *Pipeline) writeHEC(ctx context.Context, seedTag string, body []byte, n int, walk func(func(*hecItem) error) error) (*Result, error) {
	p.stats.Received.Add(int64(n))
	p.stats.LastSeen.Store(p.now().Unix())
	total := &Result{Received: n}
	if n == 0 {
		return total, nil
	}
	seed := bodySeed(seedTag, body)
	batch := make([]Event, 0, min(n, batchEvents))
	ids := make([]string, 0, cap(batch))
	size, done, pos := 0, 0, 0
	flush := func() error {
		res, err := p.write(ctx, batch, ids)
		done += len(batch)
		clear(batch)
		batch, ids, size = batch[:0], ids[:0], 0
		if err != nil {
			p.stats.Failed.Add(int64(n - done))
			return err
		}
		total.add(res)
		return nil
	}
	err := walk(func(it *hecItem) error {
		ev, drop := p.hecEvent(it, p.now())
		pos++
		if drop {
			return nil
		}
		batch = append(batch, ev)
		ids = append(ids, recordID(seed, pos-1))
		total.noteHost(&batch[len(batch)-1])
		size += it.size
		if len(batch) >= batchEvents || size >= batchBytes {
			return flush()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(batch) > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return total, nil
}

// walkHEC reads the events of an /event body: JSON objects one after
// another, with or without white space between them. Without keep it only
// checks them, decoding no more than it must.
func walkHEC(body []byte, keep bool, fn func(*hecItem) error) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return &HECError{Status: http.StatusBadRequest, Code: HECNoData, Text: "No data", Event: -1}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var last int64
	for i := 0; ; i++ {
		var obj map[string]json.RawMessage
		err := dec.Decode(&obj)
		if err == io.EOF {
			return nil
		}
		if i >= MaxRecords {
			return &HECError{Status: http.StatusRequestEntityTooLarge, Code: HECInvalidFormat, Event: i,
				Text: fmt.Sprintf("the request has more than %d events; send smaller batches", MaxRecords)}
		}
		if err != nil {
			var te *json.UnmarshalTypeError
			if errors.As(err, &te) {
				return hecBad(HECInvalidFormat, i, "Invalid data format: event %d is not a JSON object", i)
			}
			return hecBad(HECInvalidFormat, i, "Invalid data format: event %d is not valid JSON", i)
		}
		end := dec.InputOffset()
		raw := body[last:end]
		last = end
		if len(raw) > MaxRecordBytes {
			return &HECError{Status: http.StatusRequestEntityTooLarge, Code: HECInvalidFormat, Event: i,
				Text: fmt.Sprintf("event %d is %d bytes; the limit is %d bytes (1 MB) per event", i, len(raw), MaxRecordBytes)}
		}
		if d := depth(raw); d > MaxDepth {
			return hecBad(HECInvalidFormat, i, "Invalid data format: event %d nests objects or arrays %d levels deep; the limit is %d", i, d, MaxDepth)
		}
		it, err := hecObject(obj, i, keep)
		if err != nil {
			return err
		}
		it.size = len(raw)
		if err := fn(it); err != nil {
			return err
		}
	}
}

// hecObject reads one /event object. Without keep, the event itself is
// only checked.
func hecObject(obj map[string]json.RawMessage, i int, keep bool) (*hecItem, error) {
	it := &hecItem{}
	for _, k := range []string{"host", "source", "sourcetype", "index"} {
		raw, ok := obj[k]
		if !ok || string(raw) == "null" {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, hecBad(HECInvalidFormat, i, "Invalid data format: %s of event %d must be a string", k, i)
		}
		switch k {
		case "host":
			it.meta.Host = s
		case "source":
			it.meta.Source = s
		case "sourcetype":
			it.meta.Sourcetype = s
		case "index":
			it.meta.Index = s
		}
	}
	if raw, ok := obj["time"]; ok {
		it.meta.Time = hecTime(raw)
	}
	it.meta = cleanHECMeta(it.meta)
	raw, ok := obj["event"]
	if !ok || string(raw) == "null" {
		return nil, hecBad(HECEventRequired, i, "Event field is required (event %d)", i)
	}
	var ev any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&ev); err != nil {
		return nil, hecBad(HECInvalidFormat, i, "Invalid data format: event %d", i)
	}
	switch v := ev.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, hecBad(HECEventBlank, i, "Event field cannot be blank (event %d)", i)
		}
		it.line = v
	case map[string]any:
		if len(v) == 0 {
			return nil, hecBad(HECEventBlank, i, "Event field cannot be blank (event %d)", i)
		}
		it.record = v
	default:
		// A number, true or false, or an array: kept as its JSON.
		it.line = string(bytes.TrimSpace(raw))
	}
	if raw, ok := obj["fields"]; ok && string(raw) != "null" {
		var fields map[string]any
		fd := json.NewDecoder(bytes.NewReader(raw))
		fd.UseNumber()
		if fd.Decode(&fields) != nil {
			return nil, hecBad(HECBadFields, i, "Error in handling indexed fields: fields of event %d must be an object", i)
		}
		if len(fields) > hecMaxFields {
			return nil, hecBad(HECBadFields, i, "Error in handling indexed fields: event %d has %d; the limit is %d", i, len(fields), hecMaxFields)
		}
		for k, v := range fields {
			if !hecFieldValue(v) {
				return nil, hecBad(HECBadFields, i, "Error in handling indexed fields: %q of event %d must be a string, a number or a list of them", k, i)
			}
		}
		it.fields = fields
	}
	if !keep {
		it.line, it.record, it.fields = "", nil, nil
	}
	return it, nil
}

// hecFieldValue reports whether v may be an indexed field's value: a
// string, number or true/false, or a list of them.
func hecFieldValue(v any) bool {
	switch x := v.(type) {
	case string, json.Number, bool:
		return true
	case []any:
		for _, e := range x {
			switch e.(type) {
			case string, json.Number, bool:
			default:
				return false
			}
		}
		return true
	}
	return false
}

// hecTime reads an event's time: epoch seconds, as a number or a string,
// with a fraction for sub-second times. Anything else is no time.
func hecTime(raw json.RawMessage) time.Time {
	s := strings.Trim(string(bytes.TrimSpace(raw)), `"`)
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 || f > 1e11 {
		return time.Time{}
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC()
}

// cleanHECMeta trims the metadata and caps its length.
func cleanHECMeta(m HECMeta) HECMeta {
	m.Host = truncateUTF8(CapValue(strings.TrimSpace(m.Host)), maxHostLen)
	m.Source = truncateUTF8(CapValue(strings.TrimSpace(m.Source)), maxSourceLen)
	m.Sourcetype = truncateUTF8(CapValue(strings.TrimSpace(m.Sourcetype)), hecMaxMeta)
	m.Index = truncateUTF8(CapValue(strings.TrimSpace(m.Index)), hecMaxMeta)
	return m
}

// walkHECRaw reads the lines of a /raw body.
func walkHECRaw(body []byte, meta HECMeta, fn func(*hecItem) error) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return &HECError{Status: http.StatusBadRequest, Code: HECNoData, Text: "No data", Event: -1}
	}
	n := 0
	for rest := body; len(rest) > 0; {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = nil
		}
		line = bytes.TrimRight(line, "\r")
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if n >= MaxRecords {
			return &HECError{Status: http.StatusRequestEntityTooLarge, Code: HECInvalidFormat, Event: n,
				Text: fmt.Sprintf("the request has more than %d lines; send smaller batches", MaxRecords)}
		}
		if len(line) > MaxRecordBytes {
			return &HECError{Status: http.StatusRequestEntityTooLarge, Code: HECInvalidFormat, Event: n,
				Text: fmt.Sprintf("line %d is %d bytes; the limit is %d bytes (1 MB) per event", n, len(line), MaxRecordBytes)}
		}
		if err := fn(&hecItem{meta: meta, line: string(line), size: len(line)}); err != nil {
			return err
		}
		n++
	}
	return nil
}

// hecEvent turns a HEC event into a Signalith event.
func (p *Pipeline) hecEvent(it *hecItem, now time.Time) (Event, bool) {
	st := strings.ToLower(it.meta.Sourcetype)
	rec := it.record
	if rec == nil && (st == "_json" || st == "json") {
		// A JSON event sent as text, as /raw sends it.
		if s := strings.TrimSpace(it.line); len(s) > 1 && s[0] == '{' && depth([]byte(s)) <= MaxDepth {
			d := json.NewDecoder(strings.NewReader(s))
			d.UseNumber()
			var m map[string]any
			if d.Decode(&m) == nil && len(m) > 0 {
				rec = m
			}
		}
	}
	var ev Event
	var drop bool
	if rec != nil {
		ev, drop = p.normalize(hecTag(st), rec, now)
		if drop {
			return Event{}, true
		}
	} else {
		ev = hecLine(it.line, st, it.meta.Host, now)
	}
	if ev.Fields == nil {
		ev.Fields = map[string]any{}
	}
	f := ev.Fields
	m := it.meta
	if !m.Time.IsZero() {
		ev.Time = m.Time
	}
	if h, _ := f["host"].(string); h == "" && m.Host != "" {
		f["host"] = m.Host
	}
	if m.Source != "" && !hasSource(f) {
		f["source"] = m.Source
	}
	if m.Sourcetype != "" {
		cur, _ := f["sourcetype"].(string)
		switch {
		case ev.Model == "Other" || cur == "" || cur == "json":
			f["sourcetype"] = m.Sourcetype
		case cur != m.Sourcetype:
			f["orig_sourcetype"] = m.Sourcetype
		}
	}
	if m.Index != "" {
		f["orig_index"] = m.Index
	}
	for k, v := range it.fields {
		if _, taken := f[k]; taken || !ValidFieldName(k) {
			continue
		}
		if l, ok := v.([]any); ok {
			vals := make([]any, 0, len(l))
			for _, e := range l {
				vals = append(vals, hecScalar(e))
			}
			f[k] = vals
			continue
		}
		f[k] = hecScalar(v)
	}
	return ev, false
}

func hecScalar(v any) any {
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	return v
}

// hecTag is the agent tag whose parser reads JSON events of a sourcetype,
// for the sources Signalith has a parser for; other events are told apart
// by what they hold, as the agent's are.
func hecTag(st string) string {
	switch {
	case st == "aws:cloudtrail":
		return CloudTrailTag
	case strings.HasPrefix(st, "o365:") || strings.HasPrefix(st, "ms:o365:"):
		return O365Tag
	case strings.HasPrefix(st, "okta:") || st == "okta":
		return OktaTag
	case strings.HasPrefix(st, "google:gcp:") || strings.HasPrefix(st, "gcp:"):
		return GCPTag
	case strings.HasPrefix(st, "azure:") || strings.HasPrefix(st, "mscs:azure:"):
		return AzureTag
	case strings.HasPrefix(st, "github:"):
		return GitHubTag
	}
	return "hec"
}

// hecLine parses an event sent as text.
func hecLine(line, st, host string, now time.Time) (ev Event) {
	defer func() {
		if recover() != nil {
			parserPanics.Add(1)
			ev = Event{Model: "Other", Fields: map[string]any{"message": line}}
		}
	}()
	switch {
	case st == "linux_secure" || st == "linux:auth":
		return parseSyslogLine(line, "linux:auth", now)
	case st == "syslog" || strings.HasPrefix(st, "syslog:") || st == "linux_messages_syslog":
		return parseSyslogLine(line, "syslog", now)
	case strings.HasPrefix(st, "access_com") || st == "apache:access" || st == "nginx:plus:access" || st == "nginx:access":
		return parseWebRecord(map[string]any{"log": line, "hostname": host})
	}
	return Event{Model: "Other", Fields: map[string]any{"message": line}}
}
