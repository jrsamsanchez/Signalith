// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package onboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// Limits on a sample, which an admin pastes or uploads.
const (
	// MaxSample is the most of a sample read, in bytes.
	MaxSample = 512 << 10
	// MaxSampleLines is the most lines of a sample read.
	MaxSampleLines = 500
	// previewEvents is how many parsed events a preview shows.
	previewEvents = 25
	// maxExamples is how many distinct values of a field a preview shows.
	maxExamples = 3
)

// SplitSample cuts a sample into its records: lines, or the objects of a
// JSON array or of pretty-printed JSON, each made one line. Blank lines
// are dropped, and at most MaxSampleLines are kept.
func SplitSample(sample string) []string {
	if len(sample) > MaxSample {
		sample = sample[:MaxSample]
	}
	sample = strings.ToValidUTF8(strings.TrimPrefix(sample, "\ufeff"), "�")
	t := strings.TrimSpace(sample)
	if strings.HasPrefix(t, "[") || strings.HasPrefix(t, "{") && !ndjson(t) {
		if recs := jsonRecords(t); len(recs) > 0 {
			return recs
		}
	}
	var out []string
	for _, l := range strings.Split(sample, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
		if len(out) >= MaxSampleLines {
			break
		}
	}
	return out
}

// ndjson reports whether every line of s is a JSON object of its own.
func ndjson(s string) bool {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !json.Valid([]byte(l)) || !strings.HasPrefix(l, "{") {
			return false
		}
		n++
		if n >= 50 {
			break
		}
	}
	return n > 0
}

// jsonRecords reads a JSON array of objects, or objects one after the
// other however they are laid out, as compact lines.
func jsonRecords(s string) []string {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var out []string
	add := func(raw json.RawMessage) bool {
		var b bytes.Buffer
		if json.Compact(&b, raw) != nil || !bytes.HasPrefix(b.Bytes(), []byte("{")) {
			return false
		}
		out = append(out, b.String())
		return len(out) < MaxSampleLines
	}
	if strings.HasPrefix(s, "[") {
		var arr []json.RawMessage
		if json.Unmarshal([]byte(s), &arr) != nil {
			return nil
		}
		for _, r := range arr {
			if !add(r) {
				break
			}
		}
		return out
	}
	for {
		var r json.RawMessage
		if err := dec.Decode(&r); err == io.EOF {
			return out
		} else if err != nil {
			return out
		}
		if !add(r) {
			return out
		}
	}
}

// Suggestion is the parser Signalith suggests for a sample, and why.
type Suggestion struct {
	Parser Parser `json:"parser"`
	// Confidence is high, medium or low: how sure the format reading is.
	Confidence string `json:"confidence"`
	// Notes say what the admin should check.
	Notes []string `json:"notes,omitempty"`
}

// Analyze reads a sample and suggests a parser for it.
func Analyze(lines []string, now time.Time) Suggestion {
	s := Suggestion{Confidence: "low"}
	p := &s.Parser
	if len(lines) == 0 {
		p.Format, p.Model, p.Sourcetype = FormatText, "Other", "custom:text"
		s.Notes = append(s.Notes, "The sample is empty: paste a few lines of the log.")
		return s
	}
	bodies := lines
	var apps []string
	// A syslog header, or CEF and LEEF (with or without one).
	cef, leef, hdr := 0, 0, 0
	msgs := make([]syslog.Message, len(lines))
	for i, l := range lines {
		m := syslog.Parse([]byte(l), now)
		msgs[i] = m
		switch {
		case m.CEF != nil:
			cef++
		case m.LEEF != nil:
			leef++
		}
		if m.Format == "rfc5424" || m.Format == "rfc3164" && !m.Time.IsZero() && m.AppName != "" {
			hdr++
		}
	}
	most := func(n int) bool { return n*5 >= len(lines)*4 }
	switch {
	case most(cef):
		p.Format, s.Confidence = FormatCEF, "high"
		c := msgs[0].CEF
		for _, m := range msgs {
			if m.CEF != nil {
				c = m.CEF
				break
			}
		}
		p.Sourcetype = sourcetypeOf(c.Vendor, c.Product, "cef")
		p.VendorProduct = strings.TrimSpace(c.Vendor + " " + c.Product)
	case most(leef):
		p.Format, s.Confidence = FormatLEEF, "high"
		l := msgs[0].LEEF
		for _, m := range msgs {
			if m.LEEF != nil {
				l = m.LEEF
				break
			}
		}
		p.Sourcetype = sourcetypeOf(l.Vendor, l.Product, "leef")
		p.VendorProduct = strings.TrimSpace(l.Vendor + " " + l.Product)
	case most(hdr):
		p.Header = HeaderSyslog
		bodies = make([]string, len(lines))
		for i, m := range msgs {
			bodies[i] = m.Text
			if m.AppName != "" {
				apps = append(apps, m.AppName)
			}
		}
	}
	if p.Format == "" {
		detectBody(&s, bodies)
	}
	if p.Sourcetype == "" {
		app := mostCommon(apps)
		switch {
		case app != "":
			p.Sourcetype = sourcetypeOf("", app, "syslog")
		default:
			p.Sourcetype = "custom:" + p.Format
		}
	}
	if p.Format == FormatKV && strings.Contains(lines[0], "devid=") && strings.Contains(lines[0], "logid=") {
		p.Sourcetype, p.VendorProduct = "fortinet:fortigate", "Fortinet FortiGate"
	}
	p.Name = nameOf(p.Sourcetype)
	if a := mostCommon(apps); a != "" && appRE.MatchString(a) {
		p.SyslogApps = []string{a}
	}
	suggestFields(&s, lines, now)
	return s
}

// detectBody works out the format of the lines' bodies.
func detectBody(s *Suggestion, bodies []string) {
	p := &s.Parser
	most := func(n int) bool { return n*5 >= len(bodies)*4 }
	jsonN := 0
	for _, b := range bodies {
		t := strings.TrimSpace(b)
		if strings.HasPrefix(t, "{") && json.Valid([]byte(t)) {
			jsonN++
		}
	}
	if most(jsonN) {
		p.Format, s.Confidence = FormatJSON, "high"
		return
	}
	if delim, ok := kvLines(bodies); ok {
		p.Format, p.KVSeparator, p.Delimiter, s.Confidence = FormatKV, "=", delim, "high"
		return
	}
	if delim, cols, header, ok := csvLines(bodies); ok {
		p.Format, p.Delimiter, p.Columns = FormatCSV, delim, cols
		if header {
			s.Confidence = "high"
		} else {
			s.Confidence = "medium"
			s.Notes = append(s.Notes, "The sample has no header line, so the columns have numbered names: name them, or map them below.")
		}
		return
	}
	if inf, ok := inferPattern(bodies); ok && inf.matched*2 >= len(bodies) {
		p.Format, p.Pattern = FormatRegex, inf.pattern
		s.Confidence = "medium"
		if inf.matched < len(bodies) {
			s.Confidence = "low"
			s.Notes = append(s.Notes, fmt.Sprintf("The pattern reads %d of the %d lines. Lines it does not read are still stored, searchable by text.", inf.matched, len(bodies)))
		}
		s.Notes = append(s.Notes, "Free text is read with a regular expression written from the sample. Check the field names, or ask the AI model to improve it.")
		return
	}
	p.Format = FormatText
	s.Notes = append(s.Notes, "No fields could be found in the sample. The lines are stored as they are, searchable by text; write a regular expression to pull out fields.")
}

// kvLines reports whether most lines are key=value pairs, and how pairs
// are separated.
func kvLines(lines []string) (string, bool) {
	best, bestN := "", 0
	for _, delim := range []string{"", ",", ";", "|"} {
		n := 0
		for _, l := range lines {
			pairs := ParseKV(l, "=", delim)
			covered := 0
			for _, kv := range pairs {
				covered += len(kv[0]) + len(kv[1]) + 1
			}
			if len(pairs) >= 3 && covered*10 >= len(strings.TrimSpace(l))*6 {
				n++
			}
		}
		if n > bestN {
			best, bestN = delim, n
		}
	}
	if bestN*5 >= len(lines)*4 {
		if best != "" && !kvDelimUsed(lines, best) {
			best = ""
		}
		return best, true
	}
	return "", false
}

// kvDelimUsed reports whether pairs are really separated by delim (a
// comma after values), not just by white space.
func kvDelimUsed(lines []string, delim string) bool {
	for _, l := range lines {
		if strings.Contains(l, delim+" ") || strings.Count(l, delim) >= 2 && !strings.Contains(l, " ") {
			return true
		}
	}
	return false
}

// csvLines reports whether the lines are delimited columns: the
// delimiter, the column names, and whether the first line was a header.
func csvLines(lines []string) (string, []string, bool, bool) {
	type cand struct {
		delim string
		n     int
	}
	var best *cand
	for _, d := range []string{",", "\t", "|", ";"} {
		counts := map[int]int{}
		for _, l := range lines {
			counts[len(csvRow(l, d))]++
		}
		n, top := 0, 0
		for k, v := range counts {
			if v > top || v == top && k > n {
				n, top = k, v
			}
		}
		need := 3
		if len(lines) == 1 {
			need = 4
		}
		if n >= need && top*5 >= len(lines)*4 && (best == nil || n > best.n) {
			best = &cand{d, n}
		}
	}
	if best == nil {
		return "", nil, false, false
	}
	first := csvRow(lines[0], best.delim)
	header := len(lines) > 1 && len(first) == best.n
	seen := map[string]bool{}
	for _, c := range first {
		name := columnName(c)
		if name == "" || seen[name] || valueKind([]string{c}) != "text" {
			header = false
			break
		}
		seen[name] = true
	}
	cols := make([]string, best.n)
	for i := range cols {
		if header {
			cols[i] = columnName(first[i])
		} else {
			cols[i] = fmt.Sprintf("column%d", i+1)
		}
	}
	return best.delim, cols, header, true
}

// suggestFields reads the lines with the parser found so far, then picks
// the time field, the data model and the fields to rename.
func suggestFields(s *Suggestion, lines []string, now time.Time) {
	p := &s.Parser
	p.Model = "Other"
	c, err := Compile(*p)
	if err != nil {
		return
	}
	values := map[string][]string{}
	var order []string
	for _, l := range lines {
		ev, drop := c.ParseLine(l, now)
		if drop {
			continue
		}
		for k, v := range ev.Fields {
			if k == "message" || k == "sourcetype" || k == "vendor_product" {
				continue
			}
			if _, ok := values[k]; !ok {
				order = append(order, k)
			}
			values[k] = append(values[k], fmt.Sprint(v))
		}
	}
	sort.Strings(order)
	// The time field: a field named like one first, then any whose every
	// value reads as a time.
	if p.Format != FormatCEF && p.Format != FormatLEEF {
		pick := func(names []string, epochOK bool) bool {
			for _, k := range names {
				if f := detectTimeFormat(values[k], epochOK, now); f != nil {
					p.TimeField, p.TimeFormat = k, f.Name
					return true
				}
			}
			return false
		}
		var named []string
		for _, k := range order {
			if timeName(k) {
				named = append(named, k)
			}
		}
		if !pick(named, true) && !pick(order, false) {
			// A date and a time in fields of their own (date=... time=...).
			if dv, tv := values["date"], values["time"]; len(dv) > 0 && len(dv) == len(tv) {
				joined := make([]string, len(dv))
				for i := range dv {
					joined[i] = dv[i] + " " + tv[i]
				}
				if f := detectTimeFormat(joined, false, now); f != nil {
					p.TimeField, p.TimeFormat = "date+time", f.Name
				}
			}
		}
	}
	// What each field would map to without a model, to guess the model;
	// then again for that model.
	var mapped []string
	for _, k := range order {
		if t := MapName(k); t != "" {
			mapped = append(mapped, t)
		} else if modelHas("", k) || isModelField(k) {
			mapped = append(mapped, k)
		}
	}
	p.Model = GuessModel(mapped, strings.Join(lines[:min(len(lines), 50)], "\n"))
	taken := map[string]bool{}
	for _, k := range order {
		if isModelField(k) && MapNameFor(p.Model, k) == k {
			taken[k] = true // already the data model's name
		}
	}
	p.Mappings = nil
	for _, k := range order {
		if k == p.TimeField || taken[k] || slices.Contains(strings.Split(p.TimeField, "+"), k) {
			continue
		}
		t := MapNameFor(p.Model, k)
		if t == "" || t == k || taken[t] {
			continue
		}
		if t == "src" || t == "dest" {
			// An address field must hold addresses or names, not numbers.
			if valueKind(values[k]) == "number" {
				continue
			}
		}
		taken[t] = true
		p.Mappings = append(p.Mappings, Mapping{From: k, To: t})
	}
	if p.Model == "Other" {
		s.Notes = append(s.Notes, "No data model fits the sample well, so events go to Other. Choose a model if one fits, and map its fields, so detections can use them.")
	}
	if p.TimeField == "" && p.Header == "" && p.Format != FormatCEF && p.Format != FormatLEEF {
		s.Notes = append(s.Notes, "No time was found in the lines, so events get the time they arrive.")
	}
}

var timeNames = []string{"time", "timestamp", "ts", "date", "datetime", "@timestamp", "eventtime", "event_time", "logtime",
	"log_time", "created", "createdat", "created_at", "generated", "receivedtime", "starttime", "start_time", "time_generated", "eventdate"}

func timeName(k string) bool {
	k = strings.ToLower(k)
	if i := strings.LastIndexByte(k, '.'); i >= 0 {
		k = k[i+1:]
	}
	return slices.Contains(timeNames, k) || slices.Contains(timeNames, squash(k))
}

// isModelField reports whether name is a field of any data model.
func isModelField(name string) bool {
	for _, m := range Models() {
		if modelHas(m, name) {
			return true
		}
	}
	return false
}

func mostCommon(xs []string) string {
	n := map[string]int{}
	best, bestN := "", 0
	for _, x := range xs {
		n[x]++
		if n[x] > bestN || n[x] == bestN && x < best {
			best, bestN = x, n[x]
		}
	}
	return best
}

// sourcetypeOf makes a sourcetype from a vendor and product.
func sourcetypeOf(vendor, product, fallback string) string {
	clean := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(strings.TrimSpace(s)) {
			switch {
			case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
				b.WriteRune(r)
			case r == ' ' || r == '-' || r == '_' || r == '.' || r == '/':
				b.WriteByte('_')
			}
		}
		return strings.Trim(b.String(), "_")
	}
	v, p := clean(vendor), clean(product)
	var st string
	switch {
	case v != "" && p != "":
		st = v + ":" + p
	case p != "":
		st = p
	case v != "":
		st = v
	default:
		st = "custom:" + fallback
	}
	if len(st) > 64 {
		st = st[:64]
	}
	if !sourcetypeRE.MatchString(st) {
		st = "custom:" + fallback
	}
	return st
}

// nameOf makes a parser name from a sourcetype.
func nameOf(sourcetype string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(sourcetype) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	n := strings.Trim(b.String(), "-_")
	if len(n) > 48 {
		n = strings.Trim(n[:48], "-_")
	}
	if !ValidName(n) {
		n = "custom-log"
	}
	return n
}

// Field is one field a preview found.
type Field struct {
	Name string `json:"name"`
	// Count is how many of the events have it.
	Count    int      `json:"count"`
	Kind     string   `json:"kind"`
	Examples []string `json:"examples,omitempty"`
	// From is the sender's name, when a mapping renamed it.
	From string `json:"from,omitempty"`
	// InModel says the field is one of the data model's.
	InModel bool `json:"in_model"`
	// Suggest is a data model field this one could map to.
	Suggest string `json:"suggest,omitempty"`
}

// PreviewEvent is one parsed event of a preview.
type PreviewEvent struct {
	Time   time.Time      `json:"time"`
	Fields map[string]any `json:"fields"`
}

// Preview is what a parser makes of a sample.
type Preview struct {
	Lines int `json:"lines"`
	// Parsed counts the lines whose body gave fields (a syslog header aside).
	Parsed  int            `json:"parsed"`
	Skipped int            `json:"skipped,omitempty"`
	Timed   int            `json:"timed"`
	Events  []PreviewEvent `json:"events"`
	Fields  []Field        `json:"fields"`
	// Docs are the events as they would be stored, for matching
	// detections; not sent to the page.
	Docs []map[string]any `json:"-"`
}

// Run parses the sample's lines with c.
func (c *Compiled) Run(ctx context.Context, lines []string, now time.Time) (*Preview, error) {
	pv := &Preview{Lines: len(lines)}
	stats := map[string]*Field{}
	examples := map[string]map[string]bool{}
	from := map[string]string{}
	for _, m := range c.P.Mappings {
		from[m.To] = m.From
	}
	for _, l := range lines {
		if err := ctx.Err(); err != nil {
			return nil, errors.New("reading the sample took too long; try fewer lines or a simpler pattern")
		}
		ev, drop, read := c.parseLine(l, now)
		if drop {
			pv.Skipped++
			continue
		}
		if !ev.Time.IsZero() {
			pv.Timed++
		} else {
			ev.Time = now.UTC()
		}
		ev.Model = c.P.Model
		if read > 0 {
			pv.Parsed++
		}
		for k, v := range ev.Fields {
			if k == "message" || k == "sourcetype" || k == "vendor_product" {
				continue
			}
			f := stats[k]
			if f == nil {
				f = &Field{Name: k, From: from[k], InModel: modelHas(c.P.Model, k)}
				if !f.InModel {
					f.Suggest = MapNameFor(c.P.Model, k)
				}
				stats[k] = f
				examples[k] = map[string]bool{}
			}
			f.Count++
			s := fmt.Sprint(v)
			if len(s) > 200 {
				s = s[:200] + "…"
			}
			if len(f.Examples) < maxExamples && !examples[k][s] {
				examples[k][s] = true
				f.Examples = append(f.Examples, s)
			}
		}
		doc := ev.Document()
		pv.Docs = append(pv.Docs, doc)
		if len(pv.Events) < previewEvents {
			pv.Events = append(pv.Events, PreviewEvent{Time: ev.Time, Fields: doc})
		}
	}
	for _, f := range stats {
		f.Kind = valueKind(f.Examples)
		pv.Fields = append(pv.Fields, *f)
	}
	sort.Slice(pv.Fields, func(i, j int) bool {
		a, b := pv.Fields[i], pv.Fields[j]
		if a.InModel != b.InModel {
			return a.InModel
		}
		return a.Name < b.Name
	})
	return pv, nil
}
