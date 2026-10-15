package ingest

import (
	"encoding/json"
	"slices"
	"strings"
)

// The query string of a web address (after the ?) can carry tokens,
// session IDs and passwords. ingest.url_query decides what is stored of
// it: everything (keep, the default), the parameter names with their
// values hidden (redact), or nothing (drop). It applies to the fields
// that hold web addresses, whatever sent them (a sensor's web requests,
// IDS alerts and file downloads, web server logs, proxy logs over
// syslog), and to the raw event, so the values are not kept anywhere.

// URL query modes (config.URLQueryMode).
const (
	URLQueryKeep   = "keep"
	URLQueryRedact = "redact"
	URLQueryDrop   = "drop"
)

// RedactedValue replaces each query value in redact mode.
const RedactedValue = "REDACTED"

// urlQueryFields hold whole addresses (or targets: /path?query); the
// query alone is uri_query.
var urlQueryFields = []string{"url", "http_referrer"}

// SetURLQuery changes ingest.url_query while the pipeline runs; anything
// but redact and drop keeps query strings.
func (p *Pipeline) SetURLQuery(mode string) {
	var m int32
	switch mode {
	case URLQueryRedact:
		m = 1
	case URLQueryDrop:
		m = 2
	}
	p.urlQuery.Store(m)
}

// URLQuery returns the ingest.url_query mode in use.
func (p *Pipeline) URLQuery() string {
	switch p.urlQuery.Load() {
	case 1:
		return URLQueryRedact
	case 2:
		return URLQueryDrop
	}
	return URLQueryKeep
}

// rawQueryFields hold whole events or payloads as text, which can carry
// a query string again: the raw message, a Suricata alert's payload and
// an unmapped Suricata event's details.
var rawQueryFields = []string{"suricata_payload_printable", "suricata_detail"}

// ApplyURLQuery hides or drops the query strings of an event's web
// address fields, and the same query strings in its raw message and
// payloads, as mode says.
func ApplyURLQuery(f map[string]any, mode string) {
	if mode != URLQueryRedact && mode != URLQueryDrop {
		return
	}
	// Each query string seen (with its ?) and what replaces it.
	var pairs [][2]string
	note := func(q, nq string) {
		if q == "" || q == nq {
			return
		}
		for _, p := range pairs {
			if p[0] == "?"+q {
				return
			}
		}
		if mode == URLQueryDrop {
			pairs = append(pairs, [2]string{"?" + q, ""})
		} else {
			pairs = append(pairs, [2]string{"?" + q, "?" + nq})
		}
	}
	for _, k := range urlQueryFields {
		s, ok := f[k].(string)
		if !ok {
			continue
		}
		i := strings.IndexByte(s, '?')
		if i < 0 {
			continue
		}
		q, frag := s[i+1:], ""
		if j := strings.IndexByte(q, '#'); j >= 0 {
			q, frag = q[:j], q[j:]
		}
		var ns string
		if mode == URLQueryDrop {
			ns = s[:i] + frag
		} else {
			ns = s[:i+1] + redactQuery(q) + frag
		}
		note(q, redactQuery(q))
		f[k] = ns
		if k == "url" {
			if _, ok := f["url_length"]; ok {
				f["url_length"] = int64(len(ns))
			}
		}
	}
	if q, ok := f["uri_query"].(string); ok {
		note(q, redactQuery(q))
		if mode == URLQueryDrop {
			delete(f, "uri_query")
		} else {
			f["uri_query"] = redactQuery(q)
		}
	}
	if len(pairs) == 0 {
		return
	}
	// Longest first, so a query that holds another is replaced whole.
	slices.SortStableFunc(pairs, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	for _, k := range append([]string{"message"}, rawQueryFields...) {
		s, ok := f[k].(string)
		if !ok {
			continue
		}
		for _, p := range pairs {
			for _, v := range rawForms(p[0]) {
				s = strings.ReplaceAll(s, v, rawFormLike(v, p[0], p[1]))
			}
		}
		f[k] = s
	}
}

// redactQuery keeps a query's parameter names and hides their values:
// a=1&b=2 is a=REDACTED&b=REDACTED; a value without a name is hidden
// whole, and an empty value stays empty.
func redactQuery(q string) string {
	parts := strings.Split(q, "&")
	for i, p := range parts {
		name, val, hasVal := strings.Cut(p, "=")
		switch {
		case hasVal && val == "":
			parts[i] = name + "="
		case hasVal:
			parts[i] = name + "=" + RedactedValue
		case p != "":
			parts[i] = RedactedValue
		}
	}
	return strings.Join(parts, "&")
}

// rawForms are the ways s can be written in a raw event: as it is, and
// in JSON text by Zeek, Suricata or Go (which writes & as & and may
// escape / and ").
func rawForms(s string) []string {
	forms := []string{s}
	add := func(v string) {
		for _, f := range forms {
			if f == v {
				return
			}
		}
		forms = append(forms, v)
	}
	b, _ := json.Marshal(s)
	add(string(b[1 : len(b)-1]))
	var esc strings.Builder
	enc := json.NewEncoder(&esc)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	plain := strings.TrimSuffix(esc.String(), "\n")
	plain = plain[1 : len(plain)-1]
	add(plain)
	add(strings.ReplaceAll(plain, "/", `\/`))
	return forms
}

// rawFormLike writes repl the way form writes orig: as it is, or JSON
// escaped as form is.
func rawFormLike(form, orig, repl string) string {
	if form == orig {
		return repl
	}
	if strings.Contains(form, `&`) {
		b, _ := json.Marshal(repl)
		return string(b[1 : len(b)-1])
	}
	var esc strings.Builder
	enc := json.NewEncoder(&esc)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(repl)
	s := strings.TrimSuffix(esc.String(), "\n")
	s = s[1 : len(s)-1]
	if strings.Contains(form, `\/`) {
		s = strings.ReplaceAll(s, "/", `\/`)
	}
	return s
}
