package ingest

import (
	"encoding/json"
	"regexp"
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

// urlQueryFields hold whole addresses (or targets: /path?query), as
// parsers name them: a web request's address, referrer and redirect
// (Location), OpenTelemetry's url.original, http.url and http.target,
// a generic JSON record's uri or request, and a CEF request context.
// urlQueryOnlyFields hold the query alone.
var (
	urlQueryFields = []string{
		"url", "http_referrer", "http_redirect", "url_original", "http_url", "http_target",
		"uri", "request", "cef_requestcontext",
	}
	urlQueryOnlyFields = []string{"uri_query", "url_query"}
)

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
// a query string again: a Suricata alert's payload and an unmapped
// Suricata event's details. The raw message is one too, for the events
// that hold a web address (see sweepMessage), and so are the zeek_*
// fields, which keep a Zeek log's own keys.
var rawQueryFields = []string{"suricata_payload_printable", "suricata_detail"}

// ApplyURLQuery hides or drops the query strings of an event's web
// address fields, and the query strings in its raw message, payloads and
// Zeek keys, as mode says.
//
// A query string recorded in a field is found again in the raw text in
// each way a sender writes it (as it is, JSON escaped, CEF escaped,
// Apache escaped) and up to where it ends there, so one cut short in the
// field (CapValue) goes whole. Then any other query string of a web
// address in that text (a path or address followed by ?) goes too, so
// one that no field holds (an unmapped Suricata or Zeek event, a
// request without a Host header) is not kept either.
func ApplyURLQuery(f map[string]any, mode string) {
	if mode != URLQueryRedact && mode != URLQueryDrop {
		return
	}
	drop := mode == URLQueryDrop
	// Each query string seen (without its ?) and what replaces it.
	var pairs [][2]string
	note := func(q string) {
		if q == "" {
			return
		}
		for _, p := range pairs {
			if p[0] == q {
				return
			}
		}
		pairs = append(pairs, [2]string{q, redactQuery(q)})
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
		// A query ends at a fragment, and in a field that may hold a
		// whole request line ("GET /a?b HTTP/1.1") at a space.
		end := len(s)
		if j := strings.IndexByte(s[i+1:], '#'); j >= 0 {
			end = i + 1 + j
		}
		if k != "url" {
			if j := strings.IndexAny(s[i+1:end], " \t\r\n"); j >= 0 {
				end = i + 1 + j
			}
		}
		q := s[i+1 : end]
		var ns string
		if drop {
			ns = s[:i] + s[end:]
		} else {
			ns = s[:i+1] + redactQuery(q) + s[end:]
		}
		note(q)
		f[k] = ns
		if k == "url" {
			if _, ok := f["url_length"]; ok {
				f["url_length"] = int64(len(ns))
			}
		}
	}
	for _, k := range urlQueryOnlyFields {
		if q, ok := f[k].(string); ok {
			note(q)
			if drop {
				delete(f, k)
			} else {
				f[k] = redactQuery(q)
			}
		}
	}
	// Longest first, so a query that holds another is replaced whole.
	slices.SortStableFunc(pairs, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	clean := func(s string) string {
		if strings.IndexByte(s, '?') < 0 {
			return s
		}
		for _, p := range pairs {
			s = replaceQuery(s, p[0], p[1], drop)
		}
		return sweepQueries(s, drop)
	}
	keys := slices.Clone(rawQueryFields)
	if len(pairs) > 0 || sweepMessage(f) {
		keys = append(keys, "message")
	}
	for k, v := range f {
		if _, ok := v.(string); ok && strings.HasPrefix(k, "zeek_") {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		if s, ok := f[k].(string); ok {
			f[k] = clean(s)
		}
	}
}

// sweepMessage reports whether an event's raw message is searched for
// query strings although no field held one: an event of a network
// sensor (Zeek, Suricata), a web server or a proxy (CEF, LEEF). Other
// events' raw text (a script, a command line) is left as it was sent.
func sweepMessage(f map[string]any) bool {
	st, _ := f["sourcetype"].(string)
	for _, p := range []string{"zeek", "suricata", "cef", "leef"} {
		if st == p || strings.HasPrefix(st, p+":") {
			return true
		}
	}
	return strings.HasSuffix(st, ":access")
}

// redactQuery keeps a query's parameter names and hides their values:
// a=1&b=2 is a=REDACTED&b=REDACTED; a value without a name is hidden
// whole, and an empty value stays empty.
func redactQuery(q string) string {
	parts := strings.Split(q, "&")
	for i, p := range parts {
		parts[i] = redactParam(p)
	}
	return strings.Join(parts, "&")
}

func redactParam(p string) string {
	name, val, hasVal := strings.Cut(p, "=")
	switch {
	case hasVal && val == "":
		return name + "="
	case hasVal:
		return name + "=" + RedactedValue
	case p != "":
		return RedactedValue
	}
	return p
}

// rawSeps are the ways raw text separates query parameters: & as it is,
// and as JSON writes it with HTML escaping.
var rawSeps = []string{"&", `&`}

// redactRawQuery is redactQuery for a query as raw text writes it: its
// parameters may be separated by &, and a CEF name ends in \ (its
// = is written \=), which stays.
func redactRawQuery(q string) string {
	var b strings.Builder
	for {
		i, n := -1, 0
		for _, sep := range rawSeps {
			if j := strings.Index(q, sep); j >= 0 && (i < 0 || j < i) {
				i, n = j, len(sep)
			}
		}
		if i < 0 {
			b.WriteString(redactParam(q))
			return b.String()
		}
		b.WriteString(redactParam(q[:i]))
		b.WriteString(q[i : i+n])
		q = q[i+n:]
	}
}

// queryEnd returns where a query string that starts at i in raw text
// ends: at whitespace, a quote, < or >, a fragment's #, or the end. A
// backslash just before a quote is the quote's escape, not the query's.
func queryEnd(s string, i int) int {
	for j := i; j < len(s); j++ {
		switch c := s[j]; c {
		case ' ', '\t', '\r', '\n', '"', '\'', '<', '>', '#':
			return j
		case '\\':
			if j+1 < len(s) && (s[j+1] == '"' || s[j+1] == '\'') {
				return j
			}
		}
	}
	return len(s)
}

// replaceQuery replaces the query string q (redacted, it is red) where
// raw text s holds it after a ?, in each way it can be written there.
// Each one found runs on to where the query ends in s, since the field q
// came from may hold only its start: the rest is dropped, or redacted
// from the next parameter on.
func replaceQuery(s, q, red string, drop bool) string {
	for _, form := range rawForms {
		fq := form(q)
		needle := "?" + fq
		if !strings.Contains(s, needle) {
			continue
		}
		var b strings.Builder
		for {
			i := strings.Index(s, needle)
			if i < 0 {
				b.WriteString(s)
				break
			}
			end := queryEnd(s, i+len(needle))
			b.WriteString(s[:i])
			if !drop {
				b.WriteString("?" + form(red))
				if tail := s[i+len(needle) : end]; tail != "" {
					b.WriteString(redactTail(tail))
				}
			}
			s = s[end:]
		}
		s = b.String()
	}
	return s
}

// redactTail redacts the rest of a query whose start was replaced: what
// is left of the value cut short goes, and the parameters after it are
// redacted.
func redactTail(tail string) string {
	i, n := -1, 0
	for _, sep := range rawSeps {
		if j := strings.Index(tail, sep); j >= 0 && (i < 0 || j < i) {
			i, n = j, len(sep)
		}
	}
	if i < 0 {
		return ""
	}
	return tail[i:i+n] + redactRawQuery(tail[i+n:])
}

// addressQuery finds the query strings of web addresses in raw text: a
// run of address characters holding a / (a path, or a whole address,
// JSON escaped or not), then ? and the query.
var addressQuery = regexp.MustCompile(`[^\s"'<>?#]*/[^\s"'<>?#]*\?`)

// sweepQueries hides or drops every query string of a web address in
// raw text s.
func sweepQueries(s string, drop bool) string {
	locs := addressQuery.FindAllStringIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, l := range locs {
		start := l[1] // after the ?
		if start < last {
			continue
		}
		end := queryEnd(s, start)
		q := s[start:end]
		if q == "" {
			continue
		}
		if drop {
			b.WriteString(s[last : start-1])
		} else {
			b.WriteString(s[last:start])
			b.WriteString(redactRawQuery(q))
		}
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

// rawForms are the ways a query string can be written in a raw event: as
// it is; in JSON text by Zeek, Suricata or Go (which writes & as &
// and may escape / as \/); in a CEF extension (\ and = escaped as \\ and
// \=, and | as \|); and in an Apache access log (\ and " as \\ and \").
var rawForms = []func(string) string{
	func(s string) string { return s },
	func(s string) string { return jsonText(s, true) },
	func(s string) string { return jsonText(s, false) },
	func(s string) string { return strings.ReplaceAll(jsonText(s, false), "/", `\/`) },
	func(s string) string { return strings.ReplaceAll(jsonText(s, true), "/", `\/`) },
	cefEscaper.Replace,
	strings.NewReplacer(`\`, `\\`, "=", `\=`).Replace,
	strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace,
}

var cefEscaper = strings.NewReplacer(`\`, `\\`, "=", `\=`, "|", `\|`)

// jsonText is s as it is written inside a JSON string, with & < >
// escaped when html.
func jsonText(s string, html bool) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(html)
	_ = enc.Encode(s)
	out := strings.TrimSuffix(b.String(), "\n")
	return out[1 : len(out)-1]
}
