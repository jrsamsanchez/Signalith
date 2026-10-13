package search

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// IntelFields maps event fields to the indicator classes their values
// can hold. Fields not listed are checked against every class.
var IntelFields = map[string][]string{
	"src":            {intel.TypeIP},
	"src_ip":         {intel.TypeIP},
	"dest":           {intel.TypeIP, intel.TypeDomain},
	"dest_ip":        {intel.TypeIP},
	"dest_host":      {intel.TypeDomain},
	"domain":         {intel.TypeDomain},
	"query":          {intel.TypeDomain},
	"url_domain":     {intel.TypeDomain},
	"url":            {intel.TypeURL, intel.TypeDomain},
	"process_hash":   {"hash"},
	"process_md5":    {"hash"},
	"process_sha1":   {"hash"},
	"process_sha256": {"hash"},
	"file_hash":      {"hash"},
	"file_md5":       {"hash"},
	"file_sha1":      {"hash"},
	"file_sha256":    {"hash"},
	"hash":           {"hash"},
	"md5":            {"hash"},
	"sha1":           {"hash"},
	"sha256":         {"hash"},
	"sender":         {intel.TypeEmail},
	"recipient":      {intel.TypeEmail},
	"src_user":       {intel.TypeEmail},
	"user":           {intel.TypeEmail},
}

// DefaultIntelFields are checked when intel or threatmatch names no
// fields, in the order a match is reported.
var DefaultIntelFields = []string{
	"src", "dest", "src_ip", "dest_ip", "dest_host", "domain", "query", "url_domain", "url",
	"process_sha256", "process_sha1", "process_md5", "process_hash",
	"file_sha256", "file_sha1", "file_md5", "file_hash", "hash", "md5", "sha1", "sha256",
	"sender", "recipient", "src_user", "user",
}

// allClasses are the lookup classes of every indicator type.
var allClasses = []string{intel.TypeIP, intel.TypeDomain, intel.TypeURL, "hash", intel.TypeEmail}

func intelClasses(field string) []string {
	if c, ok := IntelFields[field]; ok {
		return c
	}
	return allClasses
}

// threatTargetFields says which field holds the system on our side of a
// match: the destination when the source matched, and the source (or the
// reporting host) when the destination, a domain or URL matched.
var threatTargetFields = map[string][]string{
	"src":    {"dest", "dest_host", "host"},
	"src_ip": {"dest", "dest_host", "host"},
	// A file an antivirus found is on the host the event is about.
	"file_sha256": {"dest", "host"},
	"file_sha1":   {"dest", "host"},
	"file_md5":    {"dest", "host"},
	"file_hash":   {"dest", "host"},
}

var defaultTargetFields = []string{"src", "src_host", "dest", "host"}

// termsBatch is how many values go in one terms clause, well under
// OpenSearch's index.max_terms_count default of 65536.
const termsBatch = 10000

// maxNetworkClauses caps the prefix clauses that network indicators add
// to a threatmatch filter, staying under OpenSearch's default limit of
// 1024 clauses. Networks beyond it are matched only by the intel command.
const maxNetworkClauses = 800

var errIntelOff = errors.New("threat intel is not available on this server")

// noMatch matches nothing.
var noMatch = map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"match_all": map[string]any{}}}}}

// threatFilter compiles threatmatch into a filter that keeps events
// where any field equals an active indicator value. Values go to
// OpenSearch as terms clauses, so events never stream through the server.
func (e *Engine) threatFilter(c *query.ThreatMatch) (map[string]any, error) {
	if e.Intel == nil {
		return nil, errIntelOff
	}
	fields := c.Fields
	if len(fields) == 0 {
		fields = DefaultIntelFields
	}
	values := map[string][]string{}
	for _, class := range allClasses {
		vs := e.Intel.Values(class)
		if class == "hash" {
			// Hashes are often logged in upper case.
			up := make([]string, len(vs))
			for i, v := range vs {
				up[i] = strings.ToUpper(v)
			}
			vs = append(vs, up...)
		}
		values[class] = vs
	}
	nets := e.Intel.Networks()
	var should []any
	clauses := 0
	for _, f := range fields {
		for _, class := range intelClasses(f) {
			if f == "url" && class == intel.TypeDomain {
				continue // URLs hold more than the domain; the intel command checks their host
			}
			vs := values[class]
			for start := 0; start < len(vs); start += termsBatch {
				should = append(should, map[string]any{"terms": map[string]any{f: vs[start:min(start+termsBatch, len(vs))]}})
				clauses++
			}
			if class != intel.TypeIP {
				continue
			}
			for _, p := range nets {
				if !p.Addr().Is4() {
					continue
				}
				q, _ := cidrQuery(f, p.String())
				n := 1
				if b, ok := q["bool"].(map[string]any); ok {
					n = len(b["should"].([]any))
				}
				if clauses+n > maxNetworkClauses {
					break
				}
				clauses += n
				should = append(should, q)
			}
		}
	}
	if len(should) == 0 {
		return noMatch, nil
	}
	return map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}, nil
}

// stringValues returns the string values of a row cell.
func stringValues(v any) []string {
	switch x := v.(type) {
	case string:
		if x != "" {
			return []string{x}
		}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

type intelHit struct {
	field, value string
	ind          intel.Indicator   // the strongest match
	all          []intel.Indicator // every source listing the value
}

// lookupRow returns the best match per field, in field order.
func (e *Engine) lookupRow(r Row, fields []string) []intelHit {
	var hits []intelHit
	for _, f := range fields {
		for _, v := range stringValues(r[f]) {
			if m := e.Intel.Lookup(v, intelClasses(f)...); len(m) > 0 {
				hits = append(hits, intelHit{f, v, m[0], m})
				break
			}
		}
	}
	return hits
}

func sources(m []intel.Indicator) string {
	var out []string
	for _, i := range m {
		if !slices.Contains(out, i.Source) {
			out = append(out, i.Source)
		}
	}
	return strings.Join(out, ", ")
}

func fmtWeight(w float64) any {
	if w == float64(int64(w)) {
		return int64(w)
	}
	return w
}

// intelSuffixes are the columns the intel command adds after a field.
var intelSuffixes = []string{"intel_source", "intel_type", "intel_weight", "intel_description"}

// intelEnrich adds <field>_intel_source, _intel_type, _intel_weight and
// _intel_description for values that match an indicator.
func (e *Engine) intelEnrich(res *Result, c *query.Intel) error {
	if e.Intel == nil {
		return errIntelOff
	}
	fields := c.Fields
	if len(fields) == 0 {
		fields = DefaultIntelFields
	}
	added := map[string]bool{}
	for _, r := range res.Rows {
		for _, f := range fields {
			for _, v := range stringValues(r[f]) {
				m := e.Intel.Lookup(v, intelClasses(f)...)
				if len(m) == 0 {
					continue
				}
				set := func(suffix string, val any) {
					if s, ok := val.(string); ok && s == "" {
						return
					}
					r[f+"_"+suffix] = val
					added[f+"_"+suffix] = true
				}
				set("intel_source", sources(m))
				set("intel_type", m[0].Type)
				set("intel_weight", fmtWeight(m[0].Weight))
				set("intel_description", m[0].Description)
				break
			}
		}
	}
	var cols []string
	for _, col := range res.Columns {
		cols = append(cols, col)
		for _, suffix := range intelSuffixes {
			if added[col+"_"+suffix] && !slices.Contains(res.Columns, col+"_"+suffix) {
				cols = append(cols, col+"_"+suffix)
			}
		}
	}
	res.Columns = cols
	return nil
}

// ThreatColumns are the columns threatmatch adds to each event.
var ThreatColumns = []string{"threat_match_field", "threat_match_value", "threat_indicator", "threat_type",
	"threat_source", "threat_weight", "threat_description", "threat_target"}

// threatAnnotate adds the threat_* columns describing each event's
// strongest match. With dropUnmatched, rows the in-memory check does not
// confirm (an indicator that expired a moment ago) are removed.
func (e *Engine) threatAnnotate(res *Result, c *query.ThreatMatch, dropUnmatched bool) {
	fields := c.Fields
	if len(fields) == 0 {
		fields = DefaultIntelFields
	}
	out := res.Rows[:0:0]
	matched := false
	for _, r := range res.Rows {
		hits := e.lookupRow(r, fields)
		if len(hits) == 0 {
			if !dropUnmatched {
				out = append(out, r)
			}
			continue
		}
		best := hits[0]
		for _, h := range hits[1:] {
			if h.ind.Weight > best.ind.Weight {
				best = h
			}
		}
		r["threat_match_field"] = best.field
		r["threat_match_value"] = best.value
		r["threat_indicator"] = best.ind.Value
		r["threat_type"] = best.ind.Type
		r["threat_source"] = sources(best.all)
		r["threat_weight"] = fmtWeight(best.ind.Weight)
		if best.ind.Description != "" {
			r["threat_description"] = best.ind.Description
		}
		targets, ok := threatTargetFields[best.field]
		if !ok {
			targets = defaultTargetFields
		}
		for _, t := range targets {
			if t == best.field {
				continue
			}
			if vs := stringValues(r[t]); len(vs) > 0 {
				r["threat_target"] = vs[0]
				break
			}
		}
		matched = true
		out = append(out, r)
	}
	res.Rows = out
	if !matched {
		return
	}
	// The threat columns go right after _time so they are seen first.
	var cols []string
	for _, col := range res.Columns {
		if !slices.Contains(ThreatColumns, col) {
			cols = append(cols, col)
		}
	}
	at := 0
	if len(cols) > 0 && cols[0] == "_time" {
		at = 1
	}
	res.Columns = append(append(append([]string{}, cols[:at]...), ThreatColumns...), cols[at:]...)
}

// checkThreatMatch reports a threatmatch that is not right after the search.
func checkThreatMatch(cmds []query.Command) error {
	for i, c := range cmds {
		if _, ok := c.(*query.ThreatMatch); ok && i > 0 {
			return fmt.Errorf("threatmatch must come right after the search (before %s); it filters events inside OpenSearch", cmds[0].Name())
		}
	}
	return nil
}
