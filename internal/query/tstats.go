// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"sort"
	"strings"
)

// tstats is Splunk's | tstats, read as the search and stats it stands
// for: | tstats count from datamodel=Endpoint.Processes where
// Processes.process_name=cmd.exe by Processes.dest is
// datamodel=Endpoint process_name=cmd.exe | stats count by dest, with the
// columns named as tstats names them (Processes.dest).
type tstats struct {
	q    Query // the search: data model, filter and time range
	cmds []Command
}

func (*tstats) Name() string { return "tstats" }

// tstatsNode is a CIM data model node Signalith stores as a data model of
// its own.
type tstatsNode struct {
	model string
	// fields are the node's fields Signalith stores under another name.
	fields map[string]string
}

// tstatsNodes maps a CIM data model and node, as tstats names them, to
// Signalith's data model. A data model named without a node is its root
// node, listed under "" and under the root's own name.
var tstatsNodes = map[string]map[string]tstatsNode{
	"Authentication":      {"": {model: "Authentication"}, "Authentication": {model: "Authentication"}},
	"Endpoint":            {"": {model: "Endpoint"}, "Processes": {model: "Endpoint"}, "Filesystem": {model: "Filesystem"}, "Registry": {model: "Registry"}},
	"Network_Traffic":     {"": {model: "Network_Traffic"}, "All_Traffic": {model: "Network_Traffic", fields: map[string]string{"app": "process_path", "dest_ip": "dest", "src_ip": "src"}}},
	"Network_Resolution":  {"": {model: "Network_Resolution"}, "DNS": {model: "Network_Resolution"}},
	"Web":                 {"": {model: "Web"}, "Web": {model: "Web"}},
	"Change":              {"": {model: "Change"}, "All_Changes": {model: "Change"}},
	"Malware":             {"": {model: "Malware"}, "Malware_Attacks": {model: "Malware"}},
	"Intrusion_Detection": {"": {model: "Intrusion_Detection"}, "IDS_Attacks": {model: "Intrusion_Detection"}},
	"Certificates":        {"": {model: "Certificates"}, "All_Certificates": {model: "Certificates"}},
	"Vulnerabilities":     {"": {model: "Vulnerabilities"}, "Vulnerabilities": {model: "Vulnerabilities"}},
	"Risk":                {"": {model: "Risk"}, "All_Risk": {model: "Risk"}},
	"Alerts":              {"": {model: "Alerts"}, "Alerts": {model: "Alerts"}},
}

// rootNodes names each CIM data model's root node, the prefix its fields
// carry when tstats names the data model alone.
var rootNodes = map[string]string{
	"Authentication": "Authentication", "Endpoint": "Processes", "Network_Traffic": "All_Traffic",
	"Network_Resolution": "DNS", "Web": "Web", "Change": "All_Changes", "Malware": "Malware_Attacks",
	"Intrusion_Detection": "IDS_Attacks", "Certificates": "All_Certificates", "Vulnerabilities": "Vulnerabilities",
	"Risk": "All_Risk", "Alerts": "Alerts",
}

// tstatsTarget reads datamodel=Model[.Node]: Signalith's data model, the
// node whose name prefixes fields, and the node's renamed fields.
func tstatsTarget(v string) (model, node string, fields map[string]string, ok bool) {
	dm, n, _ := strings.Cut(v, ".")
	nodes, known := tstatsNodes[dm]
	if !known {
		if n == "" && CheckDatamodel(dm) == nil {
			return dm, dm, nil, true
		}
		return "", "", nil, false
	}
	t, ok := nodes[n]
	if !ok {
		return "", "", nil, false
	}
	if n == "" {
		n = rootNodes[dm]
		t = nodes[n]
	}
	return t.model, n, t.fields, true
}

func (p *parser) parseTstats(cmd token) (Command, error) {
	const example = "| tstats count from datamodel=Authentication where Authentication.action=failure by Authentication.user"
	var toks []token
	depth := 0
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		switch t.kind {
		case tokLParen:
			depth++
		case tokRParen:
			depth--
		}
		toks = append(toks, p.next())
	}
	end := token{tokEOF, "", p.peek().pos}
	sub := func(ts []token) *parser {
		return &parser{toks: append(append([]token{}, ts...), end), depth: p.depth}
	}
	// keyword returns the index of the first of words at paren depth 0
	// from i on, or len(toks).
	keyword := func(i int, words ...string) int {
		d := 0
		for ; i < len(toks); i++ {
			switch toks[i].kind {
			case tokLParen:
				d++
			case tokRParen:
				d--
			case tokWord:
				if d == 0 {
					for _, w := range words {
						if strings.EqualFold(toks[i].text, w) {
							return i
						}
					}
				}
			}
		}
		return len(toks)
	}

	// Options, then the functions, up to from, where or by.
	i := 0
	fill, hasFill := "", false
	for i+2 < len(toks) && toks[i].kind == tokWord && toks[i+1].kind == tokOp && toks[i+1].text == "=" {
		switch strings.ToLower(toks[i].text) {
		case "summariesonly", "allow_old_summaries", "local", "chunk_size", "include_reduced_buckets":
		case "fillnull_value":
			// By fields an event lacks group under this value, where
			// tstats would otherwise leave the event out.
			v := toks[i+2]
			if v.kind != tokWord && v.kind != tokString {
				return nil, errorf(v.pos, "tstats fillnull_value= takes a value, such as fillnull_value=null")
			}
			fill, hasFill = v.text, true
		case "prestats":
			if b, err := parseBool(toks[i+2]); err != nil || b {
				return nil, errorf(toks[i+2].pos, "tstats prestats=t is not supported")
			}
		default:
			return nil, errorf(toks[i].pos, "unknown tstats option %q", toks[i].text)
		}
		i += 3
	}
	headEnd := keyword(i, "from", "where", "by")
	ap := sub(toks[i:headEnd])
	aggs, err := ap.parseAggs(cmd.pos)
	if err != nil {
		return nil, err
	}
	if err := noWildcardAggs("tstats", cmd.pos, aggs); err != nil {
		return nil, err
	}
	if t := ap.peek(); t.kind != tokEOF {
		return nil, errorf(t.pos, "unexpected %s in tstats; it expects: %s", describe(t), example)
	}
	ts := &tstats{}
	i = headEnd
	node := ""
	var renamed map[string]string
	if i < len(toks) && strings.EqualFold(toks[i].text, "from") {
		if i+3 >= len(toks) || !strings.EqualFold(toks[i+1].text, "datamodel") || toks[i+2].kind != tokOp || toks[i+2].text != "=" ||
			toks[i+3].kind != tokWord && toks[i+3].kind != tokString {
			return nil, errorf(toks[i].pos, "tstats reads from datamodel=<name>, for example: %s", example)
		}
		v := toks[i+3]
		model, n, fields, ok := tstatsTarget(v.text)
		if !ok {
			return nil, errorf(v.pos, "tstats cannot read %q; use a data model such as Authentication, Endpoint.Processes, Endpoint.Filesystem, Endpoint.Registry, Network_Traffic, Network_Resolution or Web", v.text)
		}
		ts.q.Datamodel, node, renamed = model, n, fields
		i += 4
	}
	field := func(f string) string {
		pre, rest, ok := strings.Cut(f, ".")
		if !ok || node == "" || pre != node || rest == "" {
			return f
		}
		if r, ok := renamed[rest]; ok {
			return r
		}
		return rest
	}
	byAt := keyword(i, "by")
	if i < byAt {
		if !strings.EqualFold(toks[i].text, "where") || toks[i].kind != tokWord {
			return nil, errorf(toks[i].pos, "unexpected %s in tstats; it expects: %s", describe(toks[i]), example)
		}
		wp := sub(toks[i+1 : byAt])
		wp.src, wp.base = p.src, p.base // for "Node.field"=value
		var wq Query
		if err := wp.parseSearch(&wq); err != nil {
			return nil, err
		}
		if t := wp.peek(); t.kind != tokEOF {
			return nil, errorf(t.pos, "unexpected %s in tstats where", describe(t))
		}
		if wq.Datamodel != "" {
			return nil, errorf(toks[i].pos, "name the data model with from datamodel=, not in where")
		}
		if wq.Index != "" && ts.q.Datamodel != "" {
			return nil, errorf(toks[i].pos, "tstats reads either a data model or index=, not both")
		}
		ts.q.Index, ts.q.Earliest, ts.q.Latest = wq.Index, wq.Earliest, wq.Latest
		ts.q.Search = renameFields(wq.Search, field)
		if node != "" {
			// A subsearch's rows name fields as tstats does
			// (Processes.process_name); its terms use Signalith's.
			ren := &Rename{}
			var keys []string
			for k := range renamed {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				ren.Pairs = append(ren.Pairs, [2]string{node + "." + k, renamed[k]})
			}
			ren.Pairs = append(ren.Pairs, [2]string{node + ".*", "*"})
			WalkSubsearches(ts.q.Search, func(s *Subsearch) {
				sq := *s.Query
				sq.Commands = append(append([]Command{}, sq.Commands...), ren)
				s.Query = &sq
			})
		}
	}
	var by []string
	span := ""
	if byAt < len(toks) {
		bp := sub(toks[byAt+1:])
		for {
			t := bp.peek()
			if t.kind == tokEOF {
				break
			}
			if t.kind == tokComma {
				bp.next()
				continue
			}
			if t.kind == tokWord && strings.EqualFold(t.text, "span") && bp.peekAt(1).kind == tokOp && bp.peekAt(1).text == "=" {
				bp.next()
				bp.next()
				at := bp.peek().pos
				v, err := bp.value()
				if err != nil {
					return nil, err
				}
				if secs, _, err := BinSpan(v); err != nil || secs == 0 {
					return nil, errorf(at, "tstats span is a time such as 1h or 15m")
				}
				span = v
				continue
			}
			// A by field becomes a stats by field, which is written bare.
			if t.kind != tokWord && t.kind != tokString || t.text == "" || strings.EqualFold(t.text, "by") || FormatValue(t.text) != t.text {
				return nil, errorf(t.pos, "unexpected %s in tstats by", describe(t))
			}
			if strings.Contains(t.text, "*") {
				return nil, errorf(t.pos, "by %s: wildcard field names are not supported in by; name each field", t.text)
			}
			bp.next()
			by = append(by, t.text)
		}
		if len(by) == 0 {
			return nil, errorf(toks[byAt].pos, `expected a field after "by"`)
		}
	}
	if span != "" && !containsFold(by, "_time") {
		return nil, errorf(cmd.pos, "tstats span= needs _time among the by fields")
	}

	// The search, then stats on Signalith's names, then the columns
	// renamed to the names tstats gives them.
	st := &Stats{}
	for _, a := range aggs {
		if f := field(a.Field); f != a.Field {
			if a.Alias == "" {
				a.Alias = a.Column()
			}
			a.Field = f
		}
		st.Aggs = append(st.Aggs, a)
	}
	ren := &Rename{}
	for _, f := range by {
		g := field(f)
		st.By = append(st.By, g)
		if g != f {
			ren.Pairs = append(ren.Pairs, [2]string{g, f})
		}
	}
	if span != "" {
		ts.cmds = append(ts.cmds, &Bin{Field: "_time", Span: span})
	}
	if hasFill && len(st.By) > 0 {
		ts.cmds = append(ts.cmds, &Fillnull{Value: fill, Fields: append([]string{}, st.By...)})
	}
	ts.cmds = append(ts.cmds, st)
	if len(ren.Pairs) > 0 {
		ts.cmds = append(ts.cmds, ren)
	}
	return ts, nil
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// renameFields returns e with each field name passed through f.
func renameFields(e Expr, f func(string) string) Expr {
	switch e := e.(type) {
	case *And:
		out := &And{}
		for _, c := range e.Children {
			out.Children = append(out.Children, renameFields(c, f))
		}
		return out
	case *Or:
		out := &Or{}
		for _, c := range e.Children {
			out.Children = append(out.Children, renameFields(c, f))
		}
		return out
	case *Not:
		return &Not{Child: renameFields(e.Child, f)}
	case *Compare:
		c := *e
		c.Field = f(c.Field)
		return &c
	case *In:
		c := *e
		c.Field = f(c.Field)
		return &c
	}
	return e
}
