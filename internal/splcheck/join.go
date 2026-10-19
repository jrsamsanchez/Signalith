// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// Joins: a search's later stage may join its rows to those of a tstats
// subsearch over another Endpoint node, or over a host's connections
// (join process_guid [| tstats ... FROM datamodel=Endpoint.Filesystem
// ...]), as Signalith's join command does: the subsearch's rows that
// share the join fields' values add their fields to each row, the
// subsearch's values winning. The subsearch is read as a rule of its own
// (Join.Sub), with its tstats grouping first, and converted the same
// way; the detection runs it as join's subsearch (in internal/detect).
// Its dest, and the join's, is the computer that logged the event, as
// security_content's data sources map Sysmon's events (Computer:
// Processes.dest), which Signalith keeps as host.
//
// A test case of such a rule is an event of the search's own node with
// the events the subsearch reads With it, on the same host
// (sigmacheck.Case.With).

// Join is one join stage of a rule's later stages.
type Join struct {
	Fields []string
	// Left keeps rows with no match (type=left or outer).
	Left bool
	// Max is how many of the subsearch's rows join one row (0 for all).
	Max int
	// Sub is the subsearch, read as a rule: its node, where clause and
	// later stages, its tstats grouping first.
	Sub *Rule
}

var (
	// joinWordRe is the start of a join stage, and joinStageRe a whole
	// one: its options and fields, and its subsearch.
	joinWordRe  = regexp.MustCompile(`(?i)^\s*join\s`)
	joinStageRe = regexp.MustCompile(`(?is)^join\s+([^\[]*)\[(.*)\]$`)
	joinFieldRe = regexp.MustCompile(`^[A-Za-z_]\w*$`)
)

// joinNodes are the nodes a join's subsearch may read.
var joinNodes = map[string]bool{"Processes": true, "Filesystem": true, "Registry": true, "All_Traffic": true}

// joinStage reads a join stage: opts is the text before its subsearch,
// inner the subsearch. It returns the stage as Signalith runs it, with
// the subsearch's filter left as * (the detection's is the converted
// where clause), and the join's fields.
func (r *Rule) joinStage(opts, inner string) (string, []string, error) {
	refuse := func(why string, args ...any) (string, []string, error) {
		return "", nil, fmt.Errorf("a join "+why+" is not supported", args...)
	}
	if r.sub {
		return refuse("in a join's subsearch")
	}
	j := &Join{Max: 1}
	for _, tok := range strings.FieldsFunc(opts, func(c rune) bool { return c == ',' || unicode.IsSpace(c) }) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			if !joinFieldRe.MatchString(tok) {
				return refuse("on %s", tok)
			}
			j.Fields = append(j.Fields, tok)
			continue
		}
		switch strings.ToLower(k) {
		case "type":
			switch strings.ToLower(v) {
			case "inner":
				j.Left = false
			case "left", "outer":
				j.Left = true
			default:
				return refuse("of type=%s", v)
			}
		case "max":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > query.MaxJoinMatches {
				// Signalith joins a row to at most MaxJoinMatches rows.
				return refuse("with max=%s", v)
			}
			j.Max = n
		default:
			return refuse("with the option %s", k)
		}
	}
	if len(j.Fields) == 0 {
		return refuse("with no fields")
	}
	inner = strings.TrimSpace(inner)
	if !strings.HasPrefix(inner, "|") {
		return refuse("of a subsearch that is not a tstats search")
	}
	sub := &Rule{Name: r.Name, ID: r.ID, Type: r.Type, Status: r.Status, DataSource: r.DataSource, Search: inner, sub: true}
	if _, err := sub.parse(r.macros, r.opt); err != nil {
		return "", nil, fmt.Errorf("join's subsearch: %w", err)
	}
	switch {
	case !joinNodes[sub.Node] || IsSensorNode(sub.Node):
		return refuse("of a subsearch of %s", sub.Node)
	case sub.Threshold != nil:
		return refuse("of a subsearch that counts")
	case sub.Linux != r.Linux || sub.MacOS != r.MacOS:
		return refuse("of a subsearch of another platform")
	case len(sub.Lookups) > 0 || sub.IPLocation():
		return refuse("of a subsearch that looks values up")
	case sub.Post == "":
		return refuse("of a subsearch with no rows")
	}
	j.Sub = sub
	r.Joins = append(r.Joins, j)
	parts := []string{"join"}
	if j.Left {
		parts = append(parts, "type=left")
	}
	if j.Max != 1 {
		parts = append(parts, "max="+strconv.Itoa(j.Max))
	}
	parts = append(parts, strings.Join(j.Fields, ", "))
	return strings.Join(parts, " ") + " [search * | " + strings.ReplaceAll(sub.Post, "\n| ", " | ") + "]", j.Fields, nil
}

// joinInput is what a join's subsearch reads in a test: the events With
// a case, and whether join i's subsearch finds one of them (its filter,
// as Splunk or the detection reads it).
type joinInput struct {
	with  []sigmacheck.Case
	reads func(i int, c sigmacheck.Case) bool
}

// splunkJoins is the joinInput of the events with a case as Splunk reads
// them: each join's subsearch finds the events its where clause matches.
func (r *Rule) splunkJoins(with []sigmacheck.Case) *joinInput {
	return &joinInput{with: with, reads: func(i int, c sigmacheck.Case) bool { return reads(r.Joins[i].Sub, c) }}
}

// joinMarker is the search of a join's subsearch in runJoin, which
// subsearchRows answers with the subsearch's rows.
const joinMarker = "splcheck_join_subsearch"

// runJoin runs a join stage (the i-th) over rows, the subsearch's rows
// being those its later stages keep of the events it finds (jc), by
// Signalith's own join.
func (r *Rule) runJoin(ctx context.Context, rows []map[string]any, c *query.Join, i int, jc *joinInput) ([]search.Row, error) {
	if i >= len(r.Joins) {
		return nil, fmt.Errorf("join %d of %d", i+1, len(r.Joins))
	}
	var subDocs []map[string]any
	if jc != nil {
		for _, w := range jc.with {
			if jc.reads(i, w) {
				docs, _ := StoredCopies(w)
				subDocs = append(subDocs, docs...)
			}
		}
	}
	var subRows []map[string]any
	if len(subDocs) > 0 {
		got, err := r.Joins[i].Sub.runPost(subDocs)
		if err != nil {
			return nil, err
		}
		for _, row := range got {
			subRows = append(subRows, row)
		}
	}
	j := *c
	j.Sub = &query.Query{Search: &query.Compare{Field: joinMarker, Op: "=", Value: "1"}, Commands: []query.Command{&query.Head{N: len(subRows) + 1}}}
	eng := &search.Engine{Store: subsearchRows{rows: rows, sub: subRows}}
	q := &query.Query{Commands: []query.Command{&j, &query.Head{N: len(rows)*max(1, len(subRows)) + 1}}}
	res, err := eng.Execute(search.Background(ctx), q)
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// subsearchRows answers a search with rows, and runJoin's subsearch with
// sub.
type subsearchRows struct{ rows, sub []map[string]any }

func (s subsearchRows) Search(ctx context.Context, index string, body map[string]any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	if strings.Contains(string(b), joinMarker) {
		return rowsSearcher(s.sub).Search(ctx, index, body)
	}
	return rowsSearcher(s.rows).Search(ctx, index, body)
}

// keepsWith reports whether the later stages keep a row for events,
// with the events their joins' subsearches read.
func (r *Rule) keepsWith(docs []map[string]any, jc *joinInput) bool {
	if len(r.post) == 0 {
		return true
	}
	rows, err := r.runPostWith(docs, jc)
	return err == nil && len(rows) > 0
}

// joinReads reports whether Splunk's search finds a case of a rule with
// joins: its events match the where clause and, with the events with it,
// the later stages keep a row.
func (r *Rule) joinReads(c sigmacheck.Case) bool {
	docs, model := StoredCopies(c)
	if !InModel(r.Node, model) {
		return false
	}
	for _, d := range docs {
		if !Eval(r.Where, View(d)) {
			return false
		}
	}
	return r.keepsWith(docs, r.splunkJoins(c.With))
}

// upTo is the rule with only its later stages before its i-th join (and
// the joins before it).
func (r *Rule) upTo(i int) *Rule {
	out := *r
	out.Joins = r.Joins[:i]
	n := 0
	for k, c := range r.post {
		if _, ok := c.(*query.Join); ok {
			if n == i {
				out.post = r.post[:k]
				break
			}
			n++
		}
	}
	stages := strings.Split(r.Post, "\n| ")
	n = 0
	for k, s := range stages {
		if joinWordRe.MatchString(s) {
			if n == i {
				out.Post = strings.Join(stages[:k], "\n| ")
				break
			}
			n++
		}
	}
	return &out
}

// joinPairs is how many joined cases a rule's tests have.
const joinPairs = 3

// The values a join's events are given to share: a process GUID, or a
// number (a process ID), which Windows' security log writes in hex.
var joinMarkers = []string{"{6C1F3A2B-7D00-6E01-2B03-00000000AB0%d}", "57%d2"}

// joinKeys are the event fields tried first for the value a join's
// fields share.
var joinKeys = []string{"ProcessGuid", "ParentProcessGuid", "ProcessId", "ParentProcessId", "NewProcessId"}

// joinCases makes a rule's test cases: events of its node its stages
// before the first join keep, each with events of each join's subsearch
// that share the join fields' values with it (found by giving the events
// one value in the fields that make them), and the same without those
// events or with their value changed, which the rule must not find.
func (r *Rule) joinCases() []sigmacheck.Case {
	var mains, others []sigmacheck.Case
	for _, c := range Cases(r.upTo(0)) {
		if c.Repeat > 1 {
			continue
		}
		if c.Expect {
			mains = append(mains, c)
		} else {
			others = append(others, c)
		}
	}
	subs := make([][]sigmacheck.Case, len(r.Joins))
	subMisses := make([][]sigmacheck.Case, len(r.Joins))
	for i, j := range r.Joins {
		for _, c := range Cases(j.Sub) {
			switch {
			case c.Repeat > 1:
			case c.Expect:
				subs[i] = append(subs[i], c)
			default:
				subMisses[i] = append(subMisses[i], c)
			}
		}
	}
	var out []sigmacheck.Case
	var first *sigmacheck.Case
	var firstLinked [][]string
	pairs := 0
	for _, m := range mains {
		if pairs == joinPairs {
			break
		}
		c, linked, ok := r.link(m, subs)
		if !ok || !r.joinReads(c) {
			continue
		}
		pairs++
		c.Expect = true
		out = append(out, c)
		if first == nil {
			first, firstLinked = &c, linked
		}
		// Without the subsearch's events, and with each of them sharing
		// another value.
		alone := c
		alone.With = nil
		alone.Expect = r.joinReads(alone)
		out = append(out, alone)
		for k, keys := range linked {
			for _, key := range keys {
				miss := c
				miss.With = slices.Clone(c.With)
				miss.With[k].Data = maps.Clone(c.With[k].Data)
				miss.With[k].Data[key] = otherValue(miss.With[k].Data[key])
				miss.Expect = r.joinReads(miss)
				out = append(out, miss)
			}
		}
	}
	if first != nil {
		// Events the rule's own where clause leaves out, with the
		// subsearch's events.
		for _, o := range others[:min(len(others), 4)] {
			o.With = first.With
			o.Expect = r.joinReads(o)
			out = append(out, o)
		}
		// Events the subsearch's where clause leaves out, sharing the
		// values the joined ones do.
		for k := range first.With {
			for _, s := range subMisses[k][:min(len(subMisses[k]), 4)] {
				miss := *first
				miss.With = slices.Clone(first.With)
				s.Data = maps.Clone(s.Data)
				for _, key := range append(slices.Clone(joinKeys), firstLinked[k]...) {
					if v, ok := first.With[k].Data[key]; ok {
						s.Data[key] = v
					}
				}
				miss.With[k] = s
				miss.Expect = r.joinReads(miss)
				out = append(out, miss)
			}
		}
	}
	for i := range out {
		out[i].Source = "synthesized"
		for k := range out[i].With {
			out[i].With[k].Source, out[i].With[k].Expect = "synthesized", false
		}
	}
	seen := map[string]bool{}
	out = slices.DeleteFunc(out, func(c sigmacheck.Case) bool {
		k, _ := json.Marshal(c)
		if seen[string(k)] {
			return true
		}
		seen[string(k)] = true
		return false
	})
	slices.SortStableFunc(out, func(a, b sigmacheck.Case) int {
		switch {
		case a.Expect && !b.Expect:
			return -1
		case b.Expect && !a.Expect:
			return 1
		}
		return 0
	})
	return out
}

// otherValue is a value of an event's field other than v, of its kind.
func otherValue(v string) string {
	if n, err := strconv.ParseInt(v, 0, 64); err == nil {
		if strings.HasPrefix(v, "0x") {
			return "0x" + strconv.FormatInt(n+1, 16)
		}
		return strconv.FormatInt(n+1, 10)
	}
	return "{0D9B4E77-1A00-6F02-4C05-00000000CD07}"
}

// link gives an event of the rule's node (main) an event of each join's
// subsearch (subs) that the join joins to it, and returns the case and,
// for each event with it, the fields set to make it share the values;
// false when none joins.
func (r *Rule) link(main sigmacheck.Case, subs [][]sigmacheck.Case) (sigmacheck.Case, [][]string, bool) {
	cur := main
	cur.Data = maps.Clone(main.Data)
	cur.With = nil
	var linked [][]string
	for i := range r.Joins {
		ok := false
		for _, s := range subs[i] {
			c, keys, found := r.linkOne(cur, i, s)
			if found {
				cur, ok = c, true
				linked = append(linked, keys)
				break
			}
		}
		if !ok {
			return main, nil, false
		}
	}
	return cur, linked, true
}

// joinValue is a value as Signalith's join compares it, false for a row
// without one.
func joinValue(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return x, x != ""
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := joinValue(e); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n"), len(parts) > 0
	}
	return fmt.Sprint(v), true
}

// linkOne gives cur (an event of the rule's node, with the events of its
// first i joins) the event s of the i-th join's subsearch, with the
// fields of s, and if need be of cur's events, set so that the join's
// fields share their values.
func (r *Rule) linkOne(cur sigmacheck.Case, i int, s sigmacheck.Case) (sigmacheck.Case, []string, bool) {
	before := r.upTo(i)
	left := func(c sigmacheck.Case) []search.Row {
		docs, model := StoredCopies(c)
		if !InModel(r.Node, model) {
			return nil
		}
		for _, d := range docs {
			if !Eval(r.Where, View(d)) {
				return nil
			}
		}
		rows, err := before.runPostWith(docs, r.splunkJoins(c.With))
		if err != nil {
			return nil
		}
		return rows
	}
	sub := r.Joins[i].Sub
	right := func(c sigmacheck.Case) []search.Row {
		if !reads(sub, c) {
			return nil
		}
		docs, _ := StoredCopies(c)
		rows, err := sub.runPost(docs)
		if err != nil {
			return nil
		}
		return rows
	}
	real := func(v string, ok bool) bool { return ok && !strings.EqualFold(v, "unknown") }
	shares := func(rows []search.Row, f, v string) bool {
		return slices.ContainsFunc(rows, func(row search.Row) bool {
			w, ok := joinValue(row[f])
			return ok && w == v
		})
	}
	// keys are the fields of an event tried for a value.
	keys := func(c sigmacheck.Case) []string {
		out := slices.Clone(joinKeys)
		for _, k := range slices.Sorted(maps.Keys(c.Data)) {
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
		return out
	}
	// forms are the ways an event may write a value.
	forms := func(v string) []string {
		out := []string{v}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			out = append(out, "0x"+strconv.FormatInt(n, 16))
		}
		return out
	}
	cur.Data = maps.Clone(cur.Data)
	cur.With = slices.Clone(cur.With)
	s.Data = maps.Clone(s.Data)
	s.With = nil
	var set []string
	for fi, f := range r.Joins[i].Fields {
		rows := left(cur)
		if len(rows) == 0 {
			return cur, nil, false
		}
		v, ok := joinValue(rows[0][f])
		if !real(v, ok) {
			// The rule's events make no value of f: one of them is given
			// one.
			found := false
			for e := -1; e < len(cur.With) && !found; e++ {
				ev := &cur
				if e >= 0 {
					cur.With[e].Data = maps.Clone(cur.With[e].Data)
					ev = &cur.With[e]
				}
				for _, k := range keys(*ev) {
					old, had := ev.Data[k]
					for _, m := range joinMarkers {
						for _, raw := range forms(fmt.Sprintf(m, i*len(r.Joins[i].Fields)+fi)) {
							ev.Data[k] = raw
							if rows := left(cur); len(rows) > 0 {
								if w, ok := joinValue(rows[0][f]); real(w, ok) && w != v {
									v, found = w, true
									break
								}
							}
						}
						if found {
							break
						}
					}
					if found {
						break
					}
					if had {
						ev.Data[k] = old
					} else {
						delete(ev.Data, k)
					}
				}
			}
			if !found {
				v, ok = joinValue(rows[0][f])
				if !ok {
					return cur, nil, false
				}
			}
		}
		if shares(right(s), f, v) {
			continue
		}
		found := false
		for _, k := range keys(s) {
			old, had := s.Data[k]
			for _, raw := range forms(v) {
				s.Data[k] = raw
				if shares(right(s), f, v) {
					found = true
					break
				}
			}
			if found {
				set = append(set, k)
				break
			}
			if had {
				s.Data[k] = old
			} else {
				delete(s.Data, k)
			}
		}
		if !found {
			return cur, nil, false
		}
	}
	cur.With = append(cur.With, s)
	// The values set for one field may have lost another's.
	after := r.upTo(i + 1)
	if i+1 == len(r.Joins) {
		after = r
	}
	docs, _ := StoredCopies(cur)
	if !after.keepsWith(docs, r.splunkJoins(cur.With)) {
		return cur, nil, false
	}
	return cur, set, true
}

// joinSafe are the stored fields of each node a join may match on: the
// fields Signalith keeps as Splunk's add-ons give them, so that rows
// share a value in Signalith exactly when they do in Splunk. A user is
// left out (Signalith keeps DOMAIN\name, Splunk the name), as are a
// registry value's data (Signalith keeps "DWORD (0x1)") and a
// connection's src and dest, which security_content's data source for
// Sysmon's network connections does not map.
var joinSafe = map[string][]string{
	"Processes": {
		"host", "process_guid", "parent_process_guid", "process_id", "parent_process_id", "process_name", "process_path",
		"process", "parent_process_name", "parent_process_path", "parent_process", "process_current_directory", "original_file_name",
	},
	"Filesystem":  {"host", "process_guid", "process_id", "process_name", "process_path", "file_path", "file_name"},
	"Registry":    {"host", "process_guid", "process_id", "process_name", "process_path", "registry_path"},
	"All_Traffic": {"process_guid", "process_id", "process_path", "dest_port", "src_port", "transport"},
}

// joinSource is the stored field a row's field f holds the value of
// after cmds, the stages that make the row (a rename, a copy or a rex
// of it), false when a stage computes it otherwise or Signalith cannot
// tell.
func joinSource(cmds []query.Command, f string) (string, bool) {
	for k := len(cmds) - 1; k >= 0; k-- {
		switch c := cmds[k].(type) {
		case *query.Rename:
			for p := len(c.Pairs) - 1; p >= 0; p-- {
				from, to := c.Pairs[p][0], c.Pairs[p][1]
				if !strings.Contains(to, "*") {
					if to == f {
						if strings.Contains(from, "*") {
							return "", false
						}
						f = from
					}
					continue
				}
				pre, post, _ := strings.Cut(to, "*")
				if strings.Count(to, "*") != 1 || strings.Count(from, "*") != 1 {
					return "", false
				}
				if mid, ok := strings.CutPrefix(f, pre); ok && strings.HasSuffix(mid, post) && len(mid) >= len(post) {
					f = strings.Replace(from, "*", mid[:len(mid)-len(post)], 1)
				}
			}
		case *query.Eval:
			for a := len(c.Assigns) - 1; a >= 0; a-- {
				if c.Assigns[a].Field != f {
					continue
				}
				x, ok := c.Assigns[a].Expr.(*query.Field)
				if !ok {
					return "", false
				}
				f = x.Name
			}
		case *query.Rex:
			if c.Sed != "" {
				return "", false
			}
			for _, m := range rexGroupRe.FindAllStringSubmatch(c.Pattern, -1) {
				if m[1] == f {
					// Part of another field's value: as safe as it is.
					f = c.Field
				}
			}
		case *query.Stats:
			if !slices.Contains(c.By, f) {
				return "", false
			}
		case *query.Fillnull, *query.Table, *query.Where, *query.Dedup, *query.Sort, *query.Head, *query.Regex:
		default:
			return "", false
		}
	}
	return f, true
}

// joinFieldsSafe returns an error for a join whose fields are not, on
// both sides, values of fields a join may match on (joinSafe): main are
// the stages before the join.
func joinFieldsSafe(node string, main []query.Command, j *Join) error {
	for _, f := range j.Fields {
		for _, side := range []struct {
			node string
			cmds []query.Command
		}{{node, main}, {j.Sub.Node, j.Sub.post}} {
			src, ok := joinSource(side.cmds, f)
			if !ok || !slices.Contains(joinSafe[side.node], src) {
				return fmt.Errorf("a join on %s %s, which Signalith may keep differently than Splunk", side.node, f)
			}
		}
	}
	return nil
}

// joinQuery is a join's subsearch as the detection runs it.
type joinQuery struct {
	datamodel string
	filter    query.Expr
	regexes   []query.Command
}

// reads reports whether the subsearch finds a case's events.
func (j joinQuery) reads(c sigmacheck.Case) bool {
	docs, model := StoredCopies(c)
	if j.datamodel != "" && !strings.EqualFold(model, j.datamodel) {
		return false
	}
	for _, d := range docs {
		if ok, err := search.MatchDoc(j.filter, d); err != nil || !ok {
			return false
		}
	}
	if len(j.regexes) > 0 {
		rows, err := search.RunCommands(context.Background(), docs, j.regexes)
		return err == nil && len(rows) == len(docs)
	}
	return true
}

// joinQueries are the subsearches of a detection's joins, one for each
// of the rule's.
func joinQueries(r *Rule, q *query.Query) ([]joinQuery, error) {
	var out []joinQuery
	for _, c := range q.Commands {
		j, ok := c.(*query.Join)
		if !ok {
			continue
		}
		jq := joinQuery{datamodel: j.Sub.Datamodel, filter: j.Sub.Search}
		for _, sc := range j.Sub.Commands {
			if _, ok := sc.(*query.Regex); !ok {
				break
			}
			jq.regexes = append(jq.regexes, sc)
		}
		out = append(out, jq)
	}
	if len(out) != len(r.Joins) {
		return nil, fmt.Errorf("the detection has %d joins, the rule %d", len(out), len(r.Joins))
	}
	return out, nil
}
