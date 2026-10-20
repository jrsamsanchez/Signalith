// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// A later transaction (transaction user startswith=(...) endswith=(...)
// maxspan=2m) runs as Signalith's transaction command, which groups
// events as Splunk's does. What Splunk finds also depends on its search
// window, the hour that ended 10 minutes before each run: a transaction
// is found only when the window holds it whole. A detection runs every
// few minutes over a window as long as the run interval plus the
// longest transaction the rule keeps, so each one Splunk finds is whole
// in some run; like a count over a time span (splunkThreshold), it may
// also find one that straddles the edge of Splunk's window.
//
// That holds only when what a transaction is depends on its own events
// alone, not on the events before it in the window, and when the rule
// keeps only short transactions:
//
//   - It needs startswith= and endswith=: a start ends any transaction
//     open before it, so a transaction is the events from a start to
//     its end, wherever the window begins. Without startswith=, where a
//     transaction begins depends on where the window does.
//   - It needs maxspan=, or a later test that keeps only a transaction
//     shorter than some duration (where duration<300, or eval
//     x=case(duration<300, "TRUE") then search x=TRUE): the window
//     must hold the longest transaction kept.
//
// Each field of a transaction other than the ones it groups by (and
// duration, eventcount and _time) holds the values of all its events. A
// later stats grouped by such a field groups a transaction under each of
// its values, as Splunk's stats does, by an mvexpand of the field first;
// a later test or eval of such a field is refused, since Splunk's
// reading of several values differs from Signalith's.

// maxTransactionSpan is the longest transaction a rule may keep, which
// bounds the window each run of its detection searches.
const maxTransactionSpan = time.Hour

// txnStageRe is a later transaction stage.
var txnStageRe = regexp.MustCompile(`(?i)^transaction\b`)

// txnStages follows a rule's later stages from a transaction to the stats
// that regroups its rows.
type txnStages struct {
	seen   bool // a transaction came
	active bool // its rows are the rows, not yet regrouped
	// single are the fields that hold one value in each row.
	single map[string]bool
	// short are the fields an eval set to a value only for a transaction
	// shorter than some seconds: x=case(duration<300, "TRUE").
	short map[string]shortField
	span  time.Duration // the longest transaction the stages keep; 0 for no limit
}

type shortField struct {
	value string
	span  time.Duration
}

// stage checks one later stage, as written in Signalith's language,
// returning stages to run before it (mvexpand before a stats). grouped
// is set when an earlier stage (a tstats search's own grouping, or a
// stats) has already made the rows groups of events.
func (t *txnStages) stage(s string, grouped bool) ([]string, error) {
	q, err := query.Parse("* | " + s)
	if err != nil || len(q.Commands) != 1 {
		if t.active || strings.HasPrefix(strings.ToLower(s), "transaction") {
			return nil, fmt.Errorf("%s: %s", laterStage, firstWords(s))
		}
		return nil, nil // reported when the stages are parsed
	}
	c := q.Commands[0]
	if x, ok := c.(*query.Transaction); ok {
		return nil, t.transaction(x, grouped)
	}
	if !t.active {
		return nil, nil
	}
	switch c := c.(type) {
	case *query.Eval:
		for _, a := range c.Assigns {
			if f := t.multiRead(a.Expr); f != "" {
				return nil, fmt.Errorf("a later eval of %s, which a transaction makes multivalue, is not supported", f)
			}
			t.single[a.Field] = true
			delete(t.short, a.Field)
			if sf, ok := shortCase(a.Expr); ok {
				t.short[a.Field] = sf
			}
		}
	case *query.Where:
		if f := t.multiFilter(c.Expr); f != "" {
			return nil, fmt.Errorf("a later %s of %s, which a transaction makes multivalue, is not supported", c.Name(), f)
		}
		for _, k := range andKids(c.Expr) {
			if span, ok := t.shortTest(k, c.Search); ok && (t.span == 0 || span < t.span) {
				t.span = span
			}
		}
	case *query.Rename:
		for _, p := range c.Pairs {
			if strings.Contains(p[0], "*") || strings.Contains(p[1], "*") {
				// A pattern may put any field in place of one that
				// held one value.
				for f := range t.single {
					if _, ok := query.RenameField(p, f); ok || query.MatchField(p[1], f) {
						delete(t.single, f)
					}
				}
				for f := range t.short {
					if query.MatchField(p[1], f) {
						delete(t.short, f)
					}
				}
				continue
			}
			one := t.single[p[0]]
			sf, short := t.short[p[0]]
			delete(t.single, p[0])
			delete(t.short, p[0])
			delete(t.single, p[1])
			delete(t.short, p[1])
			if one {
				t.single[p[1]] = true
			}
			if short {
				t.short[p[1]] = sf
			}
		}
	case *query.Fillnull, *query.Table, *query.FieldsRemove:
	case *query.Stats:
		// Grouped by a field of several values, Splunk's stats counts
		// the transaction in the group of each.
		var pre []string
		for _, f := range c.By {
			if !t.single[f] {
				pre = append(pre, "mvexpand "+quoteField(f))
			}
		}
		t.active = false
		return pre, nil
	default:
		return nil, fmt.Errorf("a later %s after a transaction is not supported", c.Name())
	}
	return nil, nil
}

// transaction checks a later transaction stage.
func (t *txnStages) transaction(c *query.Transaction, grouped bool) error {
	switch {
	case t.seen:
		return fmt.Errorf("a search with two later transactions is not supported")
	case c.StartsWith == nil:
		return fmt.Errorf("a later transaction without startswith= depends on Splunk's search window")
	case c.EndsWith == nil:
		return fmt.Errorf("a later transaction without endswith= depends on Splunk's search window")
	case grouped:
		return fmt.Errorf("a later transaction of grouped rows is not supported")
	}
	t.seen, t.active = true, true
	t.single = map[string]bool{"_time": true, "duration": true, "eventcount": true}
	for _, f := range c.Fields {
		t.single[f] = true
	}
	t.short = map[string]shortField{}
	t.span = time.Duration(c.MaxSpan) * time.Second
	return nil
}

// done checks the stages once all are read, returning the longest
// transaction they keep (0 when there is no transaction).
func (t *txnStages) done() (time.Duration, error) {
	if !t.seen {
		return 0, nil
	}
	if t.span == 0 {
		return 0, fmt.Errorf("a later transaction with no maxspan= depends on Splunk's search window, which may cut it")
	}
	if t.span > maxTransactionSpan {
		return 0, fmt.Errorf("a later transaction longer than %s is not supported", formatSpan(maxTransactionSpan))
	}
	return t.span, nil
}

// multiRead is a field an eval expression reads that holds several values
// ("" for none).
func (t *txnStages) multiRead(e query.EvalExpr) string {
	bad := ""
	query.WalkEval(e, func(x query.EvalExpr) {
		if f, ok := x.(*query.Field); ok && !t.single[f.Name] && bad == "" {
			bad = f.Name
		}
	})
	return bad
}

// multiFilter is a field a filter reads that holds several values ("" for
// none). Free text in a search reads the raw event, which a transaction
// joins.
func (t *txnStages) multiFilter(e query.Expr) string {
	switch x := e.(type) {
	case *query.And:
		for _, k := range x.Children {
			if f := t.multiFilter(k); f != "" {
				return f
			}
		}
	case *query.Or:
		for _, k := range x.Children {
			if f := t.multiFilter(k); f != "" {
				return f
			}
		}
	case *query.Not:
		return t.multiFilter(x.Child)
	case *query.Compare:
		if !t.single[x.Field] {
			return x.Field
		}
	case *query.In:
		if !t.single[x.Field] {
			return x.Field
		}
	case *query.Cond:
		return t.multiRead(x.X)
	default:
		return "_raw"
	}
	return ""
}

// andKids are the terms of a filter that every row it keeps passes.
func andKids(e query.Expr) []query.Expr {
	a, ok := e.(*query.And)
	if !ok {
		return []query.Expr{e}
	}
	var out []query.Expr
	for _, k := range a.Children {
		out = append(out, andKids(k)...)
	}
	return out
}

// shortTest reports whether a filter term keeps only a transaction
// shorter than some span: duration<300, or a field shortCase set, tested
// for its value.
func (t *txnStages) shortTest(e query.Expr, search bool) (time.Duration, bool) {
	switch x := e.(type) {
	case *query.Compare:
		if x.Field == "duration" {
			return durationBound(x.Op, x.Value)
		}
		sf, ok := t.short[x.Field]
		if ok && x.Op == "=" && (x.Value == sf.value || search && strings.EqualFold(x.Value, sf.value)) && !strings.Contains(x.Value, "*") {
			return sf.span, true
		}
	case *query.Cond:
		b, ok := x.X.(*query.Binary)
		if !ok {
			return 0, false
		}
		f, ok := b.L.(*query.Field)
		if !ok {
			return 0, false
		}
		if f.Name == "duration" {
			if n, ok := b.R.(*query.Num); ok {
				return durationBound(b.Op, n.Text)
			}
			return 0, false
		}
		sf, ok := t.short[f.Name]
		if v, isStr := b.R.(*query.Str); ok && isStr && (b.Op == "=" || b.Op == "==") && v.Value == sf.value {
			return sf.span, true
		}
	}
	return 0, false
}

// shortCase reads case(duration<300, "TRUE"): a value only for a
// transaction shorter than 300 seconds, and null otherwise.
func shortCase(e query.EvalExpr) (shortField, bool) {
	c, ok := e.(*query.Call)
	if !ok || c.Func != "case" || len(c.Args) != 2 {
		return shortField{}, false
	}
	b, ok := c.Args[0].(*query.Binary)
	if !ok {
		return shortField{}, false
	}
	f, ok := b.L.(*query.Field)
	n, isNum := b.R.(*query.Num)
	v, isStr := c.Args[1].(*query.Str)
	if !ok || !isNum || !isStr || f.Name != "duration" {
		return shortField{}, false
	}
	span, ok := durationBound(b.Op, n.Text)
	if !ok {
		return shortField{}, false
	}
	return shortField{value: v.Value, span: span}, true
}

// durationBound is the span a test of duration (in seconds) keeps a
// transaction within: duration<300 or duration<=300 is 300 seconds.
func durationBound(op, value string) (time.Duration, bool) {
	if op != "<" && op != "<=" {
		return 0, false
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil || n <= 0 || n > 1e9 { // (a longer one is refused, not overflowed)
		return 0, false
	}
	return time.Duration(n * float64(time.Second)), true
}

// txnIndex is the index of a rule's later transaction among its parsed
// later stages, or -1.
func (r *Rule) txnIndex() int {
	return slices.IndexFunc(r.post, func(c query.Command) bool {
		_, ok := c.(*query.Transaction)
		return ok
	})
}

// sequences returns, for an event the rule's filter matches but its
// later transaction drops, the run of events it keeps: the event made a
// start (startswith=) and a copy of it made an end (endswith=) shortly
// after, by setting the fields their tests name. With it come runs it
// does not keep, each found or not as the later stages say: the end
// past the longest transaction kept, the end before the start, the end
// alone, and the end with another value of a field the transaction
// groups by. nil when no such run comes through.
func (r *Rule) sequences(c sigmacheck.Case) []sigmacheck.Case {
	i := r.txnIndex()
	if i < 0 || r.PostSpan <= 0 {
		return nil
	}
	t := r.post[i].(*query.Transaction)
	before := r.post[:i]
	start, ok := r.toward(c, t.StartsWith, before)
	if !ok {
		return nil
	}
	end, ok := r.toward(start, t.EndsWith, before)
	if !ok || r.passes(end, t.StartsWith, before) {
		return nil
	}
	later := max(int(min(r.PostSpan/2, time.Minute)/time.Second), 1)
	run := func(first, next sigmacheck.Case, after int) sigmacheck.Case {
		next.Source, next.Expect, next.Later, next.Then = "synthesized", false, after, nil
		first.Source, first.Later = "synthesized", 0
		first.Then = []sigmacheck.Case{next}
		first.Expect = r.readsAll(first)
		return first
	}
	pos := run(start, end, later)
	if !pos.Expect {
		return nil
	}
	out := []sigmacheck.Case{pos, run(start, end, int(r.PostSpan/time.Second)+60), run(end, start, later)}
	alone := end
	alone.Source, alone.Then, alone.Later = "synthesized", nil, 0
	alone.Expect = r.readsAll(alone)
	out = append(out, alone)
	for _, k := range slices.Sorted(maps.Keys(end.Data)) {
		other := end
		other.Data = maps.Clone(end.Data)
		other.Data[k] = otherValueN(end.Data[k], 1)
		if !r.passes(other, t.EndsWith, before) || !reads(r, other) {
			continue
		}
		if o := run(start, other, later); !o.Expect {
			out = append(out, o)
			break
		}
	}
	return out
}

// readsAll reports whether Splunk's search finds a case with the events
// that follow it: each matches the where clause, and the later stages
// keep a row.
func (r *Rule) readsAll(c sigmacheck.Case) bool {
	docs, model := StoredAll(c)
	if !InModel(r.Node, model) {
		return false
	}
	for _, d := range docs {
		if !Eval(r.Where, View(d)) {
			return false
		}
	}
	return r.KeepsAll(docs)
}

// passes reports whether an event, after the later stages before a
// transaction, passes one of the transaction's tests (startswith=).
func (r *Rule) passes(c sigmacheck.Case, e query.Expr, before []query.Command) bool {
	doc, _ := Stored(c)
	cmds := append(slices.Clone(before), &query.Where{Expr: e, Search: true})
	rows, err := search.RunCommands(context.Background(), []map[string]any{doc}, cmds)
	return err == nil && len(rows) == 1
}

// toward is an event changed to pass one of a transaction's tests, by
// setting each field its terms compare (field="value") that the event
// does not pass yet; the where clause must still match it.
func (r *Rule) toward(c sigmacheck.Case, e query.Expr, before []query.Command) (sigmacheck.Case, bool) {
	if r.passes(c, e, before) {
		return c, true
	}
	c.Data = maps.Clone(c.Data)
	for _, k := range andKids(e) {
		x, ok := k.(*query.Compare)
		if !ok || x.Op != "=" || strings.ContainsAny(x.Value, "*?") || r.passes(c, x, before) {
			continue
		}
		c.Data[x.Field] = x.Value
	}
	return c, reads(r, c) && r.passes(c, e, before)
}
