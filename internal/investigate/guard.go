package investigate

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// The model reads log text that attackers can write, so what it asks for
// is checked here: its searches may only filter, count and list, and may
// touch a masked field only by naming one of its stand-ins, so a search
// can neither copy a masked value into a column with another name
// (eval, rename, values()) nor test guesses against it (wildcards,
// regular expressions, comparisons).

// guardQuery checks a search the model wrote, before its stand-ins are
// turned back into real values.
func guardQuery(q *query.Query, m *Masker) error {
	if err := guardExpr(q.Search, m); err != nil {
		return err
	}
	for _, c := range q.Commands {
		switch c := c.(type) {
		case *query.Stats:
			if err := guardAggs(c.Aggs, m); err != nil {
				return err
			}
		case *query.Timechart:
			if err := guardAggs(c.Aggs, m); err != nil {
				return err
			}
		case *query.Where:
			if err := guardExpr(c.Expr, m); err != nil {
				return err
			}
		case *query.Top, *query.Sort, *query.Head, *query.Tail, *query.Table, *query.Dedup,
			*query.Reverse, *query.FieldsRemove, *query.Enrich, *query.Intel:
			// These keep each value under its own column name, which is
			// what masking goes by.
		default:
			return fmt.Errorf("the %s command is not allowed in an AI investigation's searches; use search, where, stats, timechart, top, sort, head, table, dedup or fields", c.Name())
		}
	}
	return nil
}

// countOnly are the aggregations that give a number, never a value.
var countOnly = []string{"count", "dc", "distinct_count"}

func guardAggs(aggs []query.Agg, m *Masker) error {
	for _, a := range aggs {
		if a.Field != "" && m.Masks(a.Field) && !slices.Contains(countOnly, strings.ToLower(a.Func)) {
			return fmt.Errorf("%s(%s) would show values of a masked field; only count and dc work on it", a.Func, a.Field)
		}
	}
	return nil
}

// guardExpr lets a masked field be matched only against its stand-ins.
func guardExpr(e query.Expr, m *Masker) error {
	switch e := e.(type) {
	case nil:
		return nil
	case *query.And:
		for _, c := range e.Children {
			if err := guardExpr(c, m); err != nil {
				return err
			}
		}
	case *query.Or:
		for _, c := range e.Children {
			if err := guardExpr(c, m); err != nil {
				return err
			}
		}
	case *query.Not:
		return guardExpr(e.Child, m)
	case *query.Compare:
		if m.Masks(e.Field) && ((e.Op != "=" && e.Op != "!=") || !m.isToken(e.Value)) {
			return fmt.Errorf("%s is masked: match it only with = or != and one of its stand-ins, such as masked-%s-1", e.Field, kindOf(e.Field))
		}
	case *query.In:
		if m.Masks(e.Field) {
			for _, v := range e.Values {
				if !m.isToken(v) {
					return fmt.Errorf("%s is masked: match it only with its stand-ins", e.Field)
				}
			}
		}
	case *query.Text:
	case *query.Cond:
		// A value expression (like(), len(), substr(), comparisons of
		// two fields) could test guesses, so it may not touch one.
		if f := maskedIn(e.X, m); f != "" {
			return fmt.Errorf("%s is masked: a where expression cannot use it", f)
		}
	default:
		return fmt.Errorf("this kind of condition is not allowed in an AI investigation's searches: %s", e.String())
	}
	return nil
}

// maskedIn returns a masked field a value expression reads, or "".
func maskedIn(x query.EvalExpr, m *Masker) string {
	switch x := x.(type) {
	case *query.Field:
		if m.Masks(x.Name) {
			return x.Name
		}
	case *query.Call:
		for _, a := range x.Args {
			if f := maskedIn(a, m); f != "" {
				return f
			}
		}
	case *query.Unary:
		return maskedIn(x.X, m)
	case *query.Binary:
		if f := maskedIn(x.L, m); f != "" {
			return f
		}
		return maskedIn(x.R, m)
	case *query.Num, *query.Str:
	default:
		return "an unknown expression"
	}
	return ""
}

// isToken reports whether v is a stand-in this masker made.
func (m *Masker) isToken(v string) bool {
	_, ok := m.byToken[v]
	return ok
}

// kindOf is the middle part of a field's stand-ins.
func kindOf(field string) string {
	k := strings.Trim(nonWord.ReplaceAllString(strings.ToLower(field), "-"), "-")
	if k == "" {
		return "value"
	}
	return k
}

// newFence returns the random word that marks where untrusted data starts
// and ends in what is sent: data written before the investigation cannot
// know it, so it cannot close the block early.
func newFence() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// fenced wraps untrusted data in the run's markers, removing any copy of
// them from the data first.
func (r *run) fenced(data string) string {
	open, end := "<<<DATA "+r.fence, "END DATA "+r.fence+">>>"
	data = strings.ReplaceAll(strings.ReplaceAll(data, open, ""), end, "")
	return open + "\n" + strings.TrimRight(data, "\n") + "\n" + end + "\n"
}

// seen reports whether v is a value the investigation showed: a finding
// entity, a value in the row that fired or in a step's rows. Suggested
// actions may act only on these, so text planted in a log cannot point
// one at a user or host the evidence never mentions.
func (r *run) seen(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return false
	}
	var found bool
	var walk func(x any)
	walk = func(x any) {
		if found {
			return
		}
		switch x := x.(type) {
		case string:
			found = strings.EqualFold(strings.TrimSpace(r.mask.Reveal(x)), v)
		case []any:
			for _, e := range x {
				walk(e)
			}
		case []string:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case nil:
		default:
			found = strings.EqualFold(fmt.Sprint(x), v)
		}
	}
	for _, e := range r.f.Entities {
		walk(e)
	}
	walk(map[string]any(r.f.Result))
	for _, st := range r.steps {
		for _, row := range st.Rows {
			walk(row)
		}
	}
	return found
}
