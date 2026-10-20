// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package investigate

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/respond"
)

// The model reads log text that attackers can write, so what it asks for
// is checked here: its searches may only filter, count and list, and may
// touch a masked field (or the event text) only by naming one of its
// stand-ins, so a search can neither copy a masked value into a column
// with another name (eval, rename, values(), timechart columns) nor test
// guesses against it (wildcards, regular expressions, functions).
//
// The same value is often kept under other names too (user and
// TargetUserName, or the message text), so the values themselves are
// guarded on every field: a literal, wildcard pattern or free-text word
// that could match a masked value seen so far is refused, whatever field
// it names. A refusal still tells the model that something it wrote
// matches a masked value, so the rules that do not depend on the values
// (no regular expressions, at least three characters between wildcards,
// no ranges on text, no functions that take a value apart) keep each
// refusal to a guess of a whole value or of three characters of one,
// never a character at a time.

// guardQuery checks a search the model wrote, before its stand-ins are
// turned back into real values.
func guardQuery(q *query.Query, m *Masker) error {
	if err := guardExpr(q.Search, m, false); err != nil {
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
			// Its by values become column names, which masking does not
			// look at.
			if c.By != "" && guarded(c.By, m) {
				return fmt.Errorf("timechart by %s would show its values as column names; use stats count by %s", c.By, c.By)
			}
		case *query.Where:
			// After a command, a search's free text would match inside
			// any column, masked ones too.
			if err := guardExpr(c.Expr, m, true); err != nil {
				return err
			}
		case *query.Top, *query.Sort, *query.Head, *query.Tail, *query.Table, *query.Dedup,
			*query.Reverse, *query.FieldsRemove:
			// These keep each value under its own column name, which is
			// what masking goes by.
		default:
			return fmt.Errorf("the %s command is not allowed in an AI investigation's searches; use search, where, stats, timechart, top, sort, head, table, dedup or fields", c.Name())
		}
	}
	return nil
}

// guarded reports whether a field may be matched only against stand-ins:
// a masked field, or the event text, which holds every field's value.
func guarded(field string, m *Masker) bool {
	return m.Masks(field) || strings.EqualFold(field, "_raw")
}

// countOnly are the aggregations that give a number, never a value.
var countOnly = []string{"count", "dc", "distinct_count"}

func guardAggs(aggs []query.Agg, m *Masker) error {
	for _, a := range aggs {
		if a.Field != "" && guarded(a.Field, m) && !slices.Contains(countOnly, strings.ToLower(a.Func)) {
			return fmt.Errorf("%s(%s) would show values of a masked field; only count and dc work on it", a.Func, a.Field)
		}
	}
	return nil
}

// guardExpr lets a masked field be matched only against its stand-ins,
// free text only as whole words, and no field against anything that
// could match a masked value: a wildcard would let counts spell out a
// hidden value one character at a time.
func guardExpr(e query.Expr, m *Masker, piped bool) error {
	switch e := e.(type) {
	case nil:
		return nil
	case *query.And:
		for _, c := range e.Children {
			if err := guardExpr(c, m, piped); err != nil {
				return err
			}
		}
	case *query.Or:
		for _, c := range e.Children {
			if err := guardExpr(c, m, piped); err != nil {
				return err
			}
		}
	case *query.Not:
		return guardExpr(e.Child, m, piped)
	case *query.Compare:
		if guarded(e.Field, m) && ((e.Op != "=" && e.Op != "!=") || !m.isToken(e.Value)) {
			return fmt.Errorf("%s is masked: match it only with = or != and one of its stand-ins, such as masked-%s-1", e.Field, kindOf(e.Field))
		}
		return m.guardCompare(e)
	case *query.In:
		for _, v := range e.Values {
			if guarded(e.Field, m) && !m.isToken(v) {
				return fmt.Errorf("%s is masked: match it only with its stand-ins", e.Field)
			}
			if err := m.guardLiteral(e.Field+" IN ", v); err != nil {
				return err
			}
		}
	case *query.Text:
		if m.isToken(e.Value) {
			return nil
		}
		if piped {
			return fmt.Errorf("free text after a command is not allowed; name the field to match, such as src=10.0.0.1")
		}
		if strings.ContainsAny(e.Value, "*?") {
			return fmt.Errorf("free text with wildcards is not allowed; search for whole words, or name the field")
		}
		if len([]rune(strings.TrimSpace(e.Value))) < minTextMask {
			return fmt.Errorf("free text %q is too short; search for words of at least %d characters, or name the field", e.Value, minTextMask)
		}
		// Free text matches inside any field, so a word inside a masked
		// value, or one holding it, would confirm a guess.
		if m.overlaps(e.Value) {
			return errMaskedValue(e.Value)
		}
	case *query.Cond:
		// A value expression (like(), match(), len(), substr(),
		// comparisons of two fields) could test guesses, so it may not
		// touch one.
		if f := maskedIn(e.X, m); f != "" {
			return fmt.Errorf("%s is masked: a where expression cannot use it", f)
		}
		return m.guardEval(e.X)
	default:
		return fmt.Errorf("this kind of condition is not allowed in an AI investigation's searches: %s", e.String())
	}
	return nil
}

// errMaskedValue refuses a value that could match a masked one. It does
// not say which one, or of which field.
func errMaskedValue(v string) error {
	return fmt.Errorf("%q could match a masked value; match masked values only with their stand-ins, such as masked-user-1", v)
}

// guardCompare checks a comparison on any field against the masked values.
func (m *Masker) guardCompare(e *query.Compare) error {
	switch e.Op {
	case "=", "!=":
		return m.guardLiteral(e.Field+e.Op, e.Value)
	case "=~":
		return fmt.Errorf("regular expressions (=~) are not allowed in an AI investigation's searches; use = with a value, or with * for part of one")
	case "<", "<=", ">", ">=":
		return m.guardRange(e.Field, e.Value)
	}
	return fmt.Errorf("the operator %s is not allowed in an AI investigation's searches", e.Op)
}

// guardLiteral checks a value matched with =, != or IN: an exact value, a
// network or a wildcard pattern.
func (m *Masker) guardLiteral(what, v string) error {
	if m.isToken(v) {
		return nil
	}
	if strings.ContainsAny(v, "*?") {
		return m.guardPattern(what, v, "*", "?")
	}
	if p, err := netip.ParsePrefix(strings.TrimSpace(v)); err == nil && !p.IsSingleIP() && m.anyIP() {
		// A network matches every masked address inside it, so halving it
		// search by search would find one.
		return fmt.Errorf("%s%s: matching a network is not allowed while masked values include addresses; name single addresses", what, v)
	}
	if m.holds(v) {
		return errMaskedValue(v)
	}
	return nil
}

// guardPattern checks a wildcard pattern: many and one are its wildcards
// for any run of characters and for one. Each stretch of text between
// wildcards must be at least minTextMask characters long, whatever the
// masked values are, and none may lie inside a masked value or hold one.
func (m *Masker) guardPattern(what, v string, many, one string) error {
	chunks := strings.FieldsFunc(v, func(r rune) bool { return strings.ContainsRune(many+one, r) })
	if len(chunks) == 0 {
		return fmt.Errorf("%s%s: a pattern needs some text besides wildcards", what, v)
	}
	for _, c := range chunks {
		if len([]rune(c)) < minTextMask {
			return fmt.Errorf("%s%s: put at least %d characters between wildcards", what, v, minTextMask)
		}
	}
	if m.overlaps(chunks...) || m.globMatches(v, many, one) {
		return errMaskedValue(v)
	}
	return nil
}

// guardRange allows a range only on time, or on a number while no masked
// value is a number: halving a range search by search would find one.
func (m *Masker) guardRange(field, v string) error {
	if strings.EqualFold(field, "_time") {
		return nil
	}
	if _, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err != nil {
		return fmt.Errorf("%s: ranges (<, >) work only on numbers and _time in an AI investigation's searches", field)
	}
	if m.anyNumber() {
		return fmt.Errorf("%s: ranges are not allowed while masked values include numbers", field)
	}
	return nil
}

// safeCalls are the functions a where expression may use: none of them
// takes a value apart, so a value is only ever compared whole.
var safeCalls = []string{"len", "lower", "upper", "trim", "ltrim", "rtrim", "abs", "ceil", "ceiling", "floor", "round",
	"min", "max", "isnull", "isnotnull", "isnum", "isint", "isstr", "coalesce", "if", "case", "like", "in", "cidrmatch",
	"mvcount", "now", "relative_time", "null", "true", "false"}

// guardEval checks a where expression on fields that are not masked: only
// safeCalls, text compared whole (=, !=, in()) or by like() under the
// pattern rules, and no ranges on text.
func (m *Masker) guardEval(x query.EvalExpr) error {
	switch x := x.(type) {
	case nil, *query.Num, *query.Field:
		return nil
	case *query.Str:
		return m.guardLiteral("", x.Value)
	case *query.Unary:
		return m.guardEval(x.X)
	case *query.Binary:
		_, ls := x.L.(*query.Str)
		_, rs := x.R.(*query.Str)
		switch strings.ToUpper(x.Op) {
		case "LIKE":
			if s, ok := x.R.(*query.Str); ok {
				if err := m.guardPattern("like ", s.Value, "%", "_"); err != nil {
					return err
				}
				return m.guardEval(x.L)
			}
		case "<", "<=", ">", ">=":
			if ls || rs {
				return fmt.Errorf("comparing text with < or > is not allowed in an AI investigation's searches; use = or !=")
			}
			if m.anyNumber() {
				return fmt.Errorf("comparing with < or > is not allowed while masked values include numbers")
			}
		}
		if err := m.guardEval(x.L); err != nil {
			return err
		}
		return m.guardEval(x.R)
	case *query.Call:
		f := strings.ToLower(x.Func)
		if !slices.Contains(safeCalls, f) {
			return fmt.Errorf("%s() is not allowed in an AI investigation's where expressions; compare fields with = or !=, or use len(), like() or in()", x.Func)
		}
		for i, a := range x.Args {
			if s, ok := a.(*query.Str); ok && f == "like" && i == 1 {
				if err := m.guardPattern("like ", s.Value, "%", "_"); err != nil {
					return err
				}
				continue
			}
			if err := m.guardEval(a); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("this kind of expression is not allowed in an AI investigation's searches")
}

// holds reports whether a value is a masked value, or holds one long
// enough to be masked in text, ignoring case.
func (m *Masker) holds(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	for mv := range m.byValue {
		if l == mv || (len(mv) >= minTextMask && strings.Contains(l, mv)) {
			return true
		}
	}
	return false
}

// overlaps reports whether any of parts holds a masked value or lies
// inside one (as its start, its end or any other part), ignoring case.
func (m *Masker) overlaps(parts ...string) bool {
	for _, p := range parts {
		l := strings.ToLower(strings.TrimSpace(p))
		if l == "" {
			continue
		}
		if m.holds(l) {
			return true
		}
		for mv := range m.byValue {
			if strings.Contains(mv, l) {
				return true
			}
		}
	}
	return false
}

// globMatches reports whether a pattern matches a whole masked value,
// ignoring case.
func (m *Masker) globMatches(pattern, many, one string) bool {
	var b strings.Builder
	b.WriteString(`(?is)^`)
	for _, r := range pattern {
		switch {
		case strings.ContainsRune(many, r):
			b.WriteString(`.*`)
		case strings.ContainsRune(one, r):
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString(`$`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		return true
	}
	for mv := range m.byValue {
		if re.MatchString(mv) {
			return true
		}
	}
	return false
}

// anyIP reports whether a masked value is an IP address.
func (m *Masker) anyIP() bool {
	for mv := range m.byValue {
		if _, err := netip.ParseAddr(mv); err == nil {
			return true
		}
	}
	return false
}

// anyNumber reports whether a masked value is a number.
func (m *Masker) anyNumber() bool {
	for mv := range m.byValue {
		if _, err := strconv.ParseFloat(mv, 64); err == nil {
			return true
		}
	}
	return false
}

// maskedIn returns a guarded field a value expression reads, or "".
func maskedIn(x query.EvalExpr, m *Masker) string {
	switch x := x.(type) {
	case *query.Field:
		if guarded(x.Name, m) {
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

// revealQuery puts the real values back into a checked query, in its
// parsed form, so no value can change how the query reads.
func (m *Masker) revealQuery(q *query.Query) {
	var walk func(e query.Expr)
	walk = func(e query.Expr) {
		switch e := e.(type) {
		case *query.And:
			for _, c := range e.Children {
				walk(c)
			}
		case *query.Or:
			for _, c := range e.Children {
				walk(c)
			}
		case *query.Not:
			walk(e.Child)
		case *query.Compare:
			e.Value = m.real(e.Value)
		case *query.In:
			for i, v := range e.Values {
				e.Values[i] = m.real(v)
			}
		case *query.Text:
			e.Value = m.real(e.Value)
		}
	}
	walk(q.Search)
	for _, c := range q.Commands {
		if w, ok := c.(*query.Where); ok {
			walk(w.Expr)
		}
	}
}

// real returns the real value behind a stand-in, or v.
func (m *Masker) real(v string) string {
	if r, ok := m.byToken[v]; ok {
		return r
	}
	return v
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

// fenced masks untrusted data and wraps it in the run's markers, removing
// any copy of them from the data first. Masking comes first, so a stand-in
// can never rewrite a marker.
func (r *run) fenced(data string) string {
	data = r.mask.Text(data)
	open, end := "<<<DATA "+r.fence, "END DATA "+r.fence+">>>"
	data = strings.ReplaceAll(strings.ReplaceAll(data, open, ""), end, "")
	return open + "\n" + strings.TrimRight(data, "\n") + "\n" + end + "\n"
}

// suggestable reports whether the model may suggest an action: only
// containment (blocking, isolating, disabling) on one address, host or
// user, never undoing one or a workflow that takes any target.
func suggestable(a respond.Info) bool {
	return a.Problem == "" && a.Disruptive &&
		(a.Target == respond.TargetIP || a.Target == respond.TargetHost || a.Target == respond.TargetUser)
}

// entityFields are the fields whose values an action may act on, by the
// kind of target.
var entityFields = map[string][]string{
	respond.TargetIP:   {"src", "dest", "src_ip", "dest_ip", "dvc_ip", "ip", "dvc"},
	respond.TargetHost: {"host", "dest", "src", "dvc", "dest_host", "src_host", "dest_nt_host", "src_nt_host", "hostname", "computer"},
	respond.TargetUser: {"user", "src_user", "dest_user", "user_name", "account"},
}

// evidenceValue returns the value an action of this kind may act on that
// equals target: one of the finding's entities, or an entity field of the
// row that fired or of what Signalith gathered itself, never of a search
// the model asked for. It returns the evidence's own spelling. Names are
// compared ignoring ASCII case only, so look-alike letters do not match.
func (r *run) evidenceValue(kind, target string) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", false
	}
	fields := entityFields[kind]
	match := func(v any) (string, bool) {
		var vals []string
		switch x := v.(type) {
		case string:
			vals = []string{x}
		case []any:
			for _, e := range x {
				if s, ok := e.(string); ok {
					vals = append(vals, s)
				}
			}
		case []string:
			vals = x
		}
		for _, s := range vals {
			s = strings.TrimSpace(r.mask.Reveal(s))
			if asciiEqualFold(s, target) {
				return s, true
			}
			if kind == respond.TargetIP {
				a, err1 := netip.ParseAddr(s)
				b, err2 := netip.ParseAddr(target)
				if err1 == nil && err2 == nil && a == b {
					return s, true
				}
			}
		}
		return "", false
	}
	for k, v := range r.f.Entities {
		if k == "risk_object_type" {
			continue
		}
		if s, ok := match(v); ok {
			return s, true
		}
	}
	rows := []map[string]any{r.f.Result}
	for _, st := range r.steps {
		if st.By != "ai" {
			rows = append(rows, st.Rows...)
		}
	}
	for _, row := range rows {
		for _, f := range fields {
			if s, ok := match(row[f]); ok {
				return s, true
			}
		}
	}
	return "", false
}

// asciiEqualFold is strings.EqualFold for ASCII letters only.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
