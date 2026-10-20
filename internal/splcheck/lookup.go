// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// A rule's later stages may look values up in one of security_content's
// tables (lookups/<name>.csv, described by lookups/<name>.yml): lookup
// browser_process_and_path browser_process_path as process_path OUTPUT
// is_valid_browser_path. The pack ships the tables its rules read, and
// the lookup runs as written in Signalith's search language against the
// pack's copy of the table, named LookupTable(name) so that it is never
// an admin's own table of the same name. Splunk's reading of the table
// is kept:
//
//   - match_type WILDCARD(col) columns hold patterns and
//     case_sensitive_match: false ignores case, as the table's options;
//   - default_match fills the output fields of a row no table row
//     matches (an eval after the lookup);
//   - max_matches: 1 keeps the first matching row's values, in the
//     table's order (an mvindex after the lookup), when Signalith finds
//     the matching rows in that order too;
//   - an output several table rows can give different values for one key
//     is multivalue in both, and a later stage may only test whether it
//     is there, list its values, group by each of them (an mvexpand
//     before the stats, which Splunk's stats does by itself), or compare
//     it with a value no row holds; an output the matching rows all give
//     the same value is that one value.
//
// A rule whose lookup Signalith cannot read the same way does not
// convert, and the generator's report says why.

// LookupPack is the content pack whose tables the rules read.
const LookupPack = "splunk"

// LookupTable is the name the pack's copy of a security_content table
// has in Signalith.
func LookupTable(name string) string { return LookupPack + "-" + name }

// splunkMaxMatches is Splunk's max_matches when a table names none, and
// maxLookupMatches the most rows Signalith's lookup takes values from.
const (
	splunkMaxMatches = 1000
	maxLookupMatches = 100
)

// Lookup is one of security_content's tables, as Signalith keeps it.
type Lookup struct {
	// Name is the table's name in security_content, as rules name it.
	Name string
	// Table is Signalith's copy, named LookupTable(Name).
	Table *lookuptables.Table
	// MaxMatches is max_matches (Splunk's default when the table names
	// none), and Default default_match when min_matches asks for it
	// (HasDefault).
	MaxMatches int
	Default    string
	HasDefault bool
	// padded are the columns with a cell that has spaces around it, which
	// Splunk keeps and Signalith does not.
	padded map[string]bool

	mu     sync.Mutex
	shapes map[string]*lookupShape
}

// lookupMeta is a security_content lookup's yml. Only the settings below
// are read; a table with any other is not supported.
type lookupMeta struct {
	Name          string   `yaml:"name"`
	LookupType    string   `yaml:"lookup_type"`
	MatchType     []string `yaml:"match_type"`
	CaseSensitive *bool    `yaml:"case_sensitive_match"`
	MinMatches    *int     `yaml:"min_matches"`
	MaxMatches    *int     `yaml:"max_matches"`
	DefaultMatch  *string  `yaml:"default_match"`
}

// lookupKeys are the yml settings ParseLookup reads, and the ones that
// only describe the table.
var lookupKeys = []string{
	"name", "lookup_type", "match_type", "case_sensitive_match", "min_matches", "max_matches", "default_match",
	"id", "version", "creation_date", "modification_date", "date", "author", "description",
}

var wildcardRe = regexp.MustCompile(`^WILDCARD\(\s*([^()\s]+)\s*\)$`)

// ParseLookup reads a security_content table: its CSV and its yml.
func ParseLookup(meta, data []byte) (*Lookup, error) {
	var keys map[string]any
	if err := yaml.Unmarshal(meta, &keys); err != nil {
		return nil, err
	}
	for k := range keys {
		if !slices.Contains(lookupKeys, k) {
			return nil, fmt.Errorf("lookup setting %s is not supported", k)
		}
	}
	var m lookupMeta
	if err := yaml.Unmarshal(meta, &m); err != nil {
		return nil, err
	}
	if m.Name == "" {
		return nil, errors.New("the lookup has no name")
	}
	if m.LookupType != "csv" {
		return nil, fmt.Errorf("lookup %s is a %s lookup, not a CSV table", m.Name, m.LookupType)
	}
	var opts lookuptables.Options
	for _, mt := range m.MatchType {
		w := wildcardRe.FindStringSubmatch(strings.TrimSpace(mt))
		if w == nil {
			return nil, fmt.Errorf("lookup %s: match_type %s is not supported", m.Name, mt)
		}
		opts.Wildcard = append(opts.Wildcard, w[1])
	}
	opts.IgnoreCase = m.CaseSensitive != nil && !*m.CaseSensitive
	t, err := lookuptables.NewPackTable(LookupPack, LookupTable(m.Name), data, opts)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", m.Name, err)
	}
	l := &Lookup{Name: m.Name, Table: t, MaxMatches: splunkMaxMatches, padded: map[string]bool{}, shapes: map[string]*lookupShape{}}
	if m.MaxMatches != nil {
		if *m.MaxMatches < 1 {
			return nil, fmt.Errorf("lookup %s: max_matches %d is not supported", m.Name, *m.MaxMatches)
		}
		l.MaxMatches = *m.MaxMatches
	}
	minMatches := 0
	if m.MinMatches != nil {
		minMatches = *m.MinMatches
	}
	switch {
	case minMatches > 1:
		return nil, fmt.Errorf("lookup %s: min_matches %d is not supported", m.Name, minMatches)
	case minMatches == 1 && m.DefaultMatch != nil && *m.DefaultMatch != "":
		// Splunk's default default_match is empty, which leaves the
		// output fields out, as no match does.
		l.Default, l.HasDefault = *m.DefaultMatch, true
		if strings.ContainsAny(l.Default, "\"\\\n") {
			return nil, fmt.Errorf("lookup %s: default_match %q is not supported", m.Name, l.Default)
		}
	}
	// The cells as Splunk reads them, spaces and all.
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\ufeff"))))
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", m.Name, err)
	}
	for _, rec := range recs[1:] {
		for i, v := range rec {
			if i < len(t.Columns) && v != strings.TrimSpace(v) {
				l.padded[t.Columns[i]] = true
			}
		}
	}
	return l, nil
}

// lookupShape is what any one set of key values can match in a table,
// for its key columns.
type lookupShape struct {
	// bound is the most rows one set of values can match.
	bound int
	// differ are the columns two rows that match the same values can
	// hold different values in, and same those they can hold the same
	// value in (so that the value comes twice).
	differ, same map[string]bool
	// tableOrder is whether Signalith's lookup takes the matching rows
	// in the table's order, as Splunk does: it takes rows without
	// patterns first.
	tableOrder bool
	// empty are the columns with an empty cell in a row that can match.
	empty map[string]bool
	// err says why Signalith does not look values up in the table on
	// these keys.
	err error
}

// shape is what a lookup on keys can match.
func (l *Lookup) shape(keys []string) *lookupShape {
	k := strings.Join(keys, "\x00")
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.shapes[k]; ok {
		return s
	}
	s := l.computeShape(keys)
	l.shapes[k] = s
	return s
}

// keyCell is one key cell of a row: its text, folded when the table
// ignores case, and whether it is a pattern.
type keyCell struct {
	text    string
	pattern bool
}

// maxPatternRows is the most rows with patterns a table's lookup may
// have: each event tries them one by one, and checking which of them can
// match the same value compares them two by two.
const maxPatternRows = 2000

func (l *Lookup) computeShape(keys []string) *lookupShape {
	t := l.Table
	s := &lookupShape{differ: map[string]bool{}, same: map[string]bool{}, empty: map[string]bool{}, tableOrder: true}
	cols := make([]int, len(keys))
	for i, k := range keys {
		cols[i] = t.Column(k)
	}
	type row struct {
		i     int
		cells []keyCell
		exact bool
	}
	var rows []row
	patterns := 0
next:
	for i, r := range t.Rows {
		var cells []keyCell
		exact := true
		for _, c := range cols {
			v := r[c]
			if v == "" {
				continue next
			}
			if t.IgnoreCase {
				v = strings.ToLower(v)
			}
			p := slices.Contains(t.Wildcard, t.Columns[c]) && strings.Contains(v, "*")
			exact = exact && !p
			cells = append(cells, keyCell{v, p})
		}
		if !exact {
			patterns++
		}
		rows = append(rows, row{i, cells, exact})
		for j, v := range r {
			if v == "" {
				s.empty[t.Columns[j]] = true
			}
		}
	}
	if patterns > maxPatternRows {
		s.err = fmt.Errorf("has %d rows with patterns in %s, which each event tries one by one (Signalith takes up to %d)", patterns, strings.Join(keys, ", "), maxPatternRows)
		return s
	}
	meet := func(a, b []keyCell) bool {
		for i := range a {
			if !cellsMeet(a[i], b[i]) {
				return false
			}
		}
		return true
	}
	// Two rows meet when some value matches both: rows without patterns
	// only when their keys are the same, so they are grouped by key, and
	// a row with a pattern is compared with every other row.
	adj := map[int]map[int]bool{}
	link := func(i, j int) {
		if i > j {
			i, j = j, i
		}
		if adj[i] == nil {
			adj[i] = map[int]bool{}
		}
		if adj[j] == nil {
			adj[j] = map[int]bool{}
		}
		if adj[i][j] {
			return
		}
		adj[i][j], adj[j][i] = true, true
		a, b := rows[i], rows[j]
		if !a.exact && b.exact {
			// A pattern row before a row without one that it matches:
			// Splunk takes the pattern row first, Signalith the other.
			s.tableOrder = false
		}
		ra, rb := t.Rows[a.i], t.Rows[b.i]
		for c, col := range t.Columns {
			if ra[c] != rb[c] {
				s.differ[col] = true
			} else if ra[c] != "" {
				s.same[col] = true
			}
		}
	}
	byKey := map[string][]int{}
	var pattern []int
	for i, r := range rows {
		if !r.exact {
			pattern = append(pattern, i)
			continue
		}
		var k []string
		for _, c := range r.cells {
			k = append(k, c.text)
		}
		key := strings.Join(k, "\x00")
		for _, j := range byKey[key] {
			link(j, i)
		}
		byKey[key] = append(byKey[key], i)
	}
	for _, i := range pattern {
		for j := range rows {
			if j != i && (rows[j].exact || j > i) && meet(rows[i].cells, rows[j].cells) {
				link(i, j)
			}
		}
	}
	// The rows one value matches all meet each other, two by two: at
	// most a largest such group (clique). A row that meets no other is a
	// group of one.
	s.bound = min(len(rows), 1)
	if len(adj) > 0 {
		nodes := slices.Sorted(maps.Keys(adj))
		at := make(map[int]int, len(nodes))
		for k, n := range nodes {
			at[n] = k
		}
		m := make([][]bool, len(nodes))
		for k, n := range nodes {
			m[k] = make([]bool, len(nodes))
			for o := range adj[n] {
				m[k][at[o]] = true
			}
		}
		s.bound = max(s.bound, maxClique(m))
	}
	return s
}

// maxCliqueSteps caps the search for a largest clique; past it, the
// bound is the most rows any one row meets, and itself.
const maxCliqueSteps = 1_000_000

// maxClique is the size of a largest group of rows that all meet each
// other (Bron and Kerbosch's search, with a pivot), or an upper bound on
// it when the search takes too long.
func maxClique(adj [][]bool) int {
	n := len(adj)
	if n == 0 {
		return 0
	}
	degree := 0
	for _, row := range adj {
		d := 0
		for _, m := range row {
			if m {
				d++
			}
		}
		degree = max(degree, d)
	}
	best, steps := 0, 0
	var search func(size int, p, x []int) bool
	search = func(size int, p, x []int) bool {
		if steps++; steps > maxCliqueSteps {
			return false
		}
		if len(p) == 0 && len(x) == 0 {
			best = max(best, size)
			return true
		}
		if size+len(p) <= best {
			return true
		}
		pivot, most := -1, -1
		for _, u := range append(slices.Clone(p), x...) {
			c := 0
			for _, v := range p {
				if adj[u][v] {
					c++
				}
			}
			if c > most {
				pivot, most = u, c
			}
		}
		for _, v := range slices.Clone(p) {
			if pivot >= 0 && adj[pivot][v] {
				continue
			}
			var np, nx []int
			for _, w := range p {
				if adj[v][w] {
					np = append(np, w)
				}
			}
			for _, w := range x {
				if adj[v][w] {
					nx = append(nx, w)
				}
			}
			if !search(size+1, np, nx) {
				return false
			}
			p = slices.DeleteFunc(p, func(w int) bool { return w == v })
			x = append(x, v)
		}
		return true
	}
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	if !search(0, all, nil) {
		return degree + 1
	}
	return best
}

// cellsMeet reports whether some value matches both key cells.
func cellsMeet(a, b keyCell) bool {
	switch {
	case !a.pattern && !b.pattern:
		return a.text == b.text
	case a.pattern && !b.pattern:
		return lookuptables.Glob(a.text, b.text)
	case !a.pattern && b.pattern:
		return lookuptables.Glob(b.text, a.text)
	}
	return globsMeet(a.text, b.text)
}

// globsMeet reports whether some text matches both patterns, in which *
// is any run of characters: a search of the pairs of places in the two.
func globsMeet(p, q string) bool {
	type at struct{ i, j int }
	seen := map[at]bool{}
	stack := []at{{0, 0}}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[s] {
			continue
		}
		seen[s] = true
		i, j := s.i, s.j
		if i == len(p) && j == len(q) {
			return true
		}
		pStar, qStar := i < len(p) && p[i] == '*', j < len(q) && q[j] == '*'
		if pStar {
			stack = append(stack, at{i + 1, j})
		}
		if qStar {
			stack = append(stack, at{i, j + 1})
		}
		if i < len(p) && j < len(q) {
			switch {
			case !pStar && !qStar && p[i] == q[j]:
				stack = append(stack, at{i + 1, j + 1})
			case pStar && !qStar:
				stack = append(stack, at{i, j + 1})
			case qStar && !pStar:
				stack = append(stack, at{i + 1, j})
			}
		}
	}
	return false
}

// lookupMarker is the field a converted lookup with a default_match sets
// on the rows a table row matches, and removes after.
const lookupMarker = "splunk_lookup_matched"

// lookupOut is a lookup's output field: whether it may hold several
// values (multi), the same value twice (twice), more values than
// Signalith's lookup keeps (capped, the most rows one value matches), or
// values with spaces around them that Signalith takes off (padded).
type lookupOut struct {
	lookup       *Lookup
	column       string
	multi, twice bool
	capped       int
	padded       bool
}

// lookupStage converts a lookup stage: the lookup, on the pack's copy of
// the table, and the stages that keep Splunk's reading of it. earlier are
// the stages before it, as converted, grouped whether one of them keeps
// only the fields it names (stats, table), and single reports whether a
// field holds one value on every row.
func (r *Rule) lookupStage(stage, earlier string, grouped bool, field func(string) (string, bool), single func(string) bool, outs map[string]*lookupOut) (stages, names []string, err error) {
	q, err := query.Parse("* | " + stage)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %s", laterStage, positionRe.ReplaceAllString(err.Error(), ""))
	}
	c, ok := q.Commands[0].(*query.Lookup)
	if !ok || len(q.Commands) != 1 {
		return nil, nil, fmt.Errorf("%s: %s", laterStage, firstWords(stage))
	}
	l := r.lookups[c.Table]
	if l == nil {
		if err := r.lookupErrs[c.Table]; err != nil {
			return nil, nil, fmt.Errorf("%s: lookup %s: %v", laterStage, c.Table, err)
		}
		return nil, nil, fmt.Errorf("%s: lookup %s, a table security_content does not ship", laterStage, c.Table)
	}
	t := l.Table
	reads := func(why string, a ...any) error {
		return fmt.Errorf("search has a later stage Signalith reads differently: lookup %s %s", l.Name, fmt.Sprintf(why, a...))
	}
	var keys, keyFields []string
	for _, k := range c.Keys {
		if t.Column(k.Column) < 0 {
			return nil, nil, fmt.Errorf("%s: lookup %s has no column %s", laterStage, l.Name, k.Column)
		}
		if l.padded[k.Column] {
			return nil, nil, reads("has values with spaces around them in %s, which Splunk matches with the spaces and Signalith without", k.Column)
		}
		keys = append(keys, k.Column)
		keyFields = append(keyFields, k.Field())
	}
	outputs := slices.Clone(c.Outputs)
	if len(outputs) == 0 {
		// Every other column, as Splunk's lookup without OUTPUT.
		for _, col := range t.Columns {
			if !slices.Contains(keys, col) {
				outputs = append(outputs, query.LookupField{Column: col})
			}
		}
	}
	sh := l.shape(keys)
	if sh.err != nil {
		return nil, nil, reads("%v", sh.err)
	}
	keyed := true
	for _, f := range keyFields {
		keyed = keyed && single(f)
	}
	var fields []string
	for _, o := range outputs {
		if t.Column(o.Column) < 0 {
			return nil, nil, fmt.Errorf("%s: lookup %s has no column %s", laterStage, l.Name, o.Column)
		}
		f := o.Field()
		if slices.Contains(keyFields, f) || slices.Contains(fields, f) {
			return nil, nil, reads("writes %s, which it also reads", f)
		}
		// Splunk's OUTPUT clears a field no table row gives a value;
		// Signalith's leaves it. The fields must be new.
		if _, ok := field(f); ok && !grouped {
			return nil, nil, reads("writes %s, which the events may already have", f)
		}
		for _, m := range fieldTokenRe.FindAllStringSubmatch(earlier, -1) {
			if m[1]+m[2] == f {
				return nil, nil, reads("writes %s, which an earlier stage sets", f)
			}
		}
		fields = append(fields, f)
	}
	stages = nil
	conv := *c
	conv.Table = t.Name
	conv.Outputs = outputs
	if l.HasDefault {
		if c.New {
			return nil, nil, reads("fills fields that are missing (OUTPUTNEW) and has a default_match")
		}
		conv.Outputs = append(slices.Clone(outputs), query.LookupField{Column: keys[0], As: lookupMarker})
	}
	stages = append(stages, query.CommandString(&conv))
	var evals []string
	for _, o := range outputs {
		f, col := o.Field(), o.Column
		out := &lookupOut{lookup: l, column: col}
		switch {
		case !keyed:
			// Several key values match several rows.
			out.multi, out.twice = true, true
		case l.MaxMatches == 1 && sh.differ[col]:
			// The first matching row's value, as Splunk keeps it.
			if !sh.tableOrder {
				return nil, nil, reads("keeps the first matching row (max_matches: 1), and Signalith takes the rows in another order")
			}
			if sh.empty[col] {
				return nil, nil, reads("keeps the first matching row (max_matches: 1), and %s is empty in some rows", col)
			}
			evals = append(evals, quoteField(f)+"=mvindex("+quoteField(f, true)+", 0)")
		case sh.differ[col]:
			out.multi, out.twice = true, sh.same[col]
			if sh.bound > min(maxLookupMatches, l.MaxMatches) {
				// Only a later stage that reads the values can tell.
				out.capped = sh.bound
			}
		case sh.same[col]:
			// Several rows give the same value: Splunk's and Signalith's
			// lookups give it once for each, which compares as the one
			// value.
			evals = append(evals, quoteField(f)+"=mvdedup("+quoteField(f, true)+")")
			out.twice = true
		}
		out.padded = l.padded[col]
		outs[f] = out
	}
	if len(evals) > 0 {
		stages = append(stages, "eval "+strings.Join(evals, ", "))
	}
	if l.HasDefault {
		// default_match: the output fields of a row with its key fields
		// that no table row matches.
		cond := "isnull(" + lookupMarker + ")"
		for _, f := range keyFields {
			cond += " AND isnotnull(" + quoteField(f, true) + ")"
		}
		var fill []string
		for _, f := range fields {
			fill = append(fill, quoteField(f)+"=if("+cond+", \""+l.Default+"\", "+quoteField(f, true)+")")
		}
		stages = append(stages, "eval "+strings.Join(fill, ", "), "fields - "+lookupMarker)
	}
	if !slices.Contains(r.Lookups, l.Name) {
		r.Lookups = append(r.Lookups, l.Name)
	}
	if len(keyFields) == 1 {
		// Test events with the table's values (hints).
		r.lookupHints = append(r.lookupHints, lookupHint{field: keyFields[0], lookup: l, column: keys[0]})
	}
	return stages, append(keyFields, fields...), nil
}

// lookupHint is a lookup's key field and the table column it matches,
// whose values make test events (hints).
type lookupHint struct {
	field  string
	lookup *Lookup
	column string
}

// maxLookupHints is how many of a table's values a lookup's hints try.
const maxLookupHints = 6

// values are the table values the hint tries: the first rows', which
// the later stages read like the rest.
func (h lookupHint) values() []string {
	t := h.lookup.Table
	c := t.Column(h.column)
	var out []string
	for _, r := range t.Rows {
		if v := r[c]; v != "" && !slices.Contains(out, v) {
			out = append(out, v)
			if len(out) == maxLookupHints {
				break
			}
		}
	}
	return out
}

// multiUse returns an error for a later stage that reads a lookup output
// that may hold several values in a way Splunk and Signalith read
// differently; for a stats that groups by one, it returns the mvexpand
// stages to put before it, as Splunk's stats groups by each value. A
// stats ends the outputs' tracking: what it keeps is one value or a list
// of values in both.
func multiUse(stage string, outs map[string]*lookupOut) (before []string, err error) {
	var multi []string
	for f, o := range outs {
		if o.multi || o.padded {
			multi = append(multi, f)
		}
	}
	if len(multi) == 0 {
		return nil, nil
	}
	slices.Sort(multi)
	named := false
	for _, m := range fieldTokenRe.FindAllStringSubmatch(stage, -1) {
		named = named || slices.Contains(multi, m[1]+m[2])
	}
	q, perr := query.Parse("* | " + stage)
	clear := func() {
		for f := range outs {
			delete(outs, f)
		}
	}
	if perr != nil || len(q.Commands) != 1 {
		if named {
			return nil, multiErr(stage, outs, multi)
		}
		return nil, nil
	}
	reads := func(f string) error { return multiErr(stage, outs, []string{f}) }
	// A read Splunk and Signalith agree on for several values, but not
	// for more than Signalith keeps or for values with spaces around them.
	allowed := func(f string, spaced bool) error {
		if o := outs[f]; o.padded && !spaced || o.capped > 0 {
			return reads(f)
		}
		return nil
	}
	switch c := q.Commands[0].(type) {
	case *query.Stats:
		for _, a := range c.Aggs {
			if slices.Contains(multi, a.Field) {
				if a.Func != "values" {
					return nil, reads(a.Field)
				}
				if err := allowed(a.Field, true); err != nil {
					return nil, err
				}
			}
		}
		for _, f := range c.By {
			if slices.Contains(multi, f) {
				if err := allowed(f, false); err != nil || outs[f].twice {
					return nil, reads(f)
				}
				before = append(before, "mvexpand "+query.FormatValue(f))
			}
		}
		clear()
		return before, nil
	case *query.Where:
		if x, ok := c.Expr.(*query.Cond); ok {
			var bad error
			walkMulti(x.X, multi, false, func(f string) { bad = firstErr(bad, reads(f)) })
			return nil, bad
		}
		var bad error
		walkFilter(c.Expr, func(e query.Expr) {
			var f string
			var vals []string
			switch x := e.(type) {
			case *query.Compare:
				f, vals = x.Field, []string{x.Value}
			case *query.In:
				f, vals = x.Field, x.Values
			default:
				return
			}
			if !slices.Contains(multi, f) {
				return
			}
			// A value no row holds: no value matches it in either.
			bad = firstErr(bad, allowed(f, true))
			for _, v := range vals {
				if strings.Contains(v, "*") || outs[f].lookup.holds(outs[f].column, v) {
					bad = firstErr(bad, reads(f))
				}
			}
		})
		return nil, bad
	case *query.Eval:
		var bad error
		for _, a := range c.Assigns {
			walkMulti(a.Expr, multi, false, func(f string) { bad = firstErr(bad, reads(f)) })
			if slices.Contains(multi, a.Field) {
				delete(outs, a.Field)
			}
		}
		return nil, bad
	case *query.Table, *query.FieldsRemove:
		return nil, nil
	}
	if named {
		return nil, multiErr(stage, outs, multi)
	}
	return nil, nil
}

func firstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

func multiErr(stage string, outs map[string]*lookupOut, fields []string) error {
	f := fields[0]
	o := outs[f]
	why := "can give several values"
	switch {
	case o.padded:
		why = "gives with spaces around it, which Splunk keeps and Signalith does not"
	case o.capped > 0:
		why = fmt.Sprintf("can give from %d rows, more than Signalith's lookup takes (%d)", o.capped, maxLookupMatches)
	}
	return fmt.Errorf("search has a later stage Signalith reads differently: %s reads %s, which lookup %s %s", firstWords(stage), f, o.lookup.Name, why)
}

// holds reports whether a column holds v, whatever the case.
func (l *Lookup) holds(col, v string) bool {
	c := l.Table.Column(col)
	for _, r := range l.Table.Rows {
		if strings.EqualFold(r[c], v) {
			return true
		}
	}
	return false
}

// walkMulti calls bad for each multivalue field an expression reads,
// other than to test whether it is there.
func walkMulti(e query.EvalExpr, multi []string, tested bool, bad func(string)) {
	switch x := e.(type) {
	case *query.Field:
		if !tested && slices.Contains(multi, x.Name) {
			bad(x.Name)
		}
	case *query.Call:
		null := (x.Func == "isnull" || x.Func == "isnotnull") && len(x.Args) == 1
		for _, a := range x.Args {
			walkMulti(a, multi, null, bad)
		}
	case *query.Unary:
		walkMulti(x.X, multi, false, bad)
	case *query.Binary:
		walkMulti(x.L, multi, false, bad)
		walkMulti(x.R, multi, false, bad)
	}
}

// walkFilter calls fn for each part of a filter expression.
func walkFilter(e query.Expr, fn func(query.Expr)) {
	fn(e)
	switch x := e.(type) {
	case *query.And:
		for _, k := range x.Children {
			walkFilter(k, fn)
		}
	case *query.Or:
		for _, k := range x.Children {
			walkFilter(k, fn)
		}
	case *query.Not:
		walkFilter(x.Child, fn)
	}
}

// fieldSingle reports whether a field holds one value on every row the
// stages before a lookup make: a field a stats groups by or counts, one
// an eval makes with a function of one value, or a rex extracts, and
// on a raw search an event's own field.
func fieldSingle(f string, stages []string, raw bool) bool {
	for i := len(stages) - 1; i >= 0; i-- {
		q, err := query.Parse("* | " + stages[i])
		if err != nil {
			return false
		}
		for j := len(q.Commands) - 1; j >= 0; j-- {
			switch c := q.Commands[j].(type) {
			case *query.Stats:
				if slices.Contains(c.By, f) {
					return true
				}
				for _, a := range c.Aggs {
					if a.Column() == f {
						return a.Func != "values" && a.Func != "list"
					}
				}
				return false
			case *query.EventStats:
				for _, a := range c.Aggs {
					if a.Column() == f {
						return false
					}
				}
			case *query.Eval:
				for k := len(c.Assigns) - 1; k >= 0; k-- {
					if a := c.Assigns[k]; a.Field == f {
						return singleExpr(a.Expr, stages[:i], raw)
					}
				}
			case *query.Rename:
				for _, p := range c.Pairs {
					if p[1] == f {
						return fieldSingle(p[0], stages[:i], raw)
					}
				}
			case *query.Rex:
				if c.MaxMatch == 1 && (strings.Contains(c.Pattern, "<"+f+">")) {
					return true
				}
			case *query.Lookup:
				for _, o := range c.Outputs {
					if o.Field() == f {
						return false
					}
				}
			case *query.MakeMV, *query.MVExpand, *query.Fillnull, *query.Where, *query.Table, *query.FieldsRemove, *query.Dedup, *query.Sort, *query.Head, *query.IPLocation:
				// An iplocation's field is one value where it locates the
				// address, and the row's own where it does not.
				if mv, ok := c.(*query.MakeMV); ok && mv.Field == f {
					return false
				}
				if mv, ok := c.(*query.MVExpand); ok && mv.Field == f {
					return true
				}
			default:
				return false
			}
		}
	}
	return raw
}

// singleExpr reports whether an eval expression is one value.
func singleExpr(e query.EvalExpr, stages []string, raw bool) bool {
	switch x := e.(type) {
	case *query.Str, *query.Num:
		return true
	case *query.Field:
		return fieldSingle(x.Name, stages, raw)
	case *query.Call:
		switch x.Func {
		case "mvjoin", "len", "mvcount":
			return true
		case "mvindex":
			return len(x.Args) == 2
		case "lower", "upper", "trim", "ltrim", "rtrim", "replace", "substr", "tostring":
			return len(x.Args) > 0 && singleExpr(x.Args[0], stages, raw)
		}
	case *query.Binary:
		return x.Op == "." || x.Op == "+" && singleExpr(x.L, stages, raw) && singleExpr(x.R, stages, raw)
	}
	return false
}

// runPost runs the rule's later stages over events, with its lookups
// against the pack's tables.
func (r *Rule) runPost(docs []map[string]any) ([]search.Row, error) {
	return r.runPostWith(docs, nil)
}

// runPostWith is runPost with the events a join's subsearch reads (nil
// for none).
func (r *Rule) runPostWith(docs []map[string]any, jc *joinInput) ([]search.Row, error) {
	ctx := context.Background()
	cmds := r.post
	var rows []search.Row
	joins := 0
	for len(cmds) > 0 {
		i := slices.IndexFunc(cmds, func(c query.Command) bool {
			switch c.(type) {
			case *query.Lookup, *query.IPLocation, *query.Join:
				return true
			}
			return false
		})
		if i < 0 {
			i = len(cmds)
		}
		var err error
		if i > 0 {
			rows, err = search.RunCommands(ctx, docs, cmds[:i])
		} else if j, ok := cmds[0].(*query.Join); ok {
			rows, err = r.runJoin(ctx, docs, j, joins, jc)
			joins++
			i = 1
		} else {
			rows, err = r.runLookup(ctx, docs, cmds[0])
			i = 1
		}
		if err != nil {
			return nil, err
		}
		cmds = cmds[i:]
		docs = make([]map[string]any, len(rows))
		for j, row := range rows {
			docs[j] = row
		}
	}
	return rows, nil
}

// runLookup runs a lookup, or an iplocation against the test GeoIP
// database (TestGeoIP), over rows, as a search does.
func (r *Rule) runLookup(ctx context.Context, docs []map[string]any, c query.Command) ([]search.Row, error) {
	eng := &search.Engine{Store: rowsSearcher(docs), Lookups: r.lookupStore}
	if _, ok := c.(*query.IPLocation); ok {
		eng.GeoIP = TestGeoIP()
	}
	q := &query.Query{Commands: []query.Command{c, &query.Head{N: len(docs) + 1}}}
	res, err := eng.Execute(search.Background(ctx), q)
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// rowsSearcher answers every search with its rows, in order.
type rowsSearcher []map[string]any

func (s rowsSearcher) Search(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
	hits := make([]any, len(s))
	for i, d := range s {
		hits[i] = map[string]any{"_source": d}
	}
	return map[string]any{"hits": map[string]any{"total": map[string]any{"value": len(s)}, "hits": hits}}, nil
}
