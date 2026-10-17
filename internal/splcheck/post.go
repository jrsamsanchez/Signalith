package splcheck

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// A search's later stages that do more than filter events (eval, rex,
// stats, eventstats, dedup...) run as written, in Signalith's search
// language, after the converted filter: the rule's Post. Before them,
// each field they name by Splunk's name is copied from the field
// Signalith stores it as, and a tstats search's own grouping comes first
// (the data model's missing fields are "unknown", as in the CIM). A test
// event is one the rule finds when the filter matches it and the later
// stages keep a row for it (Keeps).

// postMacros are the macros a later stage may name that change nothing
// Signalith shows: time formats, the data model's field prefixes, and
// the rule's own (empty) filter.
var postMacros = regexp.MustCompile("`(security_content_ctime\\([^`]*\\)|drop_dm_object_name\\([^`]*\\)|[\\w-]+_filter)`")

// nodeFieldRe is a tstats field with its node's prefix (Processes.dest).
var nodeFieldRe = regexp.MustCompile(`\b(?:Processes|Filesystem|Registry|Web|All_Traffic|DNS|Network_Resolution|Network_Traffic|Authentication|All_Changes)\.(\w+)`)

// fieldTokenRe is a field a stage may name: a quoted field ('Actor{}.ID')
// or a bare word; double-quoted strings are skipped.
var fieldTokenRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'([^']+)'|([A-Za-z_][\w.{}]*)`)

// postCommands checks and stores a search's later stages as the rule's
// Post: stages are the search's stages from the first one Signalith does
// not read as a filter, field the Signalith field of each field they may
// name (false for none), and group the tstats grouping that comes first
// ("" for a raw search).
func (r *Rule) postCommands(stages []string, field func(string) (string, bool), group string) error {
	var parts []string
	// scan are the stages as they name fields, for the copies below: a
	// lookup's fields without its table and columns.
	var scan []string
	multi := map[string]bool{}
	lists := map[string]bool{}
	outs := map[string]*lookupOut{}
	grouped := group != ""
	located := false
	var groupStages []string
	if group != "" {
		groupStages = strings.Split(nodeFieldRe.ReplaceAllString(group, "$1"), "\n| ")
	}
	for i, s := range stages {
		s = strings.TrimSpace(postMacros.ReplaceAllString(s, ""))
		if s == "" {
			continue
		}
		if strings.Contains(s, "`") {
			return fmt.Errorf("search has a later stage Signalith does not run: %s", firstWords(s))
		}
		if conv, ok, err := iplocationStage(s); err != nil {
			return err
		} else if ok && !readsLocation(stages[i+1:]) {
			// iplocation only adds columns, which no later stage reads.
			continue
		} else if ok {
			located = true
			parts = append(parts, conv...)
			scan = append(scan, s)
			continue
		}
		if located {
			if err := iplocationLater(s); err != nil {
				return err
			}
		}
		if lookupStageRe.MatchString(s) {
			s = nodeFieldRe.ReplaceAllString(s, "$1")
			before := append(slices.Clone(groupStages), parts...)
			single := func(f string) bool { return fieldSingle(f, before, group == "") }
			conv, names, err := r.lookupStage(s, strings.Join(before, "\n| "), grouped, field, single, outs)
			if err != nil {
				return err
			}
			parts = append(parts, conv...)
			scan = append(scan, "table "+strings.Join(names, " "))
			continue
		}
		if w, ok := multiIn(s, multi); ok {
			s = w
		} else if err := multiFilter(s, multi); err != nil {
			return err
		}
		// A later search filters the rows as Signalith's search command
		// does: case-insensitive, with wildcards, terms side by side
		// joined by AND, and OR before AND, as in Splunk's search.
		if m := searchRe.FindStringSubmatch(s); m != nil {
			if err := laterSearch(m[1]); err != nil {
				return err
			}
			s = "search " + m[1]
			if w, ok, err := listSearch(m[1]); err != nil {
				return err
			} else if ok {
				s = w
			}
		} else if m := whereRe.FindStringSubmatch(s); m != nil {
			cond := inStarCompared(quoteCompared(quoteDotted(m[1])))
			s = "where " + cond
			if err := splunkWhere(cond); err != nil {
				return err
			}
		} else if m := postEvalRe.FindStringSubmatch(s); m != nil {
			s = "eval " + quoteDotted(m[1])
		}
		// A raw search's stats keeps no row for an event without a field
		// it groups by. Splunk's add-ons give every event the fields they
		// define; a field Signalith keeps none of is "unknown" instead, as
		// a tstats search's missing fields are.
		expand, err := multiUse(nodeFieldRe.ReplaceAllString(s, "$1"), outs)
		if err != nil {
			return err
		}
		if err := listGroups(s, lists); err != nil {
			return err
		}
		parts = append(parts, expand...)
		if group == "" {
			if fill := missingGroups(s, parts, field); len(fill) > 0 {
				parts = append(parts, "fillnull value=unknown "+strings.Join(fill, " "))
			}
		}
		parts = append(parts, s)
		scan = append(scan, s)
		grouped = grouped || strings.HasPrefix(s, "stats ") || strings.HasPrefix(s, "table ")
	}
	if len(parts) == 0 {
		return nil
	}
	text := strings.Join(parts, "\n| ")
	named := strings.Join(scan, "\n| ")
	if group != "" {
		text = group + "\n| " + nodeFieldRe.ReplaceAllString(text, "$1")
		named = group + "\n| " + nodeFieldRe.ReplaceAllString(named, "$1")
	}
	// The fields the stages name, copied to Splunk's names.
	var copies []string
	seen := map[string]bool{}
	for _, m := range fieldTokenRe.FindAllStringSubmatch(named, -1) {
		name := m[1] + m[2]
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if f, ok := field(name); ok && f != name {
			copies = append(copies, quoteField(name)+"="+quoteField(f))
		}
	}
	slices.Sort(copies)
	if len(copies) > 0 {
		text = "eval " + strings.Join(copies, ", ") + "\n| " + text
	}
	q, err := query.Parse("* | " + text)
	if err != nil {
		return fmt.Errorf("search has a later stage Signalith does not run: %s", positionRe.ReplaceAllString(err.Error(), ""))
	}
	for _, c := range q.Commands {
		switch c.(type) {
		case *query.Join, *query.Append, *query.Union, *query.MultiSearch, *query.Set, *query.AppendPipe, *query.InputLookup, *query.EventCount, *query.OutputLookup, *query.Transaction, *query.Map, *query.AddInfo:
			return fmt.Errorf("search has a later stage Signalith does not run: %s", c.Name())
		}
	}
	r.Post = text
	r.post = q.Commands
	r.postField = field
	if len(r.Lookups) > 0 {
		var ts []*lookuptables.Table
		for _, name := range r.Lookups {
			ts = append(ts, r.lookups[name].Table)
		}
		r.lookupStore = lookuptables.NewPackStore(ts)
	}
	return nil
}

// makemvRe is a makemv stage, with the field it splits; splitEvalRe an
// eval that sets a field to a split of text.
var (
	makemvRe    = regexp.MustCompile(`(?is)^makemv\b.*?\s([A-Za-z_][\w.]*)\s*$`)
	splitEvalRe = regexp.MustCompile(`(?i)(?:^eval\s+|,\s*)([A-Za-z_][\w.]*)\s*=\s*split\s*\(`)
)

// multiFilter returns an error for a later search or where that filters
// on a field an earlier stage made multivalue (makemv, split), noting
// the fields stage makes so in multi. Splunk keeps the row when any of
// the values matches; Signalith's filter does not.
func multiFilter(stage string, multi map[string]bool) error {
	if m := makemvRe.FindStringSubmatch(stage); m != nil {
		multi[m[1]] = true
		return nil
	}
	for _, m := range splitEvalRe.FindAllStringSubmatch(stage, -1) {
		multi[m[1]] = true
	}
	cond := ""
	if m := searchRe.FindStringSubmatch(stage); m != nil {
		cond = m[1]
	} else if m := whereRe.FindStringSubmatch(stage); m != nil {
		cond = m[1]
	}
	for _, m := range fieldTokenRe.FindAllStringSubmatch(cond, -1) {
		if f := m[1] + m[2]; multi[f] {
			return fmt.Errorf("search has a later stage Signalith reads differently: %s filters the values of multivalue %s", firstWords(stage), f)
		}
	}
	return nil
}

// multiInRe is a later search of one field against a list, and inItemRe
// one of its values: quoted text or a bare word.
var (
	multiInRe = regexp.MustCompile(`(?is)^search\s+([A-Za-z_][\w.]*)\s+IN\s*\(([^()]*)\)\s*$`)
	inItemRe  = regexp.MustCompile(`^(?:"([^"*\\]*)"|([A-Za-z_][\w.\-]*))$`)
)

// multiIn writes a later search of a field an earlier stage made
// multivalue against a list of values as the where Signalith reads the
// same way: Splunk's search keeps the row when one of the field's values
// is one of the list's, ignoring case, and drops it when the field has no
// value; in() over the field's values in lower case does both. Only text
// without a * qualifies (no number, which a search may read as one).
func multiIn(stage string, multi map[string]bool) (string, bool) {
	m := multiInRe.FindStringSubmatch(stage)
	if m == nil || !multi[m[1]] {
		return "", false
	}
	var vals []string
	for _, v := range strings.Split(m[2], ",") {
		p := inItemRe.FindStringSubmatch(strings.TrimSpace(v))
		if p == nil {
			return "", false
		}
		t := p[1] + p[2]
		if t == "" || strings.EqualFold(t, "AND") || strings.EqualFold(t, "OR") || strings.EqualFold(t, "NOT") {
			return "", false
		}
		if _, err := strconv.ParseFloat(t, 64); err == nil {
			return "", false
		}
		vals = append(vals, `"`+strings.ToLower(t)+`"`)
	}
	f := quoteField(m[1])
	return "where in(mvmap(" + f + ", lower(" + f + ")), " + strings.Join(vals, ", ") + ")", true
}

// listGroups returns an error for a stats that groups by a field that
// holds the values spath takes from a JSON list ({}.EntitlementId, or a
// rename or copy of one), noting in lists the fields stage makes so.
// Splunk's stats groups an event by each of a field's values, and Splunk
// does not say how it counts one that holds the same value twice;
// Signalith's groups by the values as one.
func listGroups(stage string, lists map[string]bool) error {
	q, err := query.Parse("* | " + stage)
	if err != nil || len(q.Commands) != 1 {
		return nil // reported when the stages are parsed
	}
	isList := func(f string) bool { return strings.HasPrefix(f, "{}") || lists[f] }
	var by []string
	switch c := q.Commands[0].(type) {
	case *query.Rename:
		for _, p := range c.Pairs {
			if !strings.Contains(p[0], "*") {
				lists[p[1]] = isList(p[0])
			}
		}
	case *query.Eval:
		for _, a := range c.Assigns {
			f, copied := a.Expr.(*query.Field)
			lists[a.Field] = copied && isList(f.Name)
		}
	case *query.Stats:
		by = c.By
	case *query.EventStats:
		by = c.By
	}
	for _, f := range by {
		if isList(f) {
			return fmt.Errorf("search has a later stage Signalith reads differently: %s groups by %s, which holds a list's values", firstWords(stage), f)
		}
	}
	return nil
}

// adjacentQuotedRe is a quoted string right after another, with no space
// between ("a""b"="c").
var adjacentQuotedRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*""`)

// listSearch writes a later search that names a field of a list (one
// with {} in its name, as spath and a record's lists make, which may
// hold several values) as the where Signalith reads the same way.
// Splunk's search keeps the row when one of the field's values matches,
// ignoring case, and drops it when the field has no value; Signalith's
// search compares the values as one, so each field=value of such a field
// is in() over its values in lower case, and the terms keep their AND
// and OR. A list's field compared other than with = to text without a *
// (a number, which a search may read as one), or under NOT, is refused.
// ok is false for a search that names no list's field.
func listSearch(terms string) (where string, ok bool, err error) {
	if !strings.Contains(terms, "{}") {
		return "", false, nil
	}
	q, perr := query.Parse("* | search " + terms)
	if perr != nil || len(q.Commands) != 1 {
		return "", false, nil // reported when the stages are parsed
	}
	w, isWhere := q.Commands[0].(*query.Where)
	if !isWhere {
		return "", false, nil
	}
	list := false
	walkFilter(w.Expr, func(e query.Expr) {
		switch x := e.(type) {
		case *query.Compare:
			list = list || strings.Contains(x.Field, "{}")
		case *query.In:
			list = list || strings.Contains(x.Field, "{}")
		}
	})
	if !list {
		return "", false, nil
	}
	if adjacentQuotedRe.MatchString(terms) {
		return "", false, fmt.Errorf("search has a later stage Signalith reads differently: search %s has two terms with no space between them", firstWords(terms))
	}
	refuse := func(why string) error {
		return fmt.Errorf("search has a later stage Signalith reads differently: search %s %s", firstWords(terms), why)
	}
	text := func(v string) (string, error) {
		if v == "" || strings.ContainsAny(v, `*"\`) {
			return "", refuse("compares a list's field with " + v)
		}
		if _, err := strconv.ParseFloat(v, 64); err == nil {
			return "", refuse("compares a list's field with the number " + v)
		}
		return `"` + strings.ToLower(v) + `"`, nil
	}
	var write func(e query.Expr) (string, error)
	join := func(kids []query.Expr, op string) (string, error) {
		var parts []string
		for _, k := range kids {
			s, err := write(k)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "(" + strings.Join(parts, " "+op+" ") + ")", nil
	}
	write = func(e query.Expr) (string, error) {
		switch x := e.(type) {
		case *query.And:
			return join(x.Children, "AND")
		case *query.Or:
			// Tests of one field joined by OR are one test of it against
			// all their values (f=a OR f=b is f IN (a, b)).
			var kids []query.Expr
			byField := map[string]*query.In{}
			for _, k := range x.Children {
				var in *query.In
				switch c := k.(type) {
				case *query.Compare:
					if c.Op == "=" {
						in = &query.In{Field: c.Field, Values: []string{c.Value}}
					}
				case *query.In:
					in = &query.In{Field: c.Field, Values: slices.Clone(c.Values)}
				}
				if in == nil {
					kids = append(kids, k)
				} else if had := byField[in.Field]; had != nil {
					had.Values = append(had.Values, in.Values...)
				} else {
					byField[in.Field] = in
					kids = append(kids, in)
				}
			}
			if len(kids) == 1 {
				return write(kids[0])
			}
			return join(kids, "OR")
		case *query.Compare:
			if x.Op != "=" {
				return "", refuse("compares " + x.Field + " with " + x.Op)
			}
			v, err := text(x.Value)
			if err != nil {
				return "", err
			}
			f := quoteField(x.Field, true)
			return "in(mvmap(" + f + ", lower(" + f + ")), " + v + ")", nil
		case *query.In:
			var vals []string
			for _, s := range x.Values {
				v, err := text(s)
				if err != nil {
					return "", err
				}
				vals = append(vals, v)
			}
			f := quoteField(x.Field, true)
			return "in(mvmap(" + f + ", lower(" + f + ")), " + strings.Join(vals, ", ") + ")", nil
		case *query.Not:
			return "", refuse("tests a list's field under NOT")
		}
		return "", refuse(fmt.Sprintf("has the term %s", e))
	}
	s, err := write(w.Expr)
	if err != nil {
		return "", false, err
	}
	return "where " + s, true, nil
}

// laterSearch returns an error for a later search's terms that Signalith
// reads differently: a bare term (Splunk looks for it in the event's raw
// text, which a row of a later stage need not have).
func laterSearch(terms string) error {
	q, err := query.Parse("* | search " + terms)
	if err != nil || len(q.Commands) != 1 || strings.HasPrefix(strings.TrimSpace(terms), "[") {
		return nil // reported when the stages are parsed (a subsearch's too)
	}
	var bad error
	w, ok := q.Commands[0].(*query.Where)
	if !ok {
		return nil // search *, which keeps every row
	}
	walkFilter(w.Expr, func(e query.Expr) {
		if t, ok := e.(*query.Text); ok && bad == nil {
			bad = fmt.Errorf("search has a later stage Signalith reads differently: search %s has the bare term %s", firstWords(terms), t.Value)
		}
	})
	return bad
}

// positionRe is where a query error says it is, which only the query's
// author can place.
var positionRe = regexp.MustCompile(`^at position \d+: `)

// plainFieldRe is a field an eval names without quotes.
var plainFieldRe = regexp.MustCompile(`^[A-Za-z_]\w*$`)

// quoteField is a field as an eval names it, quoted when always is set
// (as a where must, to read it as a field).
func quoteField(f string, always ...bool) string {
	if plainFieldRe.MatchString(f) && len(always) == 0 {
		return f
	}
	return "'" + f + "'"
}

// tstatsGroup is the stats stage that groups events as a tstats search
// does: aggs and by are its own (with their node prefixes), and the
// missing by fields are "unknown".
func tstatsGroup(aggs, by string) (string, error) {
	aggs = strings.TrimSpace(nodeFieldRe.ReplaceAllString(aggs, "$1"))
	by = strings.TrimSpace(nodeFieldRe.ReplaceAllString(by, "$1"))
	if strings.Contains(by, "span") || strings.Contains(aggs, "`") {
		return "", fmt.Errorf("a tstats search grouped by time is not supported")
	}
	fields := strings.Fields(strings.ReplaceAll(by, ",", " "))
	if len(fields) == 0 {
		return "", fmt.Errorf("a tstats search with no by fields is not supported")
	}
	var fill []string
	for _, f := range fields {
		if f != "_time" {
			fill = append(fill, f)
		}
	}
	return "fillnull value=unknown " + strings.Join(fill, " ") + "\n| stats " + aggs + " by " + strings.Join(fields, " "), nil
}

// Keeps reports whether the rule's later stages keep a row for an event
// as Signalith stores it (true when the rule has none).
func (r *Rule) Keeps(doc map[string]any) bool {
	return r.KeepsAll([]map[string]any{doc})
}

// KeepsAll reports whether the rule's later stages keep a row for events
// that all happen (a repeated case's).
func (r *Rule) KeepsAll(docs []map[string]any) bool {
	if len(r.post) == 0 {
		return true
	}
	rows, err := r.runPost(docs)
	return err == nil && len(rows) > 0
}

// Bursts: a rule whose later stages count events (stats count, dc,
// eventstats) keeps no row for one event, but may for the same event
// repeated; one that groups by a field keeps none for an event without
// it. maxBursts is how many of a rule's events are tried, and burstSizes
// the repeats tried, smallest first (1: the event once, with the fields
// it groups by).
const maxBursts = 2

var burstSizes = []int{1, 2, 3, 4, 6, 11, 21, 26, 31, 51, 101, 201}

// bursts returns, for an event the rule's filter matches but its later
// stages drop, the smallest repeat of it that they keep (with one or
// none of its fields different each time, or failing that every field
// they count distinct values of), and the largest smaller one tried,
// which they drop; nil when no repeat comes through.
func (r *Rule) bursts(c sigmacheck.Case) []sigmacheck.Case {
	// Splunk's stats drops events that miss a field it groups by, so the
	// event gets each one it misses (the record's own names, as a cloud
	// rule's are), unless that loses the filter's match.
	by, counted := r.postFields()
	if r.IPLocation() {
		// Fields iplocation adds come from the address, not the event.
		made := func(f string) bool { return slices.Contains(iplocationFields, f) }
		by, counted = slices.DeleteFunc(by, made), slices.DeleteFunc(counted, made)
	}
	filled := c
	filled.Data = maps.Clone(c.Data)
	for _, f := range by {
		if _, ok := filled.Data[f]; !ok && !strings.HasPrefix(f, "_") {
			filled.Data[f] = "test-" + strings.ToLower(f)
		}
	}
	if doc, _ := Stored(filled); Eval(r.Where, View(doc)) {
		c = filled
	}
	varies := [][]string{nil}
	for _, k := range slices.Sorted(maps.Keys(c.Data)) {
		varies = append(varies, []string{k})
	}
	for _, k := range counted {
		if _, ok := c.Data[k]; !ok {
			varies = append(varies, []string{k})
		}
	}
	if out := r.burst(c, varies); out != nil {
		return out
	}
	if len(counted) > 1 {
		// A count of several fields' distinct values (addresses and
		// browsers): all of them different each time.
		return r.burst(c, [][]string{counted})
	}
	return nil
}

// burst is bursts with the fields each repeat varies.
func (r *Rule) burst(c sigmacheck.Case, varies [][]string) []sigmacheck.Case {
	for i, n := range burstSizes {
		for _, vary := range varies {
			if n == 1 && vary != nil {
				break
			}
			b := c
			if n > 1 {
				b.Repeat, b.Vary = n, vary
			}
			docs, model := StoredCopies(b)
			if !InModel(r.Node, model) {
				continue
			}
			if !slices.ContainsFunc(docs, func(d map[string]any) bool { return !Eval(r.Where, View(d)) }) && r.KeepsAll(docs) {
				b.Expect = true
				out := []sigmacheck.Case{b}
				if i > 0 {
					less := b
					less.Repeat = burstSizes[i-1]
					docs, _ := StoredCopies(less)
					less.Expect = r.KeepsAll(docs)
					if !less.Expect {
						out = append(out, less)
					}
				}
				return out
			}
		}
	}
	return nil
}

// PostGroups are the fields the rows of a rule's later stages are groups
// of: the by fields of their last stats, by the names later renames give
// them (none when they end in events).
func (r *Rule) PostGroups() []string {
	var by []string
	for _, c := range r.post {
		switch c := c.(type) {
		case *query.Stats:
			by = slices.Clone(c.By)
		case *query.Rename:
			for _, p := range c.Pairs {
				if i := slices.Index(by, p[0]); i >= 0 {
					by[i] = p[1]
				}
			}
		}
	}
	return by
}

// Splunk's where reads its condition as an expression: a bare word is a
// field and text compares exactly. Signalith's reads a plain condition
// (x=value, x IN (a, b)) as a filter, where a bare word is a value and
// text matches ignoring case, with * as a wildcard. The two agree on
// numbers, and on quoted text without a *.
var (
	whereCmpRe = regexp.MustCompile(`(?:[^!<>=]=|!=|<=|>=|<|>)\s*([A-Za-z_][\w.]*|"[^"]*")`)
	whereInRe  = regexp.MustCompile(`(?i)\bIN\s*\(([^)]*)\)`)
	whereItem  = regexp.MustCompile(`^(?:-?[0-9.]+|"[^"*]*")$`)
)

// splunkWhere returns an error when Signalith reads a where condition of
// a Splunk search differently than Splunk does.
func splunkWhere(cond string) error {
	q, err := query.Parse("* | where " + cond)
	if err != nil {
		return nil // reported when the stages are parsed
	}
	if _, expr := q.Commands[0].(*query.Where).Expr.(*query.Cond); expr {
		return nil
	}
	var values []string
	for _, m := range whereCmpRe.FindAllStringSubmatch(" "+cond, -1) {
		values = append(values, m[1])
	}
	for _, m := range whereInRe.FindAllStringSubmatch(cond, -1) {
		for _, v := range strings.Split(m[1], ",") {
			v = strings.TrimSpace(v)
			if plainFieldRe.MatchString(v) {
				// Splunk reads a bare word in the list as a field, which
				// can hold several values or none; its documentation does
				// not say what IN does with those.
				return fmt.Errorf("search has a later stage Signalith reads differently: where IN with a field in its list (%s)", v)
			}
			values = append(values, v)
		}
	}
	for _, v := range values {
		if v != "" && !whereItem.MatchString(v) {
			return fmt.Errorf("search has a later stage Signalith reads differently: where %s compares with %s", firstWords(cond), v)
		}
	}
	return nil
}

// notBeforeRe is a NOT just before a term.
var notBeforeRe = regexp.MustCompile(`(?i)\bNOT\s*$`)

// missingGroups are the fields a stats stage groups by that neither
// Signalith keeps (field) nor an earlier stage makes.
func missingGroups(stage string, earlier []string, field func(string) (string, bool)) []string {
	if !strings.HasPrefix(stage, "stats ") {
		return nil
	}
	q, err := query.Parse("* | " + stage)
	if err != nil {
		return nil
	}
	st, ok := q.Commands[0].(*query.Stats)
	if !ok {
		return nil
	}
	made := strings.Join(earlier, "\n")
	var out []string
	for _, f := range st.By {
		if _, kept := field(f); kept || strings.HasPrefix(f, "_") || strings.Contains(made, f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// fieldCmpRe is a comparison of a field with a bare word, which Splunk's
// where reads as another field (process_name != parent_process_name).
var fieldCmpRe = regexp.MustCompile(`('[^']+'|\b[A-Za-z_]\w*|\))(\s*(?:!=|==|<=|>=|=|<|>)\s*)([A-Za-z_]\w*)(\s*\(?)`)

// whereWords are the bare words of a where condition that are not fields.
var whereWords = []string{"and", "or", "not", "in", "like", "true", "false", "null"}

// quotedRe is a double-quoted string.
var quotedRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// quoteCompared quotes both fields of each comparison of two fields in a
// where condition, which Signalith then reads as an expression, as Splunk
// does: the two fields' values compared exactly. Quoted text is left as
// it is.
func quoteCompared(cond string) string {
	var b strings.Builder
	last := 0
	for _, loc := range quotedRe.FindAllStringIndex(cond, -1) {
		b.WriteString(quoteComparedText(cond[last:loc[0]]))
		b.WriteString(cond[loc[0]:loc[1]])
		last = loc[1]
	}
	b.WriteString(quoteComparedText(cond[last:]))
	return b.String()
}

// starCmpRe is a field compared with = to quoted text that holds a *.
var starCmpRe = regexp.MustCompile(`(^|[\s(])([A-Za-z_][\w.{}]*|'[^']+')\s*==?\s*("[^"\\]*\*[^"\\]*")`)

// inStarCompared writes each comparison of a field with = to quoted text
// holding a * as in(field, text), which Signalith reads as Splunk's where
// reads the comparison: the text compared exactly, * and all, and false
// for a field with no value. (A plain filter would read the * as a
// wildcard.) Under NOT, which may differ on a null field, it is left as
// it is, and refused.
func inStarCompared(cond string) string {
	var b strings.Builder
	last := 0
	for _, m := range starCmpRe.FindAllStringSubmatchIndex(cond, -1) {
		name := cond[m[4]:m[5]]
		if strings.Count(cond[:m[0]], `"`)%2 == 1 || slices.Contains(whereWords, strings.ToLower(name)) ||
			notBeforeRe.MatchString(cond[:m[4]]) {
			continue
		}
		b.WriteString(cond[last:m[4]])
		b.WriteString("in(" + quoteField(strings.Trim(name, "'"), true) + ", " + cond[m[6]:m[7]] + ")")
		last = m[1]
	}
	b.WriteString(cond[last:])
	return b.String()
}

func quoteComparedText(cond string) string {
	return fieldCmpRe.ReplaceAllStringFunc(cond, func(m string) string {
		p := fieldCmpRe.FindStringSubmatch(m)
		left, op, right, after := p[1], p[2], p[3], p[4]
		if strings.HasSuffix(after, "(") || slices.Contains(whereWords, strings.ToLower(right)) ||
			slices.Contains(whereWords, strings.ToLower(left)) {
			return m
		}
		if left != ")" {
			left = quoteField(strings.Trim(left, "'"), true)
		}
		return left + op + quoteField(right, true) + after
	})
}

// lookupStageRe is a lookup stage.
var lookupStageRe = regexp.MustCompile(`(?i)^lookup\s`)

// postEvalRe is an eval stage.
var postEvalRe = regexp.MustCompile(`(?is)^eval\s+(.+)$`)

// dottedRe is a field with a dot in its name (userIdentity.userName), or
// a quoted string, which is left as it is.
var dottedRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'[^']*'|\b[A-Za-z_]\w*(?:\.[A-Za-z_][\w{}]*)+`)

// quoteDotted quotes the dotted field names of an expression: Splunk
// reads userIdentity.userName as the field, Signalith as two fields
// joined.
func quoteDotted(x string) string {
	return dottedRe.ReplaceAllStringFunc(x, func(m string) string {
		if m[0] == '"' || m[0] == '\'' {
			return m
		}
		return "'" + m + "'"
	})
}

// postFields are the fields the rule's later stages group by and the
// fields they count distinct values of (dc), by the names they use.
func (r *Rule) postFields() (by, counted []string) {
	add := func(aggs []query.Agg, groups []string) {
		for _, f := range groups {
			if !slices.Contains(by, f) {
				by = append(by, f)
			}
		}
		for _, a := range aggs {
			if a.Func == "dc" && a.Field != "" && !slices.Contains(counted, a.Field) {
				counted = append(counted, a.Field)
			}
		}
	}
	for _, c := range r.post {
		switch c := c.(type) {
		case *query.Stats:
			add(c.Aggs, c.By)
		case *query.EventStats:
			add(c.Aggs, c.By)
		}
	}
	return by, counted
}
