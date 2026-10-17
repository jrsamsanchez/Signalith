package splcheck

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
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
	for _, s := range stages {
		s = strings.TrimSpace(postMacros.ReplaceAllString(s, ""))
		if s == "" {
			continue
		}
		if strings.Contains(s, "`") {
			return fmt.Errorf("search has a later stage Signalith does not run: %s", firstWords(s))
		}
		// A later search filters the rows as a where of the same terms
		// does in Signalith: case-insensitive, with wildcards.
		if m := searchRe.FindStringSubmatch(s); m != nil {
			s = "where " + m[1]
		} else if m := whereRe.FindStringSubmatch(s); m != nil {
			cond := quoteCompared(quoteDotted(m[1]))
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
		if group == "" {
			if fill := missingGroups(s, parts, field); len(fill) > 0 {
				parts = append(parts, "fillnull value=unknown "+strings.Join(fill, " "))
			}
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return nil
	}
	text := strings.Join(parts, "\n| ")
	if group != "" {
		text = group + "\n| " + nodeFieldRe.ReplaceAllString(text, "$1")
	}
	// The fields the stages name, copied to Splunk's names.
	var copies []string
	seen := map[string]bool{}
	for _, m := range fieldTokenRe.FindAllStringSubmatch(text, -1) {
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
		case *query.Lookup, *query.Join, *query.Append, *query.AppendPipe, *query.InputLookup, *query.Transaction, *query.IPLocation, *query.Map, *query.AddInfo:
			return fmt.Errorf("search has a later stage Signalith does not run: %s", c.Name())
		}
	}
	r.Post = text
	r.post = q.Commands
	return nil
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
	rows, err := search.RunCommands(context.Background(), docs, r.post)
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
// none of its fields different each time), and the largest smaller one
// tried, which they drop; nil when no repeat comes through.
func (r *Rule) bursts(c sigmacheck.Case) []sigmacheck.Case {
	// Splunk's stats drops events that miss a field it groups by, so the
	// event gets each one it misses (the record's own names, as a cloud
	// rule's are), unless that loses the filter's match.
	by, counted := r.postFields()
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
			values = append(values, strings.TrimSpace(v))
		}
	}
	for _, v := range values {
		if v != "" && !whereItem.MatchString(v) {
			return fmt.Errorf("search has a later stage Signalith reads differently: where %s compares with %s", firstWords(cond), v)
		}
	}
	return nil
}

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
