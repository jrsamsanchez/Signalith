package splcheck

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
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
var nodeFieldRe = regexp.MustCompile(`\b(?:Processes|Filesystem|Registry|Web|All_Traffic|DNS|Network_Resolution|Network_Traffic)\.(\w+)`)

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
			s = "where " + quoteDotted(m[1])
			if err := splunkWhere(m[1]); err != nil {
				return err
			}
		} else if m := postEvalRe.FindStringSubmatch(s); m != nil {
			s = "eval " + quoteDotted(m[1])
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
		case *query.Lookup, *query.Join, *query.Append, *query.AppendPipe, *query.InputLookup, *query.Transaction:
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

// quoteField is a field as an eval names it.
func quoteField(f string) string {
	if plainFieldRe.MatchString(f) {
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
	if len(r.post) == 0 {
		return true
	}
	rows, err := search.RunCommands(context.Background(), []map[string]any{doc}, r.post)
	return err == nil && len(rows) > 0
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
