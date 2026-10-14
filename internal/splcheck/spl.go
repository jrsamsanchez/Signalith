// Package splcheck reads Splunk security_content detections: the YAML
// rule, the tstats search over a CIM data model node, and the where clause
// that selects events, with the project's macros expanded. It evaluates
// that where clause on an event the way Splunk does, and makes test events
// from it, so the Splunk content pack can prove each converted rule finds
// what the original finds (see Verify).
package splcheck

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is one Splunk security_content detection.
type Rule struct {
	Name           string   `yaml:"name"`
	ID             string   `yaml:"id"`
	Author         string   `yaml:"author"`
	Status         string   `yaml:"status"`
	Type           string   `yaml:"type"` // TTP, Anomaly, Hunting or Correlation
	Description    string   `yaml:"description"`
	DataSource     []string `yaml:"data_source"`
	Search         string   `yaml:"search"`
	HowToImplement string   `yaml:"how_to_implement"`
	FalsePositives string   `yaml:"known_false_positives"`
	References     []string `yaml:"references"`
	Tags           struct {
		MitreAttackID  []string `yaml:"mitre_attack_id"`
		AnalyticStory  []string `yaml:"analytic_story"`
		SecurityDomain string   `yaml:"security_domain"`
	} `yaml:"tags"`
	AnalyticStory []string `yaml:"analytic_story"`
	// MitreAttackID is where newer rules list their techniques (older
	// ones use tags.mitre_attack_id).
	MitreAttackID []string `yaml:"mitre_attack_id"`
	Finding       struct {
		Title  string `yaml:"title"`
		Entity struct {
			Field string `yaml:"field"`
			Type  string `yaml:"type"`
			Score int    `yaml:"score"`
		} `yaml:"entity"`
	} `yaml:"finding"`
	RBA struct {
		Message     string `yaml:"message"`
		RiskObjects []struct {
			Field string `yaml:"field"`
			Type  string `yaml:"type"`
			Score int    `yaml:"score"`
		} `yaml:"risk_objects"`
	} `yaml:"rba"`

	// Node is the data model node the search reads: Processes,
	// Filesystem or Registry (from datamodel=Endpoint.<Node>).
	Node string `yaml:"-"`
	// Where selects the node's events.
	Where Expr `yaml:"-"`
}

// Score is the risk the rule assigns, 0 when it names none.
func (r *Rule) Score() int {
	if r.Finding.Entity.Score > 0 {
		return r.Finding.Entity.Score
	}
	best := 0
	for _, o := range r.RBA.RiskObjects {
		best = max(best, o.Score)
	}
	return best
}

// Macro is one of security_content's search macros.
type Macro struct {
	Name       string   `yaml:"name"`
	Definition string   `yaml:"definition"`
	Arguments  []string `yaml:"arguments"`
}

// ParseMacro reads a macro file.
func ParseMacro(src []byte) (*Macro, error) {
	var m Macro
	if err := yaml.Unmarshal(src, &m); err != nil {
		return nil, err
	}
	if m.Name == "" {
		return nil, errors.New("macro has no name")
	}
	return &m, nil
}

// Nodes are the data model nodes splcheck reads, with the fields a where
// clause may name on each (the CIM names, which are also Signalith's).
var Nodes = map[string][]string{
	"Processes": {
		"process", "process_name", "process_path", "original_file_name", "parent_process",
		"parent_process_name", "parent_process_path", "user", "process_integrity_level",
		"process_current_directory", "process_id", "parent_process_id",
	},
	"Filesystem": {"file_path", "file_name", "action", "process_name", "process_path", "user"},
	"Registry": {
		"registry_path", "registry_key_name", "registry_value_name", "registry_value_data", "action",
		"process_name", "process_path", "user",
	},
}

// The stages after the where clause that only reshape the results.
var (
	tstatsRe    = regexp.MustCompile(`(?is)^\|\s*tstats\s+.*?\bfrom\s+datamodel=Endpoint\.(\w+)\s+where\s+(.*?)\s+by\s+[^|]*$`)
	harmlessRe  = regexp.MustCompile("^`(drop_dm_object_name|security_content_ctime)\\([^`]*\\)`$")
	filterRe    = regexp.MustCompile("^`[\\w-]+_filter`$")
	summariesRe = regexp.MustCompile("`security_content_summariesonly`")
	commentRe   = regexp.MustCompile("(?s)```.*?```")
	// where isnotnull(field) after the tstats keeps the rows that have
	// the field, which is field=* in the where clause.
	notNullRe = regexp.MustCompile(`(?i)^where\s+isnotnull\((\w+)\)$`)
)

// Parse reads a detection and its search. Only a tstats search over
// Endpoint.Processes, Filesystem or Registry whose later stages just
// rename fields, format times and apply the rule's own (empty) filter
// macro is understood; anything else is an error that says what.
func Parse(src []byte, macros map[string]*Macro) (*Rule, error) {
	var r Rule
	if err := yaml.Unmarshal(src, &r); err != nil {
		return nil, err
	}
	if r.ID == "" || r.Name == "" || r.Search == "" {
		return nil, errors.New("not a detection: name, id and search are required")
	}
	// ```text``` is a comment in SPL.
	stages := pipes(strings.TrimSpace(commentRe.ReplaceAllString(r.Search, " ")))
	if len(stages) == 0 {
		return nil, errors.New("empty search")
	}
	if m := rawRe.FindStringSubmatch(stages[0]); m != nil {
		return parseRaw(&r, m[1], m[2], stages[1:], macros)
	}
	first := summariesRe.ReplaceAllString("| "+stages[0], "")
	m := tstatsRe.FindStringSubmatch(first)
	if m == nil {
		return nil, errors.New("search is not a tstats search of Endpoint.Processes, Filesystem or Registry")
	}
	r.Node = m[1]
	fields, ok := Nodes[r.Node]
	if !ok {
		return nil, fmt.Errorf("data model node Endpoint.%s is not supported", r.Node)
	}
	var present []Expr
	for _, s := range stages[1:] {
		if nn := notNullRe.FindStringSubmatch(s); nn != nil && slices.Contains(fields, nn[1]) {
			present = append(present, &Cmp{Field: nn[1], Values: []string{"*"}})
			continue
		}
		if !harmlessRe.MatchString(s) && !filterRe.MatchString(s) {
			return nil, fmt.Errorf("search has a later stage Signalith does not run: %s", firstWords(s))
		}
	}
	where, err := ParseWhere(m[2], r.Node, macros)
	if err != nil {
		return nil, err
	}
	if len(present) > 0 {
		where = &And{Kids: append([]Expr{where}, present...)}
	}
	r.Where = where
	return &r, nil
}

// Raw event searches: a source macro, then terms on the event's own
// fields. Each source is a node whose fields map to Signalith's.
var (
	rawRe     = regexp.MustCompile("(?s)^`(powershell)`\\s+(.*)$")
	rawNodes  = map[string]string{"powershell": "PowerShell"}
	rawEvents = map[string]string{"PowerShell": "4104"}
	// RawFields are the event fields a raw search may name on each node,
	// with the Signalith field each is stored as.
	RawFields = map[string]map[string]string{
		"PowerShell": {"ScriptBlockText": "script_block_text"},
	}
	fillnullRe = regexp.MustCompile(`(?i)^fillnull$`)
	statsRe    = regexp.MustCompile(`(?is)^stats\s`)
	renameRe   = regexp.MustCompile(`(?is)^rename\s`)
)

// parseRaw reads a raw event search of one source: its terms must name
// the source's event code (EventCode=4104) and otherwise only fields the
// node maps. Later, fillnull then stats only count the events (fillnull
// keeps stats from dropping events that miss a by field), and rename only
// renames the counts.
func parseRaw(r *Rule, source, terms string, later []string, macros map[string]*Macro) (*Rule, error) {
	r.Node = rawNodes[source]
	filled, counted := false, false
	for _, s := range later {
		switch {
		case harmlessRe.MatchString(s) || filterRe.MatchString(s):
		case fillnullRe.MatchString(s) && !counted:
			filled = true
		case statsRe.MatchString(s) && filled && !counted:
			counted = true
		case renameRe.MatchString(s) && counted:
		default:
			return nil, fmt.Errorf("search has a later stage Signalith does not run: %s", firstWords(s))
		}
	}
	where, err := ParseWhere(terms, r.Node, macros)
	if err != nil {
		return nil, err
	}
	// The event code is the node itself, so it leaves the clause.
	and, ok := where.(*And)
	if !ok {
		return nil, errors.New("a raw search must name its event code and a field")
	}
	var kids []Expr
	code := false
	for _, k := range and.Kids {
		if c, ok := k.(*Cmp); ok && c.Field == eventCode {
			if c.Neg || len(c.Values) != 1 || c.Values[0] != rawEvents[r.Node] {
				return nil, fmt.Errorf("a %s search must be of event %s", source, rawEvents[r.Node])
			}
			code = true
			continue
		}
		kids = append(kids, k)
	}
	if !code {
		return nil, fmt.Errorf("a %s search must name EventCode=%s", source, rawEvents[r.Node])
	}
	if hasField(&And{Kids: kids}, eventCode) {
		return nil, errors.New("the event code may only be named once, at the top")
	}
	if len(kids) == 1 {
		r.Where = kids[0]
	} else {
		r.Where = &And{Kids: kids}
	}
	return r, nil
}

// eventCode stands for EventCode or EventID in a raw search.
const eventCode = "\x00event_code"

func hasField(e Expr, f string) bool {
	switch x := e.(type) {
	case *And:
		return slices.ContainsFunc(x.Kids, func(k Expr) bool { return hasField(k, f) })
	case *Or:
		return slices.ContainsFunc(x.Kids, func(k Expr) bool { return hasField(k, f) })
	case *Not:
		return hasField(x.Kid, f)
	case *Cmp:
		return x.Field == f
	}
	return false
}

func firstWords(s string) string {
	f := strings.Fields(s)
	if len(f) > 3 {
		f = f[:3]
	}
	return strings.Join(f, " ")
}

// pipes splits a search into its stages at the | outside quotes and macro
// backticks. The leading | of a generating command is dropped.
func pipes(q string) []string {
	var out []string
	var cur strings.Builder
	quoted, tick, esc := false, false, false
	for _, ch := range q {
		switch {
		case esc:
			esc = false
		case ch == '\\' && quoted:
			esc = true
		case ch == '"' && !tick:
			quoted = !quoted
		case ch == '`' && !quoted:
			tick = !tick
		case ch == '|' && !quoted && !tick:
			if s := strings.TrimSpace(cur.String()); s != "" {
				out = append(out, s)
			}
			cur.Reset()
			continue
		}
		cur.WriteRune(ch)
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}
