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
	tstatsRe    = regexp.MustCompile(`(?s)^\|\s*tstats\s+.*?\bfrom\s+datamodel=Endpoint\.(\w+)\s+where\s+(.*?)\s+by\s+[^|]*$`)
	harmlessRe  = regexp.MustCompile("^`(drop_dm_object_name|security_content_ctime)\\([^`]*\\)`$")
	filterRe    = regexp.MustCompile("^`[\\w-]+_filter`$")
	summariesRe = regexp.MustCompile("`security_content_summariesonly`")
	commentRe   = regexp.MustCompile("(?s)```.*?```")
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
	first := summariesRe.ReplaceAllString("| "+stages[0], "")
	m := tstatsRe.FindStringSubmatch(first)
	if m == nil {
		return nil, errors.New("search is not a tstats search of Endpoint.Processes, Filesystem or Registry")
	}
	for _, s := range stages[1:] {
		if !harmlessRe.MatchString(s) && !filterRe.MatchString(s) {
			return nil, fmt.Errorf("search has a later stage Signalith does not run: %s", firstWords(s))
		}
	}
	r.Node = m[1]
	if _, ok := Nodes[r.Node]; !ok {
		return nil, fmt.Errorf("data model node Endpoint.%s is not supported", r.Node)
	}
	where, err := ParseWhere(m[2], r.Node, macros)
	if err != nil {
		return nil, err
	}
	r.Where = where
	return &r, nil
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
