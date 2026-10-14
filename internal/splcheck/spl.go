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
	// Linux is set for a rule over Sysmon for Linux events only.
	Linux bool `yaml:"-"`
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
	r.Linux = len(r.DataSource) > 0 && !slices.ContainsFunc(r.DataSource, func(s string) bool {
		return !strings.HasPrefix(s, "Sysmon for Linux ")
	})
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
// fields, which must name the event code (EventCode=10). The code picks
// the node, and each node's fields map to the Signalith fields they are
// stored as. The code stays in the clause as signature_id.
var (
	rawRe = regexp.MustCompile("(?s)^`(powershell|sysmon|wineventlog_security)`\\s+(.*)$")
	// rawNodes are the nodes of each source by event code.
	rawNodes = map[string]map[string]string{
		"powershell": {"4104": "PowerShell"},
		"sysmon":     {"7": "ImageLoad", "8": "ProcessAccess", "10": "ProcessAccess"},
		// Security events the Windows parser reads.
		"wineventlog_security": {"4698": "TaskCreated", "4663": "ObjectAccess"},
	}
	// RawFields are the event fields a raw search may name on each node,
	// with the Signalith field each is stored as.
	RawFields = map[string]map[string]string{
		"PowerShell": {"ScriptBlockText": "script_block_text"},
		"ImageLoad": {
			"ImageLoaded": "loaded_file_path", "loaded_file_path": "loaded_file_path",
			"Image": "process_path", "process_path": "process_path", "process_name": "process_name",
			"Signed": "signed", "SignatureStatus": "signature_status", "Signature": "signature",
		},
		"ProcessAccess": {
			"SourceImage": "process_path", "TargetImage": "target_process_path",
			"GrantedAccess": "granted_access", "CallTrace": "call_trace", "SourceUser": "user",
		},
		"TaskCreated": {"TaskName": "task_name", "TaskContent": "task_content", "user": "user"},
		"ObjectAccess": {
			"ObjectName": "object_path", "object_file_path": "object_path", "object_file_name": "object_name",
			"ObjectType": "object_type", "AccessList": "access_list", "AccessMask": "access_mask",
			"ProcessName": "process_path", "process_path": "process_path",
		},
	}
	// XMLKVFields are the fields xmlkv takes from a scheduled task's XML
	// (TaskCreated), with the Signalith field each is stored as.
	XMLKVFields = map[string]string{"Command": "task_command", "Arguments": "task_arguments"}
	xmlkvRe     = regexp.MustCompile(`(?i)^xmlkv\s+(Message|TaskContent)$`)
	searchRe    = regexp.MustCompile(`(?is)^search\s+(.+)$`)
	fillnullRe  = regexp.MustCompile(`(?i)^fillnull$`)
	statsRe     = regexp.MustCompile(`(?is)^stats\s`)
	renameRe    = regexp.MustCompile(`(?is)^rename\s`)
)

// eventCode is the stored field of EventCode or EventID.
const eventCode = "signature_id"

// rawSource is the pseudo node a raw search is parsed against before its
// event code names the node.
func rawSource(source string) string { return "raw:" + source }

// xmlkvSuffix marks a raw source whose search stage may also name the
// fields xmlkv extracts.
const xmlkvSuffix = "+xmlkv"

// parseRaw reads a raw event search of one source. Later, fillnull and
// stats only count the events and rename only renames the counts.
// (Without fillnull, Splunk's stats also drops events that miss one of
// its by fields; Signalith keeps them, so it finds those too.)
func parseRaw(r *Rule, source, terms string, later []string, macros map[string]*Macro) (*Rule, error) {
	filled, counted, xml := false, false, false
	var searches []string
	for _, s := range later {
		switch {
		case harmlessRe.MatchString(s) || filterRe.MatchString(s):
		case xmlkvRe.MatchString(s) && !counted && !filled && !xml && len(searches) == 0:
			xml = true
		case searchRe.MatchString(s) && xml && !counted && !filled:
			// A search after xmlkv filters on what it extracted.
			searches = append(searches, searchRe.FindStringSubmatch(s)[1])
		case fillnullRe.MatchString(s) && !counted && !filled:
			filled = true
		case statsRe.MatchString(s) && !counted:
			counted = true
		case renameRe.MatchString(s) && counted:
		default:
			return nil, fmt.Errorf("search has a later stage Signalith does not run: %s", firstWords(s))
		}
	}
	where, err := ParseWhere(terms, rawSource(source), macros)
	if err != nil {
		return nil, err
	}
	// The event code, named once at the top, picks the node.
	var top []Expr
	if a, ok := where.(*And); ok {
		top = a.Kids
	} else {
		top = []Expr{where}
	}
	var code *Cmp
	for _, k := range top {
		if c, ok := k.(*Cmp); ok && c.Field == eventCode {
			if code != nil || c.Neg {
				return nil, fmt.Errorf("a %s search must name its event code once", source)
			}
			code = c
		}
	}
	if code == nil || countField(where, eventCode) != 1 {
		return nil, fmt.Errorf("a %s search must name its event code (EventCode=...) once, at the top", source)
	}
	for _, v := range code.Values {
		n := rawNodes[source][v]
		if n == "" || (r.Node != "" && n != r.Node) {
			return nil, fmt.Errorf("%s event %s is not supported", source, v)
		}
		r.Node = n
	}
	if xml && r.Node != "TaskCreated" {
		return nil, fmt.Errorf("xmlkv on %s events is not supported", r.Node)
	}
	for _, s := range searches {
		e, err := ParseWhere(s, rawSource(source)+xmlkvSuffix, macros)
		if err != nil {
			return nil, err
		}
		if countField(e, eventCode) != 0 {
			return nil, fmt.Errorf("a %s search must name its event code once, at the top", source)
		}
		top = append(top, e)
	}
	if len(top) < 2 {
		return nil, fmt.Errorf("a %s search must name a field besides its event code", source)
	}
	where = &And{Kids: top}
	if len(top) == 1 {
		where = top[0]
	}
	if err := fieldsOf(where, r.Node, xml); err != nil {
		return nil, err
	}
	unescapeXML(where)
	r.Where = where
	return r, nil
}

// fieldsOf checks that a raw clause names only fields of node, and of
// xmlkv's when the search runs it.
func fieldsOf(e Expr, node string, xml bool) error {
	switch x := e.(type) {
	case *And:
		for _, k := range x.Kids {
			if err := fieldsOf(k, node, xml); err != nil {
				return err
			}
		}
	case *Or:
		for _, k := range x.Kids {
			if err := fieldsOf(k, node, xml); err != nil {
				return err
			}
		}
	case *Not:
		return fieldsOf(x.Kid, node, xml)
	case *Cmp:
		if x.Field == eventCode {
			return nil
		}
		for _, f := range RawFields[node] {
			if f == x.Field {
				return nil
			}
		}
		for _, f := range XMLKVFields {
			if xml && f == x.Field {
				return nil
			}
		}
		return fmt.Errorf("field %s is not a field of %s events", x.Field, node)
	}
	return nil
}

func countField(e Expr, f string) int {
	n := 0
	switch x := e.(type) {
	case *And:
		for _, k := range x.Kids {
			n += countField(k, f)
		}
	case *Or:
		for _, k := range x.Kids {
			n += countField(k, f)
		}
	case *Not:
		n = countField(x.Kid, f)
	case *Cmp:
		if x.Field == f {
			n = 1
		}
	}
	return n
}

func firstWords(s string) string {
	f := strings.Fields(s)
	if len(f) > 3 {
		f = f[:3]
	}
	return strings.Join(f, " ")
}

// xmlFields are the raw fields that hold XML. Splunk keeps the XML
// escaped (&lt;Hidden&gt;) and Signalith stores it as it is (<Hidden>),
// so a rule's values are unescaped to match.
var xmlFields = map[string]bool{"task_content": true}

var xmlUnescape = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&")

func unescapeXML(e Expr) {
	switch x := e.(type) {
	case *And:
		for _, k := range x.Kids {
			unescapeXML(k)
		}
	case *Or:
		for _, k := range x.Kids {
			unescapeXML(k)
		}
	case *Not:
		unescapeXML(x.Kid)
	case *Cmp:
		if xmlFields[x.Field] {
			for i, v := range x.Values {
				x.Values[i] = xmlUnescape.Replace(v)
			}
		}
	}
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
