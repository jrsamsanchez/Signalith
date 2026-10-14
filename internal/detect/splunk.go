package detect

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// Splunk security_content detections ship in a pack with format splunk:
// the detection YAML files as Splunk publishes them and the macros their
// searches use. Each converts when Signalith starts (SplunkDetection).

// splunkEvents are the Windows events each data model node is, so a rule
// over Endpoint.Processes reads process creations, not process access.
var splunkEvents = map[string][]string{
	"Processes":     {"1", "4688"},
	"Filesystem":    {"11", "23", "26"},
	"Registry":      {"12", "13", "14"},
	"PowerShell":    {"4104"},
	"ImageLoad":     {"7"},
	"ProcessAccess": {"8", "10"},
}

// UseMacros gives a splunk pack the macros its rules' searches use (the
// pack generator reads them from a security_content checkout).
func (p *Pack) UseMacros(m map[string]*splcheck.Macro) { p.macros = m }

// loadMacros reads a splunk pack's macros folder.
func loadMacros(fsys fs.FS, dir string) (map[string]*splcheck.Macro, error) {
	files, err := fs.Glob(fsys, path.Join(dir, "macros", "*.yml"))
	if err != nil {
		return nil, err
	}
	out := map[string]*splcheck.Macro{}
	for _, f := range files {
		src, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		m, err := splcheck.ParseMacro(src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out[m.Name] = m
	}
	return out, nil
}

// SplunkFilter is a Splunk rule's where clause as a Signalith filter,
// limited to the Windows events of its data model node. Field names are
// the CIM's, which Signalith uses too. A != comparison needs the field
// present, as in Splunk.
func SplunkFilter(r *splcheck.Rule) (query.Expr, error) {
	e, err := splunkExpr(r.Where)
	if err != nil {
		return nil, err
	}
	scope := and([]query.Expr{
		&query.Compare{Field: "sourcetype", Op: "=", Value: windowsSourcetypes},
		&query.In{Field: "signature_id", Values: splunkEvents[r.Node]},
	})
	return and([]query.Expr{scope, e}), nil
}

func splunkExpr(e splcheck.Expr) (query.Expr, error) {
	switch x := e.(type) {
	case *splcheck.And, *splcheck.Or:
		var kids []splcheck.Expr
		if a, ok := x.(*splcheck.And); ok {
			kids = a.Kids
		} else {
			kids = x.(*splcheck.Or).Kids
		}
		out := make([]query.Expr, 0, len(kids))
		for _, k := range kids {
			q, err := splunkExpr(k)
			if err != nil {
				return nil, err
			}
			out = append(out, q)
		}
		if _, ok := x.(*splcheck.And); ok {
			return and(out), nil
		}
		return or(out), nil
	case *splcheck.Not:
		q, err := splunkExpr(x.Kid)
		if err != nil {
			return nil, err
		}
		return &query.Not{Child: q}, nil
	case *splcheck.Cmp:
		for _, v := range x.Values {
			// ? is literal in Splunk and a wildcard in Signalith.
			if strings.Contains(v, "?") {
				return nil, fmt.Errorf("value %q of %s has a ?, which Splunk reads literally", v, x.Field)
			}
			if v == "" {
				return nil, fmt.Errorf("an empty value of %s is not supported", x.Field)
			}
		}
		match := valuesMatch(x.Field, x.Values)
		if x.Field == "registry_value_data" {
			// Signalith keeps Sysmon's "DWORD (0x00000001)" as it is;
			// Splunk's add-on reads it as 0x00000001 (splcheck.View).
			words := make([]string, 0, 2*len(x.Values))
			for _, v := range x.Values {
				words = append(words, "DWORD ("+v+")", "QWORD ("+v+")")
			}
			match = or([]query.Expr{
				and([]query.Expr{match, &query.Not{Child: valuesMatch(x.Field, []string{"DWORD (0x*)", "QWORD (0x*)"})}}),
				valuesMatch(x.Field, words),
			})
		}
		if x.Neg {
			return and([]query.Expr{&query.Compare{Field: x.Field, Op: "=", Value: "*"}, &query.Not{Child: match}}), nil
		}
		return match, nil
	}
	return nil, fmt.Errorf("unknown where clause %T", e)
}

// valuesMatch is field=v, or field IN (v...) for several values.
func valuesMatch(field string, values []string) query.Expr {
	if len(values) == 1 {
		return &query.Compare{Field: field, Op: "=", Value: values[0]}
	}
	return &query.In{Field: field, Values: values}
}

// splunkSeverity is a rule's severity: TTPs by their risk score, and
// anomalies low, since Splunk's risk-based alerting only counts them
// towards risk.
func splunkSeverity(r *splcheck.Rule) string {
	if !strings.EqualFold(r.Type, "TTP") {
		return "low"
	}
	switch s := r.Score(); {
	case s >= 80:
		return "critical"
	case s >= 64:
		return "high"
	case s >= 30:
		return "medium"
	}
	return "low"
}

var splunkTechnique = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// SplunkDetection converts one rule of a splunk pack into an off
// detection: TTP rules raise findings and add risk, anomalies only add
// risk, as in Splunk's risk-based alerting. A finding is made once a day
// per host, program and what it acted on.
func SplunkDetection(p *Pack, r PackRule, src []byte) (*Detection, error) {
	rule, err := splcheck.Parse(src, p.macros)
	if err != nil {
		return nil, err
	}
	filter, err := SplunkFilter(rule)
	if err != nil {
		return nil, err
	}
	dm := splcheck.NodeModel[rule.Node]
	q := &query.Query{Datamodel: dm, Search: filter}
	var mitre []string
	for _, t := range append(rule.MitreAttackID, rule.Tags.MitreAttackID...) {
		if t = strings.ToUpper(strings.TrimSpace(t)); splunkTechnique.MatchString(t) && !slices.Contains(mitre, t) {
			mitre = append(mitre, t)
		}
	}
	score := rule.Score()
	if score == 0 {
		score = 25
	}
	d := &Detection{
		ID:          r.ID,
		Title:       strings.TrimSpace(rule.Name) + " on $host$",
		Description: strings.TrimSpace(rule.Description),
		Query:       q.String(),
		Schedule:    "5m",
		Lookback:    "10m",
		Severity:    splunkSeverity(rule),
		MITRE:       mitre,
		Throttle:    Throttle{Window: "24h", Fields: packThrottle("", dm)},
		Risk:        &Risk{Score: score, Objects: []RiskObject{{Field: "user", Type: "user"}, {Field: "host", Type: "system"}}, Only: !strings.EqualFold(rule.Type, "TTP")},
		Tags:        []string{"splunk", p.Name, strings.ToLower(rule.Type), strings.ToLower(rule.Node)},
	}
	if fp := strings.TrimSpace(rule.FalsePositives); fp != "" {
		d.Guidance = "Known false positives: " + fp
	}
	d.Origin = &Origin{
		Pack: p.Name, PackTitle: p.Title, Rule: rule.ID, Author: strings.TrimSpace(rule.Author),
		License: p.License, LicenseURL: p.LicenseURL, Status: rule.Status,
		URL:        strings.TrimSuffix(p.Source, "/") + "/blob/" + p.Version + "/" + r.Path,
		References: rule.References,
	}
	d.Defaults()
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}
