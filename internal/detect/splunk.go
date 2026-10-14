package detect

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// Splunk security_content detections ship in a pack with format splunk:
// the detection YAML files as Splunk publishes them and the macros their
// searches use. Each converts when Signalith starts (SplunkDetection).

// splunkEvents are the Windows events each data model node is, so a rule
// over Endpoint.Processes reads process creations, not process access.
var splunkEvents = splcheck.NodeEvents

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
	sourcetype := windowsSourcetypes
	if r.Linux {
		sourcetype = ingest.SysmonLinuxSourcetype
	}
	scope := and([]query.Expr{
		&query.Compare{Field: "sourcetype", Op: "=", Value: sourcetype},
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
		if x.Regex {
			return splunkRegex(x)
		}
		for _, v := range x.Values {
			if v == "" {
				return nil, fmt.Errorf("an empty value of %s is not supported", x.Field)
			}
		}
		field := x.Field
		if field == splcheck.RawUser {
			field = "user"
		}
		match := valuesMatch(field, x.Values)
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
		if x.Field == "user" && !slices.ContainsFunc(x.Values, func(v string) bool { return strings.Contains(v, `\`) }) {
			// Signalith keeps Sysmon's DOMAIN\name; Splunk's add-on
			// reads the name alone (splcheck.View).
			named := make([]string, len(x.Values))
			for i, v := range x.Values {
				named[i] = `*\` + v
			}
			match = or([]query.Expr{
				and([]query.Expr{&query.Not{Child: &query.Compare{Field: x.Field, Op: "=", Value: `*\*`}}, match}),
				valuesMatch(x.Field, named),
			})
		}
		if x.Neg {
			return and([]query.Expr{&query.Compare{Field: field, Op: "=", Value: "*"}, &query.Not{Child: match}}), nil
		}
		return match, nil
	}
	return nil, fmt.Errorf("unknown where clause %T", e)
}

// splunkRegex is a regex stage or match() as field=~"re". Fields whose
// stored form differs from Splunk's (user, registry_value_data) are left
// out, as are patterns OpenSearch cannot search exactly.
func splunkRegex(x *splcheck.Cmp) (query.Expr, error) {
	if x.Neg || len(x.Values) != 1 || x.Field == splcheck.RawUser || x.Field == "user" || x.Field == "registry_value_data" {
		return nil, fmt.Errorf("a regular expression on %s is not supported", x.Field)
	}
	p := x.Values[0]
	if _, err := search.ParseRegex(p); err != nil {
		return nil, err
	}
	if search.WildcardFields[x.Field] && search.CaseMatters(p) {
		return nil, fmt.Errorf("a case-sensitive regular expression on %s, which is searched ignoring case", x.Field)
	}
	return &query.Compare{Field: x.Field, Op: "=~", Value: p}, nil
}

// valuesMatch is field=v, or field IN (v...) for several values. A value
// with a ?, which Splunk reads literally and Signalith as a wildcard, is
// a regular expression instead (splunkGlobRegex).
func valuesMatch(field string, values []string) query.Expr {
	var plain []string
	var kids []query.Expr
	for _, v := range values {
		if strings.Contains(v, "?") {
			kids = append(kids, &query.Compare{Field: field, Op: "=~", Value: splunkGlobRegex(v)})
		} else {
			plain = append(plain, v)
		}
	}
	switch len(plain) {
	case 0:
	case 1:
		kids = append([]query.Expr{&query.Compare{Field: field, Op: "=", Value: plain[0]}}, kids...)
	default:
		kids = append([]query.Expr{&query.In{Field: field, Values: plain}}, kids...)
	}
	return or(kids)
}

// splunkGlobRegex is a Splunk pattern as a regular expression: * is any
// run of characters, case is ignored, and everything else is literal.
func splunkGlobRegex(v string) string {
	parts := strings.Split(v, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return "(?is)^" + strings.Join(parts, ".*") + "$"
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

// splunkThrottle is packThrottle for a Splunk rule: an object access is
// one a day per host, program and object, a scheduled task per host and
// task, a service per host and service, a directory change per object
// and attribute, a share access per client, share and path, a Kerberos
// ticket per account and service, an account change or group member
// added per account or group.
func splunkThrottle(node, dm string) []string {
	switch node {
	case "ObjectAccess":
		return []string{"host", "process_path", "object_path"}
	case "TaskCreated":
		return []string{"host", "task_name"}
	case "ServiceInstalled":
		return []string{"host", "service_name"}
	case "DirectoryChange":
		return []string{"host", "object", "ad_attribute"}
	case "ShareAccess":
		return []string{"host", "src", "share_name", "share_target"}
	case "KerberosTGT", "KerberosService":
		return []string{"host", "user", "kerberos_service"}
	case "UserChanged":
		return []string{"host", "object"}
	case "GroupMemberAdded":
		return []string{"host", "object", "member_sid"}
	}
	return packThrottle("", dm)
}

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
		Throttle:    Throttle{Window: "24h", Fields: splunkThrottle(rule.Node, dm)},
		Risk:        &Risk{Score: score, Objects: []RiskObject{{Field: "user", Type: "user"}, {Field: "host", Type: "system"}}, Only: !strings.EqualFold(rule.Type, "TTP")},
		Tags:        []string{"splunk", p.Name, strings.ToLower(rule.Type), strings.ToLower(rule.Node)},
	}
	if fp := strings.TrimSpace(rule.FalsePositives); fp != "" {
		d.Guidance = "Known false positives: " + fp
	}
	if rule.Threshold != nil {
		splunkThreshold(d, q, rule)
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

// splunkThreshold makes a detection count as its rule does: stats over
// the rule's groups, then its limits. Each run counts the span the rule
// counts over plus the time since the last run, so a burst that Splunk
// finds in one of its fixed buckets is in some run's window even when
// its events arrive a little late. (That can also find a burst that
// straddles two of Splunk's buckets.) A group is found once a day.
func splunkThreshold(d *Detection, q *query.Query, rule *splcheck.Rule) {
	t := rule.Threshold
	span := t.Span
	if span == 0 {
		span = splcheck.DefaultSpan
	}
	every := min(max(span, time.Minute), 5*time.Minute)
	d.Schedule = formatDuration(every)
	d.Lookback = formatDuration(span + every)
	aggs := []string{"count"}
	for _, a := range t.Aggs {
		if a.Func == "dc" {
			aggs = append(aggs, "dc("+a.Field+") as "+a.Name)
		}
	}
	var limits []string
	for _, l := range t.Limits {
		limits = append(limits, fmt.Sprintf("%s %s %d", l.Name, l.Op, l.Value))
	}
	d.Query = q.String() + "\n| stats " + strings.Join(aggs, ", ") + " by " + strings.Join(t.By, ", ") +
		"\n| where " + strings.Join(limits, " AND ")
	// In canonical form; Validate reports a query that does not parse.
	if pq, err := query.Parse(d.Query); err == nil {
		d.Query = pq.String()
	}
	d.Title = strings.TrimSpace(rule.Name)
	for _, tok := range []struct{ field, word string }{{"dest", "on"}, {"host", "on"}, {"src", "from"}, {"user", "for"}} {
		if slices.Contains(t.By, tok.field) {
			d.Title += " " + tok.word + " $" + tok.field + "$"
			break
		}
	}
	d.Throttle = Throttle{Window: "24h", Fields: slices.Clone(t.By)}
	var objects []RiskObject
	for _, f := range t.By {
		switch f {
		case "user":
			objects = append(objects, RiskObject{Field: f, Type: "user"})
		case "dest", "host", "src":
			objects = append(objects, RiskObject{Field: f, Type: "system"})
		}
	}
	if len(objects) == 0 {
		objects = []RiskObject{{Field: t.By[0], Type: "other"}}
	}
	d.Risk.Objects = objects
}

// formatDuration writes a duration as a detection schedule: 90s, 5m, 1h.
func formatDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
