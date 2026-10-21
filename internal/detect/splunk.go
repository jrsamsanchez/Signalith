// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/lookuptables"
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

// UseLookups gives a splunk pack the tables its rules' lookup stages read
// (the pack generator reads them from a security_content checkout).
func (p *Pack) UseLookups(l map[string]*splcheck.Lookup) { p.lookups = l }

// Lookups are a splunk pack's tables, by their names in security_content.
func (p *Pack) Lookups() map[string]*splcheck.Lookup { return p.lookups }

// loadLookups reads a splunk pack's lookups folder: each table's yml, as
// security_content describes it, and its CSV beside it.
func loadLookups(fsys fs.FS, dir string) (map[string]*splcheck.Lookup, error) {
	files, err := fs.Glob(fsys, path.Join(dir, "lookups", "*.yml"))
	if err != nil {
		return nil, err
	}
	out := map[string]*splcheck.Lookup{}
	for _, f := range files {
		meta, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		data, err := fs.ReadFile(fsys, strings.TrimSuffix(f, ".yml")+".csv")
		if err != nil {
			return nil, err
		}
		l, err := splcheck.ParseLookup(meta, data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if l.Name != strings.TrimSuffix(path.Base(f), ".yml") {
			return nil, fmt.Errorf("%s: the table is named %s", f, l.Name)
		}
		out[l.Name] = l
	}
	return out, nil
}

// usePackTables makes the tables of packs the ones lookup searches read,
// as the packs' rules do.
func usePackTables(ps []*Pack) {
	var ts []*lookuptables.Table
	for _, p := range ps {
		for _, name := range slices.Sorted(maps.Keys(p.lookups)) {
			ts = append(ts, p.lookups[name].Table)
		}
	}
	lookuptables.SetPackTables(ts)
}

// SplunkSearch is a Splunk rule's filter (SplunkFilter) and the regex
// stages that run after it: a regular expression OpenSearch cannot search
// exactly only because of its word boundaries (\b, \B), which Signalith's
// regex command reads as Splunk does, is left out of the filter and runs
// on the events it finds, before the rule's later stages. Only one every
// event must match (an AND term of the where clause) can run later.
func SplunkSearch(r *splcheck.Rule) (query.Expr, []*query.Regex, error) {
	var later []*query.Regex
	var keep []splcheck.Expr
	others := 0
	for _, k := range conjuncts(r.Where) {
		if re := laterRegex(k); re != nil {
			later = append(later, re)
			// The pattern without its word boundaries matches every
			// value the whole one does, so the filter keeps it: the
			// search finds only the events the regex stage may keep.
			if loose := looseRegex(k.(*splcheck.Cmp)); loose != nil {
				keep = append(keep, loose)
			}
			continue
		}
		keep = append(keep, k)
		others++
	}
	if len(later) == 0 {
		f, err := SplunkFilter(r)
		return f, nil, err
	}
	if others == 0 {
		return nil, nil, fmt.Errorf("a search of only regular expressions with word boundaries is not supported")
	}
	rest := *r
	rest.Where = &splcheck.And{Kids: keep}
	f, err := SplunkFilter(&rest)
	return f, later, err
}

// conjuncts are the terms of a where clause joined by AND.
func conjuncts(e splcheck.Expr) []splcheck.Expr {
	a, ok := e.(*splcheck.And)
	if !ok {
		return []splcheck.Expr{e}
	}
	var out []splcheck.Expr
	for _, k := range a.Kids {
		out = append(out, conjuncts(k)...)
	}
	return out
}

// laterRegex is a regular expression term as a regex stage when only its
// word boundaries keep OpenSearch from searching it (splunkRegex), or nil.
// Splunk's regular expressions are PCRE's, which read \b and \B as Go's
// do: between an ASCII letter, digit or _ and anything else, or the
// value's start or end. Signalith's regex stage, like Splunk's, drops an
// event without the field, and matches a field of several values when one
// of them does, as the search would.
func laterRegex(e splcheck.Expr) *query.Regex {
	x, ok := e.(*splcheck.Cmp)
	if !ok || !x.Regex || x.Neg || len(x.Values) != 1 ||
		x.Field == splcheck.RawUser || x.Field == "user" || x.Field == "registry_value_data" ||
		x.Field == search.StoredRawField || !plainField.MatchString(x.Field) {
		return nil
	}
	if _, err := splunkRegex(x); err == nil {
		return nil
	}
	// Without its word boundaries, the rest is one OpenSearch could
	// search: nothing else Signalith reads differently from Splunk.
	loose, ok := splcheck.WithoutBoundaries(x.Values[0])
	if !ok {
		return nil
	}
	if _, err := search.ParseRegex(loose); err != nil {
		return nil
	}
	return &query.Regex{Field: x.Field, Pattern: x.Values[0]}
}

// looseRegex is a regular expression term with its word boundaries left
// out, when OpenSearch can search it (splunkRegex), or nil.
func looseRegex(x *splcheck.Cmp) *splcheck.Cmp {
	loose, ok := splcheck.WithoutBoundaries(x.Values[0])
	if !ok {
		return nil
	}
	c := *x
	c.Values = []string{loose}
	if _, err := splunkRegex(&c); err != nil {
		return nil
	}
	return &c
}

// plainField is a stored field's name, not a raw or internal one.
var plainField = regexp.MustCompile(`^[A-Za-z][\w.]*$`)

// SplunkFilter is a Splunk rule's where clause as a Signalith filter,
// limited to the Windows events of its data model node. Field names are
// the CIM's, which Signalith uses too. A != comparison needs the field
// present, as in Splunk.
func SplunkFilter(r *splcheck.Rule) (query.Expr, error) {
	e, err := splunkExpr(r.Where)
	if err != nil {
		return nil, err
	}
	if r.Node == splcheck.SensorDNSNode {
		// The lookups that name the address that asked, as a sensor's
		// do: the rules count by src. A host's own lookups (Sysmon 22)
		// name only the host, which the endpoint rules cover.
		return and([]query.Expr{&query.Compare{Field: "src", Op: "=", Value: "*"}, e}), nil
	}
	if splcheck.IsSensorNode(r.Node) {
		// Every connection, from a network sensor, a firewall or a
		// host, as Splunk's tstats over the data model.
		return e, nil
	}
	if r.Node == splcheck.AuditdNode {
		// Every Linux audit record, of any type.
		return and([]query.Expr{&query.Compare{Field: "sourcetype", Op: "=", Value: ingest.AuditdSourcetype}, e}), nil
	}
	if r.Node == splcheck.CloudTrailNode {
		return and([]query.Expr{&query.Compare{Field: "sourcetype", Op: "=", Value: ingest.CloudTrailSourcetype}, e}), nil
	}
	if r.Node == splcheck.AzureNode || r.Node == splcheck.O365Node || r.Node == splcheck.OktaNode || splcheck.IsOktaTstatsNode(r.Node) ||
		r.Node == splcheck.KubernetesNode || r.Node == splcheck.GitHubNode {
		// The where clause names the macro's sourcetype, or Okta's for a
		// tstats search over Okta's events.
		return e, nil
	}
	if r.Node == "Web" {
		// Every web request: a web server's access log, or a network
		// sensor's.
		return e, nil
	}
	if r.MacOS && r.Node == "Processes" {
		// A macOS program start, as osquery reads it from
		// EndpointSecurity.
		return and([]query.Expr{&query.Compare{Field: "sourcetype", Op: "=", Value: macProcessSourcetype}, e}), nil
	}
	sourcetype := windowsSourcetypes
	if st := splcheck.ChannelSourcetype(r.Node); st != "" {
		// The events of the rule's one log.
		sourcetype = st
	}
	if r.Linux {
		sourcetype = ingest.SysmonLinuxSourcetype
	}
	scope := and([]query.Expr{
		&query.Compare{Field: "sourcetype", Op: "=", Value: sourcetype},
		&query.In{Field: "signature_id", Values: splunkEvents[r.Node]},
	})
	if r.Linux && r.Node == "Processes" {
		// A Linux program start as auditd records it, too, as Splunk's
		// add-on for Linux puts it in Endpoint.Processes.
		scope = or([]query.Expr{scope, and([]query.Expr{
			&query.Compare{Field: "sourcetype", Op: "=", Value: ingest.AuditdSourcetype},
			&query.Compare{Field: "signature_id", Op: "=", Value: ingest.ProcessStartSignatureID},
		})})
	}
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

// splunkSeverity is a rule's severity. Anomalies are low, since Splunk's
// risk-based alerting only counts them towards risk. TTPs once had risk
// scores from 0 to 100 that gave their severity; security_content now
// gives nearly every TTP a score of 50, so a TTP with that score is
// ranked by what it detects (DQ-01): critical for ransomware, wiping and
// the exploitation of a named vulnerability, high for credential theft,
// defense tampering, lateral movement and privilege escalation, else
// medium. A rule that still has an older score keeps its band.
func splunkSeverity(r *splcheck.Rule) string {
	if !strings.EqualFold(r.Type, "TTP") {
		return "low"
	}
	s := r.Score()
	switch {
	case s >= 80:
		return "critical"
	case s < 30:
		return "low"
	case s < 50:
		return "medium"
	}
	has := func(set map[string]bool) bool {
		for _, t := range append(r.MitreAttackID, r.Tags.MitreAttackID...) {
			t, _, _ = strings.Cut(strings.ToUpper(strings.TrimSpace(t)), ".")
			if set[t] {
				return true
			}
		}
		return false
	}
	switch {
	case has(splunkCritical), len(r.CVE) > 0 && has(splunkExploit):
		return "critical"
	case s >= 64, has(splunkHigh):
		return "high"
	}
	return "medium"
}

// splunkCritical are the ATT&CK techniques of a TTP that makes it
// critical: data encrypted, recovery inhibited, data or disks destroyed.
var splunkCritical = map[string]bool{"T1485": true, "T1486": true, "T1490": true, "T1561": true}

// splunkExploit are the exploitation techniques that make a TTP naming a
// CVE critical.
var splunkExploit = map[string]bool{"T1190": true, "T1203": true, "T1210": true, "T1211": true, "T1212": true, "T1068": true}

// splunkHigh are the techniques that make a TTP high: credential theft,
// defenses disabled, exploitation, injection, lateral movement and
// domain-wide changes.
var splunkHigh = map[string]bool{
	"T1003": true, // OS credential dumping
	"T1055": true, // process injection
	"T1068": true, // exploitation for privilege escalation
	"T1134": true, // access token manipulation
	"T1190": true, // exploit public-facing application
	"T1207": true, // rogue domain controller
	"T1210": true, // exploitation of remote services
	"T1212": true, // exploitation for credential access
	"T1484": true, // domain or tenant policy modification
	"T1505": true, // server software component (web shells)
	"T1550": true, // alternate authentication material
	"T1552": true, // unsecured credentials
	"T1555": true, // credentials from password stores
	"T1556": true, // modify authentication process
	"T1557": true, // adversary in the middle
	"T1558": true, // Kerberos tickets
	"T1562": true, // impair defenses
	"T1570": true, // lateral tool transfer
	"T1611": true, // escape to host
	"T1649": true, // authentication certificates
	"T1685": true, // disable or modify tools (T1562.001 before ATT&CK 19)
}

var splunkTechnique = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// splunkThrottle is packThrottle for a Splunk rule: an object access is
// one a day per host, program and object, a scheduled task per host and
// task, a service per host and service, a directory change per object
// and attribute, a share access per client, share and path, a Kerberos
// ticket per account and service, an account change or group member
// added per account or group, a logon or credential check per account
// and where it came from, a certificate request per requester and
// request, a named pipe or raw disk read per host, program and pipe or
// drive,
// an audit record per host, type, program and what it ran or touched.
func splunkThrottle(node, dm string) []string {
	if parts, ok := splcheck.UnionNodes[node]; ok {
		// A node of several others' events, as the first's.
		node = parts[0]
	}
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
	case "UserChanged", "ComputerChanged", "AccountRenamed", "GroupChanged", "AccountChanged":
		return []string{"host", "object"}
	case "DirectoryAccess":
		return []string{"host", "user", "object"}
	case "FilterChanged":
		return []string{"host", "security_filter_key"}
	case "ExplicitLogon":
		return []string{"host", "src_user", "user"}
	case "NtlmAuth":
		return []string{"host", "src_host", "user"}
	case "KerberosPreAuth":
		return []string{"host", "src", "user"}
	case "LocalGroupRead":
		return []string{"host", "process_path", "object"}
	case "CertRequest":
		return []string{"host", "cert_requester", "cert_request_id"}
	case "ProcessTerminated":
		return []string{"host", "process_path"}
	case "RawAccessRead":
		return []string{"host", "process_path", "device"}
	case "GroupMemberAdded":
		return []string{"host", "object", "member_sid"}
	case "Pipe":
		return []string{"host", "process_path", "pipe_name"}
	case splcheck.AuditdNode:
		return []string{"host", "auditd_type", "auditd_exe", "process", "auditd_name"}
	case splcheck.CloudTrailNode:
		return []string{"vendor_account", "user", "src", "eventName"}
	case splcheck.AzureNode:
		return []string{"vendor_account", "user", "src", "operationName"}
	case splcheck.O365Node:
		return []string{"vendor_account", "user", "src", "Operation"}
	case splcheck.OktaNode:
		return []string{"user", "src", "eventType"}
	case splcheck.KubernetesNode:
		return []string{"user", "src", "signature"}
	case splcheck.OktaAuthNode, splcheck.OktaChangeNode:
		return []string{"user", "src", "signature"}
	case splcheck.GitHubNode:
		return []string{"user", "vendor_account", "dest", "signature"}
	}
	return packThrottle("", dm)
}

// SplunkDetection converts one rule of a splunk pack into an off
// detection: TTP rules raise findings and add risk, anomalies only add
// risk, as in Splunk's risk-based alerting. A finding is made once a day
// per host, program and what it acted on.
func SplunkDetection(p *Pack, r PackRule, src []byte) (*Detection, error) {
	rule, err := splcheck.ParseWith(src, p.macros, splcheck.ParseOptions{Network: SplunkNetworkRule(r.Path), Lookups: p.lookups})
	if err != nil {
		return nil, err
	}
	filter, later, err := SplunkSearch(rule)
	if err != nil {
		return nil, err
	}
	dm := splcheck.NodeModel[rule.Node]
	q := &query.Query{Datamodel: dm, Search: filter}
	for _, re := range later {
		q.Commands = append(q.Commands, re)
	}
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
		Risk:        &Risk{Score: score, Objects: riskObjects(dm), Only: !strings.EqualFold(rule.Type, "TTP")},
		Tags:        []string{"splunk", p.Name, strings.ToLower(rule.Type), strings.ToLower(rule.Node)},
	}
	if fp := strings.TrimSpace(rule.FalsePositives); fp != "" {
		d.Guidance = "Known false positives: " + fp
	}
	if rule.IPLocation() {
		// Splunk ships a GeoIP database; Signalith reads one an admin
		// adds.
		d.Guidance = strings.TrimSpace(GeoIPSetup + "\n\n" + d.Guidance)
		d.Tags = append(d.Tags, "geoip")
	}
	if splcheck.IsSensorNode(rule.Node) {
		// About the address that sent the traffic, not the sensor that
		// saw it.
		d.Title = strings.TrimSpace(rule.Name) + " from $src$"
		d.Throttle.Fields = packNetworkThrottle("", dm)
		d.Risk.Objects = []RiskObject{{Field: "src", Type: "system"}, {Field: "user", Type: "user"}}
		d.Tags = append(d.Tags, "network")
	} else if cloudNode(rule.Node) {
		// An AWS call, an Entra ID sign-in or change, or a Microsoft 365
		// action is the account's, from an address; the host is only the
		// Collector that read it.
		d.Title = strings.TrimSpace(rule.Name) + " for $user$"
		d.Risk.Objects = []RiskObject{{Field: "user", Type: "user"}, {Field: "src", Type: "system"}}
	}
	if rule.Threshold != nil {
		splunkThreshold(d, q, rule)
	} else if rule.Post != "" {
		if err := splunkPost(d, q, rule); err != nil {
			return nil, err
		}
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

// riskObjects are what a pack rule's risk is about: the account and the
// host, or for a web request the client and the web server.
func riskObjects(datamodel string) []RiskObject {
	if strings.EqualFold(datamodel, ingest.WebModel) {
		return []RiskObject{{Field: "src", Type: "system"}, {Field: "host", Type: "system"}}
	}
	return []RiskObject{{Field: "user", Type: "user"}, {Field: "host", Type: "system"}}
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
		} else if a.Name != "count" {
			aggs = append(aggs, "count as "+a.Name)
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
	groupedBy(d, rule, t.By)
}

// groupedBy makes a detection whose rows are groups (stats ... by) find
// each group once a day, with the title and risk about the group's host,
// address or account.
func groupedBy(d *Detection, rule *splcheck.Rule, by []string) {
	d.Title = strings.TrimSpace(rule.Name)
	toks := []struct{ field, word string }{{"dest", "on"}, {"host", "on"}, {"src", "from"}, {"user", "for"}}
	if cloudNode(rule.Node) {
		// dest is the AWS service, the Azure resource or the Microsoft
		// 365 workload.
		toks = toks[2:]
	}
	for _, tok := range toks {
		if slices.Contains(by, tok.field) {
			d.Title += " " + tok.word + " $" + tok.field + "$"
			break
		}
	}
	d.Throttle = Throttle{Window: "24h", Fields: slices.Clone(by)}
	var objects []RiskObject
	for _, f := range by {
		switch f {
		case "user", "src_user":
			objects = append(objects, RiskObject{Field: f, Type: "user"})
		case "dest", "host", "src":
			if f != "src" && cloudNode(rule.Node) {
				continue
			}
			objects = append(objects, RiskObject{Field: f, Type: "system"})
		}
	}
	if len(objects) == 0 {
		objects = []RiskObject{{Field: by[0], Type: "other"}}
	}
	d.Risk.Objects = objects
}

// GeoIPSetup is the setup note of a pack rule that runs iplocation.
const GeoIPSetup = "Setup: this rule runs iplocation, which needs a GeoIP City database (.mmdb), such as DB-IP's free " +
	"IP to City Lite (the one Splunk ships) or MaxMind's GeoLite2 City, in the geoip folder next to the lookup tables " +
	"on each server (docs/lookups.md, GeoIP database for iplocation). Without one, every run of the rule fails with " +
	"\"iplocation needs a GeoIP database\", shown as the detection's last error, and finds nothing for that run."

// splunkPost runs a rule's later stages after its filter, as they are
// written. When they end in groups, each is found once a day.
func splunkPost(d *Detection, q *query.Query, rule *splcheck.Rule) error {
	d.Query = q.String() + "\n| " + rule.Post
	if rule.PostCompared {
		// Counts compared within each time bucket: only a bucket the
		// run's window holds whole, as Splunk's hourly window does, is
		// kept (a part of one may stand out where the whole does not).
		d.Query += fmt.Sprintf("\n| addinfo\n| where _time >= info_min_time AND _time + %d <= info_max_time\n| fields - info_min_time, info_max_time, info_search_time",
			int64(rule.PostSpan/time.Second))
	}
	// In canonical form; Validate reports a query that does not parse.
	if pq, err := query.Parse(d.Query); err == nil {
		if err := splunkJoins(pq, rule); err != nil {
			return err
		}
		d.Query = pq.String()
	} else if len(rule.Joins) > 0 {
		return err
	}
	if by := rule.PostGroups(); len(by) > 0 {
		groupedBy(d, rule, by)
	}
	if span := rule.PostSpan; span > 0 {
		// Grouped by time: as a count is (splunkThreshold), each run
		// searches the span plus the time since the last run, so each
		// bucket is whole in some run. The same holds for the longest
		// transaction a later transaction keeps.
		every := min(max(span, time.Minute), 5*time.Minute)
		d.Schedule = formatDuration(every)
		d.Lookback = formatDuration(span + every)
	}
	return nil
}

// splunkJoins gives each join of a rule's later stages its subsearch's
// search: the subsearch's data model and converted filter, and the regex
// stages that run right after it, before its own later stages.
func splunkJoins(q *query.Query, rule *splcheck.Rule) error {
	i := 0
	for _, c := range q.Commands {
		j, ok := c.(*query.Join)
		if !ok {
			continue
		}
		if i >= len(rule.Joins) {
			return fmt.Errorf("the later stages have more joins than the rule")
		}
		sub := rule.Joins[i].Sub
		filter, later, err := SplunkSearch(sub)
		if err != nil {
			return fmt.Errorf("join's subsearch: %w", err)
		}
		j.Sub.Datamodel = splcheck.NodeModel[sub.Node]
		j.Sub.Search = filter
		var cmds []query.Command
		for _, re := range later {
			cmds = append(cmds, re)
		}
		j.Sub.Commands = append(cmds, j.Sub.Commands...)
		i++
	}
	if i != len(rule.Joins) {
		return fmt.Errorf("the later stages have fewer joins than the rule")
	}
	return nil
}

// cloudNode reports whether a node is a cloud service's records:
// CloudTrail's, Entra ID's and Azure's, or Microsoft 365's.
func cloudNode(node string) bool {
	return node == splcheck.CloudTrailNode || node == splcheck.AzureNode || node == splcheck.O365Node || node == splcheck.OktaNode ||
		splcheck.IsOktaTstatsNode(node) || node == splcheck.KubernetesNode || node == splcheck.GitHubNode
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

// SplunkNetworkRule reports whether a security_content rule is one of its
// network detections (detections/network), which read the network data
// models from any source (splcheck.ParseOptions).
func SplunkNetworkRule(path string) bool { return strings.HasPrefix(path, "detections/network/") }
