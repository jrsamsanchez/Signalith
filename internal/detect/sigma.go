package detect

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf16"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// SigmaResult is a converted Sigma rule.
type SigmaResult struct {
	Detection *Detection `json:"detection"`
	// Warnings describe approximations the admin should review.
	Warnings []string `json:"warnings,omitempty"`
}

type sigmaRule struct {
	Title       string         `yaml:"title"`
	ID          string         `yaml:"id"`
	Status      string         `yaml:"status"`
	Description string         `yaml:"description"`
	Level       string         `yaml:"level"`
	Tags        []string       `yaml:"tags"`
	Logsource   map[string]any `yaml:"logsource"`
	Detection   map[string]any `yaml:"detection"`
	FalsePos    []string       `yaml:"falsepositives"`
}

// sigmaFields maps Sigma (Sysmon, Windows Security and antivirus) field names to
// Signalith data model fields.
var sigmaFields = map[string]string{
	"image":               "process_path",
	"commandline":         "process",
	"parentimage":         "parent_process_path",
	"parentcommandline":   "parent_process",
	"user":                "user",
	"hashes":              "process_hash",
	"processid":           "process_id",
	"destinationip":       "dest",
	"destinationport":     "dest_port",
	"destinationhostname": "dest_host",
	"sourceip":            "src",
	"sourceport":          "src_port",
	"protocol":            "transport",
	"eventid":             "signature_id",
	"targetusername":      "user",
	"subjectusername":     "src_user",
	"ipaddress":           "src",
	"ipport":              "src_port",
	"logontype":           "logon_type",
	"workstationname":     "src_host",
	"computer":            "host",
	"computername":        "host",
	"targetdomainname":    "user_domain",
	"membername":          "member",
	"targetsid":           "object",
	// Sysmon process fields (event 1).
	"originalfilename":  "original_file_name",
	"description":       "process_description",
	"product":           "process_product",
	"company":           "process_company",
	"fileversion":       "process_file_version",
	"integritylevel":    "process_integrity_level",
	"currentdirectory":  "process_current_directory",
	"parentprocessid":   "parent_process_id",
	"parentuser":        "parent_user",
	"logonid":           "logon_id",
	"processguid":       "process_guid",
	"parentprocessguid": "parent_process_guid",
	// Sysmon network fields (event 3); Initiated becomes direction.
	"sourcehostname": "src_host",
	"initiated":      "direction",
	"signature":      "signature",
	"filename":       "file_path",
}

// sigmaEventFields maps the fields of Sysmon and PowerShell log sources
// whose events land in other data models. In these log sources only the
// listed fields are mapped: a name such as Description means the loaded
// DLL's description in image_load, not the process's, so the process
// creation mapping would be wrong.
var sigmaEventFields = func() map[string]map[string]string {
	common := map[string]string{
		"image": "process_path", "user": "user", "processid": "process_id", "processguid": "process_guid",
		"computer": "host", "computername": "host", "eventid": "signature_id",
	}
	with := func(m map[string]string) map[string]string {
		for k, v := range common {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		return m
	}
	file := with(map[string]string{"targetfilename": "file_path"})
	registry := with(map[string]string{"targetobject": "registry_path", "details": "registry_value_data", "newname": "registry_new_path"})
	access := with(map[string]string{
		"sourceimage": "process_path", "sourceprocessid": "process_id", "sourceprocessguid": "process_guid",
		"sourceuser": "user", "targetimage": "target_process_path", "targetprocessid": "target_process_id",
		"targetprocessguid": "target_process_guid", "grantedaccess": "granted_access", "calltrace": "call_trace",
		"startaddress": "start_address", "startmodule": "start_module", "startfunction": "start_function",
		"image": "", "processid": "", "processguid": "", "user": "",
	})
	load := with(map[string]string{
		"imageloaded": "loaded_file_path", "signed": "signed", "signature": "signature", "signaturestatus": "signature_status",
	})
	// Security log events: the account that acted (Subject*) is the
	// user, except in a logon, where it is the account logged on
	// (Target*).
	security := func(m map[string]string) map[string]string {
		for k, v := range map[string]string{
			"subjectusername": "user", "subjectdomainname": "user_domain", "subjectlogonid": "logon_id",
			"computer": "host", "computername": "host", "eventid": "signature_id",
		} {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		return m
	}
	logon := map[string]string{
		"targetusername": "user", "targetdomainname": "user_domain", "targetusersid": "user_sid",
		"logontype": "logon_type", "logonprocessname": "logon_process", "authenticationpackagename": "authentication_method",
		"workstationname": "src_host", "ipaddress": "src", "ipport": "src_port", "processname": "process_path",
		"computer": "host", "computername": "host", "eventid": "signature_id",
	}
	return map[string]map[string]string{
		"file_event": file, "file_delete": file,
		"registry_add": registry, "registry_delete": registry, "registry_set": registry, "registry_event": registry,
		"dns_query":            with(map[string]string{"queryname": "query", "queryresults": "answer"}),
		"image_load":           load,
		"driver_load":          with(map[string]string{"imageloaded": "loaded_file_path", "signed": "signed", "signature": "signature", "signaturestatus": "signature_status", "image": "", "user": "", "processid": "", "processguid": ""}),
		"process_access":       access,
		"create_remote_thread": access,
		"security_4624":        logon,
		"security_4625":        logon,
		"security_4663": security(map[string]string{
			"objectname": "object_path", "objecttype": "object_type", "accesslist": "access_list",
			"accessmask": "access_mask", "processname": "process_path",
		}),
		"security_4697": security(map[string]string{
			"servicename": "service_name", "servicefilename": "service_path", "servicetype": "service_type",
			"servicestarttype": "service_start_type", "serviceaccount": "service_account",
		}),
		"security_4698": security(map[string]string{"taskname": "task_name", "taskcontent": "task_content"}),
		"system": {
			"servicename": "service_name", "imagepath": "service_path", "servicetype": "service_type",
			"starttype": "service_start_type", "accountname": "service_account", "provider_name": "provider",
			"computer": "host", "computername": "host", "eventid": "signature_id",
		},
		"ps_script": {
			"scriptblocktext": "script_block_text", "path": "script_path", "scriptblockid": "script_block_id",
			"computer": "host", "computername": "host", "eventid": "signature_id",
		},
	}
}()

// sigmaWindowsEvents are the Windows event IDs each log source is, so a
// Windows rule only sees its own kind of event: process creation and
// process access both land in Endpoint, for example.
var sigmaWindowsEvents = map[string][]string{
	"process_creation":     {"1", "4688"},
	"network_connection":   {"3"},
	"file_event":           {"11"},
	"file_delete":          {"23", "26"},
	"registry_add":         {"12"},
	"registry_delete":      {"12"},
	"registry_set":         {"13"},
	"registry_event":       {"12", "13", "14"},
	"dns_query":            {"22"},
	"image_load":           {"7"},
	"driver_load":          {"6"},
	"process_access":       {"10"},
	"create_remote_thread": {"8"},
	"ps_script":            {"4104"},
	"system":               {"7045"},
	"security_4624":        {"4624"},
	"security_4625":        {"4625"},
	"security_4663":        {"4663"},
	"security_4697":        {"4697"},
	"security_4698":        {"4698"},
}

// sigmaSecurityModels are the Security log events Security log rules
// (service: security) convert for, with each one's data model: an object
// access is a file's (Filesystem) or a registry key's (Registry), so its
// rules search any.
var sigmaSecurityModels = map[string]string{
	"4624": "Authentication", "4625": "Authentication", "4663": "", "4697": "Change", "4698": "Change",
}

// anyModel reports whether the rule's events land in more than one data
// model, so it searches them all.
func (c *sigmaConv) anyModel() bool { return c.category == "security_4663" }

// sigmaEventIDs returns the event IDs a rule's selections name (EventID
// without modifiers), sorted.
func sigmaEventIDs(det map[string]any) []string {
	seen := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, it := range x {
				walk(it)
			}
		case map[string]any:
			for k, val := range x {
				if k != "EventID" {
					continue
				}
				if list, ok := val.([]any); ok {
					for _, it := range list {
						seen[fmt.Sprint(it)] = true
					}
				} else {
					seen[fmt.Sprint(val)] = true
				}
			}
		}
	}
	for k, v := range det {
		if k != "condition" {
			walk(v)
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// sigmaLevels maps Sigma levels to severities.
var sigmaLevels = map[string]string{
	"informational": "informational", "low": "low", "medium": "medium", "high": "high", "critical": "critical",
}

var sigmaTechnique = regexp.MustCompile(`^attack\.(t\d{4}(?:\.\d{3})?)$`)

// SigmaOptions changes how a rule converts.
type SigmaOptions struct {
	// Strict refuses any approximation, instead of warning about it: a
	// field without a Signalith mapping, a free-text keyword search, a log
	// source without a data model, and |cased. The SigmaHQ content pack
	// converts strictly, so every shipped rule means exactly what its
	// author wrote.
	Strict bool
}

// ConvertSigma converts one Sigma rule (YAML) into a disabled detection.
// Rules that use features Signalith cannot express, such as regular
// expressions, return an error naming the feature.
func ConvertSigma(src []byte) (*SigmaResult, error) {
	return ConvertSigmaWith(src, SigmaOptions{})
}

// ConvertSigmaWith is ConvertSigma with options.
func ConvertSigmaWith(src []byte, opt SigmaOptions) (*SigmaResult, error) {
	var r sigmaRule
	if err := yaml.Unmarshal(src, &r); err != nil {
		return nil, fmt.Errorf("not valid Sigma YAML: %w", err)
	}
	if r.Title == "" || r.Detection == nil {
		return nil, errors.New("not a Sigma rule: title and detection are required")
	}
	category, _ := r.Logsource["category"].(string)
	if product, _ := r.Logsource["product"].(string); category == "" && strings.EqualFold(product, "windows") {
		switch service, _ := r.Logsource["service"].(string); strings.ToLower(service) {
		case "system":
			// The System log's events Signalith reads are services
			// installed (7045).
			category = "system"
		case "security":
			// A Security log rule's fields are its event's own, so it
			// converts for one event.
			category = "security"
			if ids := sigmaEventIDs(r.Detection); len(ids) == 1 {
				if _, ok := sigmaSecurityModels[ids[0]]; ok {
					category = "security_" + ids[0]
				}
			}
		}
	}
	c := &sigmaConv{strict: opt.Strict, category: strings.ToLower(category)}
	dm := c.datamodel(r.Logsource)
	if c.category == "security" {
		c.approx("Signalith converts Security log rules about one of the events %s", strings.Join(slices.Sorted(maps.Keys(sigmaSecurityModels)), ", "))
	}
	if dm == "" && opt.Strict && !c.anyModel() {
		return nil, fmt.Errorf("log source %v has no Signalith data model", r.Logsource)
	}
	cond, ok := r.Detection["condition"]
	if !ok {
		return nil, errors.New("detection.condition is missing")
	}
	condStr, ok := cond.(string)
	if !ok {
		if list, isList := cond.([]any); isList && len(list) == 1 {
			condStr, ok = list[0].(string)
		}
	}
	if !ok {
		return nil, errors.New("only a single detection.condition is supported")
	}
	if strings.Contains(condStr, "|") {
		return nil, errors.New("Sigma aggregation conditions (| count() ...) are not supported; use a correlation in the query instead")
	}
	if c.category == "system" && !bytes.Contains(src, []byte("7045")) {
		c.approx("Signalith reads only services installed (event 7045) from the System log, and this rule is about other events")
	}
	expr, err := c.condition(condStr, r.Detection)
	if err != nil {
		return nil, err
	}
	if c.err != nil {
		return nil, c.err
	}
	if scope := productScope(r.Logsource, c.category); scope != nil {
		expr = and([]query.Expr{scope, expr})
	}
	q := &query.Query{Datamodel: dm, Search: expr}

	d := &Detection{
		ID:          sigmaID(r),
		Title:       r.Title,
		Description: strings.TrimSpace(r.Description),
		Query:       q.String(),
		Schedule:    "5m",
		Lookback:    "10m",
		Severity:    "medium",
		Enabled:     false,
		Tags:        []string{"sigma"},
		Throttle:    Throttle{Window: "1h"},
	}
	if s, ok := sigmaLevels[strings.ToLower(r.Level)]; ok {
		d.Severity = s
	}
	seen := map[string]bool{}
	for _, t := range r.Tags {
		if m := sigmaTechnique.FindStringSubmatch(strings.ToLower(t)); m != nil {
			id := strings.ToUpper(m[1])
			if !seen[id] {
				seen[id] = true
				d.MITRE = append(d.MITRE, id)
			}
		}
	}
	if len(r.FalsePos) > 0 {
		d.Guidance = "Known false positives: " + strings.Join(r.FalsePos, "; ")
	}
	if r.Status != "" && r.Status != "stable" && r.Status != "test" {
		c.warn("rule status is %q; review it before enabling", r.Status)
	}
	if dm == "" {
		c.warn("log source %v has no Signalith data model, so the rule searches all events", r.Logsource)
	}
	d.Defaults()
	if err := d.Validate(); err != nil {
		return nil, err
	}
	sort.Strings(c.warnings)
	return &SigmaResult{Detection: d, Warnings: dedupe(c.warnings)}, nil
}

func dedupe(xs []string) []string {
	var out []string
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

var nonID = regexp.MustCompile(`[^a-z0-9]+`)

func sigmaID(r sigmaRule) string {
	slug := strings.Trim(nonID.ReplaceAllString(strings.ToLower(r.Title), "-"), "-")
	if len(slug) > 48 {
		slug = strings.TrimRight(slug[:48], "-")
	}
	id := "sigma-" + slug
	if len(id) < 3 {
		id = "sigma-rule"
	}
	return id
}

type sigmaConv struct {
	strict   bool
	category string // the log source category, lower case
	warnings []string
	err      error // the first approximation, in strict mode
}

func (c *sigmaConv) warn(format string, args ...any) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

// approx records an approximation: a warning, or in strict mode an error.
func (c *sigmaConv) approx(format string, args ...any) {
	if c.strict && c.err == nil {
		c.err = fmt.Errorf(format, args...)
	}
	c.warn(format, args...)
}

// windowsSourcetypes matches every event the Windows parser writes, from
// Fluent Bit and from the OpenTelemetry Collector alike.
const windowsSourcetypes = "WinEventLog:*"

// productScope limits a rule to its operating system's events: a Windows
// rule to Windows events of its log source's event IDs, and a Linux or
// macOS rule away from Windows events, since data models such as Endpoint
// hold events from every system and several kinds of event.
func productScope(ls map[string]any, category string) query.Expr {
	p, _ := ls["product"].(string)
	switch strings.ToLower(p) {
	case "windows":
		st := &query.Compare{Field: "sourcetype", Op: "=", Value: windowsSourcetypes}
		if ids := sigmaWindowsEvents[category]; len(ids) > 0 {
			return and([]query.Expr{st, &query.In{Field: "signature_id", Values: ids}})
		}
		return st
	case "linux", "macos":
		return &query.Not{Child: &query.Compare{Field: "sourcetype", Op: "=", Value: windowsSourcetypes}}
	}
	return nil
}

func (c *sigmaConv) datamodel(ls map[string]any) string {
	get := func(k string) string { s, _ := ls[k].(string); return strings.ToLower(s) }
	switch c.category {
	case "process_creation":
		return "Endpoint"
	case "network_connection", "firewall":
		return "Network_Traffic"
	case "authentication":
		return "Authentication"
	case "antivirus":
		return "Malware"
	case "file_event", "file_delete":
		return "Filesystem"
	case "registry_add", "registry_delete", "registry_set", "registry_event":
		return "Registry"
	case "dns_query":
		return "Network_Resolution"
	case "image_load", "driver_load":
		return "Image_Load"
	case "process_access", "create_remote_thread":
		return "Endpoint"
	case "ps_script":
		return "Script"
	case "system":
		return "Change"
	}
	if id, ok := strings.CutPrefix(c.category, "security_"); ok {
		return sigmaSecurityModels[id]
	}
	if get("product") == "linux" && get("service") == "auth" {
		return "Authentication"
	}
	return ""
}

func (c *sigmaConv) field(name string) string {
	if m, ok := sigmaEventFields[c.category]; ok {
		if f := m[strings.ToLower(name)]; f != "" {
			return f
		}
		c.approx("field %s has no Signalith mapping in %s and is searched as-is", name, c.category)
		return name
	}
	if f, ok := sigmaFields[strings.ToLower(name)]; ok {
		return f
	}
	c.approx("field %s has no Signalith mapping and is searched as-is", name)
	return name
}

// ---- condition expressions ----

func (c *sigmaConv) condition(cond string, det map[string]any) (query.Expr, error) {
	toks := tokenizeCondition(cond)
	p := &condParser{toks: toks, det: det, conv: c}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("condition: unexpected %q", p.toks[p.pos])
	}
	return e, nil
}

func tokenizeCondition(s string) []string {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(s)
}

type condParser struct {
	toks []string
	pos  int
	det  map[string]any
	conv *sigmaConv
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return strings.ToLower(p.toks[p.pos])
	}
	return ""
}

func (p *condParser) or() (query.Expr, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	kids := []query.Expr{left}
	for p.peek() == "or" {
		p.pos++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	return or(kids), nil
}

func (p *condParser) and() (query.Expr, error) {
	left, err := p.not()
	if err != nil {
		return nil, err
	}
	kids := []query.Expr{left}
	for p.peek() == "and" {
		p.pos++
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	return and(kids), nil
}

func (p *condParser) not() (query.Expr, error) {
	if p.peek() == "not" {
		p.pos++
		e, err := p.not()
		if err != nil {
			return nil, err
		}
		return &query.Not{Child: e}, nil
	}
	return p.primary()
}

func (p *condParser) primary() (query.Expr, error) {
	t := p.peek()
	switch {
	case t == "":
		return nil, errors.New("condition ended early")
	case t == "(":
		p.pos++
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("condition: missing )")
		}
		p.pos++
		return e, nil
	case t == "1" || t == "all" || t == "any":
		p.pos++
		if p.peek() != "of" {
			return nil, fmt.Errorf("condition: expected 'of' after %q", t)
		}
		p.pos++
		if p.pos >= len(p.toks) {
			return nil, errors.New("condition: 'of' needs a selection name, pattern or 'them'")
		}
		pat := p.toks[p.pos]
		p.pos++
		names := p.match(pat)
		if len(names) == 0 {
			return nil, fmt.Errorf("condition: no selection matches %q", pat)
		}
		var kids []query.Expr
		for _, n := range names {
			e, err := p.conv.selection(n, p.det[n])
			if err != nil {
				return nil, err
			}
			kids = append(kids, e)
		}
		if t == "all" {
			return and(kids), nil
		}
		return or(kids), nil
	}
	name := p.toks[p.pos]
	p.pos++
	v, ok := p.det[name]
	if !ok || name == "condition" {
		return nil, fmt.Errorf("condition refers to unknown selection %q", name)
	}
	return p.conv.selection(name, v)
}

func (p *condParser) match(pat string) []string {
	var out []string
	for k := range p.det {
		if k == "condition" || k == "timeframe" {
			continue
		}
		if pat == "them" || k == pat || (strings.HasSuffix(pat, "*") && strings.HasPrefix(k, strings.TrimSuffix(pat, "*"))) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// uniq drops repeated expressions, which arise when two Sigma fields map
// to the same Signalith field.
func uniq(kids []query.Expr) []query.Expr {
	seen := map[string]bool{}
	out := kids[:0:0]
	for _, k := range kids {
		if s := k.String(); !seen[s] {
			seen[s] = true
			out = append(out, k)
		}
	}
	return out
}

func and(kids []query.Expr) query.Expr {
	kids = uniq(kids)
	if len(kids) == 1 {
		return kids[0]
	}
	return &query.And{Children: kids}
}

func or(kids []query.Expr) query.Expr {
	kids = uniq(kids)
	if len(kids) == 1 {
		return kids[0]
	}
	return &query.Or{Children: kids}
}

// ---- selections ----

func (c *sigmaConv) selection(name string, v any) (query.Expr, error) {
	switch s := v.(type) {
	case map[string]any:
		return c.fieldMap(s)
	case []any:
		var kids []query.Expr
		for _, item := range s {
			switch it := item.(type) {
			case map[string]any:
				e, err := c.fieldMap(it)
				if err != nil {
					return nil, err
				}
				kids = append(kids, e)
			default:
				// Keyword list: free-text search of the raw event.
				c.approx("selection %s searches free text, which matches words of the raw event rather than exact values", name)
				kids = append(kids, &query.Text{Value: "*" + sigmaString(it) + "*"})
			}
		}
		if len(kids) == 0 {
			return nil, fmt.Errorf("selection %s is empty", name)
		}
		return or(kids), nil
	case string:
		c.approx("selection %s searches free text, which matches words of the raw event rather than exact values", name)
		return &query.Text{Value: "*" + s + "*"}, nil
	}
	return nil, fmt.Errorf("selection %s has an unsupported shape", name)
}

func (c *sigmaConv) fieldMap(m map[string]any) (query.Expr, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var kids []query.Expr
	for _, k := range keys {
		e, err := c.fieldCond(k, m[k])
		if err != nil {
			return nil, err
		}
		kids = append(kids, e)
	}
	if len(kids) == 0 {
		return nil, errors.New("empty selection")
	}
	return and(kids), nil
}

func sigmaString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func (c *sigmaConv) fieldCond(key string, v any) (query.Expr, error) {
	parts := strings.Split(key, "|")
	sigField, mods := parts[0], parts[1:]
	field := c.field(sigField)
	var values []any
	switch vv := v.(type) {
	case []any:
		values = vv
	default:
		values = []any{vv}
	}
	all := false
	how := "equals"
	// transforms apply in order to each value before matching.
	var transforms []string
	for _, m := range mods {
		switch lm := strings.ToLower(m); lm {
		case "contains", "startswith", "endswith", "cidr":
			how = lm
		case "all":
			all = true
		case "windash", "base64", "base64offset", "utf16le", "wide", "utf16be", "utf16":
			transforms = append(transforms, lm)
		case "exists":
			if b, ok := v.(bool); ok && !b {
				return &query.Not{Child: &query.Compare{Field: field, Op: "=", Value: "*"}}, nil
			}
			if s, ok := v.(string); ok && strings.EqualFold(s, "false") {
				return &query.Not{Child: &query.Compare{Field: field, Op: "=", Value: "*"}}, nil
			}
			return &query.Compare{Field: field, Op: "=", Value: "*"}, nil
		case "cased":
			c.approx("%s: |cased is matched case-insensitively", key)
		default:
			return nil, fmt.Errorf("Sigma modifier |%s (in %s) is not supported", m, key)
		}
	}
	var kids []query.Expr
	for _, raw := range values {
		if raw == nil || sigmaString(raw) == "" {
			// Signalith does not store empty values, so an empty value
			// and a missing field are the same.
			kids = append(kids, &query.Not{Child: &query.Compare{Field: field, Op: "=", Value: "*"}})
			continue
		}
		s := sigmaString(raw)
		if field == "direction" {
			// Sysmon's Initiated is stored as the direction it implies.
			switch strings.ToLower(s) {
			case "true":
				s = "outbound"
			case "false":
				s = "inbound"
			}
		}
		if how == "cidr" {
			p, err := netip.ParsePrefix(s)
			if err != nil || !p.Addr().Is4() {
				return nil, fmt.Errorf("%s: only IPv4 ranges are supported, not %q", key, s)
			}
			kids = append(kids, &query.Compare{Field: field, Op: "=", Value: p.Masked().String()})
			continue
		}
		var variants []string
		if len(transforms) > 0 {
			// Transformed values are literal text: the encodings have no
			// wildcards of their own.
			lit, err := sigmaLiteral(s)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			variants = []string{lit}
			for _, t := range transforms {
				variants = transform(t, variants)
			}
			for i, v := range variants {
				if strings.ContainsAny(v, "*?") {
					return nil, fmt.Errorf("%s: the %s form of %q holds a wildcard character", key, strings.Join(transforms, "|"), s)
				}
				if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 && r != '\t' }) {
					return nil, fmt.Errorf("%s: the %s form of %q is binary", key, strings.Join(transforms, "|"), s)
				}
				variants[i] = v
			}
		} else {
			v, err := sigmaValue(s)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			variants = []string{v}
		}
		var vk []query.Expr
		for _, s := range variants {
			switch how {
			case "contains":
				s = "*" + s + "*"
			case "startswith":
				s = s + "*"
			case "endswith":
				s = "*" + s
			}
			vk = append(vk, c.compare(field, sigField, how, s))
		}
		kids = append(kids, or(vk))
	}
	if all {
		return and(kids), nil
	}
	return or(kids), nil
}

// pathNames are the path fields whose file name every parser that sets
// them also stores.
var pathNames = map[string]string{
	"process_path": "process_name", "parent_process_path": "parent_process_name",
	"target_process_path": "target_process_name", "loaded_file_path": "loaded_file_name",
}

// compare builds field=value, preferring process_name over a path
// suffix match since it is cheaper and exact.
func (c *sigmaConv) compare(field, sigField, how, s string) query.Expr {
	if name, ok := pathNames[field]; ok && how == "endswith" {
		rest := strings.TrimPrefix(s, "*")
		if i := strings.LastIndexAny(rest, `\/`); i == 0 && !strings.ContainsAny(rest[1:], `*?\/`) {
			return &query.Compare{Field: name, Op: "=", Value: rest[1:]}
		}
	}
	return &query.Compare{Field: field, Op: "=", Value: s}
}

// sigmaValue resolves Sigma escapes: \\ is a backslash; \* and \? are
// literal wildcards, which Signalith cannot express inside a pattern.
func sigmaValue(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				b.WriteByte('\\')
				i++
				continue
			case '*', '?':
				return "", fmt.Errorf("escaped wildcard \\%c is not supported", s[i+1])
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), nil
}

// sigmaLiteral resolves a value's escapes and refuses wildcards, for
// values that are encoded before matching.
func sigmaLiteral(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\') {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '*' || c == '?' {
			return "", fmt.Errorf("a wildcard in %q cannot be encoded", s)
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

// transform applies one value-transforming Sigma modifier to each
// variant.
func transform(t string, vs []string) []string {
	var out []string
	for _, v := range vs {
		switch t {
		case "windash":
			out = append(out, windashVariants(v)...)
		case "base64":
			out = append(out, base64.StdEncoding.EncodeToString([]byte(v)))
		case "base64offset":
			out = append(out, base64Offsets(v)...)
		case "utf16le", "wide":
			out = append(out, encodeUTF16(v, false, false))
		case "utf16be":
			out = append(out, encodeUTF16(v, true, false))
		case "utf16":
			out = append(out, encodeUTF16(v, false, true))
		}
	}
	return out
}

func encodeUTF16(s string, bigEndian, bom bool) string {
	var b []byte
	if bom {
		b = append(b, 0xff, 0xfe)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			b = append(b, byte(u>>8), byte(u))
		} else {
			b = append(b, byte(u), byte(u>>8))
		}
	}
	return string(b)
}

// base64Offsets returns the base64 text of s at each of the three byte
// offsets it can start at inside longer data, cut to the characters that
// do not depend on the bytes around it (Sigma's |base64offset).
func base64Offsets(s string) []string {
	cutStart := [3]int{0, 2, 3}
	cutEnd := [3]int{0, 3, 2}
	var out []string
	for i := range 3 {
		enc := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{' '}, i), s...))
		end := len(enc) - cutEnd[(len(s)+i)%3]
		if end > cutStart[i] {
			out = append(out, enc[cutStart[i]:end])
		}
	}
	return out
}

// windashVariants expands - and / at the start of a command-line switch
// (after a non-word character or the start, before a word character) into
// every dash form Windows accepts, as Sigma's |windash defines it.
func windashVariants(s string) []string {
	dashes := []string{"-", "/", "–", "—", "―"}
	rs := []rune(s)
	word := func(r rune) bool {
		return r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range dashes {
		var b strings.Builder
		for i, r := range rs {
			if (r == '-' || r == '/') && (i == 0 || !word(rs[i-1])) && i+1 < len(rs) && word(rs[i+1]) {
				b.WriteString(d)
				continue
			}
			b.WriteRune(r)
		}
		if v := b.String(); !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
