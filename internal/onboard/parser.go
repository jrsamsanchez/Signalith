// Package onboard helps an admin bring in logs Signalith has no parser
// for. Given a sample, it works out the format (JSON, key=value, CSV,
// CEF, LEEF, syslog, or a regular expression for free text), suggests a
// sourcetype, a data model and which fields map onto it, previews the
// events, and lists the detections that could use them. Once saved, a
// custom parser runs on the records agents send under its tag
// (ingest.CustomTagPrefix + name) and on syslog messages from the
// programs it names.
//
// Everything here works offline. An AI model, when one is set up, can
// refine a suggestion (see Refine), and its answer goes through the same
// checks as an admin's.
package onboard

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// Formats a parser reads the body of a line as.
const (
	FormatJSON  = "json"
	FormatKV    = "kv"
	FormatCSV   = "csv"
	FormatCEF   = "cef"
	FormatLEEF  = "leef"
	FormatRegex = "regex"
	// FormatText keeps the line as it is: the message, searchable by text.
	FormatText = "text"
)

// Formats lists the formats, in the order the page offers them.
var Formats = []string{FormatJSON, FormatKV, FormatCSV, FormatCEF, FormatLEEF, FormatRegex, FormatText}

// HeaderSyslog says each line starts with a syslog header (RFC 3164 or
// RFC 5424), whose time, host and program are read before the body.
const HeaderSyslog = "syslog"

// Limits on what a parser may hold, so a saved one stays cheap to run on
// every record.
const (
	MaxParsers = 100
	MaxPattern = 2000
	// maxProgInst caps a pattern's compiled size, and maxRepeat its
	// counted repeats: Go's matcher takes time in proportion to both
	// and the line, so together with maxRegexInput they bound what one
	// line costs.
	maxProgInst    = 500
	maxRepeat      = 100
	maxRegexInput  = 8 << 10
	MaxColumns     = 128
	MaxMappings    = 128
	MaxSyslogApps  = 16
	MaxDescription = 500
	// MaxLine is the longest line a parser reads; the rest is kept in the
	// message only.
	MaxLine = 16 << 10
	// maxFields caps the fields one line gives.
	maxFields = 150
	// maxJSONDepth is how deep a JSON body is flattened into dotted names.
	maxJSONDepth = 4
)

// Parser is a custom parser as an admin saves it.
type Parser struct {
	// Name is the parser's id, and the end of its tag (custom.<name>).
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Sourcetype names the events, as searches and detections filter
	// them (sourcetype=acme:firewall).
	Sourcetype    string `json:"sourcetype"`
	VendorProduct string `json:"vendor_product,omitempty"`
	// Model is the data model the events are filed under.
	Model string `json:"model"`
	// Header is HeaderSyslog when lines start with a syslog header.
	Header string `json:"header,omitempty"`
	Format string `json:"format"`
	// Delimiter separates CSV columns, or key=value pairs ("" for any
	// white space).
	Delimiter string `json:"delimiter,omitempty"`
	// KVSeparator is between a key and its value: "=" (the default) or ":".
	KVSeparator string `json:"kv_separator,omitempty"`
	// Columns names the CSV columns, in order.
	Columns []string `json:"columns,omitempty"`
	// Pattern is a regular expression (RE2) whose named groups are the
	// fields, for FormatRegex.
	Pattern string `json:"pattern,omitempty"`
	// TimeField holds the event time, read as TimeFormat (see TimeFormats).
	TimeField  string `json:"time_field,omitempty"`
	TimeFormat string `json:"time_format,omitempty"`
	// Mappings rename fields onto the data model's names.
	Mappings []Mapping `json:"mappings,omitempty"`
	// KeepAction leaves action values as they are; otherwise common
	// words (accept, deny, failed...) become the data model's values
	// (allowed, blocked, success, failure) and the original is kept as
	// vendor_action.
	KeepAction bool `json:"keep_action,omitempty"`
	// SyslogApps applies the parser to syslog messages from these
	// programs (the APP-NAME or tag of the header), too.
	SyslogApps []string `json:"syslog_apps,omitempty"`

	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Mapping renames the field From to To, a data model field.
type Mapping struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Tag is the tag records for the parser are sent under.
func (p *Parser) Tag() string { return ingest.CustomTagPrefix + p.Name }

var (
	nameRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,47}$`)
	sourcetypeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.\-]{0,63}$`)
	appRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,63}$`)
)

// ValidName reports whether name can name a parser.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// InputError is a problem with a parser an admin asked to save or try.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func inputErr(format string, args ...any) error { return &InputError{fmt.Sprintf(format, args...)} }

// targetsOK are the common fields a mapping may write besides a data
// model's own; the others (_time, sourcetype, datamodel...) are set by
// the parser or by Signalith.
var targetsOK = []string{"host", "vendor_product", "signature", "signature_id"}

// MappingTargets lists the fields a mapping may write for a data model:
// the model's own fields first, then those of the other models (the
// index maps them all), then targetsOK. Risk's fields are never offered:
// risk is what detections attribute, not what senders say.
func MappingTargets(model string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if m, ok := datamodel.Get(model); ok {
		for _, f := range m.Fields {
			add(f.Name)
		}
	}
	add("host")
	add("vendor_product")
	add("signature")
	add("signature_id")
	for _, m := range datamodel.Models {
		if m.Name == datamodel.RiskModel {
			continue
		}
		for _, f := range m.Fields {
			if !riskOnly(f.Name) {
				add(f.Name)
			}
		}
	}
	return out
}

func riskOnly(name string) bool {
	return strings.HasPrefix(name, "risk_") || name == "detection_id"
}

// Models lists the data models a parser may file events under: all but
// Risk, which only detections write.
func Models() []string {
	var out []string
	for _, m := range datamodel.Models {
		if m.Name != datamodel.RiskModel {
			out = append(out, m.Name)
		}
	}
	return out
}

// Normalize trims what an admin typed and fills the defaults.
func (p *Parser) Normalize() {
	p.Name = strings.ToLower(strings.TrimSpace(p.Name))
	p.Description = strings.TrimSpace(p.Description)
	p.Sourcetype = strings.TrimSpace(p.Sourcetype)
	p.VendorProduct = strings.TrimSpace(p.VendorProduct)
	p.Format = strings.ToLower(strings.TrimSpace(p.Format))
	p.Header = strings.ToLower(strings.TrimSpace(p.Header))
	if p.Format == FormatKV && p.KVSeparator == "" {
		p.KVSeparator = "="
	}
	if p.Format == FormatCSV && p.Delimiter == "" {
		p.Delimiter = ","
	}
	if m, ok := datamodel.Get(strings.TrimSpace(p.Model)); ok {
		p.Model = m.Name
	}
	p.TimeField = strings.TrimSpace(p.TimeField)
	if p.TimeField == "" {
		p.TimeFormat = ""
	}
	for i := range p.Columns {
		p.Columns[i] = strings.TrimSpace(p.Columns[i])
	}
	maps := p.Mappings[:0]
	for _, m := range p.Mappings {
		m.From, m.To = strings.TrimSpace(m.From), strings.TrimSpace(m.To)
		if m.From != "" && m.To != "" && m.From != m.To {
			maps = append(maps, m)
		}
	}
	p.Mappings = maps
	apps := p.SyslogApps[:0]
	for _, a := range p.SyslogApps {
		if a = strings.TrimSpace(a); a != "" && !slices.Contains(apps, a) {
			apps = append(apps, a)
		}
	}
	p.SyslogApps = apps
}

// Validate checks a parser and returns every problem at once. Preview
// checks the same, without the name.
func (p *Parser) Validate() error {
	var probs []string
	if !nameRE.MatchString(p.Name) {
		probs = append(probs, "The name must be 2 to 48 lowercase letters, digits, - or _, starting with a letter or digit.")
	}
	if err := p.check(); err != nil {
		probs = append(probs, err.Error())
	}
	if len(probs) > 0 {
		return &InputError{strings.Join(probs, " ")}
	}
	return nil
}

// check is Validate without the name.
func (p *Parser) check() error {
	var probs []string
	bad := func(format string, args ...any) { probs = append(probs, fmt.Sprintf(format, args...)) }
	if !sourcetypeRE.MatchString(p.Sourcetype) {
		bad("The sourcetype must be 1 to 64 letters, digits, : _ . or -, such as acme:firewall.")
	}
	if utf8.RuneCountInString(p.Description) > MaxDescription {
		bad("The description can be at most %d characters.", MaxDescription)
	}
	if len(p.VendorProduct) > 128 {
		bad("The product name can be at most 128 characters.")
	}
	if _, ok := datamodel.Get(p.Model); !ok || p.Model == datamodel.RiskModel {
		bad("Choose one of the data models: %s.", strings.Join(Models(), ", "))
	}
	if p.Header != "" && p.Header != HeaderSyslog {
		bad(`The header is "syslog" or empty.`)
	}
	switch p.Format {
	case FormatJSON, FormatCEF, FormatLEEF, FormatText:
	case FormatKV:
		if p.KVSeparator != "=" && p.KVSeparator != ":" {
			bad(`Keys and values are separated by "=" or ":".`)
		}
		if !slices.Contains([]string{"", ",", ";", "|", "\t"}, p.Delimiter) {
			bad("Pairs are separated by spaces, commas, semicolons, | or tabs.")
		}
	case FormatCSV:
		if !slices.Contains([]string{",", ";", "|", "\t"}, p.Delimiter) {
			bad("CSV columns are separated by commas, semicolons, | or tabs.")
		}
		if len(p.Columns) == 0 {
			bad("Name the CSV columns.")
		}
		if len(p.Columns) > MaxColumns {
			bad("A CSV parser can name at most %d columns.", MaxColumns)
		}
		seen := map[string]bool{}
		for _, c := range p.Columns {
			if c == "" {
				continue // a column left out
			}
			if !ingest.ValidFieldName(c) {
				bad("The column name %q is not a valid field name: use letters, digits, _ and -, starting with a letter.", c)
			} else if seen[c] {
				bad("The column name %q is used twice.", c)
			}
			seen[c] = true
		}
	case FormatRegex:
		if _, err := compilePattern(p.Pattern); err != nil {
			bad("%s", err.Error())
		}
	default:
		bad("The format is one of %s.", strings.Join(Formats, ", "))
	}
	if p.TimeField != "" {
		names := strings.Split(p.TimeField, "+")
		for _, n := range names {
			if !ingest.ValidFieldName(n) || len(names) > 2 {
				bad("The time field %q is not a valid field name, or two joined with + (date+time).", p.TimeField)
				break
			}
		}
		if p.TimeFormat != "" && timeFormat(p.TimeFormat) == nil {
			bad("The time format %q is not one Signalith reads.", p.TimeFormat)
		}
	}
	if len(p.Mappings) > MaxMappings {
		bad("A parser can rename at most %d fields.", MaxMappings)
	}
	targets := MappingTargets(p.Model)
	from := map[string]bool{}
	for _, m := range p.Mappings {
		if !ingest.ValidFieldName(m.From) {
			bad("%q is not a valid field name.", m.From)
		}
		if !slices.Contains(targets, m.To) {
			bad("%q is not a data model field a parser can fill.", m.To)
		}
		if from[m.From] {
			bad("The field %q is renamed twice.", m.From)
		}
		from[m.From] = true
	}
	if len(p.SyslogApps) > MaxSyslogApps {
		bad("A parser can name at most %d syslog programs.", MaxSyslogApps)
	}
	for _, a := range p.SyslogApps {
		if !appRE.MatchString(a) {
			bad("%q is not a program name syslog sends: use letters, digits, _ . - and /.", a)
		}
	}
	if len(probs) > 0 {
		return errors.New(strings.Join(probs, " "))
	}
	return nil
}

// compilePattern compiles a parser's regular expression. Go's regexp is
// RE2: matching takes time linear in the line, never backtracks, and has
// no look-around. The pattern is also capped in length and in compiled
// size, and needs at least one named group.
func compilePattern(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, errors.New("Write a regular expression with named groups, such as (?P<user>\\S+).")
	}
	if len(pattern) > MaxPattern {
		return nil, fmt.Errorf("The regular expression can be at most %d characters.", MaxPattern)
	}
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("The regular expression does not compile: %v.", err)
	}
	if err := checkRepeats(re); err != nil {
		return nil, err
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, fmt.Errorf("The regular expression does not compile: %v.", err)
	}
	if len(prog.Inst) > maxProgInst {
		return nil, errors.New("The regular expression is too large; use fewer or shorter repeats.")
	}
	rx, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("The regular expression does not compile: %v.", err)
	}
	named := 0
	for _, n := range rx.SubexpNames() {
		if n == "" {
			continue
		}
		if !ingest.ValidFieldName(n) {
			return nil, fmt.Errorf("The group name %q is not a valid field name.", n)
		}
		named++
	}
	if named == 0 {
		return nil, errors.New("The regular expression needs at least one named group, such as (?P<user>\\S+), to make a field.")
	}
	if named > maxFields {
		return nil, fmt.Errorf("The regular expression can have at most %d named groups.", maxFields)
	}
	return rx, nil
}

// checkRepeats refuses counted repeats over maxRepeat, such as
// (?:\w\s?){0,1000}, which make a short pattern slow on every line.
func checkRepeats(re *syntax.Regexp) error {
	if re.Op == syntax.OpRepeat && (re.Min > maxRepeat || re.Max > maxRepeat) {
		return fmt.Errorf("Counted repeats such as {1,%d} can be at most %d.", maxRepeat, maxRepeat)
	}
	for _, s := range re.Sub {
		if err := checkRepeats(s); err != nil {
			return err
		}
	}
	return nil
}

// Compiled is a checked parser, ready to run.
type Compiled struct {
	P       Parser
	re      *regexp.Regexp
	rename  map[string]string
	time    *TimeFormatSpec
	numeric map[string]bool
}

// Compile checks a parser and readies it. The name is not checked, so a
// parser being tried out need not have one yet.
func Compile(p Parser) (*Compiled, error) {
	p.Normalize()
	if err := p.check(); err != nil {
		return nil, &InputError{err.Error()}
	}
	c := &Compiled{P: p, rename: map[string]string{}, numeric: numericFields()}
	if p.Format == FormatRegex {
		c.re, _ = compilePattern(p.Pattern)
	}
	for _, m := range p.Mappings {
		c.rename[m.From] = m.To
	}
	if p.TimeFormat != "" {
		c.time = timeFormat(p.TimeFormat)
	}
	return c, nil
}

// numericFields are the data model fields stored as numbers.
func numericFields() map[string]bool {
	out := map[string]bool{}
	for _, m := range datamodel.Models {
		for _, f := range m.Fields {
			if f.Type == "number" {
				out[f.Name] = true
			}
		}
	}
	return out
}

// Line returns the text of a record an agent sent: the line it read
// (log, or message), or "" for a record that is already structured,
// such as JSON a script sent.
func Line(r map[string]any) (string, bool) {
	for _, k := range []string{"log", "message", "MESSAGE"} {
		if s, ok := r[k].(string); ok {
			return s, true
		}
	}
	return "", false
}

// ParseRecord parses one record an agent sent. drop reports a line that
// is no event: a blank line, or a CSV file's header.
func (c *Compiled) ParseRecord(r map[string]any, now time.Time) (ev ingest.Event, drop bool) {
	line, ok := Line(r)
	if !ok {
		// Structured already: a JSON record sent by a script.
		if c.P.Format != FormatJSON {
			b, _ := json.Marshal(r)
			line = string(b)
		} else {
			fields := map[string]any{}
			flatten(fields, "", r, 0)
			b, _ := json.Marshal(r)
			return c.finish(fields, string(b), time.Time{}, "", "", now), false
		}
	}
	return c.ParseLine(line, now)
}

// ParseLine parses one line.
func (c *Compiled) ParseLine(line string, now time.Time) (ev ingest.Event, drop bool) {
	ev, drop, _ = c.parseLine(line, now)
	return ev, drop
}

// parseLine is ParseLine, and says how many fields the line's body gave
// (those of a syslog header aside).
func (c *Compiled) parseLine(line string, now time.Time) (ev ingest.Event, drop bool, read int) {
	line = strings.TrimRight(line, "\r\n\x00")
	if strings.TrimSpace(line) == "" {
		return ingest.Event{}, true, 0
	}
	raw := line
	if len(line) > MaxLine {
		line = line[:MaxLine]
	}
	body := line
	var hdrTime time.Time
	var host, app string
	if c.P.Header == HeaderSyslog || c.P.Format == FormatCEF || c.P.Format == FormatLEEF {
		m := syslog.Parse([]byte(line), now)
		if c.P.Format == FormatCEF || c.P.Format == FormatLEEF {
			if c.P.Format == FormatCEF && m.CEF == nil || c.P.Format == FormatLEEF && m.LEEF == nil {
				// Not the record the parser expects: kept as text.
				return c.finish(map[string]any{}, raw, time.Time{}, "", "", now), false, 0
			}
			sev := m.Event(netip.Addr{}, now, 0)
			f := sev.Fields
			delete(f, "dvc")
			delete(f, "message")
			if h, _ := f["host"].(string); h == "" {
				delete(f, "host")
			}
			return c.finish(f, raw, sev.Time, "", "", now), false, len(f)
		}
		if m.Format != "raw" {
			hdrTime, host, app, body = m.Time, m.Hostname, m.AppName, m.Text
		}
	}
	fields, ok := c.parseBody(body)
	if !ok && c.P.Format == FormatCSV {
		return ingest.Event{}, true, 0
	}
	return c.finish(fields, raw, hdrTime, host, app, now), false, len(fields)
}

// parseBody reads the body of a line in the parser's format. It reports
// false for a CSV header line.
func (c *Compiled) parseBody(body string) (map[string]any, bool) {
	fields := map[string]any{}
	switch c.P.Format {
	case FormatJSON:
		var v map[string]any
		dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(body)))
		dec.UseNumber()
		if dec.Decode(&v) == nil {
			flatten(fields, "", v, 0)
		}
	case FormatKV:
		for _, kv := range ParseKV(body, c.P.KVSeparator, c.P.Delimiter) {
			if len(fields) >= maxFields {
				break
			}
			if _, dup := fields[kv[0]]; !dup {
				fields[kv[0]] = kv[1]
			}
		}
	case FormatCSV:
		row := csvRow(body, c.P.Delimiter)
		header := len(row) == len(c.P.Columns)
		for i, v := range row {
			name := ""
			if i < len(c.P.Columns) {
				name = c.P.Columns[i]
				if !strings.EqualFold(columnName(v), name) {
					header = false
				}
			} else if i < MaxColumns {
				name = "column" + strconv.Itoa(i+1)
			}
			if name != "" && v != "" {
				fields[name] = v
			}
		}
		if header {
			return nil, false
		}
	case FormatRegex:
		if len(body) > maxRegexInput {
			body = body[:maxRegexInput]
		}
		m := c.re.FindStringSubmatch(body)
		if m != nil {
			for i, n := range c.re.SubexpNames() {
				if n != "" && i < len(m) && m[i] != "" {
					if _, dup := fields[n]; !dup {
						fields[n] = m[i]
					}
				}
			}
		}
	}
	return fields, true
}

// finish renames, types and times a line's fields and makes the event.
func (c *Compiled) finish(fields map[string]any, raw string, hdrTime time.Time, host, app string, now time.Time) ingest.Event {
	out := make(map[string]any, len(fields)+6)
	for k, v := range fields {
		name := SanitizeName(k)
		if name == "" {
			continue
		}
		if to, ok := c.rename[name]; ok {
			name = to
		} else if to, ok := c.rename[k]; ok {
			name = to
		}
		if _, dup := out[name]; dup {
			continue
		}
		if s, ok := v.(string); ok {
			v = ingest.CapValue(s)
		}
		out[name] = v
	}
	t := hdrTime
	if c.P.TimeField != "" {
		names := strings.Split(c.P.TimeField, "+")
		var parts []string
		for _, n := range names {
			if v, ok := out[n]; ok {
				parts = append(parts, fmt.Sprint(v))
			}
		}
		if len(parts) == len(names) {
			var v any = strings.Join(parts, " ")
			if len(names) == 1 {
				v = out[names[0]]
			}
			if pt, ok := parseTimeValue(v, c.time, now); ok {
				t = pt
				for _, n := range names {
					delete(out, n)
				}
			}
		}
	}
	if tr, ok := out["transport"]; ok {
		if name, ok := ipProtocols[fmt.Sprint(tr)]; ok {
			out["transport"] = name
		}
	}
	for k, v := range out {
		if c.numeric[k] {
			if s, ok := v.(string); ok {
				if n, ok := number(s); ok {
					out[k] = n
				}
			}
		}
	}
	if !c.P.KeepAction {
		if a, ok := out["action"].(string); ok {
			if n := NormalAction(c.P.Model, a); n != "" && n != a {
				out["action"] = n
				if _, has := out["vendor_action"]; !has {
					out["vendor_action"] = a
				}
			}
		}
	}
	if _, ok := out["host"]; !ok && host != "" && host != "-" {
		out["host"] = ingest.CapValue(host)
	}
	if _, ok := out["app"]; !ok && app != "" && app != "-" {
		out["app"] = ingest.CapValue(app)
	}
	out["sourcetype"] = c.P.Sourcetype
	if c.P.VendorProduct != "" {
		out["vendor_product"] = c.P.VendorProduct
	}
	out["message"] = raw
	for k := range out {
		if ingest.Reserved(k) {
			delete(out, k)
		}
	}
	return ingest.Event{Time: t, Model: c.P.Model, Fields: out}
}

// ipProtocols names IP protocol numbers, for a transport field.
var ipProtocols = map[string]string{"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ah", "58": "icmpv6", "132": "sctp"}

// number reads a number from a string: an integer, or a decimal.
func number(s string) (any, bool) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !strings.ContainsAny(s, "eEnN") {
		return f, true
	}
	return nil, false
}

// SanitizeName makes a sender's key a field name: characters a field
// name cannot hold become _, and a name that still is not valid, or is
// one Signalith sets itself, is dropped ("").
func SanitizeName(k string) string {
	if ingest.ValidFieldName(k) {
		return k
	}
	var b strings.Builder
	for _, r := range k {
		switch {
		case r == '.' || r == '_' || r == '-' || r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() > 128 {
			break
		}
	}
	s := strings.Trim(b.String(), "._-")
	for strings.Contains(s, "..") {
		s = strings.ReplaceAll(s, "..", ".")
	}
	if s != "" && (s[0] >= '0' && s[0] <= '9') {
		s = "f" + s
	}
	if !ingest.ValidFieldName(s) {
		return ""
	}
	return s
}

// flatten copies a JSON object's values into f under dotted names; lists
// and objects deeper than maxJSONDepth are kept as JSON text.
func flatten(f map[string]any, prefix string, v map[string]any, depth int) {
	for k, x := range v {
		if len(f) >= maxFields {
			return
		}
		name := k
		if prefix != "" {
			name = prefix + "." + k
		}
		switch y := x.(type) {
		case map[string]any:
			if depth+1 < maxJSONDepth {
				flatten(f, name, y, depth+1)
				continue
			}
			b, _ := json.Marshal(y)
			f[name] = string(b)
		case []any:
			b, _ := json.Marshal(y)
			f[name] = string(b)
		case json.Number:
			if n, err := y.Int64(); err == nil {
				f[name] = n
			} else if fl, err := y.Float64(); err == nil {
				f[name] = fl
			} else {
				f[name] = y.String()
			}
		case nil:
		default:
			f[name] = y
		}
	}
}

// columnName makes a CSV header's column a field name.
func columnName(v string) string {
	return SanitizeName(strings.ReplaceAll(strings.TrimSpace(v), " ", "_"))
}

// csvRow splits one CSV line.
func csvRow(line, delim string) []string {
	r := csv.NewReader(strings.NewReader(line))
	d, _ := utf8.DecodeRuneInString(delim)
	if d == utf8.RuneError {
		d = ','
	}
	r.Comma = d
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	row, err := r.Read()
	if err != nil {
		return strings.Split(line, delim)
	}
	return row
}
