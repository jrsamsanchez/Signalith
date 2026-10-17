package query

import (
	"regexp"
	"strconv"
	"strings"
)

// Rex extracts fields with a regular expression's named groups:
// rex field=process "-enc(?:odedcommand)? (?<encoded>\S+)".
type Rex struct {
	Field    string // default _raw
	Pattern  string // RE2, with (?<name>...) or (?P<name>...) groups
	MaxMatch int    // matches to keep per event (default 1, 0 for all)
	// Sed, with mode=sed, is a sed expression that changes the field's
	// text instead: rex field=user mode=sed "s/^CORP\\\\//". Pattern is
	// then empty.
	Sed string
}

// Dedup keeps the first N rows for each combination of the fields' values.
type Dedup struct {
	N           int
	Fields      []string
	KeepEmpty   bool // keep rows missing a field, instead of dropping them
	Consecutive bool // only drop rows that repeat the row just before
}

// Fillnull sets missing values: fillnull value=0 bytes, packets. With no
// fields it fills every column.
type Fillnull struct {
	Value  string
	Fields []string
}

// EventStats adds aggregates to every row instead of replacing the rows:
// eventstats avg(bytes) as avg_bytes by src.
type EventStats struct {
	Aggs []Agg
	By   []string
}

func (*Rex) Name() string        { return "rex" }
func (*Dedup) Name() string      { return "dedup" }
func (*Fillnull) Name() string   { return "fillnull" }
func (*EventStats) Name() string { return "eventstats" }

// MaxRexPattern caps the length of a rex pattern.
const MaxRexPattern = 1000

// parseWhere parses a where command's text. A plain filter (field=value,
// count > 20, IN lists, AND, OR, NOT) reads as it always has; anything
// else, such as a function call or arithmetic, is read as a value
// expression (see Cond).
func parseWhere(raw string, base int) (Expr, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errorf(base, "expected a condition after where, for example: where count > 10")
	}
	e, classicErr := parseClassicWhere(raw, base)
	if classicErr == nil {
		return e, nil
	}
	x, evalErr := parseEvalExprAt(raw, base)
	if evalErr != nil {
		// Report whichever reading got further into the condition.
		ce, _ := classicErr.(*Error)
		ee, _ := evalErr.(*Error)
		if ce != nil && ee != nil && ee.Pos > ce.Pos {
			return nil, evalErr
		}
		return nil, classicErr
	}
	cond := &Cond{X: x}
	// Written back, a condition must read the same way again, so one
	// that prints as a plain filter is one. One that compares a field
	// with another field is not, though it can print like one.
	if !comparesFields(x) {
		if e, err := parseClassicWhere(x.String(), 0); err == nil {
			return e, nil
		}
	}
	return cond, nil
}

// comparesFields reports whether x compares a field with another field.
func comparesFields(x EvalExpr) bool {
	switch x := x.(type) {
	case *Unary:
		return comparesFields(x.X)
	case *Call:
		for _, a := range x.Args {
			if comparesFields(a) {
				return true
			}
		}
	case *Binary:
		switch x.Op {
		case "=", "!=", "<", "<=", ">", ">=", "LIKE":
			_, l := x.L.(*Field)
			_, r := x.R.(*Field)
			if l && r {
				return true
			}
		}
		return comparesFields(x.L) || comparesFields(x.R)
	}
	return false
}

func parseClassicWhere(raw string, base int) (Expr, error) {
	toks, err := lex(raw)
	if err != nil {
		if pe, ok := err.(*Error); ok {
			pe.Pos += base
		}
		return nil, err
	}
	for i := range toks {
		toks[i].pos += base
		// 'name' is a field, as in eval, so a condition with one is read
		// as an expression: where user != 'admin_user' compares two fields.
		if toks[i].kind == tokWord && strings.HasPrefix(toks[i].text, "'") {
			return nil, errorf(toks[i].pos, "a single-quoted field name")
		}
	}
	sub := &parser{toks: toks}
	e, err := sub.parseWhereOr()
	if err != nil {
		return nil, err
	}
	if t := sub.peek(); t.kind != tokEOF {
		return nil, errorf(t.pos, "unexpected %s", describe(t))
	}
	return e, nil
}

func parseEvalExprAt(src string, base int) (EvalExpr, error) {
	toks, err := lexEval(src, base)
	if err != nil {
		return nil, err
	}
	p := &evalParser{toks: toks}
	e, err := p.expr()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != etEOF {
		return nil, errorf(t.pos, "unexpected %s", describeEval(t))
	}
	return e, nil
}

func (p *parser) parseRex(cmd token) (Command, error) {
	r := &Rex{Field: "_raw", MaxMatch: 1}
	sed := false
	var pat *token
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			key := strings.ToLower(t.text)
			p.next()
			p.next()
			switch key {
			case "field":
				v, err := p.value()
				if err != nil {
					return nil, err
				}
				if v == "" {
					return nil, errorf(t.pos, "rex field= needs a field name")
				}
				r.Field = v
			case "max_match":
				n, err := p.int()
				if err != nil {
					return nil, err
				}
				r.MaxMatch = n
			case "mode":
				v, err := p.value()
				if err != nil {
					return nil, err
				}
				if !strings.EqualFold(v, "sed") {
					return nil, errorf(t.pos, "rex mode can only be sed")
				}
				sed = true
			default:
				return nil, errorf(t.pos, "unknown rex option %q; rex takes field=, max_match= and mode=sed", t.text)
			}
			continue
		}
		if t.kind == tokString && pat == nil {
			p.next()
			pat = &t
			continue
		}
		return nil, errorf(t.pos, `unexpected %s; rex expects: rex field=<field> "<regular expression>"`, describe(t))
	}
	if pat == nil {
		if sed {
			return nil, errorf(cmd.pos, `rex mode=sed needs a quoted sed expression, for example: rex field=user mode=sed "s/^CORP\\\\//"`)
		}
		return nil, errorf(cmd.pos, `rex needs a quoted regular expression with named groups, for example: rex field=process "-enc (?<encoded>\S+)"`)
	}
	if len(pat.text) > MaxRexPattern {
		return nil, errorf(pat.pos, "the rex pattern is %d characters long; the limit is %d", len(pat.text), MaxRexPattern)
	}
	if sed {
		if r.MaxMatch != 1 {
			return nil, errorf(cmd.pos, "rex mode=sed takes no max_match=")
		}
		if _, err := ParseSed(pat.text); err != nil {
			return nil, errorf(pat.pos, "rex sed expression: %v", err)
		}
		r.Sed = pat.text
		return r, nil
	}
	re, err := regexp.Compile(pat.text)
	if err != nil {
		return nil, errorf(pat.pos, "rex pattern: %v", err)
	}
	named := false
	for _, n := range re.SubexpNames() {
		named = named || n != ""
	}
	if !named {
		return nil, errorf(pat.pos, `the rex pattern needs a named group to extract, like "user=(?<user>\w+)"`)
	}
	r.Pattern = pat.text
	return r, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func parseBool(t token) (bool, error) {
	switch strings.ToLower(t.text) {
	case "true", "t", "1", "yes":
		return true, nil
	case "false", "f", "0", "no":
		return false, nil
	}
	return false, errorf(t.pos, "expected true or false, got %s", describe(t))
}

func (p *parser) parseDedup(cmd token) (Command, error) {
	d := &Dedup{N: 1}
	first := true
	for {
		t := p.peek()
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			key := strings.ToLower(t.text)
			if key != "keepempty" && key != "consecutive" {
				return nil, errorf(t.pos, "unknown dedup option %q; dedup takes keepempty= and consecutive=", t.text)
			}
			p.next()
			p.next()
			vt := p.next()
			b, err := parseBool(vt)
			if err != nil {
				return nil, err
			}
			if key == "keepempty" {
				d.KeepEmpty = b
			} else {
				d.Consecutive = b
			}
			first = false
			continue
		}
		if t.kind == tokWord && strings.EqualFold(t.text, "sortby") {
			return nil, errorf(t.pos, "dedup sortby is not supported; sort before dedup instead")
		}
		if t.kind == tokWord && first && allDigits(t.text) {
			p.next()
			n, err := strconv.Atoi(t.text)
			if err != nil || n < 1 {
				return nil, errorf(t.pos, "dedup keeps at least 1 row per value, got %s", describe(t))
			}
			d.N = n
			first = false
			continue
		}
		if t.kind == tokWord {
			p.next()
			d.Fields = append(d.Fields, p.fieldSuffix(t.text))
			first = false
			continue
		}
		if t.kind == tokString {
			p.next()
			d.Fields = append(d.Fields, t.text)
			first = false
			continue
		}
		break
	}
	if len(d.Fields) == 0 {
		return nil, errorf(cmd.pos, "dedup needs at least one field, for example: dedup user, host")
	}
	return d, p.endCommand()
}

func (p *parser) parseFillnull() (Command, error) {
	f := &Fillnull{Value: "0"}
	for {
		t := p.peek()
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t.kind == tokWord && strings.EqualFold(t.text, "value") && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			f.Value = v
			continue
		}
		if t.kind == tokWord {
			p.next()
			f.Fields = append(f.Fields, p.fieldSuffix(t.text))
			continue
		}
		if t.kind == tokString {
			p.next()
			f.Fields = append(f.Fields, t.text)
			continue
		}
		break
	}
	return f, p.endCommand()
}

func rexString(c *Rex) string {
	s := "rex "
	if c.Field != "_raw" {
		s += "field=" + optionValue(c.Field) + " "
	}
	if c.MaxMatch != 1 {
		s += "max_match=" + strconv.Itoa(max(c.MaxMatch, 0)) + " "
	}
	if c.Sed != "" {
		return s + "mode=sed " + quote(c.Sed)
	}
	return s + quote(c.Pattern)
}

func dedupString(c *Dedup) string {
	s := "dedup "
	if c.N != 1 || len(c.Fields) > 0 && allDigits(c.Fields[0]) {
		s += strconv.Itoa(c.N) + " "
	}
	names := make([]string, len(c.Fields))
	for i, f := range c.Fields {
		names[i] = formatName(f)
		if strings.EqualFold(f, "sortby") {
			names[i] = quote(f)
		}
	}
	s += strings.Join(names, ", ")
	if c.KeepEmpty {
		s += " keepempty=true"
	}
	if c.Consecutive {
		s += " consecutive=true"
	}
	return s
}

func fillnullString(c *Fillnull) string {
	s := "fillnull"
	if c.Value != "0" {
		s += " value=" + optionValue(c.Value)
	}
	if len(c.Fields) > 0 {
		names := make([]string, len(c.Fields))
		for i, f := range c.Fields {
			names[i] = formatName(f)
		}
		s += " " + strings.Join(names, ", ")
	}
	return s
}

// Lookup adds columns from a lookup table (Settings > Lookups) to rows
// whose fields match its key columns:
// lookup owners host AS dest OUTPUT owner, team AS owner_team.
type Lookup struct {
	Table   string
	Keys    []LookupField // table column, and the row field it matches when As is set
	Outputs []LookupField // table column, and the field it is written to when As is set; none means every other column
	New     bool          // OUTPUTNEW: only fill fields the row does not have
}

// LookupField is a table column and, when it differs, the row's field.
type LookupField struct {
	Column string
	As     string
}

// Field returns the row's field for f.
func (f LookupField) Field() string {
	if f.As != "" {
		return f.As
	}
	return f.Column
}

func (*Lookup) Name() string { return "lookup" }

var lookupTableRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func (p *parser) lookupWord() bool {
	return p.isKeywordFold("output") || p.isKeywordFold("outputnew")
}

// lookupFields reads column [AS field] pairs, separated by spaces or
// commas, up to OUTPUT, OUTPUTNEW or the end of the command.
func (p *parser) lookupFields() ([]LookupField, error) {
	var out []LookupField
	name := func() (string, bool) {
		t := p.peek()
		if t.kind == tokString || t.kind == tokWord && !strings.EqualFold(t.text, "as") && !p.lookupWord() {
			p.next()
			return t.text, t.text != ""
		}
		return "", false
	}
	for {
		if p.peek().kind == tokComma {
			p.next()
			continue
		}
		col, ok := name()
		if !ok {
			return out, nil
		}
		f := LookupField{Column: col}
		if p.isKeywordFold("as") {
			at := p.next()
			if f.As, ok = name(); !ok {
				return nil, errorf(at.pos, `expected a field name after "as" in lookup`)
			}
		}
		out = append(out, f)
	}
}

func (p *parser) parseLookup(cmd token) (Command, error) {
	// Splunk's local= (run on the search head) and update= (reload the
	// table) change nothing here: tables are on this server and always
	// current.
	for {
		t := p.peek()
		if !(p.isKeywordFold("local") || p.isKeywordFold("update")) || p.peekAt(1).kind != tokOp || p.peekAt(1).text != "=" {
			break
		}
		p.option()
		if _, err := parseBool(p.next()); err != nil {
			return nil, errorf(t.pos, "lookup %s= takes true or false", strings.ToLower(t.text))
		}
	}
	t := p.peek()
	if t.kind != tokWord && t.kind != tokString {
		return nil, errorf(t.pos, "lookup needs a table name, for example: lookup owners host OUTPUT owner")
	}
	p.next()
	if !lookupTableRE.MatchString(t.text) {
		return nil, errorf(t.pos, "%q is not a lookup table name; names use lower-case letters, digits, - and _", t.text)
	}
	l := &Lookup{Table: t.text}
	var err error
	if l.Keys, err = p.lookupFields(); err != nil {
		return nil, err
	}
	if len(l.Keys) == 0 {
		return nil, errorf(p.peek().pos, "lookup needs the column to match, for example: lookup %s host OUTPUT owner", l.Table)
	}
	if p.lookupWord() {
		kw := p.next()
		l.New = strings.EqualFold(kw.text, "outputnew")
		if l.Outputs, err = p.lookupFields(); err != nil {
			return nil, err
		}
		if len(l.Outputs) == 0 {
			return nil, errorf(kw.pos, "%s needs at least one column", strings.ToUpper(kw.text))
		}
	}
	return l, p.endCommand()
}

// lookupName prints a column or field name so that it reads back as the
// same name, quoting the lookup keywords.
func lookupName(n string) string {
	switch strings.ToLower(n) {
	case "output", "outputnew":
		return quote(n)
	}
	return FormatValue(n)
}

func lookupFieldsString(fs []LookupField) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = lookupName(f.Column)
		if f.As != "" {
			parts[i] += " AS " + lookupName(f.As)
		}
	}
	return strings.Join(parts, ", ")
}

func lookupString(c *Lookup) string {
	s := "lookup " + c.Table + " " + lookupFieldsString(c.Keys)
	if len(c.Outputs) > 0 {
		kw := " OUTPUT "
		if c.New {
			kw = " OUTPUTNEW "
		}
		s += kw + lookupFieldsString(c.Outputs)
	}
	return s
}

// InputLookup starts a search with the rows of a lookup table instead of
// events: | inputlookup [max=N] owners. With append=true it can come
// later and adds the table's rows after the rows so far.
type InputLookup struct {
	Table  string
	Max    int // the most rows to read; 0 means the search's event limit
	Append bool
	Where  Expr // keeps only the rows that match these search terms
}

func (*InputLookup) Name() string { return "inputlookup" }

func (p *parser) parseInputLookup() (Command, error) {
	c := &InputLookup{}
	if err := p.inputLookupOptions(c); err != nil {
		return nil, err
	}
	t := p.peek()
	if t.kind != tokWord && t.kind != tokString {
		return nil, errorf(t.pos, "inputlookup needs a table name, for example: | inputlookup owners")
	}
	p.next()
	if !lookupTableRE.MatchString(t.text) {
		return nil, errorf(t.pos, "%q is not a lookup table name; names use lower-case letters, digits, - and _", t.text)
	}
	c.Table = t.text
	// Splunk takes the options after the name too.
	if err := p.inputLookupOptions(c); err != nil {
		return nil, err
	}
	if w := p.peek(); p.isKeywordFold("where") {
		p.next()
		var q Query
		if err := p.parseSearch(&q); err != nil {
			return nil, err
		}
		if q.Index != "" || q.Datamodel != "" || q.Earliest != "" || q.Latest != "" || exprSubsearches(q.Search) > 0 {
			return nil, errorf(w.pos, "inputlookup where takes only field terms, such as where status=active")
		}
		if q.Search == nil {
			return nil, errorf(w.pos, "expected terms after where, for example: | inputlookup owners where team=Web")
		}
		c.Where = q.Search
	}
	return c, p.endCommand()
}

func (p *parser) inputLookupOptions(c *InputLookup) error {
	for (p.isKeywordFold("max") || p.isKeywordFold("append")) && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
		key := strings.ToLower(p.next().text)
		p.next()
		if key == "append" {
			b, err := parseBool(p.next())
			if err != nil {
				return err
			}
			c.Append = b
			continue
		}
		at := p.peek().pos
		n, err := p.int()
		if err != nil {
			return err
		}
		if n < 1 {
			return errorf(at, "max must be at least 1")
		}
		c.Max = n
	}
	return nil
}

func inputLookupString(c *InputLookup) string {
	s := "inputlookup "
	if c.Append {
		s += "append=true "
	}
	if c.Max > 0 {
		s += "max=" + strconv.Itoa(c.Max) + " "
	}
	s += c.Table
	if c.Where != nil {
		s += " where " + c.Where.String()
	}
	return s
}

// Regex keeps rows whose field matches a regular expression, or with !=
// those that do not: regex process="(?i)-enc\s". With no field it looks
// at _raw.
type Regex struct {
	Field   string
	Pattern string
	Negate  bool
}

func (*Regex) Name() string { return "regex" }

func (p *parser) parseRegex(cmd token) (Command, error) {
	const usage = `regex expects: regex field="<regular expression>", field!="..." or "<regular expression>"`
	r := &Regex{Field: "_raw"}
	t := p.peek()
	var pat token
	switch {
	case (t.kind == tokWord || t.kind == tokString) && p.peekAt(1).kind == tokOp && (p.peekAt(1).text == "=" || p.peekAt(1).text == "!="):
		p.next()
		op := p.next()
		r.Field, r.Negate = t.text, op.text == "!="
		if r.Field == "" {
			return nil, errorf(t.pos, "regex needs a field name before %s", op.text)
		}
		pat = p.next()
		if pat.kind != tokString && pat.kind != tokWord {
			return nil, errorf(pat.pos, usage)
		}
	case t.kind == tokString:
		pat = p.next()
	default:
		return nil, errorf(cmd.pos, usage)
	}
	if len(pat.text) > MaxRexPattern {
		return nil, errorf(pat.pos, "the regex pattern is %d characters long; the limit is %d", len(pat.text), MaxRexPattern)
	}
	if _, err := regexp.Compile(pat.text); err != nil {
		return nil, errorf(pat.pos, "regex pattern: %v", err)
	}
	r.Pattern = pat.text
	return r, p.endCommand()
}

func regexString(c *Regex) string {
	if c.Field == "_raw" && !c.Negate {
		return "regex " + quote(c.Pattern)
	}
	op := "="
	if c.Negate {
		op = "!="
	}
	return "regex " + FormatValue(c.Field) + op + quote(c.Pattern)
}

// MakeResults starts a search with rows made up on the spot, each with
// only _time, for trying out eval and other commands: | makeresults count=3.
type MakeResults struct {
	Count int
}

func (*MakeResults) Name() string { return "makeresults" }

// MaxMakeResults caps makeresults count=.
const MaxMakeResults = 10000

func (p *parser) parseMakeResults() (Command, error) {
	m := &MakeResults{Count: 1}
	for p.peek().kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
		t := p.next()
		p.next()
		if !strings.EqualFold(t.text, "count") {
			return nil, errorf(t.pos, "unknown makeresults option %q; makeresults takes count=", t.text)
		}
		at := p.peek().pos
		n, err := p.int()
		if err != nil {
			return nil, err
		}
		if n < 1 || n > MaxMakeResults {
			return nil, errorf(at, "makeresults count is 1 to %d", MaxMakeResults)
		}
		m.Count = n
	}
	return m, p.endCommand()
}

func makeResultsString(c *MakeResults) string {
	if c.Count == 1 {
		return "makeresults"
	}
	return "makeresults count=" + strconv.Itoa(c.Count)
}

// FieldsRemove drops fields from the rows: fields - _raw, tmp_*.
type FieldsRemove struct {
	Fields []string
}

func (*FieldsRemove) Name() string { return "fields" }

func fieldsRemoveString(c *FieldsRemove) string {
	names := make([]string, len(c.Fields))
	for i, f := range c.Fields {
		names[i] = formatName(f)
	}
	return "fields - " + strings.Join(names, ", ")
}
