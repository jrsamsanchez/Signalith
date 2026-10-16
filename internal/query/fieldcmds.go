package query

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// NoMV turns a multivalue field into one value, its values joined by
// newlines: nomv recipients.
type NoMV struct{ Field string }

// MVCombine merges rows that are the same in every field but Field into
// one row holding all their Field values: mvcombine host.
type MVCombine struct {
	Field string
	Delim string // accepted for Splunk; values stay a multivalue field
}

// StrCat joins fields and quoted text into Dest: strcat src ":" port addr.
// With AllRequired, a row missing any of the fields gets no Dest.
type StrCat struct {
	Parts       []StrCatPart
	Dest        string
	AllRequired bool
}

// StrCatPart is a field, or with Literal, quoted text.
type StrCatPart struct {
	Text    string
	Literal bool
}

// RangeMap sets range to the names of the ranges Field's value falls in:
// rangemap field=count low=0-10 high=11-100 default=severe.
type RangeMap struct {
	Field   string
	Ranges  []Range
	Default string // "" is None
}

// Range is a named, inclusive number range.
type Range struct {
	Name   string
	Lo, Hi float64
}

func (*NoMV) Name() string      { return "nomv" }
func (*MVCombine) Name() string { return "mvcombine" }
func (*StrCat) Name() string    { return "strcat" }
func (*RangeMap) Name() string  { return "rangemap" }

// DefaultName is the value rangemap gives values in no range.
func (r *RangeMap) DefaultName() string {
	if r.Default == "" {
		return "None"
	}
	return r.Default
}

// MaxStrCatParts caps strcat's fields and texts; MaxRanges caps rangemap's
// ranges.
const (
	MaxStrCatParts = 100
	MaxRanges      = 100
)

// singleField reads one field name for a command that takes a single field.
func (p *parser) singleField(cmd token, usage string, opts func(key string, at token) (bool, error)) (string, error) {
	name := strings.ToLower(cmd.text)
	field := ""
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" && opts != nil {
			p.next()
			p.next()
			ok, err := opts(strings.ToLower(t.text), t)
			if err != nil {
				return "", err
			}
			if ok {
				continue
			}
			return "", errorf(t.pos, "unknown %s option %q; %s expects: %s", name, t.text, name, usage)
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && field == "" {
			p.next()
			field = t.text
			continue
		}
		return "", errorf(t.pos, "unexpected %s; %s expects: %s", describe(t), name, usage)
	}
	if field == "" {
		return "", errorf(cmd.pos, "%s expects: %s", name, usage)
	}
	return field, nil
}

func (p *parser) parseNoMV(cmd token) (Command, error) {
	f, err := p.singleField(cmd, "nomv <field>", nil)
	if err != nil {
		return nil, err
	}
	return &NoMV{Field: f}, nil
}

func (p *parser) parseMVCombine(cmd token) (Command, error) {
	c := &MVCombine{}
	f, err := p.singleField(cmd, `mvcombine [delim=" "] <field>`, func(key string, at token) (bool, error) {
		if key != "delim" {
			return false, nil
		}
		v := p.next()
		if v.kind != tokWord && v.kind != tokString || v.text == "" || len(v.text) > MaxSpathPath {
			return false, errorf(v.pos, "mvcombine delim= needs a value of 1 to %d characters", MaxSpathPath)
		}
		c.Delim = v.text
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	c.Field = f
	return c, nil
}

func (p *parser) parseStrCat(cmd token) (Command, error) {
	const usage = `strcat [allrequired=t] <field or "text"> ... <new field>`
	c := &StrCat{}
	var parts []StrCatPart
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && strings.EqualFold(t.text, "allrequired") && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			b, err := parseBool(p.next())
			if err != nil {
				return nil, err
			}
			c.AllRequired = b
			continue
		}
		switch t.kind {
		case tokString:
			parts = append(parts, StrCatPart{Text: t.text, Literal: true})
		case tokWord:
			if FormatValue(t.text) != t.text {
				return nil, errorf(t.pos, "strcat cannot read the field %q; rename it first", t.text)
			}
			parts = append(parts, StrCatPart{Text: t.text})
		default:
			return nil, errorf(t.pos, "unexpected %s; strcat expects: %s", describe(t), usage)
		}
		p.next()
		if len(parts) > MaxStrCatParts+1 {
			return nil, errorf(t.pos, "strcat joins at most %d fields and texts", MaxStrCatParts)
		}
	}
	if len(parts) < 2 || parts[len(parts)-1].Literal {
		return nil, errorf(cmd.pos, "strcat expects: %s", usage)
	}
	c.Dest = parts[len(parts)-1].Text
	c.Parts = parts[:len(parts)-1]
	return c, nil
}

// rangeNameRe is a range's name.
var rangeNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (p *parser) parseRangeMap(cmd token) (Command, error) {
	const usage = "rangemap field=<field> <name>=<low>-<high> ... [default=<name>]"
	c := &RangeMap{}
	seen := map[string]bool{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind != tokWord || p.peekAt(1).kind != tokOp || p.peekAt(1).text != "=" {
			return nil, errorf(t.pos, "unexpected %s; rangemap expects: %s", describe(t), usage)
		}
		p.next()
		p.next()
		v := p.next()
		if v.kind != tokWord && v.kind != tokString || v.text == "" {
			return nil, errorf(v.pos, "rangemap %s= needs a value", t.text)
		}
		switch strings.ToLower(t.text) {
		case "field":
			c.Field = v.text
			continue
		case "default":
			if !rangeNameRe.MatchString(v.text) {
				return nil, errorf(v.pos, "rangemap default= needs a name of letters, digits and _")
			}
			c.Default = v.text
			continue
		}
		if !rangeNameRe.MatchString(t.text) || seen[t.text] {
			return nil, errorf(t.pos, "rangemap range %q needs a new name of letters, digits and _", t.text)
		}
		lo, hi, ok := parseRange(v.text)
		if !ok {
			return nil, errorf(v.pos, "rangemap %s= needs a range like 0-100", t.text)
		}
		if len(c.Ranges) >= MaxRanges {
			return nil, errorf(t.pos, "rangemap takes at most %d ranges", MaxRanges)
		}
		seen[t.text] = true
		c.Ranges = append(c.Ranges, Range{Name: t.text, Lo: lo, Hi: hi})
	}
	if c.Field == "" || len(c.Ranges) == 0 {
		return nil, errorf(cmd.pos, "rangemap expects: %s", usage)
	}
	return c, nil
}

// parseRange reads low-high, where either may be negative: -10--1.
func parseRange(s string) (float64, float64, bool) {
	i := strings.IndexByte(s[1:], '-')
	if i < 0 {
		return 0, 0, false
	}
	lo, err1 := strconv.ParseFloat(s[:i+1], 64)
	hi, err2 := strconv.ParseFloat(s[i+2:], 64)
	if err1 != nil || err2 != nil || math.IsNaN(lo) || math.IsNaN(hi) || math.IsInf(lo, 0) || math.IsInf(hi, 0) || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

func strCatString(c *StrCat) string {
	s := "strcat"
	if c.AllRequired {
		s += " allrequired=t"
	}
	for _, part := range c.Parts {
		if part.Literal {
			s += " " + quote(part.Text)
		} else {
			s += " " + part.Text
		}
	}
	return s + " " + c.Dest
}

func rangeMapString(c *RangeMap) string {
	s := "rangemap field=" + optionValue(c.Field)
	for _, r := range c.Ranges {
		s += " " + r.Name + "=" + formatNum(r.Lo) + "-" + formatNum(r.Hi)
	}
	if c.Default != "" {
		s += " default=" + c.Default
	}
	return s
}

func formatNum(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func mvCombineString(c *MVCombine) string {
	s := "mvcombine"
	if c.Delim != "" {
		s += " delim=" + quote(c.Delim)
	}
	return s + " " + FormatValue(c.Field)
}

// ForEach runs eval commands once for each field whose name matches one of
// Fields (* matches any text), with <<FIELD>> in Body standing for the
// field's name and <<MATCHSTR>> for the text its * matched:
// foreach bytes_* [eval <<FIELD>>=round(<<FIELD>>/1024, 1)].
type ForEach struct {
	Fields []string
	Body   string
}

func (*ForEach) Name() string { return "foreach" }

// MaxForEachFields caps the field patterns foreach takes and the fields
// it runs for.
const MaxForEachFields = 1000

// ForEachName is a field name foreach puts in place of <<FIELD>>: names
// that would read back as something else are skipped.
var ForEachName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$`)

// forEachMatch is text foreach puts in place of <<MATCHSTR>>.
var forEachMatch = regexp.MustCompile(`^[A-Za-z0-9_]*$`)

func (p *parser) parseForEach(cmd token) (Command, error) {
	const example = "foreach bytes_* [eval <<FIELD>>=round(<<FIELD>>/1024, 1)]"
	opts, optsPos, inner, base, err := p.bracketed(cmd, example)
	if err != nil {
		return nil, err
	}
	toks, err := lex(opts)
	if err != nil {
		if pe, ok := err.(*Error); ok {
			pe.Pos += optsPos
		}
		return nil, err
	}
	c := &ForEach{Body: strings.TrimSpace(inner)}
	for _, t := range toks {
		if t.kind == tokEOF {
			break
		}
		if t.kind != tokWord || FormatValue(t.text) != t.text || strings.Count(t.text, "*") > 1 {
			return nil, errorf(optsPos+t.pos, "foreach takes field names with at most one *, then eval commands in [ ], for example: %s", example)
		}
		if len(c.Fields) >= MaxForEachFields {
			return nil, errorf(optsPos+t.pos, "foreach takes at most %d fields", MaxForEachFields)
		}
		c.Fields = append(c.Fields, t.text)
	}
	if len(c.Fields) == 0 || c.Body == "" {
		return nil, errorf(cmd.pos, "foreach expects: %s", example)
	}
	if _, err := c.Commands("x", "x"); err != nil {
		if pe, ok := err.(*Error); ok {
			pe.Pos = base
		}
		return nil, err
	}
	return c, p.endCommand()
}

// Commands are the eval commands foreach runs for the field name with
// the * text match.
func (c *ForEach) Commands(name, match string) ([]*Eval, error) {
	body := strings.ReplaceAll(strings.ReplaceAll(c.Body, "<<FIELD>>", name), "<<MATCHSTR>>", match)
	toks, err := lex("|" + body)
	if err != nil {
		return nil, err
	}
	sub := &parser{toks: toks}
	var evals []*Eval
	for sub.peek().kind == tokPipe {
		sub.next()
		at := sub.peek()
		cmd, err := sub.parseCommand()
		if err != nil {
			return nil, err
		}
		e, ok := cmd.(*Eval)
		if !ok {
			return nil, errorf(at.pos, "foreach runs only eval commands, not %s", cmd.Name())
		}
		evals = append(evals, e)
	}
	if t := sub.peek(); t.kind != tokEOF {
		return nil, errorf(t.pos, "foreach runs only eval commands, separated by |")
	}
	return evals, nil
}

// Match returns the text the * of the first pattern name matches took,
// and whether one does. A match whose * text holds anything but letters,
// digits and _ does not count.
func (c *ForEach) Match(name string) (string, bool) {
	for _, p := range c.Fields {
		if m, ok := RenameField([2]string{p, strings.Repeat("*", strings.Count(p, "*"))}, name); ok {
			if !strings.Contains(p, "*") {
				m = ""
			}
			if !forEachMatch.MatchString(m) {
				return "", false
			}
			return m, true
		}
	}
	return "", false
}

func forEachString(c *ForEach) string {
	return "foreach " + strings.Join(c.Fields, " ") + " [" + c.Body + "]"
}
