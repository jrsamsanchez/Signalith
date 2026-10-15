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
	// that prints as a plain filter is one.
	if e, err := parseClassicWhere(cond.String(), 0); err == nil {
		return e, nil
	}
	return cond, nil
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
	havePattern := false
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
				return nil, errorf(t.pos, "rex mode=sed is not supported; use eval with replace() instead")
			default:
				return nil, errorf(t.pos, "unknown rex option %q; rex takes field= and max_match=", t.text)
			}
			continue
		}
		if t.kind == tokString && !havePattern {
			p.next()
			if len(t.text) > MaxRexPattern {
				return nil, errorf(t.pos, "the rex pattern is %d characters long; the limit is %d", len(t.text), MaxRexPattern)
			}
			re, err := regexp.Compile(t.text)
			if err != nil {
				return nil, errorf(t.pos, "rex pattern: %v", err)
			}
			named := false
			for _, n := range re.SubexpNames() {
				named = named || n != ""
			}
			if !named {
				return nil, errorf(t.pos, `the rex pattern needs a named group to extract, like "user=(?<user>\w+)"`)
			}
			r.Pattern = t.text
			havePattern = true
			continue
		}
		return nil, errorf(t.pos, `unexpected %s; rex expects: rex field=<field> "<regular expression>"`, describe(t))
	}
	if !havePattern {
		return nil, errorf(cmd.pos, `rex needs a quoted regular expression with named groups, for example: rex field=process "-enc (?<encoded>\S+)"`)
	}
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
		s += "field=" + FormatValue(c.Field) + " "
	}
	if c.MaxMatch != 1 {
		s += "max_match=" + strconv.Itoa(max(c.MaxMatch, 0)) + " "
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
		s += " value=" + FormatValue(c.Value)
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
