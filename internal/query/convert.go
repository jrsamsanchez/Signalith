package query

import (
	"strings"
)

// Convert changes fields' values from one form to another:
// convert timeformat="%Y-%m-%d" ctime(firstTime) AS first, dur2sec(duration).
type Convert struct {
	TimeFormat string // for ctime and mktime; "" is %m/%d/%Y %H:%M:%S
	Funcs      []ConvertFunc
}

// ConvertFunc is one conversion: Func(Field) [AS As]. Field may hold *,
// matching any text; then As is empty and each matching field changes in
// place.
type ConvertFunc struct {
	Func  string
	Field string
	As    string
}

func (*Convert) Name() string { return "convert" }

// DefaultTimeFormat is convert's timeformat unless one is given.
const DefaultTimeFormat = "%m/%d/%Y %H:%M:%S"

// ConvertFuncs lists convert's functions.
var ConvertFuncs = []string{"auto", "ctime", "dur2sec", "memk", "mktime", "mstime", "none", "num", "rmcomma", "rmunit"}

// MaxConvertFuncs caps the conversions in one convert command.
const MaxConvertFuncs = 100

func (p *parser) parseConvert(cmd token) (Command, error) {
	const usage = `convert [timeformat="%Y-%m-%d"] ctime(field) [AS name], ...`
	c := &Convert{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t.kind == tokWord && strings.EqualFold(t.text, "timeformat") && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			if v == "" || len(v) > MaxSpathPath {
				return nil, errorf(t.pos, "convert timeformat= needs a format of 1 to %d characters", MaxSpathPath)
			}
			c.TimeFormat = v
			if v == DefaultTimeFormat {
				c.TimeFormat = ""
			}
			continue
		}
		if t.kind != tokWord || p.peekAt(1).kind != tokLParen {
			return nil, errorf(t.pos, "unexpected %s; convert expects: %s", describe(t), usage)
		}
		fn := strings.ToLower(t.text)
		known := false
		for _, f := range ConvertFuncs {
			known = known || f == fn
		}
		if !known {
			return nil, errorf(t.pos, "unknown convert function %q; convert takes %s", t.text, strings.Join(ConvertFuncs, ", "))
		}
		p.next()
		p.next() // (
		ft := p.next()
		if ft.kind != tokWord && ft.kind != tokString || ft.text == "" {
			return nil, errorf(ft.pos, "expected a field in %s()", fn)
		}
		if r := p.next(); r.kind != tokRParen {
			return nil, errorf(r.pos, `expected ")" after the field in %s()`, fn)
		}
		f := ConvertFunc{Func: fn, Field: ft.text}
		if strings.Count(f.Field, "*") > MaxRenameWildcards {
			return nil, errorf(ft.pos, "convert field %s has too many *", FormatValue(f.Field))
		}
		if p.isKeywordFold("as") {
			p.next()
			at := p.next()
			if at.kind != tokWord && at.kind != tokString || at.text == "" {
				return nil, errorf(at.pos, `expected a name after "as"`)
			}
			if strings.Contains(f.Field, "*") {
				return nil, errorf(at.pos, "convert cannot name the result of a field with *; it changes each matching field in place")
			}
			if fn == "none" {
				return nil, errorf(at.pos, "none() takes no AS")
			}
			f.As = at.text
		}
		if len(c.Funcs) >= MaxConvertFuncs {
			return nil, errorf(t.pos, "convert takes at most %d conversions", MaxConvertFuncs)
		}
		c.Funcs = append(c.Funcs, f)
	}
	if len(c.Funcs) == 0 {
		return nil, errorf(cmd.pos, "convert expects: %s", usage)
	}
	return c, nil
}

func convertString(c *Convert) string {
	s := "convert"
	if c.TimeFormat != "" {
		s += " timeformat=" + quote(c.TimeFormat)
	}
	for i, f := range c.Funcs {
		if i > 0 {
			s += ","
		}
		s += " " + f.Func + "(" + FormatValue(f.Field) + ")"
		if f.As != "" {
			s += " AS " + FormatValue(f.As)
		}
	}
	return s
}
