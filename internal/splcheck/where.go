package splcheck

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// Expr is a where clause.
type Expr interface{ isExpr() }

// And, Or and Not combine clauses.
type (
	And struct{ Kids []Expr }
	Or  struct{ Kids []Expr }
	Not struct{ Kid Expr }
)

// Cmp compares a field with values: field=v, field!=v or field IN (v...).
// Values are Splunk patterns: * matches any run of characters, case is
// ignored, and everything else is literal.
type Cmp struct {
	Field  string // without the node prefix
	Neg    bool   // !=
	Values []string
}

func (*And) isExpr() {}
func (*Or) isExpr()  {}
func (*Not) isExpr() {}
func (*Cmp) isExpr() {}

// ParseWhere reads a tstats where clause over node, expanding macros.
// Fields must carry the node prefix (Processes.process_name) and be one
// the node has.
func ParseWhere(s, node string, macros map[string]*Macro) (Expr, error) {
	toks, err := lex(s, macros, 0)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, node: node}
	e, err := p.and()
	if err != nil {
		return nil, err
	}
	if p.i < len(p.toks) {
		return nil, fmt.Errorf("unexpected %q in the where clause", p.toks[p.i].text)
	}
	return e, nil
}

type token struct {
	kind byte // w word, s quoted string, o operator or punctuation
	text string
}

// lex splits a where clause into tokens, replacing each `macro` by its
// definition's tokens.
func lex(s string, macros map[string]*Macro, depth int) ([]token, error) {
	if depth > 5 {
		return nil, errors.New("macros nest too deep")
	}
	var out []token
	rs := []rune(s)
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '`':
			j := i + 1
			for j < len(rs) && rs[j] != '`' {
				j++
			}
			if j == len(rs) {
				return nil, errors.New("unclosed macro")
			}
			name := string(rs[i+1 : j])
			if strings.Contains(name, "(") {
				return nil, fmt.Errorf("macro with arguments %s is not supported in a where clause", name)
			}
			m := macros[name]
			if m == nil {
				return nil, fmt.Errorf("macro %s is not defined", name)
			}
			sub, err := lex(m.Definition, macros, depth+1)
			if err != nil {
				return nil, fmt.Errorf("macro %s: %w", name, err)
			}
			out = append(out, token{'o', "("})
			out = append(out, sub...)
			out = append(out, token{'o', ")"})
			i = j + 1
		case c == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				// \\, \" and \= stand for the character; any other
				// backslash is literal.
				if rs[j] == '\\' && j+1 < len(rs) && strings.ContainsRune(`\"=`, rs[j+1]) {
					j++
				}
				b.WriteRune(rs[j])
			}
			if j == len(rs) {
				return nil, errors.New("unclosed quote")
			}
			out = append(out, token{'s', b.String()})
			i = j + 1
		case c == '(' || c == ')' || c == ',':
			out = append(out, token{'o', string(c)})
			i++
		case c == '!' && i+1 < len(rs) && rs[i+1] == '=':
			out = append(out, token{'o', "!="})
			i += 2
		case c == '=':
			out = append(out, token{'o', "="})
			i++
		case c == '<' || c == '>':
			return nil, errors.New("comparisons with < or > are not supported")
		default:
			// Unquoted, as quoted, \\ is one backslash in Splunk's search
			// syntax: *\\users\\public\\* matches C:\Users\Public\x.
			var b strings.Builder
			j := i
			for j < len(rs) && !unicode.IsSpace(rs[j]) && !strings.ContainsRune("()=,\"`!<>", rs[j]) {
				if rs[j] == '\\' && j+1 < len(rs) && rs[j+1] == '\\' {
					j++
				}
				b.WriteRune(rs[j])
				j++
			}
			out = append(out, token{'w', b.String()})
			i = j
		}
	}
	return out, nil
}

type parser struct {
	toks []token
	i    int
	node string
}

func (p *parser) peek() token {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return token{}
}

func (p *parser) keyword(k string) bool {
	t := p.peek()
	return t.kind == 'w' && strings.EqualFold(t.text, k)
}

// Splunk's search syntax, which tstats where clauses and raw searches
// use, evaluates OR before AND: "a b OR c" is a AND (b OR c). (The where
// and eval commands differ, with AND first.)
func (p *parser) and() (Expr, error) {
	var kids []Expr
	for {
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		kids = append(kids, e)
		if p.keyword("AND") {
			p.i++
			continue
		}
		// Terms side by side are ANDed, unless the clause or group ends.
		if t := p.peek(); t.kind == 0 || t.text == ")" {
			break
		}
	}
	if len(kids) == 1 {
		return kids[0], nil
	}
	return &And{kids}, nil
}

func (p *parser) or() (Expr, error) {
	var kids []Expr
	for {
		e, err := p.not()
		if err != nil {
			return nil, err
		}
		kids = append(kids, e)
		if !p.keyword("OR") {
			break
		}
		p.i++
	}
	if len(kids) == 1 {
		return kids[0], nil
	}
	return &Or{kids}, nil
}

func (p *parser) not() (Expr, error) {
	if p.keyword("NOT") {
		p.i++
		e, err := p.not()
		if err != nil {
			return nil, err
		}
		return &Not{e}, nil
	}
	return p.primary()
}

func (p *parser) primary() (Expr, error) {
	t := p.peek()
	if t.kind == 'o' && t.text == "(" {
		p.i++
		e, err := p.and()
		if err != nil {
			return nil, err
		}
		if p.peek().text != ")" {
			return nil, errors.New("missing )")
		}
		p.i++
		return e, nil
	}
	if t.kind != 'w' {
		return nil, fmt.Errorf("expected a field, found %q", t.text)
	}
	field, err := p.field(t.text)
	if err != nil {
		return nil, err
	}
	p.i++
	op := p.peek()
	switch {
	case op.kind == 'o' && (op.text == "=" || op.text == "!="):
		p.i++
		v := p.peek()
		if v.kind != 'w' && v.kind != 's' {
			return nil, fmt.Errorf("%s %s needs a value", t.text, op.text)
		}
		p.i++
		return &Cmp{Field: field, Neg: op.text == "!=", Values: []string{v.text}}, nil
	case p.keyword("IN"):
		p.i++
		if p.peek().text != "(" {
			return nil, fmt.Errorf("%s IN needs a list", t.text)
		}
		p.i++
		var vals []string
		for {
			v := p.peek()
			if v.kind != 'w' && v.kind != 's' {
				return nil, fmt.Errorf("%s IN: expected a value, found %q", t.text, v.text)
			}
			vals = append(vals, v.text)
			p.i++
			if p.peek().text == "," {
				p.i++
				// SPL allows a trailing comma.
				if p.peek().text == ")" {
					break
				}
				continue
			}
			break
		}
		if p.peek().text != ")" {
			return nil, fmt.Errorf("%s IN: missing )", t.text)
		}
		p.i++
		return &Cmp{Field: field, Values: vals}, nil
	}
	return nil, fmt.Errorf("a bare term %s is not supported", t.text)
}

// field checks a node-prefixed field name and returns it without the
// prefix.
func (p *parser) field(name string) (string, error) {
	if source, ok := strings.CutPrefix(p.node, "raw:"); ok {
		// Splunk field names are case sensitive.
		if name == "EventCode" || name == "EventID" {
			return eventCode, nil
		}
		if source, ok = strings.CutSuffix(source, xmlkvSuffix); ok {
			if f, ok := XMLKVFields[name]; ok {
				return f, nil
			}
		}
		for _, node := range rawNodes[source] {
			if f, ok := RawFields[node][name]; ok {
				return f, nil
			}
		}
		return "", fmt.Errorf("field %s has no Signalith mapping", name)
	}
	f, ok := strings.CutPrefix(name, p.node+".")
	if !ok {
		return "", fmt.Errorf("field %s is not a field of %s", name, p.node)
	}
	if !slices.Contains(Nodes[p.node], f) {
		return "", fmt.Errorf("field %s has no Signalith mapping", name)
	}
	return f, nil
}

// Eval reports whether an event, as field values, matches a where clause
// the way Splunk reads it: a field compared with = or IN must be present
// and match one of the values, and != needs the field present and
// matching none. A missing field never matches =, and NOT turns the
// result around.
func Eval(e Expr, ev map[string]string) bool {
	switch x := e.(type) {
	case *And:
		for _, k := range x.Kids {
			if !Eval(k, ev) {
				return false
			}
		}
		return true
	case *Or:
		for _, k := range x.Kids {
			if Eval(k, ev) {
				return true
			}
		}
		return false
	case *Not:
		return !Eval(x.Kid, ev)
	case *Cmp:
		v, ok := ev[x.Field]
		if !ok {
			return false
		}
		any := false
		for _, p := range x.Values {
			if Glob(p, v) {
				any = true
				break
			}
		}
		return any != x.Neg
	}
	return false
}

// Glob matches a Splunk pattern: * is any run of characters, case is
// ignored, everything else (? and \ too) is literal.
func Glob(pattern, s string) bool {
	p := []rune(strings.ToLower(pattern))
	t := []rune(strings.ToLower(s))
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] != '*' && p[pi] == t[ti]:
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
