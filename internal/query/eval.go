package query

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// EvalExpr is a value expression, as used by eval and by where conditions
// that call functions or compare fields with each other.
type EvalExpr interface{ String() string }

// Num is a number literal, kept as written so it prints back the same.
type Num struct{ Text string }

// Str is a quoted string literal.
type Str struct{ Value string }

// Field is a reference to a field's value: a bare name, or a name in single
// quotes when it holds other characters ('dc(user)', 'event.id').
type Field struct{ Name string }

// Call is a function call: lower(user), if(x>1, "a", "b").
type Call struct {
	Func string // lower case
	Args []EvalExpr
}

// Unary is -x or NOT x.
type Unary struct {
	Op string // "-" or "NOT"
	X  EvalExpr
}

// Binary is x <op> y. Op is one of + - * / % . = != < <= > >= LIKE AND
// XOR OR.
type Binary struct {
	Op   string
	L, R EvalExpr
}

// Assign is one name=expression in an eval command.
type Assign struct {
	Field string
	Expr  EvalExpr
}

// Eval computes new fields: eval ratio=round(bytes_out/bytes_in, 2), kind=lower(kind).
type Eval struct{ Assigns []Assign }

func (*Eval) Name() string { return "eval" }

// Cond is a where condition written as a value expression, such as
// where len(process) > 200 or where bytes_out > bytes_in. It is used when
// the condition is not a plain field-against-value filter.
type Cond struct{ X EvalExpr }

// String writes the condition so that it reads back as the same
// condition: where it would read as a plain filter (user != other, which
// compares user with the text "other"), its fields are put in single
// quotes ('user' != 'other').
func (c *Cond) String() string {
	s := c.X.String()
	if _, err := parseClassicWhere(s, 0); err != nil {
		return s
	}
	return quoteFields(c.X).String()
}

// quotedField is a field written in single quotes whatever its name.
type quotedField struct{ name string }

func (f *quotedField) String() string { return quoteSingle(f.name) }

// quoteFields returns x with each field written in single quotes.
func quoteFields(x EvalExpr) EvalExpr {
	switch x := x.(type) {
	case *Field:
		return &quotedField{x.Name}
	case *Call:
		c := &Call{Func: x.Func, Args: make([]EvalExpr, len(x.Args))}
		for i, a := range x.Args {
			c.Args[i] = quoteFields(a)
		}
		return c
	case *Unary:
		return &Unary{Op: x.Op, X: quoteFields(x.X)}
	case *Binary:
		return &Binary{Op: x.Op, L: quoteFields(x.L), R: quoteFields(x.R)}
	}
	return x
}

// EvalFuncs lists the functions eval and where accept, with how many
// arguments each takes (max -1 for any number).
var EvalFuncs = map[string][2]int{
	"abs": {1, 1}, "case": {2, -1}, "ceil": {1, 1}, "ceiling": {1, 1}, "cidrmatch": {2, 2},
	"coalesce": {1, -1}, "exp": {1, 1}, "false": {0, 0}, "floor": {1, 1}, "if": {3, 3},
	"in": {2, -1}, "isnotnull": {1, 1}, "isnull": {1, 1}, "isnum": {1, 1}, "isstr": {1, 1},
	"len": {1, 1}, "like": {2, 2}, "ln": {1, 1}, "log": {1, 2}, "lower": {1, 1},
	"ltrim": {1, 2}, "match": {2, 2}, "max": {1, -1}, "md5": {1, 1}, "min": {1, -1},
	"mvappend": {1, -1}, "mvcount": {1, 1}, "mvdedup": {1, 1}, "mvindex": {2, 3}, "mvjoin": {2, 2},
	"mvsort": {1, 1}, "now": {0, 0}, "null": {0, 0}, "nullif": {2, 2}, "pow": {2, 2},
	"replace": {3, 3}, "round": {1, 2}, "rtrim": {1, 2}, "sha1": {1, 1}, "sha256": {1, 1},
	"split": {2, 2}, "sqrt": {1, 1}, "strftime": {2, 2}, "strptime": {2, 2}, "substr": {2, 3},
	"time": {0, 0}, "tonumber": {1, 2}, "tostring": {1, 2}, "trim": {1, 2}, "true": {0, 0},
	"typeof": {1, 1}, "upper": {1, 1}, "urldecode": {1, 1},
	"mvfilter": {1, 1}, "mvmap": {2, 2}, "mvfind": {2, 2}, "mvzip": {2, 3},
}

// maxEvalDepth bounds how deeply an expression may nest, so a hostile
// query cannot exhaust the stack.
const maxEvalDepth = 100

// maxEvalNodes bounds the terms and operators in one expression.
const maxEvalNodes = 10000

// ---- printing ----

func (e *Num) String() string { return e.Text }
func (e *Str) String() string { return quote(e.Value) }
func (e *Field) String() string {
	if isEvalIdent(e.Name) {
		return e.Name
	}
	return quoteSingle(e.Name)
}
func (e *Call) String() string   { return evalText(e) }
func (e *Unary) String() string  { return evalText(e) }
func (e *Binary) String() string { return evalText(e) }

// evalText prints an expression into one buffer, so a long chain such as
// a OR b OR c ... prints in linear time.
func evalText(e EvalExpr) string {
	var b strings.Builder
	writeEval(&b, e)
	return b.String()
}

func writeEval(b *strings.Builder, e EvalExpr) {
	switch e := e.(type) {
	case *Call:
		b.WriteString(e.Func)
		b.WriteByte('(')
		for i, a := range e.Args {
			if i > 0 {
				b.WriteString(", ")
			}
			writeEval(b, a)
		}
		b.WriteByte(')')
	case *Unary:
		if e.Op == "NOT" {
			b.WriteString("NOT ")
			writeWrapped(b, e.X, precOf(e.X) < precNot)
			return
		}
		_, num := e.X.(*Num)
		b.WriteByte('-')
		writeWrapped(b, e.X, num || precOf(e.X) < precUnary)
	case *Binary:
		p := binaryPrec[e.Op]
		writeWrapped(b, e.L, precOf(e.L) < p)
		b.WriteString(" " + e.Op + " ")
		writeWrapped(b, e.R, precOf(e.R) <= p)
	default:
		b.WriteString(e.String())
	}
}

func writeWrapped(b *strings.Builder, e EvalExpr, paren bool) {
	if paren {
		b.WriteByte('(')
	}
	writeEval(b, e)
	if paren {
		b.WriteByte(')')
	}
}

const (
	precOr = iota + 1
	precXor
	precAnd
	precNot
	precCompare
	precAdd
	precMul
	precUnary
	precAtom
)

var binaryPrec = map[string]int{
	"OR": precOr, "XOR": precXor, "AND": precAnd,
	"=": precCompare, "!=": precCompare, "<": precCompare, "<=": precCompare, ">": precCompare, ">=": precCompare, "LIKE": precCompare,
	"+": precAdd, "-": precAdd, ".": precAdd,
	"*": precMul, "/": precMul, "%": precMul,
}

func precOf(e EvalExpr) int {
	switch e := e.(type) {
	case *Binary:
		return binaryPrec[e.Op]
	case *Unary:
		if e.Op == "NOT" {
			return precNot
		}
		return precUnary
	case *Num:
		if strings.HasPrefix(e.Text, "-") {
			return precUnary
		}
	}
	return precAtom
}

var evalKeywords = map[string]bool{"AND": true, "OR": true, "NOT": true, "XOR": true, "LIKE": true}

func isEvalIdent(s string) bool {
	if s == "" || evalKeywords[strings.ToUpper(s)] {
		return false
	}
	for i, r := range s {
		if r == '_' || r == '@' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func quoteSingle(v string) string {
	return `'` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `'`, `\'`) + `'`
}

func evalString(c *Eval) string {
	parts := make([]string, len(c.Assigns))
	for i, a := range c.Assigns {
		parts[i] = (&Field{Name: a.Field}).String() + "=" + a.Expr.String()
	}
	return "eval " + strings.Join(parts, ", ")
}

// ---- lexing ----

type evalTokKind int

const (
	etEOF evalTokKind = iota
	etNum
	etStr
	etIdent  // bare name
	etQIdent // 'quoted name'
	etOp
	etLParen
	etRParen
	etComma
)

type evalTok struct {
	kind evalTokKind
	text string
	pos  int
}

func lexEval(src string, base int) ([]evalTok, error) {
	var toks []evalTok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '(':
			toks = append(toks, evalTok{etLParen, "(", base + i})
			i++
		case c == ')':
			toks = append(toks, evalTok{etRParen, ")", base + i})
			i++
		case c == ',':
			toks = append(toks, evalTok{etComma, ",", base + i})
			i++
		case c >= '0' && c <= '9':
			start := i
			for i < len(src) && src[i] >= '0' && src[i] <= '9' {
				i++
			}
			if i+1 < len(src) && src[i] == '.' && src[i+1] >= '0' && src[i+1] <= '9' {
				i++
				for i < len(src) && src[i] >= '0' && src[i] <= '9' {
					i++
				}
			}
			if i < len(src) && (src[i] == 'e' || src[i] == 'E') {
				j := i + 1
				if j < len(src) && (src[j] == '+' || src[j] == '-') {
					j++
				}
				if j < len(src) && src[j] >= '0' && src[j] <= '9' {
					for j < len(src) && src[j] >= '0' && src[j] <= '9' {
						j++
					}
					i = j
				}
			}
			if i < len(src) && isEvalIdentRune(src[i]) {
				return nil, errorf(base+start, "%q is not a number or a field name; quote field names that start with a digit, like '%s'", src[start:i+1], src[start:i+1])
			}
			toks = append(toks, evalTok{etNum, src[start:i], base + start})
		case c == '"' || c == '\'':
			start := i
			i++
			var b strings.Builder
			closed := false
			for i < len(src) {
				if src[i] == '\\' && i+1 < len(src) && (src[i+1] == c || src[i+1] == '\\') {
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				if src[i] == c {
					closed = true
					i++
					break
				}
				b.WriteByte(src[i])
				i++
			}
			if !closed {
				return nil, errorf(base+start, "unterminated quoted string")
			}
			kind := etStr
			if c == '\'' {
				kind = etQIdent
			}
			toks = append(toks, evalTok{kind, b.String(), base + start})
		case c >= 0x80:
			r, _ := utf8.DecodeRuneInString(src[i:])
			return nil, errorf(base+i, "unexpected %q; quote field names with other characters, like 'my field'", string(r))
		case isEvalIdentRune(c):
			start := i
			for i < len(src) && (isEvalIdentRune(src[i]) || src[i] >= '0' && src[i] <= '9' ||
				// A dot between name characters is part of the name, as in
				// Splunk: userIdentity.userName is one field. With spaces
				// around it, . joins values.
				src[i] == '.' && i+1 < len(src) && (isEvalIdentRune(src[i+1]) || src[i+1] >= '0' && src[i+1] <= '9')) {
				i++
			}
			toks = append(toks, evalTok{etIdent, src[start:i], base + start})
		default:
			start := i
			op := string(c)
			if i+1 < len(src) {
				two := src[i : i+2]
				switch two {
				case "==", "!=", "<=", ">=":
					op = two
				}
			}
			switch op {
			case "+", "-", "*", "/", "%", ".", "=", "==", "!=", "<", "<=", ">", ">=":
			default:
				return nil, errorf(base+start, "unexpected %q in expression", op)
			}
			i += len(op)
			if op == "==" {
				op = "="
			}
			toks = append(toks, evalTok{etOp, op, base + start})
		}
	}
	return append(toks, evalTok{etEOF, "", base + len(src)}), nil
}

func isEvalIdentRune(c byte) bool {
	return c == '_' || c == '@' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// ---- parsing ----

type evalParser struct {
	toks  []evalTok
	i     int
	depth int
	nodes int
}

// node counts one more piece of the expression being built and fails once
// there are too many.
func (p *evalParser) node() error {
	if p.nodes++; p.nodes > maxEvalNodes {
		return errorf(p.peek().pos, "the expression is too long; the limit is %d terms", maxEvalNodes)
	}
	return nil
}

func (p *evalParser) peek() evalTok { return p.toks[p.i] }
func (p *evalParser) next() evalTok {
	t := p.toks[p.i]
	if t.kind != etEOF {
		p.i++
	}
	return t
}

func (p *evalParser) keyword(kw string) bool {
	t := p.peek()
	return t.kind == etIdent && strings.EqualFold(t.text, kw)
}

func describeEval(t evalTok) string {
	if t.kind == etEOF {
		return "end of expression"
	}
	if t.kind == etStr {
		return quote(t.text)
	}
	if t.kind == etQIdent {
		return quoteSingle(t.text)
	}
	return `"` + t.text + `"`
}

// ParseEvalExpr parses a value expression on its own.
func ParseEvalExpr(src string) (EvalExpr, error) {
	toks, err := lexEval(src, 0)
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

// parseEvalCommand parses the text after "eval": name=expr, name=expr.
func parseEvalCommand(src string, base int) (*Eval, error) {
	toks, err := lexEval(src, base)
	if err != nil {
		return nil, err
	}
	p := &evalParser{toks: toks}
	c := &Eval{}
	for {
		t := p.next()
		if t.kind != etIdent && t.kind != etQIdent && t.kind != etStr || t.text == "" {
			return nil, errorf(t.pos, "eval expects name=expression, for example: eval kb=bytes/1024")
		}
		if t.kind == etIdent && evalKeywords[strings.ToUpper(t.text)] {
			return nil, errorf(t.pos, "%s is a keyword; quote it to use it as a field name: '%s'", t.text, t.text)
		}
		// Written back, a name is single-quoted, and a quoted name can't
		// hold a pipe: the pipe would end the command.
		if strings.Contains(t.text, "|") {
			return nil, errorf(t.pos, "eval can't create a field whose name contains |")
		}
		if eq := p.next(); eq.kind != etOp || eq.text != "=" {
			return nil, errorf(eq.pos, `expected "=" after %s in eval`, t.text)
		}
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		c.Assigns = append(c.Assigns, Assign{Field: t.text, Expr: e})
		nt := p.next()
		if nt.kind == etEOF {
			return c, nil
		}
		if nt.kind != etComma {
			return nil, errorf(nt.pos, "unexpected %s in eval; separate assignments with commas", describeEval(nt))
		}
	}
}

func (p *evalParser) expr() (EvalExpr, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxEvalDepth {
		return nil, errorf(p.peek().pos, "expression nests too deeply")
	}
	return p.binary(precOr)
}

func (p *evalParser) binaryOp() (string, int) {
	t := p.peek()
	switch t.kind {
	case etOp:
		return t.text, binaryPrec[t.text]
	case etIdent:
		up := strings.ToUpper(t.text)
		switch up {
		case "AND", "OR", "XOR", "LIKE":
			return up, binaryPrec[up]
		}
	}
	return "", 0
}

// binary parses a chain of operators of precedence prec, left to right,
// whose operands hold only tighter ones.
func (p *evalParser) binary(prec int) (EvalExpr, error) {
	operand := func() (EvalExpr, error) {
		switch {
		case prec == precAnd:
			return p.not()
		case prec >= precMul:
			return p.unary()
		}
		next := prec + 1
		if next == precNot {
			next = precCompare
		}
		return p.binary(next)
	}
	l, err := operand()
	if err != nil {
		return nil, err
	}
	for {
		op, opPrec := p.binaryOp()
		if op == "" || opPrec != prec {
			return l, nil
		}
		if err := p.node(); err != nil {
			return nil, err
		}
		p.next()
		r, err := operand()
		if err != nil {
			return nil, err
		}
		l = &Binary{Op: op, L: l, R: r}
	}
}

// not parses NOT x or a comparison.
func (p *evalParser) not() (EvalExpr, error) {
	if !p.keyword("NOT") {
		return p.binary(precCompare)
	}
	p.next()
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxEvalDepth {
		return nil, errorf(p.peek().pos, "expression nests too deeply")
	}
	x, err := p.not()
	if err != nil {
		return nil, err
	}
	return &Unary{Op: "NOT", X: x}, nil
}

func (p *evalParser) unary() (EvalExpr, error) {
	t := p.peek()
	if t.kind == etOp && t.text == "-" {
		p.next()
		if n := p.peek(); n.kind == etNum {
			p.next()
			return &Num{Text: "-" + n.text}, nil
		}
		p.depth++
		defer func() { p.depth-- }()
		if p.depth > maxEvalDepth {
			return nil, errorf(p.peek().pos, "expression nests too deeply")
		}
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &Unary{Op: "-", X: x}, nil
	}
	return p.primary()
}

func (p *evalParser) primary() (EvalExpr, error) {
	if err := p.node(); err != nil {
		return nil, err
	}
	t := p.next()
	switch t.kind {
	case etNum:
		return &Num{Text: t.text}, nil
	case etStr:
		return &Str{Value: t.text}, nil
	case etQIdent:
		if t.text == "" {
			return nil, errorf(t.pos, "empty field name")
		}
		return &Field{Name: t.text}, nil
	case etIdent:
		if p.peek().kind == etLParen {
			return p.call(t)
		}
		if evalKeywords[strings.ToUpper(t.text)] {
			return nil, errorf(t.pos, "unexpected %s", t.text)
		}
		return &Field{Name: t.text}, nil
	case etLParen:
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		if rp := p.next(); rp.kind != etRParen {
			return nil, errorf(t.pos, `unmatched "("`)
		}
		return e, nil
	}
	return nil, errorf(t.pos, "expected a value, field or function, got %s", describeEval(t))
}

func (p *evalParser) call(name evalTok) (EvalExpr, error) {
	fn := strings.ToLower(name.text)
	arity, ok := EvalFuncs[fn]
	if !ok {
		return nil, errorf(name.pos, "unknown function %q", name.text)
	}
	p.next() // (
	c := &Call{Func: fn}
	if p.peek().kind == etRParen {
		p.next()
	} else {
		for {
			a, err := p.expr()
			if err != nil {
				return nil, err
			}
			c.Args = append(c.Args, a)
			t := p.next()
			if t.kind == etRParen {
				break
			}
			if t.kind != etComma {
				return nil, errorf(t.pos, `expected "," or ")" in %s()`, fn)
			}
		}
	}
	n := len(c.Args)
	switch {
	case n < arity[0] || arity[1] >= 0 && n > arity[1]:
		var want string
		switch {
		case arity[0] == arity[1]:
			want = strconv.Itoa(arity[0])
		case arity[1] < 0:
			want = "at least " + strconv.Itoa(arity[0])
		default:
			want = strconv.Itoa(arity[0]) + " or " + strconv.Itoa(arity[1])
		}
		noun := " arguments"
		if want == "1" {
			noun = " argument"
		}
		return nil, errorf(name.pos, "%s() takes %s%s, got %d", fn, want, noun, n)
	case fn == "case" && n%2 != 0:
		return nil, errorf(name.pos, "case() takes pairs of condition, value")
	}
	return c, nil
}

// WalkEval calls fn for e and every expression inside it.
func WalkEval(e EvalExpr, fn func(EvalExpr)) {
	if e == nil {
		return
	}
	fn(e)
	switch e := e.(type) {
	case *Call:
		for _, a := range e.Args {
			WalkEval(a, fn)
		}
	case *Unary:
		WalkEval(e.X, fn)
	case *Binary:
		WalkEval(e.L, fn)
		WalkEval(e.R, fn)
	}
}
