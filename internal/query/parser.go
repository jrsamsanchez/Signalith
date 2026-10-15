package query

import (
	"strconv"
	"strings"
)

// Commands lists every pipe command, for autocomplete and error messages.
var Commands = []string{"stats", "eventstats", "timechart", "top", "rare", "where", "eval", "rex", "dedup", "fillnull", "sort", "head", "table", "rename", "lookup", "inputlookup", "transaction", "enrich", "intel", "threatmatch"}

// AggFuncs lists the aggregation functions stats, eventstats and timechart
// accept. perc95 stands for every percentile from perc1 to perc99.
var AggFuncs = []string{"count", "dc", "sum", "avg", "min", "max", "median", "perc95", "stdev", "var", "range", "mode", "values", "list", "first", "last", "earliest", "latest"}

// aggAliases are other names for aggregation functions.
var aggAliases = map[string]string{"distinct_count": "dc", "mean": "avg"}

// Percentile returns N for percN (perc95, or p95 written short), or 0.
func Percentile(fn string) int {
	digits := strings.TrimPrefix(fn, "perc")
	if digits == fn {
		digits = strings.TrimPrefix(fn, "p")
	}
	if digits == fn || !allDigits(digits) || len(digits) > 2 || digits[0] == '0' {
		return 0
	}
	n, _ := strconv.Atoi(digits)
	return n
}

type parser struct {
	toks []token
	i    int
}

// Parse parses a query.
func Parse(src string) (*Query, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	q := &Query{}
	if err := p.parseSearch(q); err != nil {
		return nil, err
	}
	for p.peek().kind == tokPipe {
		p.next()
		at := p.peek().pos
		cmd, err := p.parseCommand()
		if err != nil {
			return nil, err
		}
		if _, ok := cmd.(*InputLookup); ok && (len(q.Commands) > 0 || q.Search != nil || q.Index != "" || q.Datamodel != "" || q.Earliest != "" || q.Latest != "") {
			return nil, errorf(at, "inputlookup reads a lookup table instead of events, so it starts the search: | inputlookup owners")
		}
		q.Commands = append(q.Commands, cmd)
	}
	if t := p.peek(); t.kind != tokEOF {
		return nil, errorf(t.pos, "unexpected %q", t.text)
	}
	return q, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) peekAt(n int) token {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return p.toks[len(p.toks)-1]
}
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

func (p *parser) isKeyword(kw string) bool {
	t := p.peek()
	return t.kind == tokWord && t.text == kw
}

func (p *parser) isKeywordFold(kw string) bool {
	t := p.peek()
	return t.kind == tokWord && strings.EqualFold(t.text, kw)
}

// ---- search expression ----
//
// Precedence follows SPL: NOT binds tightest, then OR, then the implicit
// (or explicit) AND between terms. So `a b OR c` means `a AND (b OR c)`.

func (p *parser) parseSearch(q *Query) error {
	var terms []Expr
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe || t.kind == tokRParen {
			break
		}
		if p.isKeyword("AND") {
			p.next()
			continue
		}
		// Pull out the special top-level terms.
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			switch strings.ToLower(t.text) {
			case "datamodel", "index", "earliest", "latest":
				p.next()
				p.next()
				at := p.peek().pos
				v, err := p.value()
				if err != nil {
					return err
				}
				switch strings.ToLower(t.text) {
				case "datamodel":
					if err := CheckDatamodel(v); err != nil {
						return &Error{Pos: at, Msg: err.Error()}
					}
					q.Datamodel = v
				case "index":
					if err := CheckIndex(v); err != nil {
						return &Error{Pos: at, Msg: err.Error()}
					}
					q.Index = v
				case "earliest":
					q.Earliest = v
				case "latest":
					q.Latest = v
				}
				continue
			}
		}
		e, err := p.parseOrTerm(true)
		if err != nil {
			return err
		}
		if e != nil {
			terms = append(terms, e)
		}
	}
	if t := p.peek(); t.kind == tokRParen {
		return errorf(t.pos, `unmatched ")"`)
	}
	q.Search = simplifyAnd(terms)
	return nil
}

func simplifyAnd(terms []Expr) Expr {
	switch len(terms) {
	case 0:
		return nil
	case 1:
		return terms[0]
	}
	return &And{Children: terms}
}

func (p *parser) parseOrTerm(search bool) (Expr, error) {
	first, err := p.parseUnary(search)
	if err != nil {
		return nil, err
	}
	children := []Expr{first}
	all := first == nil // a bare * matches every event
	for p.isKeyword("OR") {
		p.next()
		e, err := p.parseUnary(search)
		if err != nil {
			return nil, err
		}
		all = all || e == nil
		children = append(children, e)
	}
	if all {
		return nil, nil
	}
	if len(children) == 1 {
		return first, nil
	}
	return &Or{Children: children}, nil
}

func (p *parser) parseUnary(search bool) (Expr, error) {
	if p.isKeyword("NOT") {
		p.next()
		at := p.peek().pos
		e, err := p.parseUnary(search)
		if err != nil {
			return nil, err
		}
		if e == nil {
			return nil, errorf(at, "NOT * matches nothing")
		}
		return &Not{Child: e}, nil
	}
	t := p.peek()
	if t.kind == tokLParen {
		p.next()
		var terms []Expr
		star := false // the parentheses held only *
		for {
			if p.peek().kind == tokRParen {
				p.next()
				break
			}
			if p.peek().kind == tokEOF || p.peek().kind == tokPipe {
				return nil, errorf(t.pos, `unmatched "("`)
			}
			if p.isKeyword("AND") {
				p.next()
				continue
			}
			e, err := p.parseOrTerm(search)
			if err != nil {
				return nil, err
			}
			if e == nil {
				// * inside parentheses adds nothing, as at the top level.
				star = true
				continue
			}
			terms = append(terms, e)
		}
		if len(terms) == 0 && !star {
			return nil, errorf(t.pos, "empty parentheses")
		}
		return simplifyAnd(terms), nil
	}
	return p.parseAtom(search)
}

func (p *parser) parseAtom(search bool) (Expr, error) {
	t := p.peek()
	switch t.kind {
	case tokString:
		p.next()
		if search {
			return &Text{Value: t.text}, nil
		}
		return nil, errorf(t.pos, "expected a field name, got a quoted string")
	case tokWord:
		p.next()
		if !search {
			t.text = p.fieldSuffix(t.text)
		}
		nt := p.peek()
		if search && (nt.kind == tokOp || nt.kind == tokWord && nt.text == "IN") {
			switch t.text {
			case "AND", "OR", "NOT", "IN":
				// Only the first term could name such a field, so a
				// query with it could not be written back.
				return nil, errorf(t.pos, "%s is a keyword, not a field name", t.text)
			}
		}
		if nt.kind == tokOp {
			p.next()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			return &Compare{Field: t.text, Op: nt.text, Value: v}, nil
		}
		if nt.kind == tokWord && nt.text == "IN" {
			p.next()
			return p.parseIn(t.text)
		}
		if search {
			if t.text == "*" {
				return nil, nil
			}
			return &Text{Value: t.text}, nil
		}
		return nil, errorf(nt.pos, "expected a comparison after %q (for example %s=value)", t.text, t.text)
	}
	return nil, errorf(t.pos, "unexpected %s", describe(t))
}

func (p *parser) parseIn(field string) (Expr, error) {
	lp := p.next()
	if lp.kind != tokLParen {
		return nil, errorf(lp.pos, `expected "(" after IN`)
	}
	in := &In{Field: field}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		in.Values = append(in.Values, v)
		t := p.next()
		if t.kind == tokRParen {
			return in, nil
		}
		if t.kind != tokComma {
			return nil, errorf(t.pos, `expected "," or ")" in IN list`)
		}
	}
}

func (p *parser) value() (string, error) {
	t := p.peek()
	if t.kind == tokWord || t.kind == tokString {
		p.next()
		return t.text, nil
	}
	return "", errorf(t.pos, "expected a value, got %s", describe(t))
}

func describe(t token) string {
	if t.kind == tokEOF {
		return "end of query"
	}
	return strconv.Quote(t.text)
}

// ---- commands ----

func (p *parser) parseCommand() (Command, error) {
	t := p.next()
	if t.kind != tokWord {
		return nil, errorf(t.pos, "expected a command after |, such as %s", strings.Join(Commands, ", "))
	}
	switch strings.ToLower(t.text) {
	case "stats", "eventstats":
		aggs, err := p.parseAggs(t.pos)
		if err != nil {
			return nil, err
		}
		by, err := p.parseBy()
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(t.text, "eventstats") {
			return &EventStats{Aggs: aggs, By: by}, p.endCommand()
		}
		return &Stats{Aggs: aggs, By: by}, p.endCommand()
	case "timechart":
		tc := &Timechart{}
		if p.isKeywordFold("span") && p.peekAt(1).kind == tokOp {
			p.next()
			p.next()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			tc.Span = v
		}
		if p.peek().kind == tokEOF || p.peek().kind == tokPipe || p.isKeywordFold("by") {
			tc.Aggs = []Agg{{Func: "count"}}
		} else {
			aggs, err := p.parseAggs(t.pos)
			if err != nil {
				return nil, err
			}
			tc.Aggs = aggs
		}
		by, err := p.parseBy()
		if err != nil {
			return nil, err
		}
		if len(by) > 1 {
			return nil, errorf(t.pos, "timechart accepts one by field")
		}
		if len(by) == 1 {
			if len(tc.Aggs) > 1 {
				return nil, errorf(t.pos, "timechart with a by field accepts one aggregation")
			}
			tc.By = by[0]
		}
		return tc, p.endCommand()
	case "top", "rare":
		top := &Top{Limit: 10, Rare: strings.EqualFold(t.text, "rare")}
		if p.isKeywordFold("limit") && p.peekAt(1).kind == tokOp {
			p.next()
			p.next()
			n, err := p.int()
			if err != nil {
				return nil, err
			}
			top.Limit = n
		} else if n, err := strconv.Atoi(p.peek().text); err == nil && n >= 0 && p.peek().kind == tokWord {
			p.next()
			top.Limit = n
		}
		fields, err := p.fieldList(false)
		if err != nil {
			return nil, err
		}
		if len(fields) == 0 {
			return nil, errorf(t.pos, "%s needs at least one field", strings.ToLower(t.text))
		}
		top.Fields = fields
		by, err := p.parseBy()
		if err != nil {
			return nil, err
		}
		top.By = by
		return top, p.endCommand()
	case "where":
		raw := p.next()
		e, err := parseWhere(raw.text, raw.pos)
		if err != nil {
			return nil, err
		}
		return &Where{Expr: e}, nil
	case "eval":
		raw := p.next()
		if strings.TrimSpace(raw.text) == "" {
			return nil, errorf(t.pos, "eval needs an assignment, for example: eval kb=round(bytes/1024, 1)")
		}
		return parseEvalCommand(raw.text, raw.pos)
	case "rex":
		return p.parseRex(t)
	case "dedup":
		return p.parseDedup(t)
	case "fillnull":
		return p.parseFillnull()
	case "sort":
		s := &Sort{}
		for {
			nt := p.peek()
			if nt.kind != tokWord {
				break
			}
			if n, err := strconv.Atoi(nt.text); err == nil && n >= 0 && len(s.Keys) == 0 {
				p.next() // "sort 10 -count": the limit is ignored, use head
				continue
			}
			p.next()
			k := SortKey{Field: p.fieldSuffix(nt.text)}
			if strings.HasPrefix(nt.text, "-") || strings.HasPrefix(nt.text, "+") {
				k.Field = nt.text[:1] + p.fieldSuffix(nt.text[1:])
			}
			if strings.HasPrefix(k.Field, "-") {
				k.Desc, k.Field = true, k.Field[1:]
			} else if strings.HasPrefix(k.Field, "+") {
				k.Field = k.Field[1:]
			}
			if k.Field == "" {
				return nil, errorf(nt.pos, "sort field name is missing")
			}
			s.Keys = append(s.Keys, k)
			if p.peek().kind == tokComma {
				p.next()
			}
		}
		if len(s.Keys) == 0 {
			return nil, errorf(t.pos, "sort needs at least one field, for example: sort -count")
		}
		return s, p.endCommand()
	case "head", "limit":
		h := &Head{N: 10}
		if p.peek().kind == tokWord {
			n, err := p.int()
			if err != nil {
				return nil, err
			}
			h.N = n
		}
		return h, p.endCommand()
	case "table", "fields":
		fields, err := p.fieldList(true)
		if err != nil {
			return nil, err
		}
		if len(fields) == 0 {
			return nil, errorf(t.pos, "%s needs at least one field", t.text)
		}
		return &Table{Fields: fields}, p.endCommand()
	case "lookup":
		return p.parseLookup(t)
	case "inputlookup":
		return p.parseInputLookup()
	case "transaction":
		return p.parseTransaction()
	case "enrich":
		fields, err := p.fieldList(false)
		if err != nil {
			return nil, err
		}
		return &Enrich{Fields: fields}, p.endCommand()
	case "intel":
		fields, err := p.fieldList(false)
		if err != nil {
			return nil, err
		}
		return &Intel{Fields: fields}, p.endCommand()
	case "threatmatch":
		fields, err := p.fieldList(false)
		if err != nil {
			return nil, err
		}
		return &ThreatMatch{Fields: fields}, p.endCommand()
	case "rename":
		r := &Rename{}
		for {
			from := p.next()
			if from.kind != tokWord && from.kind != tokString {
				return nil, errorf(from.pos, "rename expects: rename old as new")
			}
			fromName := from.text
			if from.kind == tokWord {
				fromName = p.fieldSuffix(from.text)
			}
			if !p.isKeywordFold("as") {
				return nil, errorf(p.peek().pos, `expected "as" in rename`)
			}
			p.next()
			to := p.next()
			if to.kind != tokWord && to.kind != tokString {
				return nil, errorf(to.pos, "rename expects: rename old as new")
			}
			r.Pairs = append(r.Pairs, [2]string{fromName, to.text})
			if p.peek().kind != tokComma {
				break
			}
			p.next()
		}
		return r, p.endCommand()
	}
	return nil, errorf(t.pos, "unknown command %q; available: %s", t.text, strings.Join(Commands, ", "))
}

func (p *parser) endCommand() error {
	t := p.peek()
	if t.kind == tokEOF || t.kind == tokPipe {
		return nil
	}
	return errorf(t.pos, "unexpected %s", describe(t))
}

func (p *parser) int() (int, error) {
	t := p.next()
	n, err := strconv.Atoi(t.text)
	if err != nil || n < 0 {
		return 0, errorf(t.pos, "expected a positive number, got %s", describe(t))
	}
	return n, nil
}

func isAggFunc(s string) bool {
	if Percentile(s) > 0 {
		return strings.HasPrefix(s, "perc")
	}
	for _, f := range AggFuncs {
		if f == s {
			return true
		}
	}
	return false
}

func (p *parser) parseAggs(cmdPos int) ([]Agg, error) {
	var aggs []Agg
	for {
		t := p.peek()
		if t.kind != tokWord || strings.EqualFold(t.text, "by") {
			break
		}
		p.next()
		a := Agg{Func: strings.ToLower(t.text)}
		if f, ok := aggAliases[a.Func]; ok {
			a.Func = f
		}
		if n := Percentile(a.Func); n > 0 {
			a.Func = "perc" + strconv.Itoa(n)
		}
		if !isAggFunc(a.Func) {
			return nil, errorf(t.pos, "unknown function %q; available: %s (and perc1 to perc99)", t.text, strings.Join(AggFuncs, ", "))
		}
		if p.peek().kind == tokLParen {
			p.next()
			f := p.next()
			if f.kind != tokWord {
				return nil, errorf(f.pos, "expected a field name inside %s()", a.Func)
			}
			a.Field = f.text
			if rp := p.next(); rp.kind != tokRParen {
				return nil, errorf(rp.pos, `expected ")"`)
			}
		}
		if a.Field == "" && a.Func != "count" {
			return nil, errorf(t.pos, "%s needs a field, for example %s(bytes)", a.Func, a.Func)
		}
		if p.isKeywordFold("as") {
			p.next()
			al := p.next()
			if al.kind != tokWord && al.kind != tokString {
				return nil, errorf(al.pos, `expected a name after "as"`)
			}
			a.Alias = al.text
		}
		aggs = append(aggs, a)
		if p.peek().kind == tokComma {
			p.next()
		}
	}
	if len(aggs) == 0 {
		return nil, errorf(cmdPos, "expected an aggregation such as count, dc(user) or avg(bytes)")
	}
	return aggs, nil
}

func (p *parser) parseBy() ([]string, error) {
	if !p.isKeywordFold("by") {
		return nil, nil
	}
	byTok := p.next()
	fields, err := p.fieldList(false)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, errorf(byTok.pos, `expected a field after "by"`)
	}
	return fields, nil
}

// fieldList reads "a, b c" style field lists, stopping at "by", pipes and EOF.
func (p *parser) fieldList(allowStrings bool) ([]string, error) {
	var out []string
	for {
		t := p.peek()
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t.kind == tokWord && !strings.EqualFold(t.text, "by") {
			p.next()
			out = append(out, p.fieldSuffix(t.text))
			continue
		}
		if t.kind == tokString && allowStrings {
			p.next()
			out = append(out, t.text)
			continue
		}
		return out, nil
	}
}

// ---- where expressions: AND binds tighter than OR, as in most languages ----

func (p *parser) parseWhereOr() (Expr, error) {
	first, err := p.parseWhereAnd()
	if err != nil {
		return nil, err
	}
	children := []Expr{first}
	for p.isKeywordFold("OR") {
		p.next()
		e, err := p.parseWhereAnd()
		if err != nil {
			return nil, err
		}
		children = append(children, e)
	}
	if len(children) == 1 {
		return first, nil
	}
	return &Or{Children: children}, nil
}

func (p *parser) parseWhereAnd() (Expr, error) {
	first, err := p.parseWhereUnary()
	if err != nil {
		return nil, err
	}
	children := []Expr{first}
	for p.isKeywordFold("AND") {
		p.next()
		e, err := p.parseWhereUnary()
		if err != nil {
			return nil, err
		}
		children = append(children, e)
	}
	return simplifyAnd(children), nil
}

func (p *parser) parseWhereUnary() (Expr, error) {
	if p.isKeywordFold("NOT") {
		p.next()
		e, err := p.parseWhereUnary()
		if err != nil {
			return nil, err
		}
		return &Not{Child: e}, nil
	}
	if t := p.peek(); t.kind == tokLParen {
		p.next()
		e, err := p.parseWhereOr()
		if err != nil {
			return nil, err
		}
		if rp := p.next(); rp.kind != tokRParen {
			return nil, errorf(t.pos, `unmatched "("`)
		}
		return e, nil
	}
	return p.parseAtom(false)
}

// fieldSuffix glues "dc" "(" "user" ")" into the column name "dc(user)" so
// stats output columns can be referenced by later commands.
func (p *parser) fieldSuffix(name string) string {
	if p.peek().kind == tokLParen && p.peekAt(1).kind == tokWord && p.peekAt(2).kind == tokRParen && isAggFunc(strings.ToLower(name)) {
		inner := p.peekAt(1).text
		p.next()
		p.next()
		p.next()
		return name + "(" + inner + ")"
	}
	return name
}
