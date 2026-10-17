package query

import (
	"strconv"
	"strings"
)

// Commands lists every pipe command, for autocomplete and error messages.
var Commands = []string{"search", "stats", "eventstats", "timechart", "top", "rare", "where", "eval", "rex", "dedup", "fillnull", "sort", "head", "table", "rename", "lookup", "inputlookup", "transaction", "join", "enrich", "intel", "threatmatch", "streamstats", "bin", "bucket", "fields", "regex", "makeresults", "append", "appendpipe", "tstats", "chart", "xyseries", "untable", "spath", "mvexpand", "makemv", "reverse", "addtotals", "addcoltotals", "convert", "tail", "uniq", "fromjson", "nomv", "mvcombine", "strcat", "rangemap", "fieldformat", "foreach", "replace", "xmlkv", "iplocation", "map", "accum", "delta", "autoregress", "fieldsummary", "transpose", "filldown", "addinfo", "trendline", "concurrency", "contingency", "format", "return", "makecontinuous", "union", "geostats", "extract", "outlier", "gauge", "multisearch", "timewrap", "cluster"}

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
	toks  []token
	i     int
	depth int // subsearches around this query

	// src is the text the tokens were read from, starting at byte base of
	// what the user wrote, for commands that read part of it again: an
	// aggregation over eval(...). Empty where that is not allowed.
	src  string
	base int
	// evals are the eval(...) expressions of the command being read,
	// each to be computed into its aggregation's AS name first.
	evals []Assign
}

// Parse parses a query.
func Parse(src string) (*Query, error) { return parseAt(src, 0, 0) }

// parseAt parses a query that starts at byte base of the text the user
// wrote, depth subsearches deep.
func parseAt(src string, base, depth int) (*Query, error) {
	toks, err := lex(src)
	if err != nil {
		if pe, ok := err.(*Error); ok {
			pe.Pos += base
		}
		return nil, err
	}
	for i := range toks {
		toks[i].pos += base
	}
	p := &parser{toks: toks, depth: depth, src: src, base: base}
	// A query copied from Splunk may start with the search command's name.
	if t := p.peek(); t.kind == tokWord && strings.EqualFold(t.text, "search") {
		if n := p.peekAt(1); n.kind != tokEOF && n.kind != tokOp {
			p.next()
		}
	}
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
		if ts, ok := cmd.(*tstats); ok {
			if len(q.Commands) > 0 || q.Search != nil || q.Index != "" || q.Datamodel != "" || q.Earliest != "" || q.Latest != "" {
				return nil, errorf(at, "tstats starts the search: | tstats count from datamodel=Authentication by user")
			}
			commands := q.Commands
			*q = ts.q
			q.Commands = append(commands, ts.cmds...)
			continue
		}
		if err := p.flushEvals(&q.Commands, cmd, at); err != nil {
			return nil, err
		}
		if len(q.Commands) > 0 || q.Search != nil || q.Index != "" || q.Datamodel != "" || q.Earliest != "" || q.Latest != "" {
			switch cmd.(type) {
			case *InputLookup:
				return nil, errorf(at, "inputlookup reads a lookup table instead of events, so it starts the search: | inputlookup owners")
			case *MakeResults:
				return nil, errorf(at, "makeresults makes rows instead of searching events, so it starts the search: | makeresults count=3")
			case *MultiSearch:
				return nil, errorf(at, "multisearch runs its own subsearches, so it starts the search: %s", multiSearchExample)
			}
		}
		q.Commands = append(q.Commands, cmd)
	}
	if t := p.peek(); t.kind != tokEOF {
		return nil, errorf(t.pos, "unexpected %q", t.text)
	}
	if depth == 0 && countSubsearches(q) > MaxSubsearches {
		return nil, errorf(base, "a query can run at most %d subsearches", MaxSubsearches)
	}
	if depth == 0 && countMapSearches(q) > MaxMapSearches {
		return nil, errorf(base, "the map commands of a query can run at most %d searches in all; lower maxsearches=", MaxMapSearches)
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
		return p.parseTop(t)
	case "search":
		return p.parseSearchCommand(t)
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
		remove := false
		if strings.EqualFold(t.text, "fields") && p.peek().kind == tokWord && (p.peek().text == "-" || p.peek().text == "+") {
			remove = p.next().text == "-"
		}
		fields, err := p.fieldList(true)
		if err != nil {
			return nil, err
		}
		if len(fields) == 0 {
			return nil, errorf(t.pos, "%s needs at least one field", t.text)
		}
		if remove {
			return &FieldsRemove{Fields: fields}, p.endCommand()
		}
		return &Table{Fields: fields}, p.endCommand()
	case "streamstats":
		return p.parseStreamStats(t)
	case "bin", "bucket":
		return p.parseBin(t)
	case "regex":
		return p.parseRegex(t)
	case "makeresults":
		return p.parseMakeResults()
	case "append":
		return p.parseAppend(t)
	case "appendpipe":
		return p.parseAppendPipe(t)
	case "tstats":
		return p.parseTstats(t)
	case "chart":
		return p.parseChart(t)
	case "xyseries":
		return p.parseXYSeries(t)
	case "untable":
		return p.parseUntable(t)
	case "mvexpand":
		return p.parseMVExpand(t)
	case "makemv":
		return p.parseMakeMV(t)
	case "reverse":
		return &Reverse{}, p.endCommand()
	case "convert":
		return p.parseConvert(t)
	case "tail":
		n := 10
		if nt := p.peek(); nt.kind == tokWord {
			at := nt.pos
			var err error
			if n, err = p.int(); err != nil {
				return nil, err
			}
			if n < 1 {
				return nil, errorf(at, "tail keeps at least 1 row")
			}
		}
		return &Tail{N: n}, p.endCommand()
	case "uniq":
		return &Uniq{}, p.endCommand()
	case "addtotals", "addcoltotals":
		return p.parseAddTotals(t)
	case "spath":
		return p.parseSpath(t)
	case "fromjson":
		return p.parseFromJSON(t)
	case "nomv":
		return p.parseNoMV(t)
	case "mvcombine":
		return p.parseMVCombine(t)
	case "strcat":
		return p.parseStrCat(t)
	case "rangemap":
		return p.parseRangeMap(t)
	case "foreach":
		return p.parseForEach(t)
	case "replace":
		return p.parseReplace(t)
	case "iplocation":
		return p.parseIPLocation(t)
	case "map":
		return p.parseMap(t)
	case "accum":
		return p.parseAccum(t)
	case "delta":
		return p.parseDelta(t)
	case "autoregress":
		return p.parseAutoRegress(t)
	case "fieldsummary":
		return p.parseFieldSummary(t)
	case "transpose":
		return p.parseTranspose(t)
	case "filldown":
		return p.parseFillDown(t)
	case "addinfo":
		return p.parseAddInfo(t)
	case "trendline":
		return p.parseTrendline(t)
	case "concurrency":
		return p.parseConcurrency(t)
	case "contingency", "counttable", "ctable":
		return p.parseContingency(t)
	case "format":
		return p.parseFormat(t)
	case "return":
		return p.parseReturn(t)
	case "union":
		return p.parseUnion(t)
	case "geostats":
		return p.parseGeostats(t)
	case "extract", "kv":
		return p.parseExtract(t)
	case "outlier":
		return p.parseOutlier(t)
	case "gauge":
		return p.parseGauge(t)
	case "multisearch":
		return p.parseMultiSearch(t)
	case "timewrap":
		return p.parseTimewrap(t)
	case "cluster":
		return p.parseCluster(t)
	case "makecontinuous":
		return p.parseMakeContinuous(t)
	case "xmlkv":
		return p.parseXMLKV(t)
	case "fieldformat":
		raw := p.next()
		if strings.TrimSpace(raw.text) == "" {
			return nil, errorf(t.pos, "fieldformat needs an assignment, for example: fieldformat firstTime=strftime(firstTime, \"%%F %%T\")")
		}
		e, err := parseEvalCommand(raw.text, raw.pos)
		if err != nil {
			return nil, err
		}
		e.Format = true
		return e, nil
	case "lookup":
		return p.parseLookup(t)
	case "inputlookup":
		return p.parseInputLookup()
	case "transaction":
		return p.parseTransaction()
	case "join":
		return p.parseJoin(t)
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
			if msg := checkRename(fromName, to.text); msg != "" {
				return nil, errorf(from.pos, "rename %s %s", FormatValue(fromName), msg)
			}
			r.Pairs = append(r.Pairs, [2]string{fromName, to.text})
			// Pairs may be separated by commas or by spaces alone.
			if p.peek().kind == tokComma {
				p.next()
				continue
			}
			if k := p.peek().kind; k == tokEOF || k == tokPipe {
				break
			}
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
		var evalX EvalExpr
		evalAt := 0
		if p.peek().kind == tokLParen {
			p.next()
			if p.isKeywordFold("eval") && p.peekAt(1).kind == tokLParen {
				evalAt = p.peek().pos
				x, err := p.aggEval()
				if err != nil {
					return nil, err
				}
				evalX = x
			} else {
				f := p.next()
				if (f.kind != tokWord && f.kind != tokString) || f.text == "" {
					return nil, errorf(f.pos, "expected a field name inside %s()", a.Func)
				}
				a.Field = f.text
			}
			if rp := p.next(); rp.kind != tokRParen {
				return nil, errorf(rp.pos, `expected ")"`)
			}
		}
		if a.Field == "" && a.Func != "count" && evalX == nil {
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
		if evalX != nil {
			// Computed first into the AS name, then aggregated from it.
			if a.Alias == "" {
				return nil, errorf(evalAt, "name the result of %s(eval(...)) with AS, as in Splunk: %s(eval(...)) AS name", a.Func, a.Func)
			}
			// The name is also the field eval sets, which eval's text
			// cannot hold with a | or a single quote in it.
			if strings.ContainsAny(a.Alias, "|'\\") {
				return nil, errorf(evalAt, "the AS name of %s(eval(...)) cannot hold |, ' or \\", a.Func)
			}
			for _, e := range p.evals {
				if e.Field == a.Alias {
					return nil, errorf(evalAt, "two eval() aggregations are both named %s", a.Alias)
				}
			}
			if a.Func == "count" {
				evalX = &Call{Func: "if", Args: []EvalExpr{evalX, &Num{Text: "1"}, &Call{Func: "null"}}}
			}
			p.evals = append(p.evals, Assign{Field: a.Alias, Expr: evalX})
			a.Field = a.Alias
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

// aggEval reads eval(<expression>) inside an aggregation, from the text
// between its parentheses.
func (p *parser) aggEval() (EvalExpr, error) {
	evalTok := p.next()
	open := p.next() // (
	if p.src == "" {
		return nil, errorf(evalTok.pos, "eval() cannot be used in an aggregation here")
	}
	depth := 1
	end := p.i
	for ; end < len(p.toks); end++ {
		switch p.toks[end].kind {
		case tokLParen:
			depth++
		case tokRParen:
			depth--
		case tokEOF, tokPipe:
			return nil, errorf(open.pos, `expected ")" to end eval(`)
		}
		if depth == 0 {
			break
		}
	}
	if depth != 0 {
		return nil, errorf(open.pos, `expected ")" to end eval(`)
	}
	from, to := open.pos+1-p.base, p.toks[end].pos-p.base
	if from < 0 || to > len(p.src) || from > to {
		return nil, errorf(evalTok.pos, "eval() cannot be used in an aggregation here")
	}
	x, err := parseEvalExprAt(p.src[from:to], open.pos+1)
	if err != nil {
		return nil, err
	}
	p.i = end + 1
	return x, nil
}

// flushEvals puts an eval computing the eval(...) aggregations of cmd,
// which starts at at, into cmds before it.
func (p *parser) flushEvals(cmds *[]Command, cmd Command, at int) error {
	if len(p.evals) == 0 {
		return nil
	}
	evals := p.evals
	p.evals = nil
	var by []string
	var aggs []Agg
	switch c := cmd.(type) {
	case *Stats:
		by, aggs = c.By, c.Aggs
	case *EventStats:
		by, aggs = c.By, c.Aggs
	case *StreamStats:
		by, aggs = c.By, c.Aggs
	case *Chart:
		by, aggs = []string{c.Over, c.By}, c.Aggs
	default:
		return errorf(at, "%s cannot aggregate eval(); compute the value with eval first", cmd.Name())
	}
	for _, e := range evals {
		uses := 0
		for _, a := range aggs {
			if a.Field == e.Field {
				uses++
			}
		}
		if uses > 1 {
			return errorf(at, "an eval() aggregation is named %s, which another aggregation reads; choose another name", e.Field)
		}
		for _, f := range by {
			if f == e.Field {
				return errorf(at, "an eval() aggregation is named %s, which is also a by field", f)
			}
		}
	}
	*cmds = append(*cmds, &Eval{Assigns: evals})
	return nil
}
