package query

import (
	"strconv"
	"strings"
)

// Chart aggregates into a table with one row per Over value and, with By,
// one column per By value: chart count over host by action.
type Chart struct {
	Aggs  []Agg
	Over  string
	By    string
	Limit int // By values kept as columns, the largest first; 0 means all
}

// XYSeries turns rows into a table with one row per X value and one
// column per Y value, holding the Values field: xyseries host action count.
// With several Values fields the columns are named "value: y".
type XYSeries struct {
	X      string
	Y      string
	Values []string
	// Limit keeps the Y values with the largest totals; chart sets it.
	Limit int
}

// Untable turns a table back into rows, one per cell: untable host action
// count gives host, action (the column's name) and count (its value).
type Untable struct {
	X     string
	Label string
	Value string
}

// Spath extracts fields from JSON: spath, spath input=body, or spath
// output=user path=actor.user.name. Without a path it extracts every
// value, named by its path.
type Spath struct {
	Input  string // default _raw
	Output string // default the path
	Path   string
}

func (*Chart) Name() string    { return "chart" }
func (*XYSeries) Name() string { return "xyseries" }
func (*Untable) Name() string  { return "untable" }
func (*Spath) Name() string    { return "spath" }

// DefaultChartLimit is how many By values chart keeps unless limit= says.
const DefaultChartLimit = 10

// MaxSeriesColumns caps the columns xyseries and chart make.
const MaxSeriesColumns = 1000

func (p *parser) parseChart(cmd token) (Command, error) {
	c := &Chart{Limit: DefaultChartLimit}
	if p.isKeywordFold("limit") && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
		p.next()
		p.next()
		at := p.peek().pos
		n, err := p.int()
		if err != nil {
			return nil, err
		}
		if n > MaxSeriesColumns {
			return nil, errorf(at, "chart limit can be at most %d", MaxSeriesColumns)
		}
		c.Limit = n
	}
	if p.peek().kind == tokEOF || p.peek().kind == tokPipe || p.isKeywordFold("by") || p.isKeywordFold("over") {
		c.Aggs = []Agg{{Func: "count"}}
	} else {
		var err error
		// over ends the functions as by does.
		if c.Aggs, err = p.parseChartAggs(cmd.pos); err != nil {
			return nil, err
		}
	}
	if p.isKeywordFold("over") {
		at := p.next()
		t := p.next()
		if t.kind != tokWord && t.kind != tokString || t.text == "" {
			return nil, errorf(at.pos, `expected a field after "over"`)
		}
		c.Over = t.text
	}
	// Names chart writes back quoted (such as "by" or "]") read as names.
	var by []string
	if p.isKeywordFold("by") {
		byTok := p.next()
		var err error
		if by, err = p.fieldList(true); err != nil {
			return nil, err
		}
		if len(by) == 0 {
			return nil, errorf(byTok.pos, `expected a field after "by"`)
		}
	}
	switch {
	case c.Over == "" && len(by) > 2, c.Over != "" && len(by) > 1:
		return nil, errorf(cmd.pos, "chart takes one field to chart over and one to split by: chart count over host by action")
	case c.Over == "" && len(by) > 0:
		c.Over, by = by[0], by[1:]
	}
	if len(by) == 1 {
		c.By = by[0]
		if len(c.Aggs) > 1 {
			return nil, errorf(cmd.pos, "chart with a split field takes one function")
		}
	}
	if c.Over == "" {
		return nil, errorf(cmd.pos, "chart needs a field to chart over, for example: chart count over host by action")
	}
	return c, p.endCommand()
}

// parseChartAggs is parseAggs stopping at over too.
func (p *parser) parseChartAggs(cmdPos int) ([]Agg, error) {
	n := p.i
	for n < len(p.toks) && !(p.toks[n].kind == tokWord && strings.EqualFold(p.toks[n].text, "over")) &&
		p.toks[n].kind != tokPipe && p.toks[n].kind != tokEOF {
		n++
	}
	head := &parser{toks: append(append([]token{}, p.toks[p.i:n]...), token{tokEOF, "", p.toks[n].pos}), depth: p.depth, src: p.src, base: p.base}
	aggs, err := head.parseAggs(cmdPos)
	if err != nil {
		return nil, err
	}
	p.evals = append(p.evals, head.evals...)
	// What parseAggs left (by and its fields) is read by the caller.
	p.i += head.i
	return aggs, nil
}

func chartString(c *Chart) string {
	s := "chart "
	if c.Limit != DefaultChartLimit {
		s += "limit=" + strconv.Itoa(c.Limit) + " "
	}
	s += aggList(c.Aggs) + " over " + chartName(c.Over)
	if c.By != "" {
		s += " by " + chartName(c.By)
	}
	return s
}

func chartName(n string) string {
	if strings.EqualFold(n, "by") || strings.EqualFold(n, "over") || strings.EqualFold(n, "limit") {
		return quote(n)
	}
	return FormatValue(n)
}

// seriesField reads one field name for xyseries and untable.
func (p *parser) seriesField(cmd token, usage string) (string, error) {
	if p.peek().kind == tokComma {
		p.next()
	}
	t := p.peek()
	if t.kind != tokWord && t.kind != tokString || t.text == "" {
		return "", errorf(t.pos, "%s expects: %s", strings.ToLower(cmd.text), usage)
	}
	p.next()
	if t.kind == tokWord {
		return p.fieldSuffix(t.text), nil
	}
	return t.text, nil
}

func (p *parser) parseXYSeries(cmd token) (Command, error) {
	const usage = "xyseries <row field> <column field> <value field>"
	x := &XYSeries{}
	var err error
	if x.X, err = p.seriesField(cmd, usage); err != nil {
		return nil, err
	}
	if x.Y, err = p.seriesField(cmd, usage); err != nil {
		return nil, err
	}
	for p.peek().kind != tokEOF && p.peek().kind != tokPipe {
		v, err := p.seriesField(cmd, usage)
		if err != nil {
			return nil, err
		}
		x.Values = append(x.Values, v)
	}
	if len(x.Values) == 0 {
		return nil, errorf(cmd.pos, "xyseries expects: %s", usage)
	}
	return x, nil
}

func (p *parser) parseUntable(cmd token) (Command, error) {
	const usage = "untable <row field> <name field> <value field>"
	u := &Untable{}
	var err error
	for _, f := range []*string{&u.X, &u.Label, &u.Value} {
		if *f, err = p.seriesField(cmd, usage); err != nil {
			return nil, err
		}
	}
	return u, p.endCommand()
}

func seriesString(name string, fields ...string) string {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = formatName(f)
	}
	return name + " " + strings.Join(names, " ")
}

func (p *parser) parseSpath(cmd token) (Command, error) {
	s := &Spath{Input: "_raw"}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			key := strings.ToLower(t.text)
			p.next()
			p.next()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			if v == "" {
				return nil, errorf(t.pos, "spath %s= needs a value", key)
			}
			switch key {
			case "input":
				s.Input = v
			case "output":
				s.Output = v
			case "path":
				s.Path = v
			default:
				return nil, errorf(t.pos, "unknown spath option %q; spath takes input=, output= and path=", t.text)
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && s.Path == "" {
			p.next()
			s.Path = t.text
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; spath expects: spath [input=field] [output=field] [path=]a.b{}.c", describe(t))
	}
	if s.Path != "" {
		if err := checkSpath(s.Path); err != "" {
			return nil, errorf(cmd.pos, "spath path %q: %s", s.Path, err)
		}
	}
	if s.Output != "" && s.Path == "" {
		return nil, errorf(cmd.pos, "spath output= needs a path=")
	}
	return s, nil
}

// MaxSpathPath caps the length of an spath path.
const MaxSpathPath = 1000

// checkSpath returns what is wrong with a path, or "".
func checkSpath(path string) string {
	if len(path) > MaxSpathPath {
		return "too long"
	}
	for _, seg := range strings.Split(path, ".") {
		name := strings.TrimSuffix(seg, "{}")
		if name == "" && seg != "{}" {
			return "a part is empty"
		}
		if strings.ContainsAny(name, "{}") {
			return "use {} after a name for every item of an array, like items{}.id"
		}
	}
	return ""
}

func spathString(c *Spath) string {
	s := "spath"
	if c.Input != "_raw" {
		s += " input=" + optionValue(c.Input)
	}
	if c.Output != "" {
		s += " output=" + optionValue(c.Output)
	}
	if c.Path != "" {
		s += " path=" + optionValue(c.Path)
	}
	return s
}
