package query

import (
	"strconv"
	"strings"
)

// parseTop reads top and rare: top [N] [options] field, ... [by field, ...].
// Options may also follow the fields.
func (p *parser) parseTop(cmd token) (Command, error) {
	top := &Top{Limit: 10, Rare: strings.EqualFold(cmd.text, "rare")}
	name := strings.ToLower(cmd.text)
	if n, err := strconv.Atoi(p.peek().text); err == nil && n >= 0 && p.peek().kind == tokWord {
		p.next()
		top.Limit = n
	}
	for {
		t := p.peek()
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			if err := p.topOption(top, name); err != nil {
				return nil, err
			}
			continue
		}
		if t.kind == tokWord && !strings.EqualFold(t.text, "by") {
			p.next()
			top.Fields = append(top.Fields, p.fieldSuffix(t.text))
			continue
		}
		break
	}
	if len(top.Fields) == 0 {
		return nil, errorf(cmd.pos, "%s needs at least one field", name)
	}
	by, err := p.parseBy()
	if err != nil {
		return nil, err
	}
	top.By = by
	if !top.NoCount && !top.NoPercent && top.CountColumn() == top.PercentColumn() {
		return nil, errorf(cmd.pos, "%s countfield and percentfield need different names", name)
	}
	return top, p.endCommand()
}

func (p *parser) topOption(top *Top, name string) error {
	key := p.next()
	p.next() // =
	at := p.peek().pos
	switch strings.ToLower(key.text) {
	case "limit":
		n, err := p.int()
		if err != nil {
			return err
		}
		top.Limit = n
		return nil
	case "showcount", "showperc", "useother":
		b, err := parseBool(p.next())
		if err != nil {
			return err
		}
		switch strings.ToLower(key.text) {
		case "showcount":
			top.NoCount = !b
		case "showperc":
			top.NoPercent = !b
		default:
			top.UseOther = b
		}
		return nil
	case "countfield", "percentfield", "otherstr":
		v, err := p.value()
		if err != nil {
			return err
		}
		if v == "" || len(v) > MaxSpathPath {
			return errorf(at, "%s %s= needs a name of 1 to %d characters", name, strings.ToLower(key.text), MaxSpathPath)
		}
		// The defaults are kept as "", so the query reads back the same.
		switch strings.ToLower(key.text) {
		case "countfield":
			top.CountField = v
			if v == "count" {
				top.CountField = ""
			}
		case "percentfield":
			top.PercentField = v
			if v == "percent" {
				top.PercentField = ""
			}
		default:
			top.OtherStr = v
			if v == "OTHER" {
				top.OtherStr = ""
			}
		}
		return nil
	}
	return errorf(key.pos, "unknown %s option %q; %s takes limit=, countfield=, percentfield=, showcount=, showperc=, useother= and otherstr=", name, key.text, name)
}

// topOptions writes top's options that differ from the defaults.
func topOptions(c *Top) string {
	var s string
	if c.CountField != "" {
		s += " countfield=" + optionValue(c.CountField)
	}
	if c.PercentField != "" {
		s += " percentfield=" + optionValue(c.PercentField)
	}
	if c.NoCount {
		s += " showcount=f"
	}
	if c.NoPercent {
		s += " showperc=f"
	}
	if c.UseOther {
		s += " useother=t"
	}
	if c.OtherStr != "" {
		s += " otherstr=" + optionValue(c.OtherStr)
	}
	return s
}

// keepAll is | search *, which the parser drops.
type keepAll struct{}

func (keepAll) Name() string { return "search" }

// parseSearchCommand reads | search after the first command: it filters
// the rows with the search's syntax.
func (p *parser) parseSearchCommand(cmd token) (Command, error) {
	if t := p.peek(); t.kind == tokWord && t.text == "*" && (p.peekAt(1).kind == tokPipe || p.peekAt(1).kind == tokEOF) {
		// | search * keeps every row, as the filter macros of Splunk's
		// detections do until someone tunes them.
		p.next()
		return keepAll{}, nil
	}
	var q Query
	if err := p.parseSearch(&q); err != nil {
		return nil, err
	}
	if q.Datamodel != "" || q.Index != "" || q.Earliest != "" || q.Latest != "" {
		return nil, errorf(cmd.pos, "datamodel=, index=, earliest= and latest= go in the search before the first |")
	}
	if q.Search == nil {
		return nil, errorf(cmd.pos, "expected terms after search, for example: search count>20 user=adm*")
	}
	return &Where{Expr: q.Search, Search: true}, nil
}
