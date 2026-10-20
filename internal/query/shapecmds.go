// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
)

// Concurrency sets Output on each row to how many rows were in progress
// when it started: rows that started at or before it and whose Duration
// (in seconds) had not run out.
type Concurrency struct {
	Duration string
	Start    string // default _time
	Output   string // default concurrency
}

// Contingency counts how often each pair of RowField and ColField values
// occurs: one row per RowField value, one column per ColField value.
type Contingency struct {
	RowField, ColField string
	MaxRows, MaxCols   int
	UseTotal           bool
	TotalStr           string
}

// Format turns the rows into one search string in a field named search:
// ( ( a="1" AND b="2" ) OR ( a="3" ) ).
type Format struct {
	MaxResults int // 0 = every row
	MVSep      string
	// RowPrefix, ColPrefix, ColSep, ColEnd, RowSep, RowEnd.
	Parts [6]string
}

func (*Concurrency) Name() string { return "concurrency" }
func (*Contingency) Name() string { return "contingency" }
func (*Format) Name() string      { return "format" }

const (
	// MaxContingencyRows bounds the rows contingency writes.
	MaxContingencyRows = 10000
	// MaxFormatRows bounds the rows format turns into a search.
	MaxFormatRows = 10000

	defaultConcurrencyStart  = "_time"
	defaultConcurrencyOutput = "concurrency"
	defaultContingencyRows   = 1000
	defaultContingencyCols   = 100
	defaultContingencyTotal  = "TOTAL"
	defaultFormatMVSep       = "OR"
	// FormatField is the field format writes.
	FormatField = "search"

	concurrencyUsage = "concurrency duration=field [start=field] [output=name]"
	contingencyUsage = "contingency [maxrows=N] [maxcols=N] [usetotal=true|false] [totalstr=text] row_field col_field"
	formatUsage      = `format [maxresults=N] [mvsep=text] ["(" "(" "AND" ")" "OR" ")"]`
)

var defaultFormatParts = [6]string{"(", "(", "AND", ")", "OR", ")"}

// option reads key= from the next tokens when they are a word and =.
func (p *parser) option() (token, string, bool) {
	t := p.peek()
	if t.kind != tokWord || p.peekAt(1).kind != tokOp || p.peekAt(1).text != "=" {
		return t, "", false
	}
	p.next()
	p.next()
	return t, strings.ToLower(t.text), true
}

// optionInt reads an option's whole number from lo to hi.
func (p *parser) optionInt(cmd, key string, lo, hi int) (int, error) {
	t := p.next()
	n, err := strconv.Atoi(t.text)
	if t.kind != tokWord || err != nil || n < lo || n > hi {
		return 0, errorf(t.pos, "%s %s= takes a number from %d to %d", cmd, key, lo, hi)
	}
	return n, nil
}

// optionName reads an option's field name or text, which must not be empty.
func (p *parser) optionName(cmd, key string) (string, error) {
	vt := p.peek()
	v, err := p.value()
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errorf(vt.pos, "%s %s= needs a value", cmd, key)
	}
	return v, nil
}

func (p *parser) parseConcurrency(cmd token) (Command, error) {
	c := &Concurrency{Start: defaultConcurrencyStart, Output: defaultConcurrencyOutput}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		t, key, ok := p.option()
		if !ok {
			return nil, errorf(t.pos, "unexpected %s; concurrency expects: %s", describe(t), concurrencyUsage)
		}
		v, err := p.optionName("concurrency", key)
		if err != nil {
			return nil, err
		}
		switch key {
		case "duration":
			c.Duration = v
		case "start":
			c.Start = v
		case "output":
			c.Output = v
		default:
			return nil, errorf(t.pos, "unknown concurrency option %q; concurrency expects: %s", t.text, concurrencyUsage)
		}
	}
	if c.Duration == "" {
		return nil, errorf(cmd.pos, "concurrency needs duration=; concurrency expects: %s", concurrencyUsage)
	}
	return c, nil
}

func (p *parser) parseContingency(cmd token) (Command, error) {
	c := &Contingency{MaxRows: defaultContingencyRows, MaxCols: defaultContingencyCols, UseTotal: true, TotalStr: defaultContingencyTotal}
	var fields []string
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t, key, ok := p.option(); ok {
			var err error
			switch key {
			case "maxrows":
				c.MaxRows, err = p.optionInt("contingency", key, 1, MaxContingencyRows)
			case "maxcols":
				c.MaxCols, err = p.optionInt("contingency", key, 1, MaxSeriesColumns)
			case "usetotal":
				c.UseTotal, err = parseBool(p.next())
			case "totalstr":
				c.TotalStr, err = p.optionName("contingency", key)
			default:
				return nil, errorf(t.pos, "unknown contingency option %q; contingency expects: %s", t.text, contingencyUsage)
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && len(fields) < 2 {
			p.next()
			fields = append(fields, t.text)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; contingency expects: %s", describe(t), contingencyUsage)
	}
	if len(fields) != 2 {
		return nil, errorf(cmd.pos, "contingency needs two fields; contingency expects: %s", contingencyUsage)
	}
	c.RowField, c.ColField = fields[0], fields[1]
	return c, nil
}

func (p *parser) parseFormat(cmd token) (Command, error) {
	c := &Format{MVSep: defaultFormatMVSep, Parts: defaultFormatParts}
	var parts []string
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t, key, ok := p.option(); ok {
			var err error
			switch key {
			case "maxresults":
				c.MaxResults, err = p.optionInt("format", key, 0, MaxFormatRows)
			case "mvsep":
				c.MVSep, err = p.optionName("format", key)
			default:
				return nil, errorf(t.pos, "unknown format option %q; format expects: %s", t.text, formatUsage)
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		if t.kind == tokString && len(parts) < 6 {
			p.next()
			parts = append(parts, t.text)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; format expects: %s", describe(t), formatUsage)
	}
	if len(parts) != 0 && len(parts) != 6 {
		return nil, errorf(cmd.pos, "format takes all six quoted parts or none; format expects: %s", formatUsage)
	}
	if len(parts) == 6 {
		copy(c.Parts[:], parts)
	}
	return c, nil
}

func shapeCmdString(c Command) string {
	switch c := c.(type) {
	case *Concurrency:
		s := "concurrency duration=" + optionValue(c.Duration)
		if c.Start != defaultConcurrencyStart {
			s += " start=" + optionValue(c.Start)
		}
		if c.Output != defaultConcurrencyOutput {
			s += " output=" + optionValue(c.Output)
		}
		return s
	case *Contingency:
		s := "contingency"
		if c.MaxRows != defaultContingencyRows {
			s += " maxrows=" + strconv.Itoa(c.MaxRows)
		}
		if c.MaxCols != defaultContingencyCols {
			s += " maxcols=" + strconv.Itoa(c.MaxCols)
		}
		if !c.UseTotal {
			s += " usetotal=false"
		}
		if c.TotalStr != defaultContingencyTotal {
			s += " totalstr=" + optionValue(c.TotalStr)
		}
		return s + " " + FormatValue(c.RowField) + " " + FormatValue(c.ColField)
	case *Format:
		s := "format"
		if c.MaxResults != 0 {
			s += " maxresults=" + strconv.Itoa(c.MaxResults)
		}
		if c.MVSep != defaultFormatMVSep {
			s += " mvsep=" + optionValue(c.MVSep)
		}
		if c.Parts != defaultFormatParts {
			for _, part := range c.Parts {
				s += " " + quote(part)
			}
		}
		return s
	}
	return ""
}
