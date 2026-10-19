// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
)

// Transpose turns the first Rows rows into columns: one row per field,
// with the field's name in ColumnName and its value in each row in
// "row 1", "row 2", and so on, or in columns named by HeaderField's values.
type Transpose struct {
	Rows         int
	ColumnName   string // default "column"
	HeaderField  string
	IncludeEmpty bool // keep fields with no value in any of the rows
}

// FillDown gives each row missing one of Fields (every field when none)
// the field's last value in an earlier row.
type FillDown struct {
	Fields []string // patterns
}

// AddInfo adds the search's time range and when it ran: info_min_time,
// info_max_time and info_search_time, in seconds since 1970.
type AddInfo struct{}

// Trend is one trendline moving average: sma5(bytes) AS avg_bytes.
type Trend struct {
	Kind   string // sma, ema or wma
	Period int
	Field  string
	As     string
}

// Trendline adds moving averages of numeric fields.
type Trendline struct{ Trends []Trend }

func (*Transpose) Name() string { return "transpose" }
func (*FillDown) Name() string  { return "filldown" }
func (*AddInfo) Name() string   { return "addinfo" }
func (*Trendline) Name() string { return "trendline" }

const (
	// MaxTransposeRows bounds the rows transpose turns into columns.
	MaxTransposeRows = MaxSeriesColumns
	// MaxTrendPeriod bounds a trendline average's period.
	MaxTrendPeriod = 10000
	// MaxTrends bounds the averages one trendline adds.
	MaxTrends = 100
	// MaxFillDownFields bounds the field patterns filldown takes.
	MaxFillDownFields      = 100
	defaultTransposeRows   = 5
	defaultTransposeColumn = "column"
	transposeUsage         = "transpose [N] [column_name=name] [header_field=field] [include_empty=true|false]"
	trendlineUsage         = "trendline sma5(field) [AS name] [ema10(field) ...] (sma, ema or wma, period 2 to 10000)"
	AddInfoMinTime         = "info_min_time"
	AddInfoMaxTime         = "info_max_time"
	AddInfoSearchTime      = "info_search_time"
)

// Name is the field the average sets: As, or kind+period(field).
func (t Trend) Name() string {
	if t.As != "" {
		return t.As
	}
	return t.Kind + strconv.Itoa(t.Period) + "(" + t.Field + ")"
}

func (p *parser) parseTranspose(cmd token) (Command, error) {
	c := &Transpose{Rows: defaultTransposeRows, ColumnName: defaultTransposeColumn, IncludeEmpty: true}
	seenN := false
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
			case "include_empty":
				b, err := parseBool(p.next())
				if err != nil {
					return nil, err
				}
				c.IncludeEmpty = b
			case "column_name", "header_field":
				vt := p.peek()
				v, err := p.value()
				if err != nil {
					return nil, err
				}
				if v == "" {
					return nil, errorf(vt.pos, "transpose %s= needs a name", key)
				}
				if key == "column_name" {
					c.ColumnName = v
				} else {
					c.HeaderField = v
				}
			default:
				return nil, errorf(t.pos, "unknown transpose option %q; transpose expects: %s", t.text, transposeUsage)
			}
			continue
		}
		if t.kind == tokWord && !seenN {
			n, err := strconv.Atoi(t.text)
			if err == nil {
				if n < 1 || n > MaxTransposeRows {
					return nil, errorf(t.pos, "transpose takes 1 to %d rows", MaxTransposeRows)
				}
				p.next()
				c.Rows, seenN = n, true
				continue
			}
		}
		return nil, errorf(t.pos, "unexpected %s; transpose expects: %s", describe(t), transposeUsage)
	}
	return c, nil
}

func (p *parser) parseFillDown(cmd token) (Command, error) {
	c := &FillDown{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" {
			if len(c.Fields) >= MaxFillDownFields {
				return nil, errorf(t.pos, "filldown takes at most %d fields", MaxFillDownFields)
			}
			p.next()
			c.Fields = append(c.Fields, t.text)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; filldown expects: filldown [field ...]", describe(t))
	}
	return c, nil
}

func (p *parser) parseAddInfo(cmd token) (Command, error) {
	if t := p.peek(); t.kind != tokEOF && t.kind != tokPipe {
		return nil, errorf(t.pos, "addinfo takes no options")
	}
	return &AddInfo{}, nil
}

func (p *parser) parseTrendline(cmd token) (Command, error) {
	c := &Trendline{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t.kind != tokWord || p.peekAt(1).kind != tokLParen {
			return nil, errorf(t.pos, "unexpected %s; trendline expects: %s", describe(t), trendlineUsage)
		}
		name := strings.ToLower(t.text)
		var tr Trend
		if len(name) > 3 {
			tr.Kind = name[:3]
			tr.Period, _ = strconv.Atoi(name[3:])
		}
		if tr.Kind != "sma" && tr.Kind != "ema" && tr.Kind != "wma" || tr.Period < 2 || tr.Period > MaxTrendPeriod || strconv.Itoa(tr.Period) != name[3:] {
			return nil, errorf(t.pos, "unknown average %q; trendline expects: %s", t.text, trendlineUsage)
		}
		if len(c.Trends) >= MaxTrends {
			return nil, errorf(t.pos, "trendline takes at most %d averages", MaxTrends)
		}
		p.next()
		p.next()
		f := p.next()
		if (f.kind != tokWord && f.kind != tokString) || f.text == "" {
			return nil, errorf(f.pos, "expected a field name inside %s()", t.text)
		}
		tr.Field = f.text
		if rp := p.next(); rp.kind != tokRParen {
			return nil, errorf(rp.pos, `expected ")"`)
		}
		if p.isKeywordFold("as") {
			p.next()
			al := p.next()
			if (al.kind != tokWord && al.kind != tokString) || al.text == "" {
				return nil, errorf(al.pos, `expected a name after "as"`)
			}
			tr.As = al.text
		}
		c.Trends = append(c.Trends, tr)
	}
	if len(c.Trends) == 0 {
		return nil, errorf(cmd.pos, "trendline expects: %s", trendlineUsage)
	}
	return c, nil
}

func rowCmdString(c Command) string {
	switch c := c.(type) {
	case *Transpose:
		s := "transpose"
		if c.Rows != defaultTransposeRows {
			s += " " + strconv.Itoa(c.Rows)
		}
		if c.ColumnName != defaultTransposeColumn {
			s += " column_name=" + FormatValue(c.ColumnName)
		}
		if c.HeaderField != "" {
			s += " header_field=" + FormatValue(c.HeaderField)
		}
		if !c.IncludeEmpty {
			s += " include_empty=false"
		}
		return s
	case *FillDown:
		s := "filldown"
		for _, f := range c.Fields {
			s += " " + FormatValue(f)
		}
		return s
	case *AddInfo:
		return "addinfo"
	case *Trendline:
		parts := make([]string, 0, len(c.Trends))
		for _, t := range c.Trends {
			s := t.Kind + strconv.Itoa(t.Period) + "(" + FormatValue(t.Field) + ")"
			if t.As != "" {
				s += " AS " + FormatValue(t.As)
			}
			parts = append(parts, s)
		}
		return "trendline " + strings.Join(parts, " ")
	}
	return ""
}
