// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
)

// Return turns the first Count rows into a search string in the field
// search: src="10.0.0.1" from "return src", or the bare value from
// "return $src".
type Return struct {
	Count int
	Items []ReturnItem
}

// ReturnItem is one field return writes: Field as Field="value", as
// Alias="value" when Alias is set, or as the bare value when Bare.
type ReturnItem struct {
	Field string
	Alias string
	Bare  bool
}

// MakeContinuous adds the rows missing between the smallest and largest
// value of Field, one per Span: time buckets (span=1h) or numbers
// (span=10). Rows with no value in Field come last.
type MakeContinuous struct {
	Field string // default _time
	Span  string
}

func (*Return) Name() string         { return "return" }
func (*MakeContinuous) Name() string { return "makecontinuous" }

const (
	// MaxReturnRows bounds the rows return reads.
	MaxReturnRows = 10000
	// MaxReturnFields bounds the fields one return writes.
	MaxReturnFields = 100
	// MaxContinuousRows bounds the rows makecontinuous adds.
	MaxContinuousRows = 100000

	defaultContinuousField = "_time"
	returnUsage            = "return [N] field [alias=field] [$field] ..."
	makeContinuousUsage    = "makecontinuous [field] span=1h"
)

func (p *parser) parseReturn(cmd token) (Command, error) {
	c := &Return{Count: 1}
	first := true
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if first && t.kind == tokWord && !(p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=") {
			if n, err := strconv.Atoi(t.text); err == nil {
				if n < 1 || n > MaxReturnRows {
					return nil, errorf(t.pos, "return takes 1 to %d rows", MaxReturnRows)
				}
				p.next()
				c.Count, first = n, false
				continue
			}
		}
		first = false
		if t.kind == tokComma {
			p.next()
			continue
		}
		var it ReturnItem
		switch {
		case t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=":
			p.next()
			p.next()
			vt := p.peek()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			if v == "" {
				return nil, errorf(vt.pos, "expected a field name after %s=", t.text)
			}
			it = ReturnItem{Field: v, Alias: t.text}
		case t.kind == tokWord && len(t.text) > 1 && t.text[0] == '$':
			p.next()
			it = ReturnItem{Field: t.text[1:], Bare: true}
		case (t.kind == tokWord || t.kind == tokString) && t.text != "":
			p.next()
			it = ReturnItem{Field: t.text}
		default:
			return nil, errorf(t.pos, "unexpected %s; return expects: %s", describe(t), returnUsage)
		}
		if len(c.Items) >= MaxReturnFields {
			return nil, errorf(t.pos, "return takes at most %d fields", MaxReturnFields)
		}
		c.Items = append(c.Items, it)
	}
	if len(c.Items) == 0 {
		return nil, errorf(cmd.pos, "return needs a field; return expects: %s", returnUsage)
	}
	return c, nil
}

func (p *parser) parseMakeContinuous(cmd token) (Command, error) {
	c := &MakeContinuous{Field: defaultContinuousField}
	seenField := false
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t, key, ok := p.option(); ok {
			if key != "span" {
				return nil, errorf(t.pos, "unknown makecontinuous option %q; makecontinuous expects: %s", t.text, makeContinuousUsage)
			}
			vt := p.peek()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			if _, _, err := BinSpan(v); err != nil {
				return nil, errorf(vt.pos, "makecontinuous span: %s", err.(*Error).Msg)
			}
			c.Span = v
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && !seenField {
			p.next()
			c.Field, seenField = t.text, true
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; makecontinuous expects: %s", describe(t), makeContinuousUsage)
	}
	if c.Span == "" {
		return nil, errorf(cmd.pos, "makecontinuous needs span=; makecontinuous expects: %s", makeContinuousUsage)
	}
	return c, nil
}

// returnField writes a field name so it reads back as a field: quoted
// when it would read as a row count or a $ value.
func returnField(f string) string {
	if _, err := strconv.Atoi(f); err == nil || strings.HasPrefix(f, "$") {
		return quote(f)
	}
	return FormatValue(f)
}

func returnCmdString(c Command) string {
	switch c := c.(type) {
	case *Return:
		s := "return"
		if c.Count != 1 {
			s += " " + strconv.Itoa(c.Count)
		}
		for _, it := range c.Items {
			switch {
			case it.Alias != "":
				s += " " + it.Alias + "=" + optionValue(it.Field)
			case it.Bare:
				s += " $" + it.Field
			default:
				s += " " + returnField(it.Field)
			}
		}
		return s
	case *MakeContinuous:
		s := "makecontinuous"
		if c.Field != defaultContinuousField {
			s += " " + FormatValue(c.Field)
		}
		return s + " span=" + optionValue(c.Span)
	}
	return ""
}
