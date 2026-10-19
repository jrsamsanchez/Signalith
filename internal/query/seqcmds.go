// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
)

// Accum sets As (Field unless named) to the running total of Field over
// the rows so far: accum bytes AS total_bytes.
type Accum struct{ Field, As string }

// Delta sets As (default "delta(Field)") to Field minus Field P rows with
// a number earlier: delta count AS change p=1.
type Delta struct {
	Field, As string
	P         int
}

// AutoRegress copies Field from earlier rows: for each N from PFrom to
// PTo, Field_pN (or As, for one N) gets Field of the row N rows before.
type AutoRegress struct {
	Field, As  string
	PFrom, PTo int
}

// FieldSummary replaces the rows with one row per field: how many rows
// have it, its distinct values, and for numbers min, max, mean and stdev.
type FieldSummary struct {
	MaxVals int
	Fields  []string // patterns; none means every field
}

func (*Accum) Name() string        { return "accum" }
func (*Delta) Name() string        { return "delta" }
func (*AutoRegress) Name() string  { return "autoregress" }
func (*FieldSummary) Name() string { return "fieldsummary" }

const (
	// MaxDeltaP bounds delta p=, and the rows delta keeps.
	MaxDeltaP = 10000
	// MaxAutoRegressFields bounds the fields one autoregress adds.
	MaxAutoRegressFields = 100
	// MaxFieldSummaryVals bounds fieldsummary maxvals=.
	MaxFieldSummaryVals = 1000
	// MaxFieldSummaryFields bounds the field patterns fieldsummary takes.
	MaxFieldSummaryFields   = 100
	defaultFieldSummaryVals = 100
)

// DeltaName is the field delta sets.
func (c *Delta) DeltaName() string {
	if c.As != "" {
		return c.As
	}
	return "delta(" + c.Field + ")"
}

// AccumName is the field accum sets.
func (c *Accum) AccumName() string {
	if c.As != "" {
		return c.As
	}
	return c.Field
}

// Names returns the fields autoregress sets, nearest row first.
func (c *AutoRegress) Names() []string {
	if c.As != "" {
		return []string{c.As}
	}
	names := make([]string, 0, c.PTo-c.PFrom+1)
	for n := c.PFrom; n <= c.PTo; n++ {
		names = append(names, c.Field+"_p"+strconv.Itoa(n))
	}
	return names
}

// fieldAs reads `field [AS name]` with key=value options anywhere, which
// opt handles.
func (p *parser) fieldAs(cmd token, usage string, opt func(key string, at token) (bool, error)) (field, as string, err error) {
	name := strings.ToLower(cmd.text)
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			ok, err := opt(strings.ToLower(t.text), t)
			if err != nil {
				return "", "", err
			}
			if !ok {
				return "", "", errorf(t.pos, "unknown %s option %q; %s expects: %s", name, t.text, name, usage)
			}
			continue
		}
		if field != "" && as == "" && t.kind == tokWord && strings.EqualFold(t.text, "as") {
			p.next()
			n := p.peek()
			if (n.kind != tokWord && n.kind != tokString) || n.text == "" {
				return "", "", errorf(n.pos, "expected a field name after AS")
			}
			p.next()
			as = n.text
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && field == "" {
			p.next()
			field = t.text
			continue
		}
		return "", "", errorf(t.pos, "unexpected %s; %s expects: %s", describe(t), name, usage)
	}
	if field == "" {
		return "", "", errorf(cmd.pos, "%s expects: %s", name, usage)
	}
	return field, as, nil
}

func (p *parser) parseAccum(cmd token) (Command, error) {
	f, as, err := p.fieldAs(cmd, "accum <field> [AS <name>]", func(string, token) (bool, error) { return false, nil })
	if err != nil {
		return nil, err
	}
	return &Accum{Field: f, As: as}, nil
}

func (p *parser) parseDelta(cmd token) (Command, error) {
	c := &Delta{P: 1}
	f, as, err := p.fieldAs(cmd, "delta <field> [AS <name>] [p=N]", func(key string, _ token) (bool, error) {
		if key != "p" {
			return false, nil
		}
		at := p.peek()
		n, err := p.int()
		if err != nil {
			return false, err
		}
		if n < 1 || n > MaxDeltaP {
			return false, errorf(at.pos, "delta p= is 1 to %d", MaxDeltaP)
		}
		c.P = n
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	c.Field, c.As = f, as
	return c, nil
}

func (p *parser) parseAutoRegress(cmd token) (Command, error) {
	c := &AutoRegress{PFrom: 1, PTo: 1}
	f, as, err := p.fieldAs(cmd, "autoregress <field> [AS <name>] [p=N | p=N-M]", func(key string, _ token) (bool, error) {
		if key != "p" {
			return false, nil
		}
		at := p.next()
		lo, hi, found := strings.Cut(at.text, "-")
		from, err1 := strconv.Atoi(lo)
		to, err2 := from, error(nil)
		if found {
			to, err2 = strconv.Atoi(hi)
		}
		if at.kind != tokWord || err1 != nil || err2 != nil || from < 1 || to < from || to > MaxDeltaP || to-from+1 > MaxAutoRegressFields {
			return false, errorf(at.pos, "autoregress p= is a number or a range such as 2-5, from 1 to %d and at most %d fields", MaxDeltaP, MaxAutoRegressFields)
		}
		c.PFrom, c.PTo = from, to
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if as != "" && c.PFrom != c.PTo {
		return nil, errorf(cmd.pos, "autoregress AS names one field, so p= must be one number")
	}
	c.Field, c.As = f, as
	return c, nil
}

func (p *parser) parseFieldSummary(cmd token) (Command, error) {
	c := &FieldSummary{MaxVals: defaultFieldSummaryVals}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && strings.EqualFold(t.text, "maxvals") && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			at := p.peek()
			n, err := p.int()
			if err != nil {
				return nil, err
			}
			if n > MaxFieldSummaryVals {
				return nil, errorf(at.pos, "fieldsummary maxvals= is 0 to %d", MaxFieldSummaryVals)
			}
			c.MaxVals = n
			continue
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" {
			if len(c.Fields) >= MaxFieldSummaryFields {
				return nil, errorf(t.pos, "fieldsummary takes at most %d fields", MaxFieldSummaryFields)
			}
			p.next()
			c.Fields = append(c.Fields, t.text)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; fieldsummary expects: fieldsummary [maxvals=N] [field ...]", describe(t))
	}
	return c, nil
}

func fieldAsString(name, field, as string) string {
	s := name + " " + formatName(field)
	if as != "" {
		s += " AS " + FormatValue(as)
	}
	return s
}

func seqString(c Command) string {
	switch c := c.(type) {
	case *Accum:
		return fieldAsString("accum", c.Field, c.As)
	case *Delta:
		s := fieldAsString("delta", c.Field, c.As)
		if c.P != 1 {
			s += " p=" + strconv.Itoa(c.P)
		}
		return s
	case *AutoRegress:
		s := fieldAsString("autoregress", c.Field, c.As)
		switch {
		case c.PFrom != c.PTo:
			s += " p=" + strconv.Itoa(c.PFrom) + "-" + strconv.Itoa(c.PTo)
		case c.PFrom != 1:
			s += " p=" + strconv.Itoa(c.PFrom)
		}
		return s
	case *FieldSummary:
		s := "fieldsummary"
		if c.MaxVals != defaultFieldSummaryVals {
			s += " maxvals=" + strconv.Itoa(c.MaxVals)
		}
		for _, f := range c.Fields {
			s += " " + FormatValue(f)
		}
		return s
	}
	return ""
}
