// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
)

// Predict forecasts numeric fields of a timechart: each row gets the
// model's prediction and a confidence range, and FutureTimespan more
// points are forecast past the rows it learns from.
type Predict struct {
	Fields         []PredictField
	Algorithm      string // LL, LLT, LLP or LLP5
	FutureTimespan int
	Holdback       int // rows at the end left out of the model
	Period         int // the season's length in rows; 0 finds it
	Upper, Lower   int // confidence levels, in percent
	UpperName      string
	LowerName      string
}

// PredictField is a field predict forecasts, and the name of its
// prediction.
type PredictField struct {
	Field string
	As    string
}

// Set starts a search with the rows of two subsearches combined: the rows
// of either (union), of only one (diff) or of both (intersect).
type Set struct {
	Op   string
	Subs []*Query
}

// SetFields sets fields to fixed values on every row.
type SetFields struct {
	Values []SetValue
}

// SetValue is one field setfields sets.
type SetValue struct {
	Field string
	Value string
}

func (*Predict) Name() string   { return "predict" }
func (*Set) Name() string       { return "set" }
func (*SetFields) Name() string { return "setfields" }

const (
	// MaxPredictFields bounds the fields one predict forecasts.
	MaxPredictFields = 10
	// MaxPredictFuture bounds predict's future_timespan=.
	MaxPredictFuture = 1000
	// MaxPredictPeriod bounds predict's period=.
	MaxPredictPeriod = 10000
	// MaxSetFields bounds the fields one setfields sets.
	MaxSetFields = 100

	defaultPredictAlgorithm = "LLP5"
	defaultPredictFuture    = 5
	defaultPredictLevel     = 95

	predictUsage   = "predict field [as name] ... [algorithm=LL|LLT|LLP|LLP5] [future_timespan=5] [holdback=0] [period=N] [upper95=name] [lower95=name]"
	setExample     = "| set diff [search action=failure | fields user] [search action=success | fields user]"
	setFieldsUsage = `setfields field=value [, field=value ...]`
)

// PredictName is the field a prediction of f goes to.
func (f PredictField) PredictName() string {
	if f.As != "" {
		return f.As
	}
	return "prediction(" + f.Field + ")"
}

// BoundNames are the fields f's upper and lower bounds go to.
func (c *Predict) BoundNames(f PredictField) (string, string) {
	up, lo := c.UpperName, c.LowerName
	if up == "" {
		up = "upper" + strconv.Itoa(c.Upper) + "(" + f.PredictName() + ")"
	}
	if lo == "" {
		lo = "lower" + strconv.Itoa(c.Lower) + "(" + f.PredictName() + ")"
	}
	return up, lo
}

// predictLevel reads the 95 of upper95, from 1 to 99.
func predictLevel(key, prefix string) (int, bool) {
	digits := strings.TrimPrefix(key, prefix)
	if digits == key || digits == "" || !allDigits(digits) || len(digits) > 2 || digits[0] == '0' {
		return 0, false
	}
	n, _ := strconv.Atoi(digits)
	return n, true
}

func (p *parser) parsePredict(cmd token) (Command, error) {
	c := &Predict{Algorithm: defaultPredictAlgorithm, FutureTimespan: defaultPredictFuture, Upper: defaultPredictLevel, Lower: defaultPredictLevel}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t, key, ok := p.option(); ok {
			var err error
			switch {
			case key == "algorithm":
				vt := p.next()
				switch a := strings.ToUpper(vt.text); a {
				case "LL", "LLT", "LLP", "LLP5":
					c.Algorithm = a
				default:
					return nil, errorf(vt.pos, "predict algorithm= takes LL, LLT, LLP or LLP5")
				}
			case key == "future_timespan":
				c.FutureTimespan, err = p.optionInt("predict", key, 0, MaxPredictFuture)
			case key == "holdback":
				c.Holdback, err = p.optionInt("predict", key, 0, MaxPredictFuture)
			case key == "period":
				c.Period, err = p.optionInt("predict", key, 2, MaxPredictPeriod)
			case strings.HasPrefix(key, "upper"):
				n, ok := predictLevel(key, "upper")
				if !ok {
					return nil, errorf(t.pos, "predict takes upper1= to upper99=, the confidence level in percent")
				}
				c.Upper = n
				c.UpperName, err = p.optionName("predict", key)
			case strings.HasPrefix(key, "lower"):
				n, ok := predictLevel(key, "lower")
				if !ok {
					return nil, errorf(t.pos, "predict takes lower1= to lower99=, the confidence level in percent")
				}
				c.Lower = n
				c.LowerName, err = p.optionName("predict", key)
			default:
				return nil, errorf(t.pos, "unknown predict option %q; predict expects: %s", t.text, predictUsage)
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" {
			if len(c.Fields) >= MaxPredictFields {
				return nil, errorf(t.pos, "predict takes at most %d fields", MaxPredictFields)
			}
			p.next()
			f := PredictField{Field: t.text}
			if p.isKeywordFold("as") {
				p.next()
				al := p.next()
				if (al.kind != tokWord && al.kind != tokString) || al.text == "" {
					return nil, errorf(al.pos, `expected a name after "as"`)
				}
				f.As = al.text
			}
			c.Fields = append(c.Fields, f)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; predict expects: %s", describe(t), predictUsage)
	}
	if len(c.Fields) == 0 {
		return nil, errorf(cmd.pos, "predict needs a field; predict expects: %s", predictUsage)
	}
	if len(c.Fields) > 1 && (c.UpperName != "" || c.LowerName != "") {
		return nil, errorf(cmd.pos, "predict names its upper and lower bounds only for one field")
	}
	return c, nil
}

func predictString(c *Predict) string {
	s := "predict"
	for _, f := range c.Fields {
		s += " " + outlierField(f.Field)
		if f.As != "" {
			s += " AS " + FormatValue(f.As)
		}
	}
	if c.Algorithm != defaultPredictAlgorithm {
		s += " algorithm=" + c.Algorithm
	}
	if c.FutureTimespan != defaultPredictFuture {
		s += " future_timespan=" + strconv.Itoa(c.FutureTimespan)
	}
	if c.Holdback != 0 {
		s += " holdback=" + strconv.Itoa(c.Holdback)
	}
	if c.Period != 0 {
		s += " period=" + strconv.Itoa(c.Period)
	}
	if c.UpperName != "" {
		s += " upper" + strconv.Itoa(c.Upper) + "=" + optionValue(c.UpperName)
	}
	if c.LowerName != "" {
		s += " lower" + strconv.Itoa(c.Lower) + "=" + optionValue(c.LowerName)
	}
	return s
}

func (p *parser) parseSet(cmd token) (Command, error) {
	raw := p.next()
	if raw.kind != tokRaw {
		return nil, errorf(cmd.pos, "set needs union, diff or intersect and two subsearches, for example: %s", setExample)
	}
	body := raw.text
	i := 0
	for i < len(body) && isSpace(rune(body[i])) {
		i++
	}
	j := i
	for j < len(body) && body[j] != '[' && !isSpace(rune(body[j])) {
		j++
	}
	op := strings.ToLower(body[i:j])
	if op != "union" && op != "diff" && op != "intersect" {
		return nil, errorf(raw.pos+i, "set takes union, diff or intersect, for example: %s", setExample)
	}
	subs, err := p.subsearchesIn(cmd, body[j:], raw.pos+j, "set", setExample)
	if err != nil {
		return nil, err
	}
	if len(subs) != 2 {
		return nil, errorf(cmd.pos, "set takes two subsearches, for example: %s", setExample)
	}
	return &Set{Op: op, Subs: subs}, p.endCommand()
}

func setString(c *Set) string {
	var b strings.Builder
	b.WriteString("set " + c.Op)
	for _, s := range c.Subs {
		b.WriteString(" [search " + s.String() + "]")
	}
	return b.String()
}

func (p *parser) parseSetFields(cmd token) (Command, error) {
	c := &SetFields{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		t, _, ok := p.option()
		if !ok {
			return nil, errorf(t.pos, "unexpected %s; setfields expects: %s", describe(t), setFieldsUsage)
		}
		if len(c.Values) >= MaxSetFields {
			return nil, errorf(t.pos, "setfields sets at most %d fields", MaxSetFields)
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		c.Values = append(c.Values, SetValue{Field: t.text, Value: v})
	}
	if len(c.Values) == 0 {
		return nil, errorf(cmd.pos, "setfields needs a field=value; setfields expects: %s", setFieldsUsage)
	}
	return c, nil
}

func setFieldsString(c *SetFields) string {
	var parts []string
	for _, v := range c.Values {
		parts = append(parts, v.Field+"="+quote(v.Value))
	}
	return "setfields " + strings.Join(parts, ", ")
}
