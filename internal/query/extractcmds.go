// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"math"
	"strconv"
	"strings"
)

// Extract reads key=value pairs from _raw into fields: user=alice
// action="log in" gives user and action. Fields a row already has keep
// their values, and keys starting with _ are skipped.
type Extract struct {
	PairDelim string // characters between pairs
	KVDelim   string // characters between a key and its value
	Limit     int    // pairs read from each row
	MaxChars  int    // bytes of _raw read from each row
	MVAdd     bool   // a repeated key gives a multivalue, not its first value
	CleanKeys bool   // characters other than letters, digits and _ in keys become _
}

// Outlier finds numbers far outside the middle of each field's values:
// above the 75th percentile plus Param times the distance between the
// 25th and 75th (and with UseLower, below the 25th minus it). It clamps
// them to that bound, or with Remove drops their rows.
type Outlier struct {
	Fields   []string // none = every field with numbers, except _ fields
	Remove   bool
	Mark     bool // a clamped value is written with 000 in front
	Param    float64
	UseLower bool
}

// Gauge makes one row for a gauge chart: x is Value (a number or the
// first row's value of a field) and y1, y2, ... are the range's bounds.
type Gauge struct {
	Value string
	Range []float64
}

func (*Extract) Name() string { return "extract" }
func (*Outlier) Name() string { return "outlier" }
func (*Gauge) Name() string   { return "gauge" }

const (
	// MaxExtractPairs bounds extract's limit=.
	MaxExtractPairs = 1000
	// MaxExtractChars bounds extract's maxchars=.
	MaxExtractChars = 1 << 20
	// MaxGaugeRanges bounds gauge's range values.
	MaxGaugeRanges = 20
	// GaugeValueField is the field gauge writes its value to.
	GaugeValueField = "x"

	defaultExtractPairDelim = " \t\r\n,;"
	defaultExtractKVDelim   = "="
	defaultExtractLimit     = 50
	defaultExtractMaxChars  = 10240
	defaultOutlierParam     = 2.5
	maxOutlierParam         = 1e6

	extractUsage = `extract [pairdelim=" ,;"] [kvdelim="="] [limit=50] [maxchars=10240] [mv_add=false] [clean_keys=true]`
	outlierUsage = "outlier [action=transform|remove] [param=2.5] [uselower=false] [mark=false] [type=iqr] [field ...]"
	gaugeUsage   = "gauge field|number [range values ...]"
)

// DefaultGaugeRange is gauge's range when none is given.
var DefaultGaugeRange = []float64{0, 100}

func (p *parser) parseExtract(cmd token) (Command, error) {
	name := strings.ToLower(cmd.text)
	c := &Extract{PairDelim: defaultExtractPairDelim, KVDelim: defaultExtractKVDelim, Limit: defaultExtractLimit, MaxChars: defaultExtractMaxChars, CleanKeys: true}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		t, key, ok := p.option()
		if !ok {
			return nil, errorf(t.pos, "unexpected %s; %s takes only options, not field extractions: %s", describe(t), name, extractUsage)
		}
		var err error
		switch key {
		case "pairdelim", "kvdelim":
			var v string
			if v, err = p.optionName(name, key); err != nil {
				return nil, err
			}
			for i := 0; i < len(v); i++ {
				if v[i] >= 0x80 {
					return nil, errorf(t.pos, "%s %s= takes ASCII characters", name, key)
				}
			}
			if key == "pairdelim" {
				c.PairDelim = v
			} else {
				c.KVDelim = v
			}
		case "limit":
			c.Limit, err = p.optionInt(name, key, 1, MaxExtractPairs)
		case "maxchars":
			c.MaxChars, err = p.optionInt(name, key, 1, MaxExtractChars)
		case "mv_add", "clean_keys":
			var b bool
			if b, err = parseBool(p.next()); err == nil {
				if key == "mv_add" {
					c.MVAdd = b
				} else {
					c.CleanKeys = b
				}
			}
		default:
			return nil, errorf(t.pos, "unknown %s option %q; %s expects: %s", name, t.text, name, extractUsage)
		}
		if err != nil {
			return nil, err
		}
	}
	if strings.ContainsAny(c.PairDelim, c.KVDelim) {
		return nil, errorf(cmd.pos, "%s pairdelim= and kvdelim= must not share characters", name)
	}
	return c, nil
}

func extractString(c *Extract) string {
	s := "extract"
	if c.PairDelim != defaultExtractPairDelim {
		s += " pairdelim=" + quote(c.PairDelim)
	}
	if c.KVDelim != defaultExtractKVDelim {
		s += " kvdelim=" + quote(c.KVDelim)
	}
	if c.Limit != defaultExtractLimit {
		s += " limit=" + strconv.Itoa(c.Limit)
	}
	if c.MaxChars != defaultExtractMaxChars {
		s += " maxchars=" + strconv.Itoa(c.MaxChars)
	}
	if c.MVAdd {
		s += " mv_add=true"
	}
	if !c.CleanKeys {
		s += " clean_keys=false"
	}
	return s
}

func (p *parser) parseOutlier(cmd token) (Command, error) {
	c := &Outlier{Param: defaultOutlierParam}
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
			switch key {
			case "action":
				vt := p.next()
				switch strings.ToLower(vt.text) {
				case "transform", "tf":
					c.Remove = false
				case "remove", "rm":
					c.Remove = true
				default:
					return nil, errorf(vt.pos, "outlier action= takes transform or remove")
				}
			case "type":
				if vt := p.next(); !strings.EqualFold(vt.text, "iqr") {
					return nil, errorf(vt.pos, "outlier type= takes iqr")
				}
			case "param":
				vt := p.next()
				f, perr := strconv.ParseFloat(vt.text, 64)
				if vt.kind != tokWord || perr != nil || math.IsNaN(f) || f < 0 || f > maxOutlierParam {
					return nil, errorf(vt.pos, "outlier param= takes a number from 0 to %s", formatNum(maxOutlierParam))
				}
				c.Param = f
			case "uselower", "mark":
				var b bool
				if b, err = parseBool(p.next()); err == nil {
					if key == "uselower" {
						c.UseLower = b
					} else {
						c.Mark = b
					}
				}
			default:
				return nil, errorf(t.pos, "unknown outlier option %q; outlier expects: %s", t.text, outlierUsage)
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" {
			p.next()
			c.Fields = append(c.Fields, t.text)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; outlier expects: %s", describe(t), outlierUsage)
	}
	return c, nil
}

func outlierString(c *Outlier) string {
	s := "outlier"
	if c.Remove {
		s += " action=remove"
	}
	if c.Param != defaultOutlierParam {
		s += " param=" + formatNum(c.Param)
	}
	if c.UseLower {
		s += " uselower=true"
	}
	if c.Mark {
		s += " mark=true"
	}
	for _, f := range c.Fields {
		s += " " + outlierField(f)
	}
	return s
}

// outlierField writes a field name so it reads back as a field, not an
// option.
func outlierField(f string) string {
	if strings.Contains(f, "=") {
		return quote(f)
	}
	return FormatValue(f)
}

func (p *parser) parseGauge(cmd token) (Command, error) {
	c := &Gauge{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if c.Value == "" {
			if (t.kind != tokWord && t.kind != tokString) || t.text == "" {
				return nil, errorf(t.pos, "unexpected %s; gauge expects: %s", describe(t), gaugeUsage)
			}
			p.next()
			c.Value = t.text
			continue
		}
		p.next()
		f, err := strconv.ParseFloat(t.text, 64)
		if t.kind != tokWord || err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errorf(t.pos, "gauge range values are numbers: %s", gaugeUsage)
		}
		if len(c.Range) >= MaxGaugeRanges {
			return nil, errorf(t.pos, "gauge takes at most %d range values", MaxGaugeRanges)
		}
		c.Range = append(c.Range, f)
	}
	if c.Value == "" {
		return nil, errorf(cmd.pos, "gauge needs a field or number; gauge expects: %s", gaugeUsage)
	}
	return c, nil
}

func gaugeString(c *Gauge) string {
	s := "gauge " + FormatValue(c.Value)
	for _, f := range c.Range {
		s += " " + formatNum(f)
	}
	return s
}
