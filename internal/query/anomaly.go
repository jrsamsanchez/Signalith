// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"math"
	"strconv"
	"strings"
)

// AnomalyDetection finds rows with unlikely values: with the histogram
// method a value few rows share, with zscore a number far from the mean.
// A row is anomalous when its least likely value's probability is below
// PThresh. Action filter keeps only those rows, annotate marks every row
// and summary gives one row of counts.
type AnomalyDetection struct {
	Method  string // histogram or zscore
	Action  string // filter, annotate or summary
	PThresh float64
	Fields  []string // none = every field except _ fields
}

// Correlate counts how often each pair of fields appears in the same row:
// one row per field (RowField) and a column per field, each the share of
// rows that have both.
type Correlate struct {
	Fields []string // none = every field except _ fields
}

func (*AnomalyDetection) Name() string { return "anomalydetection" }
func (*Correlate) Name() string        { return "correlate" }

const (
	defaultAnomalyMethod  = "histogram"
	defaultAnomalyAction  = "filter"
	defaultAnomalyPThresh = 0.01
	// MaxCorrelateFields bounds the fields correlate compares.
	MaxCorrelateFields = 100
	// CorrelateRowField names the field correlate's rows are for.
	CorrelateRowField = "RowField"

	anomalyUsage = "anomalydetection [method=histogram|zscore] [action=filter|annotate|summary] [pthresh=0.01] [field ...]"
)

func (p *parser) parseAnomalyDetection(cmd token) (Command, error) {
	c := &AnomalyDetection{Method: defaultAnomalyMethod, Action: defaultAnomalyAction, PThresh: defaultAnomalyPThresh}
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
			vt := p.next()
			v := strings.ToLower(vt.text)
			switch key {
			case "method":
				if v != "histogram" && v != "zscore" {
					return nil, errorf(vt.pos, "anomalydetection method= takes histogram or zscore")
				}
				c.Method = v
			case "action":
				if v != "filter" && v != "annotate" && v != "summary" {
					return nil, errorf(vt.pos, "anomalydetection action= takes filter, annotate or summary")
				}
				c.Action = v
			case "pthresh":
				f, err := strconv.ParseFloat(vt.text, 64)
				if vt.kind != tokWord || err != nil || math.IsNaN(f) || f <= 0 || f >= 1 {
					return nil, errorf(vt.pos, "anomalydetection pthresh= takes a probability above 0 and below 1")
				}
				c.PThresh = f
			default:
				return nil, errorf(t.pos, "unknown anomalydetection option %q; anomalydetection expects: %s", t.text, anomalyUsage)
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" {
			p.next()
			c.Fields = append(c.Fields, t.text)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; anomalydetection expects: %s", describe(t), anomalyUsage)
	}
	return c, nil
}

func anomalyString(c *AnomalyDetection) string {
	s := "anomalydetection"
	if c.Method != defaultAnomalyMethod {
		s += " method=" + c.Method
	}
	if c.Action != defaultAnomalyAction {
		s += " action=" + c.Action
	}
	if c.PThresh != defaultAnomalyPThresh {
		s += " pthresh=" + formatNum(c.PThresh)
	}
	for _, f := range c.Fields {
		s += " " + outlierField(f)
	}
	return s
}

func (p *parser) parseCorrelate(cmd token) (Command, error) {
	c := &Correlate{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if (t.kind != tokWord && t.kind != tokString) || t.text == "" {
			return nil, errorf(t.pos, "unexpected %s; correlate expects: correlate [field ...]", describe(t))
		}
		if len(c.Fields) >= MaxCorrelateFields {
			return nil, errorf(t.pos, "correlate takes at most %d fields", MaxCorrelateFields)
		}
		p.next()
		c.Fields = append(c.Fields, t.text)
	}
	return c, nil
}

func correlateString(c *Correlate) string {
	s := "correlate"
	for _, f := range c.Fields {
		s += " " + FormatValue(f)
	}
	return s
}
