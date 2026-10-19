// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"math"
	"strconv"
	"strings"
)

// MultiSearch starts a search with the events of several subsearches,
// newest first: | multisearch [search action=failure] [search action=lockout].
type MultiSearch struct {
	Subs []*Query
}

// Timewrap lays a timechart's periods side by side: with Span 1d, each
// series gets a column per day, its rows the times of the latest day.
type Timewrap struct {
	Span  string
	Now   bool // align periods to the search's run time, not its newest row
	Short bool // name columns count_s0, count_s1, ... not count_latest_day, count_1day_before
}

// Cluster groups rows whose Field text is alike: Threshold of their terms
// match, by Match. It keeps the first row of each group, or with LabelOnly
// every row, and writes each row's group number to LabelField.
type Cluster struct {
	Field      string
	Threshold  float64
	Match      string // termlist, termset or ngramset
	ShowCount  bool
	CountField string
	LabelField string
	LabelOnly  bool
}

func (*MultiSearch) Name() string { return "multisearch" }
func (*Timewrap) Name() string    { return "timewrap" }
func (*Cluster) Name() string     { return "cluster" }

const (
	multiSearchExample = "| multisearch [search action=failure] [search action=lockout]"
	timewrapUsage      = "timewrap 1d [align=end|now] [series=relative|short]"
	clusterUsage       = "cluster [field=_raw] [t=0.8] [match=termlist|termset|ngramset] [showcount=false] [countfield=cluster_count] [labelfield=cluster_label] [labelonly=false]"

	defaultClusterField     = "_raw"
	defaultClusterThreshold = 0.8
	defaultClusterMatch     = "termlist"
	defaultClusterCount     = "cluster_count"
	defaultClusterLabel     = "cluster_label"
)

func (p *parser) parseMultiSearch(cmd token) (Command, error) {
	subs, err := p.subsearchGroups(cmd, "multisearch", multiSearchExample)
	if err != nil {
		return nil, err
	}
	if len(subs) < 2 {
		return nil, errorf(cmd.pos, "multisearch needs at least two subsearches, for example: %s", multiSearchExample)
	}
	return &MultiSearch{Subs: subs}, p.endCommand()
}

func multiSearchString(c *MultiSearch) string {
	var b strings.Builder
	b.WriteString("multisearch")
	for _, s := range c.Subs {
		b.WriteString(" [search " + s.String() + "]")
	}
	return b.String()
}

func (p *parser) parseTimewrap(cmd token) (Command, error) {
	c := &Timewrap{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t, key, ok := p.option(); ok {
			vt := p.next()
			v := strings.ToLower(vt.text)
			switch {
			case key == "align" && (v == "end" || v == "now"):
				c.Now = v == "now"
			case key == "series" && (v == "relative" || v == "short"):
				c.Short = v == "short"
			case key == "align":
				return nil, errorf(vt.pos, "timewrap align= takes end or now")
			case key == "series":
				return nil, errorf(vt.pos, "timewrap series= takes relative or short")
			default:
				return nil, errorf(t.pos, "unknown timewrap option %q; timewrap expects: %s", t.text, timewrapUsage)
			}
			continue
		}
		if t.kind == tokWord && c.Span == "" {
			p.next()
			if secs, _, err := BinSpan(t.text); err != nil || secs <= 0 {
				return nil, errorf(t.pos, "timewrap takes a time span like 1d or 1w; timewrap expects: %s", timewrapUsage)
			}
			c.Span = t.text
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; timewrap expects: %s", describe(t), timewrapUsage)
	}
	if c.Span == "" {
		return nil, errorf(cmd.pos, "timewrap needs a time span; timewrap expects: %s", timewrapUsage)
	}
	return c, nil
}

func timewrapString(c *Timewrap) string {
	s := "timewrap " + c.Span
	if c.Now {
		s += " align=now"
	}
	if c.Short {
		s += " series=short"
	}
	return s
}

func (p *parser) parseCluster(cmd token) (Command, error) {
	c := &Cluster{Field: defaultClusterField, Threshold: defaultClusterThreshold, Match: defaultClusterMatch, CountField: defaultClusterCount, LabelField: defaultClusterLabel}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		t, key, ok := p.option()
		if !ok {
			return nil, errorf(t.pos, "unexpected %s; cluster expects: %s", describe(t), clusterUsage)
		}
		var err error
		switch key {
		case "field":
			c.Field, err = p.optionName("cluster", key)
		case "countfield":
			c.CountField, err = p.optionName("cluster", key)
		case "labelfield":
			c.LabelField, err = p.optionName("cluster", key)
		case "t":
			vt := p.next()
			f, perr := strconv.ParseFloat(vt.text, 64)
			if vt.kind != tokWord || perr != nil || math.IsNaN(f) || f <= 0 || f > 1 {
				return nil, errorf(vt.pos, "cluster t= takes a number above 0 and at most 1")
			}
			c.Threshold = f
		case "match":
			vt := p.next()
			switch m := strings.ToLower(vt.text); m {
			case "termlist", "termset", "ngramset":
				c.Match = m
			default:
				return nil, errorf(vt.pos, "cluster match= takes termlist, termset or ngramset")
			}
		case "showcount", "labelonly":
			var b bool
			if b, err = parseBool(p.next()); err == nil {
				if key == "showcount" {
					c.ShowCount = b
				} else {
					c.LabelOnly = b
				}
			}
		default:
			return nil, errorf(t.pos, "unknown cluster option %q; cluster expects: %s", t.text, clusterUsage)
		}
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func clusterString(c *Cluster) string {
	s := "cluster"
	if c.Field != defaultClusterField {
		s += " field=" + optionValue(c.Field)
	}
	if c.Threshold != defaultClusterThreshold {
		s += " t=" + formatNum(c.Threshold)
	}
	if c.Match != defaultClusterMatch {
		s += " match=" + c.Match
	}
	if c.ShowCount {
		s += " showcount=true"
	}
	if c.CountField != defaultClusterCount {
		s += " countfield=" + optionValue(c.CountField)
	}
	if c.LabelField != defaultClusterLabel {
		s += " labelfield=" + optionValue(c.LabelField)
	}
	if c.LabelOnly {
		s += " labelonly=true"
	}
	return s
}
