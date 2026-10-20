// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
)

// StreamStats adds running aggregates to each row, over the rows before
// it in result order: streamstats current=f window=5 count, avg(bytes) by src.
type StreamStats struct {
	Aggs    []Agg
	By      []string
	Current bool // include the row itself (current=t, the default)
	Window  int  // rows per group to look back over; 0 means all
}

func (*StreamStats) Name() string { return "streamstats" }

// MaxStreamWindow caps streamstats window=.
const MaxStreamWindow = 10000

// StreamFuncs are the functions streamstats runs.
var StreamFuncs = []string{"count", "dc", "sum", "avg", "min", "max", "range", "first", "last"}

func isStreamFunc(f string) bool {
	for _, s := range StreamFuncs {
		if s == f {
			return true
		}
	}
	return false
}

func (p *parser) parseStreamStats(cmd token) (Command, error) {
	s := &StreamStats{Current: true}
	for p.peek().kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
		t := p.next()
		p.next()
		switch strings.ToLower(t.text) {
		case "current":
			b, err := parseBool(p.next())
			if err != nil {
				return nil, err
			}
			s.Current = b
		case "window":
			at := p.peek()
			n, err := p.int()
			if err != nil {
				return nil, err
			}
			if n > MaxStreamWindow {
				return nil, errorf(at.pos, "streamstats window can be at most %d rows", MaxStreamWindow)
			}
			s.Window = n
		default:
			return nil, errorf(t.pos, "unknown streamstats option %q; streamstats takes current= and window=", t.text)
		}
	}
	aggs, err := p.parseAggs(cmd.pos)
	if err != nil {
		return nil, err
	}
	for _, a := range aggs {
		if !isStreamFunc(a.Func) {
			return nil, errorf(cmd.pos, "streamstats runs %s; use eventstats or stats for %s", strings.Join(StreamFuncs, ", "), a.Func)
		}
	}
	s.Aggs = aggs
	if s.By, err = p.parseBy(); err != nil {
		return nil, err
	}
	return s, p.endCommand()
}

func streamStatsString(c *StreamStats) string {
	s := "streamstats "
	if !c.Current {
		s += "current=f "
	}
	if c.Window > 0 {
		s += "window=" + strconv.Itoa(c.Window) + " "
	}
	s += aggList(c.Aggs)
	if len(c.By) > 0 {
		s += " by " + strings.Join(c.By, ", ")
	}
	return s
}

// Bin puts a field's values into buckets of the same size: times are
// rounded down to the start of their span (bin _time span=1h), numbers
// become ranges like 0-100 (bin bytes span=100). bucket is the same.
type Bin struct {
	Field string
	Span  string
	As    string
}

func (*Bin) Name() string { return "bin" }

// spanUnits are the time units bin's span takes, in seconds.
var spanUnits = map[string]int64{
	"s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
	"m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
	"h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
	"d": 86400, "day": 86400, "days": 86400,
	"w": 604800, "week": 604800, "weeks": 604800,
}

// maxBinSeconds caps a time span at about ten years.
const maxBinSeconds = 10 * 366 * 86400

// BinSpan reads a bin span: a time span like 1h, given in seconds, or a
// positive number for numeric buckets.
func BinSpan(span string) (seconds int64, size float64, err error) {
	i := 0
	for i < len(span) && (span[i] >= '0' && span[i] <= '9' || span[i] == '.') {
		i++
	}
	num, unit := span[:i], strings.ToLower(span[i:])
	if num == "" {
		if unit == "" {
			return 0, 0, errorf(0, "the span is missing")
		}
		num = "1"
	}
	f, perr := strconv.ParseFloat(num, 64)
	if perr != nil || !(f > 0) || f > 1e15 {
		return 0, 0, errorf(0, "%q is not a span; use a time like 1h or 15m, or a number like 100", span)
	}
	if unit == "" {
		return 0, f, nil
	}
	u, ok := spanUnits[unit]
	if !ok || f != float64(int64(f)) {
		return 0, 0, errorf(0, "%q is not a span; use a whole number of s, m, h, d or w, like 1h or 15m", span)
	}
	if int64(f) > maxBinSeconds/u {
		return 0, 0, errorf(0, "the span %q is too long", span)
	}
	return int64(f) * u, 0, nil
}

func (p *parser) parseBin(cmd token) (Command, error) {
	b := &Bin{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			if !strings.EqualFold(t.text, "span") {
				return nil, errorf(t.pos, "unknown %s option %q; %s takes span=", strings.ToLower(cmd.text), t.text, strings.ToLower(cmd.text))
			}
			at := p.peek().pos
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			if _, _, err := BinSpan(v); err != nil {
				return nil, &Error{Pos: at, Msg: err.(*Error).Msg}
			}
			b.Span = v
			continue
		}
		if p.isKeywordFold("as") && b.Field != "" && b.As == "" {
			at := p.next()
			n := p.next()
			if n.kind != tokWord && n.kind != tokString || n.text == "" {
				return nil, errorf(at.pos, `expected a field name after "as"`)
			}
			b.As = n.text
			continue
		}
		if (t.kind == tokWord || t.kind == tokString && t.text != "") && b.Field == "" {
			p.next()
			b.Field = t.text
			if t.kind == tokWord {
				b.Field = p.fieldSuffix(t.text)
			}
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; %s expects: %s span=1h _time", describe(t), strings.ToLower(cmd.text), strings.ToLower(cmd.text))
	}
	if b.Field == "" {
		return nil, errorf(cmd.pos, "%s needs a field, for example: %s span=1h _time", strings.ToLower(cmd.text), strings.ToLower(cmd.text))
	}
	if b.Span == "" {
		return nil, errorf(cmd.pos, "%s needs span=, for example: %s span=1h _time", strings.ToLower(cmd.text), strings.ToLower(cmd.text))
	}
	return b, nil
}

func binString(c *Bin) string {
	s := "bin span=" + optionValue(c.Span) + " " + binName(c.Field)
	if c.As != "" {
		s += " AS " + binName(c.As)
	}
	return s
}

// binName prints a field so it reads back as the same field, quoting the
// words bin reads as keywords.
func binName(n string) string {
	if strings.EqualFold(n, "as") || strings.EqualFold(n, "span") {
		return quote(n)
	}
	return formatName(n)
}
