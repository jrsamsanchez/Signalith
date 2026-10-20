// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
)

// OutputLookup writes the rows so far to a lookup table and passes them
// on. A table that exists is changed only when Append says how: true adds
// the rows to it, false replaces it.
type OutputLookup struct {
	Table string
	// Append is nil when the query did not say, which only creates.
	Append *bool
	// CreateEmpty writes a table with no rows when there are none.
	CreateEmpty bool
	// OverrideIfEmpty lets no rows empty a table append=f replaces.
	OverrideIfEmpty bool
	Max             int // rows written, 0 for all
}

func (*OutputLookup) Name() string { return "outputlookup" }

const outputLookupUsage = "outputlookup [append=t|f] [create_empty=t|f] [override_if_empty=t|f] [max=N] table"

func (p *parser) parseOutputLookup(cmd token) (Command, error) {
	c := &OutputLookup{CreateEmpty: true, OverrideIfEmpty: true}
	for {
		t, key, ok := p.option()
		if !ok {
			break
		}
		var err error
		switch key {
		case "append":
			var v bool
			if v, err = parseBool(p.next()); err == nil {
				c.Append = &v
			}
		case "create_empty":
			c.CreateEmpty, err = parseBool(p.next())
		case "override_if_empty":
			c.OverrideIfEmpty, err = parseBool(p.next())
		case "max":
			c.Max, err = p.optionInt("outputlookup", key, 1, 1_000_000)
		default:
			return nil, errorf(t.pos, "unknown outputlookup option %q; outputlookup expects: %s", t.text, outputLookupUsage)
		}
		if err != nil {
			return nil, err
		}
	}
	t := p.peek()
	if t.kind != tokWord && t.kind != tokString {
		return nil, errorf(cmd.pos, "outputlookup needs a table name; outputlookup expects: %s", outputLookupUsage)
	}
	p.next()
	name := strings.TrimSuffix(t.text, ".csv")
	if !lookupTableRE.MatchString(name) {
		return nil, errorf(t.pos, "%q is not a lookup table name; names use lower-case letters, digits, - and _", t.text)
	}
	c.Table = name
	return c, p.endCommand()
}

func outputLookupString(c *OutputLookup) string {
	s := "outputlookup"
	if c.Append != nil {
		s += " append=" + strconv.FormatBool(*c.Append)
	}
	if !c.CreateEmpty {
		s += " create_empty=false"
	}
	if !c.OverrideIfEmpty {
		s += " override_if_empty=false"
	}
	if c.Max > 0 {
		s += " max=" + strconv.Itoa(c.Max)
	}
	return s + " " + c.Table
}

// WritesLookups reports whether q may write a lookup table: an
// outputlookup anywhere in it, its subsearches included, or in the text
// of a map search, which is only parsed when it runs.
func WritesLookups(q *Query) bool {
	for _, c := range q.Commands {
		if commandWritesLookups(c) {
			return true
		}
	}
	return false
}

func commandWritesLookups(c Command) bool {
	var subs []*Query
	switch c := c.(type) {
	case *OutputLookup:
		return true
	case *Map:
		return strings.Contains(strings.ToLower(c.Search), "outputlookup")
	case *Join:
		subs = append(subs, c.Sub)
	case *Append:
		subs = append(subs, c.Sub)
	case *Union:
		subs = c.Subs
	case *Set:
		subs = c.Subs
	case *MultiSearch:
		subs = c.Subs
	case *AppendPipe:
		for _, c := range c.Commands {
			if commandWritesLookups(c) {
				return true
			}
		}
	}
	for _, s := range subs {
		if WritesLookups(s) {
			return true
		}
	}
	return false
}
