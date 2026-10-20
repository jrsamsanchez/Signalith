// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import "strings"

// FromJSON extracts the top-level keys of the JSON object in a field:
// fromjson body, or fromjson body prefix=b_ to name them b_<key>.
type FromJSON struct {
	Field  string
	Prefix string
}

func (*FromJSON) Name() string { return "fromjson" }

func (p *parser) parseFromJSON(cmd token) (Command, error) {
	c := &FromJSON{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && strings.EqualFold(t.text, "prefix") && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			if v == "" || len(v) > MaxSpathPath {
				return nil, errorf(t.pos, "fromjson prefix= needs a value of 1 to %d characters", MaxSpathPath)
			}
			c.Prefix = v
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && c.Field == "" {
			p.next()
			c.Field = t.text
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; fromjson expects: fromjson <field> [prefix=name]", describe(t))
	}
	if c.Field == "" {
		return nil, errorf(cmd.pos, "fromjson needs a field holding JSON, like fromjson body")
	}
	return c, nil
}

func fromJSONString(c *FromJSON) string {
	s := "fromjson " + formatName(c.Field)
	if c.Prefix != "" {
		s += " prefix=" + optionValue(c.Prefix)
	}
	return s
}
