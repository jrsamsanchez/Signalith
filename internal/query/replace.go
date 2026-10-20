// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import "strings"

// Replace changes field values that match a pattern, * matching any text:
// replace "::ffff:*" WITH * IN src. Without IN it changes every field
// whose name does not start with _.
type Replace struct {
	Pairs  [][2]string // from, to
	Fields []string    // * matches any text
}

// XMLKV extracts the elements of the XML in a field (default _raw) that
// hold only text as fields named by their tags: xmlkv Message.
type XMLKV struct{ Field string }

func (*Replace) Name() string { return "replace" }
func (*XMLKV) Name() string   { return "xmlkv" }

// MaxReplacePairs caps replace's pairs and fields.
const MaxReplacePairs = 100

func (p *parser) parseReplace(cmd token) (Command, error) {
	const usage = `replace "old" WITH "new"[, "old2" WITH "new2"] [IN field, ...]`
	c := &Replace{}
	value := func() (string, bool) {
		t := p.peek()
		if (t.kind == tokString || t.kind == tokWord) && !strings.EqualFold(t.text, "with") && !strings.EqualFold(t.text, "in") {
			p.next()
			return t.text, true
		}
		return "", false
	}
	for {
		at := p.peek()
		from, ok := value()
		if !ok {
			return nil, errorf(at.pos, "unexpected %s; replace expects: %s", describe(at), usage)
		}
		// Splunk reads a stray comma before WITH.
		if p.peek().kind == tokComma && strings.EqualFold(p.peekAt(1).text, "with") {
			p.next()
		}
		if w := p.next(); !strings.EqualFold(w.text, "with") || w.kind != tokWord {
			return nil, errorf(w.pos, "expected WITH after %s; replace expects: %s", quote(from), usage)
		}
		at = p.peek()
		to, ok := value()
		if !ok {
			return nil, errorf(at.pos, "unexpected %s; replace expects: %s", describe(at), usage)
		}
		if strings.Count(to, "*") > 0 && strings.Count(to, "*") != strings.Count(from, "*") {
			return nil, errorf(at.pos, "replace %s needs as many * as %s, or none", quote(to), quote(from))
		}
		if len(c.Pairs) >= MaxReplacePairs {
			return nil, errorf(at.pos, "replace takes at most %d pairs", MaxReplacePairs)
		}
		c.Pairs = append(c.Pairs, [2]string{from, to})
		if p.peek().kind != tokComma {
			break
		}
		p.next()
	}
	if t := p.peek(); t.kind == tokWord && strings.EqualFold(t.text, "in") {
		p.next()
		fields, err := p.fieldList(true)
		if err != nil {
			return nil, err
		}
		if len(fields) == 0 || len(fields) > MaxReplacePairs {
			return nil, errorf(t.pos, "replace IN takes 1 to %d fields", MaxReplacePairs)
		}
		c.Fields = fields
	}
	if t := p.peek(); t.kind != tokEOF && t.kind != tokPipe {
		return nil, errorf(t.pos, "unexpected %s; replace expects: %s", describe(t), usage)
	}
	return c, nil
}

func replaceString(c *Replace) string {
	parts := make([]string, 0, len(c.Pairs))
	for _, p := range c.Pairs {
		parts = append(parts, quote(p[0])+" WITH "+quote(p[1]))
	}
	s := "replace " + strings.Join(parts, ", ")
	if len(c.Fields) > 0 {
		names := make([]string, 0, len(c.Fields))
		for _, f := range c.Fields {
			names = append(names, formatName(f))
		}
		s += " IN " + strings.Join(names, ", ")
	}
	return s
}

func (p *parser) parseXMLKV(cmd token) (Command, error) {
	c := &XMLKV{Field: "_raw"}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		// maxinputs= is accepted for Splunk searches and does nothing.
		if t.kind == tokWord && strings.EqualFold(t.text, "maxinputs") && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			if _, err := p.int(); err != nil {
				return nil, err
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && c.Field == "_raw" {
			p.next()
			c.Field = t.text
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; xmlkv expects: xmlkv [field]", describe(t))
	}
	return c, nil
}

func xmlkvString(c *XMLKV) string {
	if c.Field == "_raw" {
		return "xmlkv"
	}
	return "xmlkv " + FormatValue(c.Field)
}
