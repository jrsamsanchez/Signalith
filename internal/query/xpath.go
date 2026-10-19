// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
)

// XPath sets OutField to the text of the XML elements (or attributes) in
// Field that Path selects: xpath outfield=user "//Data[@Name='TargetUserName']".
type XPath struct {
	Path       string
	Field      string // default _raw
	OutField   string // default xpath
	Default    string // written when nothing matches, if HasDefault
	HasDefault bool
}

func (*XPath) Name() string { return "xpath" }

// XPathStep is one element step of a compiled path: Name ("*" for any)
// as a child of the step before, or with Desc at any depth below it,
// kept when its attribute Attr is Value and, with Pos, when it is the
// Pos-th such element of its parent.
type XPathStep struct {
	Desc  bool
	Name  string
	Attrs [][2]string
	Pos   int
}

// XPathExpr is a compiled path: its element steps, then optionally the
// attribute or text() it reads from them.
type XPathExpr struct {
	Steps []XPathStep
	Attr  string
	Text  bool // text(): only the element's own text, not its children's
}

const (
	defaultXPathField = "_raw"
	defaultXPathOut   = "xpath"
	maxXPathLen       = 1000
	maxXPathSteps     = 50
	xpathUsage        = `xpath [field=_raw] [outfield=xpath] [default=text] "//Event/System/EventID"`
)

// CompileXPath reads the part of XPath that event logs need: / and //
// steps of element names or *, predicates [@attr='value'] and [N], and a
// last step of @attr or text().
func CompileXPath(path string) (*XPathExpr, error) {
	if path == "" || len(path) > maxXPathLen {
		return nil, errorf(0, "an xpath is 1 to %d characters", maxXPathLen)
	}
	x := &XPathExpr{}
	i := 0
	for i < len(path) {
		desc := false
		switch {
		case strings.HasPrefix(path[i:], "//"):
			desc, i = true, i+2
		case path[i] == '/':
			i++
		case i > 0:
			return nil, errorf(i, "expected / in the xpath at %q", path[i:])
		}
		if i >= len(path) {
			return nil, errorf(i, "the xpath ends with /")
		}
		if x.Attr != "" || x.Text {
			return nil, errorf(i, "@attribute and text() end an xpath")
		}
		if path[i] == '@' {
			n := xpathNameEnd(path, i+1)
			if n == i+1 || desc {
				return nil, errorf(i, "expected an attribute name after /@")
			}
			x.Attr, i = path[i+1:n], n
			continue
		}
		if strings.HasPrefix(path[i:], "text()") {
			if desc {
				return nil, errorf(i, "use /text(), not //text()")
			}
			x.Text, i = true, i+len("text()")
			continue
		}
		st := XPathStep{Desc: desc}
		if path[i] == '*' {
			st.Name, i = "*", i+1
		} else {
			n := xpathNameEnd(path, i)
			if n == i {
				return nil, errorf(i, "expected an element name in the xpath at %q", path[i:])
			}
			st.Name, i = path[i:n], n
		}
		for i < len(path) && path[i] == '[' {
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				return nil, errorf(i, "a [ in the xpath has no ]")
			}
			pred := strings.TrimSpace(path[i+1 : i+end])
			if n, err := strconv.Atoi(pred); err == nil {
				if n < 1 || n > 10000 || st.Pos != 0 {
					return nil, errorf(i, "an xpath position is one number from 1 to 10000")
				}
				st.Pos = n
			} else {
				a, v, ok := xpathAttrPred(pred)
				if !ok {
					return nil, errorf(i, "xpath predicates are [@attr='value'] or [N], not [%s]", pred)
				}
				st.Attrs = append(st.Attrs, [2]string{a, v})
			}
			i += end + 1
		}
		if len(x.Steps) >= maxXPathSteps {
			return nil, errorf(i, "an xpath has at most %d steps", maxXPathSteps)
		}
		x.Steps = append(x.Steps, st)
	}
	if len(x.Steps) == 0 {
		return nil, errorf(0, "an xpath names at least one element")
	}
	return x, nil
}

// xpathNameEnd returns where the XML name starting at i ends.
func xpathNameEnd(s string, i int) int {
	for i < len(s) {
		b := s[i]
		if !(b == '_' || b == '-' || b == '.' || b == ':' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b >= 0x80) {
			break
		}
		i++
	}
	return i
}

// xpathAttrPred reads @name='value' or @name="value".
func xpathAttrPred(p string) (string, string, bool) {
	if !strings.HasPrefix(p, "@") {
		return "", "", false
	}
	n := xpathNameEnd(p, 1)
	if n == 1 {
		return "", "", false
	}
	rest := strings.TrimSpace(p[n:])
	if !strings.HasPrefix(rest, "=") {
		return "", "", false
	}
	rest = strings.TrimSpace(rest[1:])
	if len(rest) < 2 || (rest[0] != '\'' && rest[0] != '"') || rest[len(rest)-1] != rest[0] || strings.IndexByte(rest[1:len(rest)-1], rest[0]) >= 0 {
		return "", "", false
	}
	return p[1:n], rest[1 : len(rest)-1], true
}

func (p *parser) parseXPath(cmd token) (Command, error) {
	c := &XPath{Field: defaultXPathField, OutField: defaultXPathOut}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t, key, ok := p.option(); ok {
			var err error
			switch key {
			case "field":
				c.Field, err = p.optionName("xpath", key)
			case "outfield":
				c.OutField, err = p.optionName("xpath", key)
			case "default":
				c.Default, err = p.value()
				c.HasDefault = true
			default:
				return nil, errorf(t.pos, "unknown xpath option %q; xpath expects: %s", t.text, xpathUsage)
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && c.Path == "" && t.text != "" {
			p.next()
			if _, err := CompileXPath(t.text); err != nil {
				return nil, errorf(t.pos, "xpath %q: %s", t.text, err.(*Error).Msg)
			}
			c.Path = t.text
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; xpath expects: %s", describe(t), xpathUsage)
	}
	if c.Path == "" {
		return nil, errorf(cmd.pos, "xpath needs a path; xpath expects: %s", xpathUsage)
	}
	return c, nil
}

func xpathString(c *XPath) string {
	s := "xpath"
	if c.Field != defaultXPathField {
		s += " field=" + optionValue(c.Field)
	}
	if c.OutField != defaultXPathOut {
		s += " outfield=" + optionValue(c.OutField)
	}
	if c.HasDefault {
		s += " default=" + quote(c.Default)
	}
	return s + " " + quote(c.Path)
}
