package search

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// Limits on the XML xpath reads from one value.
const (
	maxXMLNodes = 10000
	maxXMLDepth = 100
)

// xnode is one element of a parsed XML value.
type xnode struct {
	name     string
	attrs    [][2]string
	text     strings.Builder // the element's own text
	parent   *xnode
	children []*xnode
	order    int // place in the document
}

// errXMLTooBig stops parsing a value with too many elements or levels.
var errXMLTooBig = errors.New("xml too big")

// parseXML reads s into a tree under a document node. Element and
// attribute names lose their namespace prefixes, as event logs need.
// Entities other than XML's own are left as written; nothing is fetched.
func parseXML(s string) (*xnode, error) {
	d := xml.NewDecoder(strings.NewReader(s))
	d.Strict = false
	root := &xnode{}
	cur, depth, n := root, 0, 0
	for {
		tok, err := d.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if n >= maxXMLNodes || depth >= maxXMLDepth {
				return nil, errXMLTooBig
			}
			el := &xnode{name: t.Name.Local, parent: cur, order: n + 1}
			for _, a := range t.Attr {
				el.attrs = append(el.attrs, [2]string{a.Name.Local, a.Value})
			}
			cur.children = append(cur.children, el)
			cur, depth, n = el, depth+1, n+1
		case xml.EndElement:
			// Without Strict an end tag may not match; close up to the
			// element it names, or ignore it.
			levels := 0
			for c := cur; c != root; c = c.parent {
				levels++
				if c.name == t.Name.Local {
					cur, depth = c.parent, depth-levels
					break
				}
			}
		case xml.CharData:
			cur.text.Write(t)
		}
	}
	return root, nil
}

// xpathSelect returns the elements x's steps select below root, in
// document order.
func xpathSelect(ev *evaluator, root *xnode, x *query.XPathExpr) ([]*xnode, bool) {
	set := []*xnode{root}
	for _, st := range x.Steps {
		in := map[*xnode]bool{}
		for _, n := range set {
			in[n] = true
		}
		var cand []*xnode
		if st.Desc {
			var walk func(n *xnode, inside bool) bool
			walk = func(n *xnode, inside bool) bool {
				inside = inside || in[n]
				for _, c := range n.children {
					if !ev.step() {
						return false
					}
					if inside && xpathNameMatch(st.Name, c.name) {
						cand = append(cand, c)
					}
					if !walk(c, inside) {
						return false
					}
				}
				return true
			}
			if !walk(root, false) {
				return nil, false
			}
		} else {
			for _, n := range set {
				for _, c := range n.children {
					if !ev.step() {
						return nil, false
					}
					if xpathNameMatch(st.Name, c.name) {
						cand = append(cand, c)
					}
				}
			}
		}
		var next []*xnode
		pos := map[*xnode]int{}
		for _, c := range cand {
			if !xpathAttrsMatch(c, st.Attrs) {
				continue
			}
			pos[c.parent]++
			if st.Pos != 0 && pos[c.parent] != st.Pos {
				continue
			}
			next = append(next, c)
		}
		sort.SliceStable(next, func(i, j int) bool { return next[i].order < next[j].order })
		set = next
		if len(set) == 0 {
			break
		}
	}
	return set, true
}

func xpathNameMatch(want, name string) bool {
	return want == "*" || want == name || (strings.IndexByte(want, ':') >= 0 && want[strings.IndexByte(want, ':')+1:] == name)
}

func xpathAttrsMatch(n *xnode, want [][2]string) bool {
	for _, w := range want {
		found := false
		for _, a := range n.attrs {
			if a[0] == w[0] && a[1] == w[1] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// xnodeText writes the text in n and below it to b, up to about limit
// bytes, a step for each element; false means the budget ran out.
func xnodeText(ev *evaluator, n *xnode, b *strings.Builder, limit int) bool {
	if !ev.step() {
		return false
	}
	if b.Len() < limit {
		b.WriteString(n.text.String())
	}
	for _, c := range n.children {
		if !xnodeText(ev, c, b, limit) {
			return false
		}
	}
	return true
}

// applyXPath sets c.OutField to the text of what c.Path selects in each
// row's c.Field: several matches give a multivalue field.
func applyXPath(ctx context.Context, res *Result, c *query.XPath) error {
	x, err := query.CompileXPath(c.Path)
	if err != nil {
		return &QueryError{Msg: "xpath: " + err.Error()}
	}
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, ok := evStr(r[c.Field])
		var vals []any
		if ok && strings.IndexByte(s, '<') >= 0 {
			if !ev.stepN(len(s)) {
				return ev.err
			}
			// The tree, at most maxXMLNodes elements of a value of at
			// most 1 MB, is let go after this row.
			root, perr := parseXML(s)
			if perr == nil {
				nodes, ok := xpathSelect(ev, root, x)
				if !ok {
					return ev.err
				}
				for _, n := range nodes {
					if len(vals) >= maxMultiValues {
						break
					}
					var v string
					switch {
					case x.Attr != "":
						found := false
						for _, a := range n.attrs {
							if a[0] == x.Attr {
								v, found = a[1], true
								break
							}
						}
						if !found {
							continue
						}
					case x.Text:
						v = n.text.String()
					default:
						var b strings.Builder
						if !xnodeText(ev, n, &b, maxEvalValue) {
							return ev.err
						}
						v = b.String()
					}
					v = strings.TrimFunc(v, unicode.IsSpace)
					// Charged as it is made: nested matches each copy
					// the text below them.
					if !ev.fits(len(v)) || !ev.charge(len(v)+fieldOverhead) {
						return ev.err
					}
					vals = append(vals, v)
				}
			}
		}
		if len(vals) == 0 {
			if !c.HasDefault {
				continue
			}
			vals = []any{c.Default}
			if !ev.charge(len(c.Default)) {
				return ev.err
			}
		}
		v := mvOut(vals)
		if !ev.newField(r, c.OutField) {
			return ev.err
		}
		r[c.OutField] = v
	}
	addColumn(res, c.OutField)
	return nil
}
