package query

import "strconv"

// Abstract shortens each row's _raw to its MaxLines lines with the most
// terms, in order, with "..." where lines were left out.
type Abstract struct {
	MaxTerms int // terms counted on one line
	MaxLines int
}

// Highlight marks terms for the results view; it leaves the rows as they
// are, so Splunk searches that use it run unchanged.
type Highlight struct {
	Terms []string
}

func (*Abstract) Name() string  { return "abstract" }
func (*Highlight) Name() string { return "highlight" }

const (
	defaultAbstractTerms = 1000
	defaultAbstractLines = 5
	maxAbstractLines     = 500
	maxHighlightTerms    = 100
	abstractUsage        = "abstract [maxterms=1000] [maxlines=5]"
)

func (p *parser) parseAbstract(cmd token) (Command, error) {
	c := &Abstract{MaxTerms: defaultAbstractTerms, MaxLines: defaultAbstractLines}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		t, key, ok := p.option()
		if !ok {
			return nil, errorf(t.pos, "unexpected %s; abstract expects: %s", describe(t), abstractUsage)
		}
		var err error
		switch key {
		case "maxterms":
			c.MaxTerms, err = p.optionInt("abstract", key, 1, defaultAbstractTerms)
		case "maxlines":
			c.MaxLines, err = p.optionInt("abstract", key, 1, maxAbstractLines)
		default:
			return nil, errorf(t.pos, "unknown abstract option %q; abstract expects: %s", t.text, abstractUsage)
		}
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func abstractString(c *Abstract) string {
	s := "abstract"
	if c.MaxTerms != defaultAbstractTerms {
		s += " maxterms=" + strconv.Itoa(c.MaxTerms)
	}
	if c.MaxLines != defaultAbstractLines {
		s += " maxlines=" + strconv.Itoa(c.MaxLines)
	}
	return s
}

func (p *parser) parseHighlight(cmd token) (Command, error) {
	c := &Highlight{}
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
			return nil, errorf(t.pos, "unexpected %s; highlight expects: highlight term [term ...]", describe(t))
		}
		if len(c.Terms) >= maxHighlightTerms {
			return nil, errorf(t.pos, "highlight takes at most %d terms", maxHighlightTerms)
		}
		p.next()
		c.Terms = append(c.Terms, t.text)
	}
	if len(c.Terms) == 0 {
		return nil, errorf(cmd.pos, "highlight needs a term; highlight expects: highlight term [term ...]")
	}
	return c, nil
}

func highlightString(c *Highlight) string {
	s := "highlight"
	for _, t := range c.Terms {
		s += " " + quote(t)
	}
	return s
}
