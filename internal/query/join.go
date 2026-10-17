package query

import (
	"strconv"
	"strings"
)

// Join adds the fields of a subsearch's rows to the rows that share the
// values of Fields, as in Splunk:
// join type=left user [search datamodel=Change | stats count as changes by user].
type Join struct {
	Fields []string
	Left   bool // type=left: keep rows with no match
	Max    int  // subsearch rows joined to one row; 0 means all (up to MaxJoinMatches)
	Sub    *Query
}

func (*Join) Name() string { return "join" }

// MaxJoinMatches caps the subsearch rows one row is joined to.
const MaxJoinMatches = 100

// MaxSubsearches bounds the subsearches one query runs, each a search of
// its own.
const MaxSubsearches = 10

func countSubsearches(q *Query) int {
	n := 0
	for _, c := range q.Commands {
		n += commandSubsearches(c)
	}
	return n
}

func commandSubsearches(c Command) int {
	switch c := c.(type) {
	case *Join:
		return 1 + countSubsearches(c.Sub)
	case *Append:
		return 1 + countSubsearches(c.Sub)
	case *Union:
		n := 0
		for _, s := range c.Subs {
			n += 1 + countSubsearches(s)
		}
		return n
	case *Set:
		n := 0
		for _, s := range c.Subs {
			n += 1 + countSubsearches(s)
		}
		return n
	case *MultiSearch:
		n := 0
		for _, s := range c.Subs {
			n += 1 + countSubsearches(s)
		}
		return n
	case *AppendPipe:
		n := 0
		for _, c := range c.Commands {
			n += commandSubsearches(c)
		}
		return n
	case *Map:
		return 1
	}
	return 0
}

// countMapSearches adds up the most searches q's map commands run.
func countMapSearches(q *Query) int {
	n := 0
	var walk func(cmds []Command)
	walk = func(cmds []Command) {
		for _, c := range cmds {
			switch c := c.(type) {
			case *Map:
				n += c.Max
			case *Join:
				walk(c.Sub.Commands)
			case *Append:
				walk(c.Sub.Commands)
			case *Union:
				for _, s := range c.Subs {
					walk(s.Commands)
				}
			case *MultiSearch:
				for _, s := range c.Subs {
					walk(s.Commands)
				}
			case *Set:
				for _, s := range c.Subs {
					walk(s.Commands)
				}
			case *AppendPipe:
				walk(c.Commands)
			}
		}
	}
	walk(q.Commands)
	return n
}

// maxSubsearchDepth bounds subsearches inside subsearches.
const maxSubsearchDepth = 3

func (p *parser) parseJoin(cmd token) (Command, error) {
	const example = "join user [search datamodel=Change | stats count by user]"
	opts, optsPos, inner, base, err := p.bracketed(cmd, example)
	if err != nil {
		return nil, err
	}
	j := &Join{Max: 1}
	if err := j.parseOptions(opts, optsPos); err != nil {
		return nil, err
	}
	if len(j.Fields) == 0 {
		return nil, errorf(cmd.pos, "join needs the fields to match on, for example: join user [search ...]")
	}
	if j.Sub, err = p.parseSubsearch(inner, base); err != nil {
		return nil, err
	}
	return j, p.endCommand()
}

// bracketed reads the text of a command that ends in [ ]: the options
// before the [, and the text inside it with the position it starts at.
func (p *parser) bracketed(cmd token, example string) (opts string, optsPos int, inner string, base int, err error) {
	name := strings.ToLower(cmd.text)
	raw := p.next()
	if raw.kind != tokRaw {
		return "", 0, "", 0, errorf(cmd.pos, "%s needs a subsearch in [ ], for example: %s", name, example)
	}
	body := strings.TrimRightFunc(raw.text, isSpace)
	open := subsearchStart(body)
	if open < 0 || body[len(body)-1] != ']' || subsearchEnd(body[open:], 0) != len(body)-open {
		return "", 0, "", 0, errorf(cmd.pos, "%s needs a subsearch in [ ], for example: %s", name, example)
	}
	if p.depth+1 > maxSubsearchDepth {
		return "", 0, "", 0, errorf(raw.pos+open, "subsearches can be at most %d deep", maxSubsearchDepth)
	}
	return raw.text[:open], raw.pos, body[open+1 : len(body)-1], raw.pos + open + 1, nil
}

// parseSubsearch parses the text inside a subsearch's [ ], which starts
// at base.
func (p *parser) parseSubsearch(inner string, base int) (*Query, error) {
	sub := strings.TrimLeftFunc(inner, isSpace)
	base += len(inner) - len(sub)
	// A subsearch starts with the word search, as in Splunk; it may be
	// left out.
	if len(sub) >= 6 && strings.EqualFold(sub[:6], "search") && (len(sub) == 6 || isSpace(rune(sub[6]))) {
		base += 6
		sub = sub[6:]
	}
	q, err := parseAt(sub, base, p.depth+1)
	if err != nil {
		return nil, err
	}
	if printed := q.String(); !bracketsBalance(printed) {
		return nil, errorf(base, "quote values in a subsearch that hold [ or ]")
	}
	return q, nil
}

func isSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v'
}

// subsearchStart returns the index of the first [ outside double quotes.
func subsearchStart(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			if end, ok := quoteEnd(s, i, '"', false); ok {
				i = end - 1
			}
		case '[':
			return i
		}
	}
	return -1
}

func (j *Join) parseOptions(text string, base int) error {
	toks, err := lex(text)
	if err != nil {
		if pe, ok := err.(*Error); ok {
			pe.Pos += base
		}
		return err
	}
	for i := range toks {
		toks[i].pos += base
	}
	p := &parser{toks: toks}
	for {
		t := p.peek()
		switch {
		case t.kind == tokEOF:
			return nil
		case t.kind == tokComma:
			p.next()
		case t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=":
			key := strings.ToLower(t.text)
			p.next()
			p.next()
			v := p.next()
			switch key {
			case "type":
				switch strings.ToLower(v.text) {
				case "inner":
					j.Left = false
				case "left", "outer":
					j.Left = true
				default:
					return errorf(v.pos, "join type is inner or left, got %s", describe(v))
				}
			case "max":
				n, err := strconv.Atoi(v.text)
				if err != nil || n < 0 || n > MaxJoinMatches || v.kind != tokWord {
					return errorf(v.pos, "join max is 0 (all matches, up to %d) or a number up to %d, got %s", MaxJoinMatches, MaxJoinMatches, describe(v))
				}
				j.Max = n
			default:
				return errorf(t.pos, "unknown join option %q; join takes type= and max=", t.text)
			}
		case t.kind == tokWord || t.kind == tokString && t.text != "":
			p.next()
			f := t.text
			if t.kind == tokWord {
				f = p.fieldSuffix(f)
			}
			if strings.ContainsAny(f, "[]") {
				return errorf(t.pos, "a join field cannot hold [ or ]")
			}
			j.Fields = append(j.Fields, f)
		default:
			return errorf(t.pos, "unexpected %s in join", describe(t))
		}
	}
}

func joinString(c *Join) string {
	parts := []string{"join"}
	if c.Left {
		parts = append(parts, "type=left")
	}
	if c.Max != 1 {
		parts = append(parts, "max="+strconv.Itoa(c.Max))
	}
	names := make([]string, len(c.Fields))
	for i, f := range c.Fields {
		names[i] = formatName(f)
	}
	parts = append(parts, strings.Join(names, ", "))
	return strings.Join(parts, " ") + " [search " + c.Sub.String() + "]"
}
