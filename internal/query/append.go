package query

import "strings"

// Append adds a subsearch's rows after the search's rows:
// append [search datamodel=Change | stats count by user].
type Append struct {
	Sub *Query
}

// AppendPipe runs commands over the rows so far and adds the rows they
// give after them, for totals and summary rows:
// appendpipe [stats sum(count) as count | eval user="TOTAL"].
type AppendPipe struct {
	Commands []Command
}

func (*Append) Name() string     { return "append" }
func (*AppendPipe) Name() string { return "appendpipe" }

func (p *parser) parseAppend(cmd token) (Command, error) {
	opts, optsPos, inner, base, err := p.bracketed(cmd, "append [search datamodel=Change | stats count by user]")
	if err != nil {
		return nil, err
	}
	if t := strings.TrimSpace(opts); t != "" {
		return nil, errorf(optsPos, "append takes only a subsearch, for example: append [search datamodel=Change]")
	}
	sub, err := p.parseSubsearch(inner, base)
	if err != nil {
		return nil, err
	}
	return &Append{Sub: sub}, p.endCommand()
}

func (p *parser) parseAppendPipe(cmd token) (Command, error) {
	const example = "appendpipe [stats sum(count) as count]"
	opts, optsPos, inner, base, err := p.bracketed(cmd, example)
	if err != nil {
		return nil, err
	}
	if t := strings.TrimSpace(opts); t != "" {
		return nil, errorf(optsPos, "appendpipe takes only commands in [ ], for example: %s", example)
	}
	// Read as if a | came before the first command, so that eval and
	// where get their whole text; the | sits where the [ is.
	toks, err := lex("|" + inner)
	if err != nil {
		if pe, ok := err.(*Error); ok {
			pe.Pos += base - 1
		}
		return nil, err
	}
	for i := range toks {
		toks[i].pos += base - 1
	}
	sub := &parser{toks: toks, depth: p.depth + 1}
	sub.next()
	if sub.peek().kind == tokPipe {
		sub.next()
	}
	a := &AppendPipe{}
	for {
		at := sub.peek().pos
		c, err := sub.parseCommand()
		if err != nil {
			return nil, err
		}
		switch c.(type) {
		case *InputLookup, *MakeResults, *Timechart, *ThreatMatch:
			return nil, errorf(at, "%s cannot run inside appendpipe", c.Name())
		}
		a.Commands = append(a.Commands, c)
		if sub.peek().kind != tokPipe {
			break
		}
		sub.next()
	}
	if t := sub.peek(); t.kind != tokEOF {
		return nil, errorf(t.pos, "unexpected %s", describe(t))
	}
	if !bracketsBalance(appendPipeString(a)) {
		return nil, errorf(base, "quote values inside appendpipe that hold [ or ]")
	}
	return a, p.endCommand()
}

func appendPipeString(c *AppendPipe) string {
	parts := make([]string, len(c.Commands))
	for i, cmd := range c.Commands {
		parts[i] = CommandString(cmd)
	}
	return "appendpipe [" + strings.Join(parts, " | ") + "]"
}
