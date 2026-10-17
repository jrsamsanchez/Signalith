package query

import "strings"

// Union adds the rows of each subsearch after the search's rows:
// union [search datamodel=Authentication] [search datamodel=Change].
type Union struct {
	Subs []*Query
}

func (*Union) Name() string { return "union" }

const unionExample = "union [search datamodel=Authentication] [search datamodel=Change]"

// unionEnd returns where a union starting at i ends: past the last of
// the [ ] groups that follow it, separated by spaces.
func unionEnd(src string, i int) int {
	end := subsearchEnd(src, i)
	for {
		j := end
		for j < len(src) && isSpace(rune(src[j])) {
			j++
		}
		if j >= len(src) || src[j] != '[' || end == i || src[end-1] != ']' {
			return end
		}
		end = subsearchEnd(src, j)
	}
}

func (p *parser) parseUnion(cmd token) (Command, error) {
	raw := p.next()
	if raw.kind != tokRaw {
		return nil, errorf(cmd.pos, "union needs subsearches in [ ], for example: %s", unionExample)
	}
	if p.depth+1 > maxSubsearchDepth {
		return nil, errorf(raw.pos, "subsearches can be at most %d deep", maxSubsearchDepth)
	}
	u := &Union{}
	body := raw.text
	i := 0
	for {
		for i < len(body) && isSpace(rune(body[i])) {
			i++
		}
		if i >= len(body) {
			break
		}
		if body[i] != '[' {
			return nil, errorf(raw.pos+i, "union takes only subsearches in [ ], for example: %s", unionExample)
		}
		end := subsearchEnd(body, i)
		if body[end-1] != ']' || subsearchEnd(body[i:end], 0) != end-i {
			return nil, errorf(raw.pos+i, "union needs subsearches in [ ], for example: %s", unionExample)
		}
		sub, err := p.parseSubsearch(body[i+1:end-1], raw.pos+i+1)
		if err != nil {
			return nil, err
		}
		u.Subs = append(u.Subs, sub)
		i = end
	}
	if len(u.Subs) == 0 {
		return nil, errorf(cmd.pos, "union needs subsearches in [ ], for example: %s", unionExample)
	}
	return u, p.endCommand()
}

func unionString(c *Union) string {
	var b strings.Builder
	b.WriteString("union")
	for _, s := range c.Subs {
		b.WriteString(" [search " + s.String() + "]")
	}
	return b.String()
}
