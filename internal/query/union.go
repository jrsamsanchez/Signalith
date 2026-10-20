// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

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
	subs, err := p.subsearchGroups(cmd, "union", unionExample)
	if err != nil {
		return nil, err
	}
	return &Union{Subs: subs}, p.endCommand()
}

// subsearchGroups reads the [ ] subsearches that follow a command such
// as union, one after another.
func (p *parser) subsearchGroups(cmd token, name, example string) ([]*Query, error) {
	raw := p.next()
	if raw.kind != tokRaw {
		return nil, errorf(cmd.pos, "%s needs subsearches in [ ], for example: %s", name, example)
	}
	return p.subsearchesIn(cmd, raw.text, raw.pos, name, example)
}

// subsearchesIn reads the [ ] subsearches that make up body, which starts
// at byte pos of the query.
func (p *parser) subsearchesIn(cmd token, body string, pos int, name, example string) ([]*Query, error) {
	if p.depth+1 > maxSubsearchDepth {
		return nil, errorf(pos, "subsearches can be at most %d deep", maxSubsearchDepth)
	}
	var subs []*Query
	i := 0
	for {
		for i < len(body) && isSpace(rune(body[i])) {
			i++
		}
		if i >= len(body) {
			break
		}
		if body[i] != '[' {
			return nil, errorf(pos+i, "%s takes only subsearches in [ ], for example: %s", name, example)
		}
		end := subsearchEnd(body, i)
		if body[end-1] != ']' || subsearchEnd(body[i:end], 0) != end-i {
			return nil, errorf(pos+i, "%s needs subsearches in [ ], for example: %s", name, example)
		}
		sub, err := p.parseSubsearch(body[i+1:end-1], pos+i+1)
		if err != nil {
			return nil, err
		}
		subs = append(subs, sub)
		i = end
	}
	if len(subs) == 0 {
		return nil, errorf(cmd.pos, "%s needs subsearches in [ ], for example: %s", name, example)
	}
	return subs, nil
}

func unionString(c *Union) string {
	var b strings.Builder
	b.WriteString("union")
	for _, s := range c.Subs {
		b.WriteString(" [search " + s.String() + "]")
	}
	return b.String()
}
