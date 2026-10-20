// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// applyReplace changes the values that match one of c's patterns; the
// first matching pair wins.
func applyReplace(ctx context.Context, res *Result, c *query.Replace) error {
	ev := evaluatorFor(ctx)
	wanted := fieldMatcher(ev, len(c.Fields), func(f string) bool {
		if len(c.Fields) == 0 {
			return !strings.HasPrefix(f, "_")
		}
		for _, p := range c.Fields {
			if query.MatchField(p, f) {
				return true
			}
		}
		return false
	})
	// prefixes[i] is the text before pair i's first *, or the whole
	// pattern when it has none.
	prefixes := make([]string, 0, len(c.Pairs))
	for _, p := range c.Pairs {
		pre, _, _ := strings.Cut(p[0], "*")
		prefixes = append(prefixes, pre)
	}
	change := func(v any) (any, bool) {
		s, ok := v.(string)
		if !ok {
			return v, true
		}
		for i, p := range c.Pairs {
			if !ev.step() {
				return nil, false
			}
			// A pattern with a * past a matching prefix searches the
			// rest of the value, so it costs as much as the value is
			// long, whatever the pattern.
			if len(prefixes[i]) < len(p[0]) && strings.HasPrefix(s, prefixes[i]) && !ev.stepN(len(s)) {
				return nil, false
			}
			if to, ok := query.RenameField(p, s); ok {
				if !ev.fits(len(to)) || !ev.charge(len(to)) {
					return nil, false
				}
				return to, true
			}
		}
		return v, true
	}
	var keys []string
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		keys = keys[:0]
		for f := range r {
			want, ok := wanted(f)
			if !ok {
				return ev.err
			}
			if want {
				keys = append(keys, f)
			}
		}
		for _, f := range keys {
			switch v := r[f].(type) {
			case []any:
				out := make([]any, 0, len(v))
				for _, e := range v {
					x, ok := change(e)
					if !ok {
						return ev.err
					}
					out = append(out, x)
				}
				r[f] = out
			default:
				x, ok := change(v)
				if !ok {
					return ev.err
				}
				r[f] = x
			}
		}
	}
	return nil
}

// applyXMLKV extracts the text-only elements of the XML in c.Field, each
// as a field named by its tag. A tag that appears more than once becomes a
// multivalue field.
func applyXMLKV(ctx context.Context, res *Result, c *query.XMLKV) error {
	ev := evaluatorFor(ctx)
	added := map[string]bool{}
	var order []string
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, ok := evStr(r[c.Field])
		if !ok || s == "" {
			continue
		}
		if !ev.stepN(len(s)) {
			return ev.err
		}
		vals := map[string][]any{}
		var names []string
		for _, kv := range xmlElements(s, maxSpathFields*4) {
			if _, ok := vals[kv[0]]; !ok {
				if len(names) >= maxSpathFields {
					continue
				}
				names = append(names, kv[0])
			}
			if len(vals[kv[0]]) < maxMultiValues {
				vals[kv[0]] = append(vals[kv[0]], kv[1])
			}
		}
		sort.Strings(names)
		for _, name := range names {
			if !added[name] && len(order) >= maxSpathNames {
				res.Truncated = true
				continue
			}
			v := mvOut(vals[name])
			if !ev.newField(r, name) || !ev.charge(valueSize(v)) {
				return ev.err
			}
			r[name] = v
			if !added[name] {
				added[name] = true
				order = append(order, name)
			}
		}
	}
	for _, name := range order {
		addColumn(res, name)
	}
	return nil
}

// xmlElements returns up to max (tag, text) pairs for the elements in s
// that hold only text: <user>alice</user> gives (user, alice).
func xmlElements(s string, max int) [][2]string {
	var out [][2]string
	// gt is the next > at or after the current <, found once for all
	// the < before it, so text like <<<<... is read in one pass.
	gt := -1
	for i := 0; i < len(s) && len(out) < max; {
		open := strings.IndexByte(s[i:], '<')
		if open < 0 {
			break
		}
		open += i
		if gt < open {
			n := strings.IndexByte(s[open:], '>')
			if n < 0 {
				break
			}
			gt = open + n
		}
		end := gt
		tag := s[open+1 : end]
		i = open + 1
		// Another < before the > starts the next tag instead.
		if lt := strings.IndexByte(s[open+1:], '<'); lt >= 0 && open+1+lt < end {
			continue
		}
		if tag == "" || strings.HasSuffix(tag, "/") || !xmlNameStart(tag[0]) {
			continue
		}
		name := tag
		if sp := strings.IndexAny(tag, " \t\r\n"); sp >= 0 {
			name = tag[:sp]
		}
		if !xmlName(name) {
			continue
		}
		text := s[end+1:]
		lt := strings.IndexByte(text, '<')
		if lt < 0 {
			break
		}
		closeTag := "</" + name + ">"
		if !strings.HasPrefix(text[lt:], closeTag) {
			continue
		}
		out = append(out, [2]string{name, xmlUnescape(text[:lt])})
		i = end + 1 + lt + len(closeTag)
	}
	return out
}

func xmlNameStart(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func xmlName(s string) bool {
	if s == "" || !xmlNameStart(s[0]) || len(s) > 200 {
		return false
	}
	for i := 1; i < len(s); i++ {
		b := s[i]
		if !xmlNameStart(b) && !(b >= '0' && b <= '9') && b != '-' && b != '.' && b != ':' {
			return false
		}
	}
	return true
}

var xmlEntities = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&")

func xmlUnescape(s string) string { return xmlEntities.Replace(s) }

// bitArgs reads the arguments of the bit_ functions as whole numbers from
// 0 to 2^53, as Splunk does.
func bitArgs(args []any) ([]uint64, bool) {
	out := make([]uint64, 0, len(args))
	for _, a := range args {
		f, ok := evNum(a)
		if !ok || f < 0 || f > 1<<53 || f != math.Trunc(f) {
			return nil, false
		}
		out = append(out, uint64(f))
	}
	return out, true
}

// callBits evaluates the bit_ functions; ok is false for other functions.
func callBits(fn string, args []any) (any, bool) {
	switch fn {
	case "bit_and", "bit_or", "bit_xor", "bit_not", "bit_shift_left", "bit_shift_right":
	default:
		return nil, false
	}
	n, ok := bitArgs(args)
	if !ok {
		return nil, true
	}
	const mask = 1<<53 - 1
	var r uint64
	switch fn {
	case "bit_and":
		r = n[0]
		for _, x := range n[1:] {
			r &= x
		}
	case "bit_or":
		for _, x := range n {
			r |= x
		}
	case "bit_xor":
		for _, x := range n {
			r ^= x
		}
	case "bit_not":
		m := uint64(mask)
		if len(n) > 1 {
			m = n[1]
		}
		r = ^n[0] & m
	case "bit_shift_left":
		if n[1] > 53 {
			return nil, true
		}
		r = n[0] << n[1] & mask
	case "bit_shift_right":
		if n[1] > 53 {
			return nil, true
		}
		r = n[0] >> n[1]
	}
	return int64(r), true
}
