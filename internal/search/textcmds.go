// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"sort"
	"strings"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// applyAbstract shortens each row's _raw to its c.MaxLines lines with the
// most terms (at most c.MaxTerms counted on a line), kept in order, with
// "..." in front of a line that follows left-out lines.
func applyAbstract(ctx context.Context, res *Result, c *query.Abstract) error {
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, ok := evStr(r[RawField])
		if !ok {
			continue
		}
		lines := strings.Split(s, "\n")
		if len(lines) <= c.MaxLines {
			continue
		}
		if !ev.stepN(len(s)) {
			return ev.err
		}
		type scored struct{ at, terms int }
		var sc []scored
		for at, l := range lines {
			n := len(strings.FieldsFunc(l, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }))
			sc = append(sc, scored{at, min(n, c.MaxTerms)})
		}
		sort.SliceStable(sc, func(i, j int) bool { return sc[i].terms > sc[j].terms })
		keep := sc[:c.MaxLines]
		sort.Slice(keep, func(i, j int) bool { return keep[i].at < keep[j].at })
		var b strings.Builder
		next := 0
		for k, l := range keep {
			if k > 0 {
				b.WriteByte('\n')
			}
			if l.at > next {
				b.WriteString("...")
			}
			b.WriteString(lines[l.at])
			next = l.at + 1
		}
		out := b.String()
		if !ev.charge(len(out)) {
			return ev.err
		}
		r[RawField] = out
	}
	return nil
}
