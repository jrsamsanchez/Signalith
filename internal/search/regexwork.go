// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"regexp"
	"regexp/syntax"
)

// Go's regular expressions run in time linear in the text, but the factor
// is the size of the compiled pattern: a{0,900}Z over 250 KB of text takes
// seconds, in one call that nothing can interrupt. So every regular
// expression a search runs over a value is charged before the call, as the
// text's length times the pattern's instructions (regexWork): the search's
// deadline is checked before each call, the work counts toward the step
// budget, and one call that could run for seconds is refused (RT-03).

// regexUnitsPerStep is how many characters times instructions count as
// one evaluation step: rex with a 45-instruction pattern over 100,000
// rows of 2 KB takes about 140 million of the 500 million steps.
const regexUnitsPerStep = 64

// maxRegexCall caps the work of one regular expression call, in
// characters times instructions: at most a second or two even for the
// slowest patterns, and room for a 250-instruction pattern over 1 MB.
const maxRegexCall = 1 << 28

// regexInsts is the number of instructions re compiles to, which bounds
// how many states its matcher follows at each character.
func regexInsts(re *regexp.Regexp) int {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return 1
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return 1
	}
	return max(1, len(prog.Inst))
}

// regexWork charges running re over n characters of text. It returns false
// with ev.err set when the search's deadline has passed, its step budget is
// spent, or the one call would take too long.
func (ev *evaluator) regexWork(re *regexp.Regexp, n int) bool {
	if ev.err != nil {
		return false
	}
	insts, ok := ev.regexCost[re]
	if !ok {
		if ev.regexCost == nil || len(ev.regexCost) >= 2*maxCachedRegexes {
			ev.regexCost = map[*regexp.Regexp]int{}
		}
		insts = regexInsts(re)
		ev.regexCost[re] = insts
	}
	units := n * insts
	if units > maxRegexCall {
		ev.fail("a regular expression of %d steps over a value of %d characters would take too long; shorten the value first (for example with substr) or simplify the pattern", insts, n)
		return false
	}
	return ev.stepN(units/regexUnitsPerStep + 1)
}
