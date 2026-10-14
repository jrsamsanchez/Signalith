package search

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
)

// maxRegexLength is OpenSearch's default index.max_regex_length: a
// regexp query longer than this is refused.
const maxRegexLength = 1000

// Regex is a query's regular expression (field=~"pattern"): RE2 syntax,
// found anywhere in the value unless ^ or $ anchor it, and case-sensitive
// unless it says (?i). It is searched as an OpenSearch regexp query,
// whose Lucene syntax is narrower, so a pattern converts only when every
// part of it means the same in both: no word boundaries (\b), line
// anchors in multi-line mode, or ^ and $ inside it. Letters a pattern
// matches in either case become both cases in Lucene, so the search
// does not depend on how Lucene folds case.
type Regex struct {
	// Lucene is the pattern for the regexp query, which matches the
	// whole value.
	Lucene string
	re     *regexp.Regexp
}

// ParseRegex checks a query's regular expression and translates it.
func ParseRegex(pattern string) (*Regex, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("regular expression %q: %w", pattern, err)
	}
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("regular expression %q: %w", pattern, err)
	}
	// ^ at the start and $ at the end anchor it; otherwise it may match
	// anywhere, as .* around it.
	parts := []*syntax.Regexp{tree}
	if tree.Op == syntax.OpConcat {
		parts = tree.Sub
	}
	start, end := false, false
	if len(parts) > 0 && parts[0].Op == syntax.OpBeginText {
		start, parts = true, parts[1:]
	}
	if len(parts) > 0 && parts[len(parts)-1].Op == syntax.OpEndText {
		end, parts = true, parts[:len(parts)-1]
	}
	var b strings.Builder
	if !start {
		b.WriteString(".*")
	}
	for _, p := range parts {
		if err := lucene(&b, p); err != nil {
			return nil, fmt.Errorf("regular expression %q: %w", pattern, err)
		}
	}
	if !end {
		b.WriteString(".*")
	}
	if b.Len() > maxRegexLength {
		return nil, fmt.Errorf("regular expression %q is too long for OpenSearch (%d characters after translation, at most %d)", pattern, b.Len(), maxRegexLength)
	}
	return &Regex{Lucene: b.String(), re: re}, nil
}

// MatchString reports whether the pattern is found in s.
func (r *Regex) MatchString(s string) bool { return r.re.MatchString(s) }

// lucene writes a parsed regular expression in Lucene syntax, using only
// what reads the same in Go's: escaped punctuation, character classes,
// groups, alternation and repetition.
func lucene(b *strings.Builder, re *syntax.Regexp) error {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 && foldable(r) {
				writeClass(b, foldRanges(r), false)
				continue
			}
			writeRune(b, r)
		}
	case syntax.OpCharClass:
		writeCharClass(b, re.Rune)
	case syntax.OpAnyChar:
		b.WriteByte('.')
	case syntax.OpAnyCharNotNL:
		b.WriteString("[^\n]")
	case syntax.OpCapture:
		if re.Sub[0].Op == syntax.OpAlternate {
			return lucene(b, re.Sub[0])
		}
		b.WriteByte('(')
		if err := lucene(b, re.Sub[0]); err != nil {
			return err
		}
		b.WriteByte(')')
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		// Lazy and greedy repetition match the same values.
		if err := group(b, re.Sub[0]); err != nil {
			return err
		}
		b.WriteByte(map[syntax.Op]byte{syntax.OpStar: '*', syntax.OpPlus: '+', syntax.OpQuest: '?'}[re.Op])
	case syntax.OpRepeat:
		if err := group(b, re.Sub[0]); err != nil {
			return err
		}
		switch {
		case re.Max == -1:
			fmt.Fprintf(b, "{%d,}", re.Min)
		case re.Min == re.Max:
			fmt.Fprintf(b, "{%d}", re.Min)
		default:
			fmt.Fprintf(b, "{%d,%d}", re.Min, re.Max)
		}
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if err := lucene(b, s); err != nil {
				return err
			}
		}
	case syntax.OpAlternate:
		b.WriteByte('(')
		for i, s := range re.Sub {
			if i > 0 {
				b.WriteByte('|')
			}
			if err := lucene(b, s); err != nil {
				return err
			}
		}
		b.WriteByte(')')
	case syntax.OpEmptyMatch:
		b.WriteString("()")
	case syntax.OpBeginText, syntax.OpEndText:
		return fmt.Errorf("^ and $ are supported only at the start and end")
	case syntax.OpBeginLine, syntax.OpEndLine:
		return fmt.Errorf("line anchors ((?m)) are not supported")
	case syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return fmt.Errorf(`word boundaries (\b, \B) are not supported`)
	default:
		return fmt.Errorf("%v is not supported", re)
	}
	return nil
}

// group writes re as one unit, for the repetition after it.
func group(b *strings.Builder, re *syntax.Regexp) error {
	switch re.Op {
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL, syntax.OpCapture, syntax.OpAlternate:
		return lucene(b, re)
	case syntax.OpLiteral:
		if len(re.Rune) == 1 {
			return lucene(b, re)
		}
	}
	b.WriteByte('(')
	if err := lucene(b, re); err != nil {
		return err
	}
	b.WriteByte(')')
	return nil
}

func foldable(r rune) bool { return unicode.SimpleFold(r) != r }

// foldRanges are the runes r matches ignoring case, as class ranges.
func foldRanges(r rune) []rune {
	out := []rune{r, r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		out = append(out, f, f)
	}
	return out
}

// writeCharClass writes a class of rune ranges (lo, hi pairs), as its
// complement when it is one (Go spells [^\n] as every other rune).
func writeCharClass(b *strings.Builder, ranges []rune) {
	if len(ranges) >= 2 && ranges[0] == 0 && ranges[len(ranges)-1] == unicode.MaxRune {
		var comp []rune
		for i := 1; i+1 < len(ranges); i += 2 {
			comp = append(comp, ranges[i]+1, ranges[i+1]-1)
		}
		if len(comp) == 0 {
			b.WriteByte('.')
			return
		}
		writeClass(b, comp, true)
		return
	}
	writeClass(b, ranges, false)
}

func writeClass(b *strings.Builder, ranges []rune, negate bool) {
	b.WriteByte('[')
	if negate {
		b.WriteByte('^')
	}
	for i := 0; i+1 < len(ranges); i += 2 {
		writeRune(b, ranges[i])
		if ranges[i+1] != ranges[i] {
			b.WriteByte('-')
			writeRune(b, ranges[i+1])
		}
	}
	b.WriteByte(']')
}

// writeRune writes one literal rune: ASCII punctuation escaped with a
// backslash, which Lucene and Go both read as the character itself, and
// anything else (letters, digits, spaces, control characters) as it is.
// (Lucene reads \n as the letter n, so a newline is written as itself.)
func writeRune(b *strings.Builder, r rune) {
	if r < 0x80 && unicode.IsPunct(r) || unicode.IsSymbol(r) && r < 0x80 {
		b.WriteByte('\\')
	}
	b.WriteRune(r)
}

// luceneRegexp compiles the Go equivalent of a Lucene pattern ParseRegex
// wrote, to evaluate a regexp query in memory: it matches the whole
// value, and . matches any character.
func luceneRegexp(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(`(?s)^(?:` + pattern + `)$`)
}
