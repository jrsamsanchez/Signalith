// Package query parses the Signalith query language: a pipe-based search
// language that reads like SPL. A query is a search expression followed by
// zero or more commands separated by "|":
//
//	datamodel=Authentication action=failure earliest=-24h
//	| stats count, dc(user) as users by src
//	| where count > 20
//	| sort -count
package query

import (
	"fmt"
	"strings"
	"unicode"
)

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokWord
	tokString
	tokOp
	tokPipe
	tokLParen
	tokRParen
	tokComma
	tokRaw // the unlexed text of an eval or where command
)

func (k tokenKind) String() string {
	switch k {
	case tokEOF:
		return "end of query"
	case tokWord:
		return "word"
	case tokString:
		return "quoted string"
	case tokOp:
		return "operator"
	case tokPipe:
		return "|"
	case tokLParen:
		return "("
	case tokRParen:
		return ")"
	case tokComma:
		return ","
	case tokRaw:
		return "expression"
	}
	return "?"
}

type token struct {
	kind tokenKind
	text string
	pos  int // byte offset in the query, for error messages
}

// Error is a parse error with the byte offset where it happened, so editors
// can underline the problem.
type Error struct {
	Pos int    `json:"pos"`
	Msg string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("at position %d: %s", e.Pos, e.Msg) }

func errorf(pos int, format string, args ...any) *Error {
	return &Error{Pos: pos, Msg: fmt.Sprintf(format, args...)}
}

func isWordRune(r rune) bool {
	if unicode.IsSpace(r) {
		return false
	}
	return !strings.ContainsRune(`|()=!<>,"`, r)
}

func lex(src string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c < 0x80 && unicode.IsSpace(rune(c)):
			// Every ASCII space ends a word (isWordRune), \f and \v too,
			// or the word below would be empty and never move on.
			i++
		case c == '|':
			toks = append(toks, token{tokPipe, "|", i})
			i++
		case c == '(':
			toks = append(toks, token{tokLParen, "(", i})
			i++
		case c == ')':
			toks = append(toks, token{tokRParen, ")", i})
			i++
		case c == ',':
			toks = append(toks, token{tokComma, ",", i})
			i++
		case c == '=' || c == '!' || c == '<' || c == '>':
			start := i
			if i+1 < len(src) && (src[i+1] == '=' || c == '=' && src[i+1] == '~') {
				// =~ matches a regular expression.
				i += 2
			} else {
				i++
			}
			op := src[start:i]
			if op == "!" {
				return nil, errorf(start, `"!" must be followed by "=" (use NOT to negate)`)
			}
			if op == "==" {
				op = "="
			}
			toks = append(toks, token{tokOp, op, start})
		case c == '"':
			start := i
			i++
			var b strings.Builder
			closed := false
			for i < len(src) {
				// \" and \\ are escapes; any other backslash is literal so
				// Windows paths like "C:\Windows\System32" work as typed.
				if src[i] == '\\' && i+1 < len(src) && (src[i+1] == '"' || src[i+1] == '\\') {
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				if src[i] == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(src[i])
				i++
			}
			if !closed {
				return nil, errorf(start, "unterminated quoted string")
			}
			toks = append(toks, token{tokString, b.String(), start})
		default:
			start := i
			for i < len(src) {
				r := rune(src[i])
				if r >= 0x80 { // multi-byte UTF-8 is always part of a word
					i++
					continue
				}
				if !isWordRune(r) {
					break
				}
				i++
			}
			toks = append(toks, token{tokWord, src[start:i], start})
			// eval and where take expressions with their own syntax
			// (eval's quoted 'field names', + and - between values), so
			// their text is kept whole and parsed by the command.
			if w := src[start:i]; len(toks) >= 2 && toks[len(toks)-2].kind == tokPipe &&
				(strings.EqualFold(w, "eval") || strings.EqualFold(w, "where") || strings.EqualFold(w, "fieldformat")) {
				end := rawEnd(src, i)
				toks = append(toks, token{tokRaw, src[i:end], i})
				i = end
			} else if len(toks) >= 2 && toks[len(toks)-2].kind == tokPipe &&
				(strings.EqualFold(w, "join") || strings.EqualFold(w, "append") || strings.EqualFold(w, "appendpipe") || strings.EqualFold(w, "foreach")) {
				// A subsearch holds pipes of its own: the command runs
				// to the ] that closes its [.
				end := subsearchEnd(src, i)
				toks = append(toks, token{tokRaw, src[i:end], i})
				i = end
			}
		}
	}
	toks = append(toks, token{tokEOF, "", len(src)})
	return toks, nil
}

// rawEnd returns where the command text starting at i ends: at the next |
// outside quotes, or at the end of the query. Double quotes are read as
// the lexer reads them. A single quote opens a quoted field name only at
// the start of a term, and such a name cannot hold a |, so apostrophes in
// values (O'Brien) do not hide the next command.
func rawEnd(src string, i int) int {
	for i < len(src) {
		switch src[i] {
		case '|':
			return i
		case '"':
			if end, ok := quoteEnd(src, i, '"', false); ok {
				i = end
				continue
			}
		case '\'':
			if i == 0 || strings.IndexByte(" \t\n\r\f\v(,=!<>+-*/%.", src[i-1]) >= 0 {
				if end, ok := quoteEnd(src, i, '\'', true); ok {
					i = end
					continue
				}
			}
		}
		i++
	}
	return i
}

// quoteEnd returns the index just past the quote that closes the one at
// i, reading \<quote> and \\ as escapes.
func quoteEnd(src string, i int, q byte, stopAtPipe bool) (int, bool) {
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			if j+1 < len(src) && (src[j+1] == q || src[j+1] == '\\') {
				j++
			}
		case q:
			return j + 1, true
		case '|':
			if stopAtPipe {
				return 0, false
			}
		}
	}
	return 0, false
}

// subsearchEnd returns where a command with a subsearch, starting at i,
// ends: just past the ] that closes its first [, counting brackets outside
// double quotes; at the next | when a | comes first; or at the end.
func subsearchEnd(src string, i int) int {
	depth := 0
	for i < len(src) {
		switch src[i] {
		case '|':
			if depth == 0 {
				return i
			}
		case '"':
			if end, ok := quoteEnd(src, i, '"', false); ok {
				i = end
				continue
			}
		case '[':
			depth++
		case ']':
			if depth--; depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return i
}

// bracketsBalance reports whether s, read as subsearchEnd reads it, holds
// no ] that closes nothing and no [ left open.
func bracketsBalance(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			if end, ok := quoteEnd(s, i, '"', false); ok {
				i = end - 1
				continue
			}
		case '[':
			depth++
		case ']':
			if depth--; depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}
