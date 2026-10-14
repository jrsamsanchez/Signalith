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
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
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
		}
	}
	toks = append(toks, token{tokEOF, "", len(src)})
	return toks, nil
}
