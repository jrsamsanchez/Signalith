package query

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Map runs Search once for each of the first Max rows, with each $field$
// in it replaced by that row's value, and gives the rows of all those
// searches, as in Splunk: map maxsearches=20 search="search
// EventCode=4624 TargetLogonId=$TargetLogonId$".
type Map struct {
	Search string
	Max    int
}

func (*Map) Name() string { return "map" }

const (
	// MaxMapSearches bounds the searches the map commands of one query
	// run together.
	MaxMapSearches = 100
	// defaultMapSearches is Splunk's maxsearches default.
	defaultMapSearches = 10
	// MaxMapSearchText bounds map's search, before and after the values
	// go in.
	MaxMapSearchText = 64 << 10
)

func (p *parser) parseMap(cmd token) (Command, error) {
	const usage = `map [maxsearches=N] search="<query using $field$>"`
	c := &Map{Max: defaultMapSearches}
	var searchTok token
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			switch strings.ToLower(t.text) {
			case "maxsearches":
				p.next()
				p.next()
				nt := p.peek()
				n, err := p.int()
				if err != nil {
					return nil, err
				}
				if n < 1 || n > MaxMapSearches {
					return nil, errorf(nt.pos, "map maxsearches= is 1 to %d", MaxMapSearches)
				}
				c.Max = n
				continue
			case "search":
				if searchTok.kind == tokString {
					return nil, errorf(t.pos, "map takes one search=")
				}
				p.next()
				p.next()
				searchTok = p.peek()
				if searchTok.kind != tokString {
					return nil, errorf(searchTok.pos, "map search= takes the search in double quotes: %s", usage)
				}
				p.next()
				continue
			}
		}
		return nil, errorf(t.pos, "unexpected %s; map expects: %s", describe(t), usage)
	}
	if searchTok.kind != tokString {
		return nil, errorf(cmd.pos, "map needs a search to run for each row: %s", usage)
	}
	c.Search = searchTok.text
	if err := checkMapSearch(c.Search, p.depth); err != nil {
		return nil, errorf(searchTok.pos, "map's search: %s", err)
	}
	return c, nil
}

// checkMapSearch parses s with every $field$ as a plain value, so a map
// whose search could never run fails before any row is read.
func checkMapSearch(s string, depth int) error {
	if len(s) > MaxMapSearchText {
		return errors.New("too long")
	}
	text, err := SubstituteMap(s, func(string) (string, bool) { return "x", true })
	if err != nil {
		return err
	}
	if depth+1 > maxSubsearchDepth {
		return errors.New("subsearches can be at most 3 deep")
	}
	if _, err := ParseMapSearch(text); err != nil {
		var pe *Error
		if errors.As(err, &pe) {
			return errors.New(pe.Msg)
		}
		return err
	}
	return nil
}

// ParseMapSearch parses map's search once its values are in. It may start
// with the word search, and runs no subsearches or maps of its own.
func ParseMapSearch(text string) (*Query, error) {
	if len(text) > MaxMapSearchText {
		return nil, errors.New("map's search is longer than 64 KB once its values are in")
	}
	sub := strings.TrimLeftFunc(text, isSpace)
	if len(sub) >= 6 && strings.EqualFold(sub[:6], "search") && (len(sub) == 6 || isSpace(rune(sub[6]))) {
		sub = sub[6:]
	}
	q, err := parseAt(sub, 0, maxSubsearchDepth)
	if err != nil {
		return nil, err
	}
	for _, c := range q.Commands {
		switch c.(type) {
		case *Join, *Append, *AppendPipe, *Map:
			return nil, errorf(0, "map's search cannot use %s", c.Name())
		}
	}
	return q, nil
}

// ErrMapField is SubstituteMap's error for a $field$ the row lacks.
var ErrMapField = errors.New("a $field$ in map's search is missing from the row")

// SubstituteMap replaces each $name$ in s with value(name). Inside double
// quotes a value is escaped so it stays in them. Elsewhere it is written
// as one quoted value unless it is a number or a plain name, and a value
// that needs quotes must stand apart from the text around it (not 'x' or
// a$name$), since there quotes could not keep it one value. So no value
// can add commands, conditions or expressions to the search. Single
// quotes are not quotes here: the search lexer reads them as such only
// in parts of eval and where. $$ is a literal $.
func SubstituteMap(s string, value func(name string) (string, bool)) (string, error) {
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\\' && inQuote && i+1 < len(s):
			b.WriteByte(ch)
			b.WriteByte(s[i+1])
			i++
		case ch == '"':
			inQuote = !inQuote
			b.WriteByte(ch)
		case ch == '$':
			end := strings.IndexByte(s[i+1:], '$')
			if end < 0 {
				return "", errors.New("a $ has no closing $ (write $$ for a $)")
			}
			name := s[i+1 : i+1+end]
			i += end + 1
			if name == "" {
				b.WriteByte('$')
				continue
			}
			v, ok := value(name)
			if !ok {
				return "", ErrMapField
			}
			if inQuote {
				b.WriteString(strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`))
				continue
			}
			out := mapValue(v)
			if out != v && (!apart(b.String(), true) || !apart(s[i+1:], false)) {
				return "", fmt.Errorf("the value of $%s$ needs quotes, so write it apart from the text around it or in double quotes, as \"$%s$\"", name, name)
			}
			b.WriteString(out)
		default:
			b.WriteByte(ch)
		}
		if b.Len() > MaxMapSearchText {
			return "", errors.New("map's search is longer than 64 KB once its values are in")
		}
	}
	return b.String(), nil
}

// apart reports whether the text before (or after) a value ends (or
// starts) where a word would: at the edge, a space, or one of | ( ) = ! < > ,
// (not a ", where the value's quotes would run into another quoted text).
func apart(s string, before bool) bool {
	if s == "" {
		return true
	}
	var r rune
	if before {
		r, _ = utf8.DecodeLastRuneInString(s)
	} else {
		r, _ = utf8.DecodeRuneInString(s)
	}
	return !isWordRune(r) && r != '"'
}

// mapValue writes a value that is not in quotes: bare when it is a number
// or a plain name, as Splunk would, and quoted otherwise, since in eval
// and where a bare a+b or x.y is an expression.
func mapValue(v string) string {
	if _, err := strconv.ParseFloat(v, 64); err == nil && !strings.ContainsAny(v, "xXpPnNiI_") {
		return v
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return quote(v)
		}
	}
	return FormatValue(v)
}

func mapString(c *Map) string {
	s := "map"
	if c.Max != defaultMapSearches {
		s += " maxsearches=" + strconv.Itoa(c.Max)
	}
	return s + " search=" + quote(c.Search)
}
