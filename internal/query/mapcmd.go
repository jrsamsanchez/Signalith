package query

import (
	"errors"
	"strconv"
	"strings"
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
// or single quotes a value is escaped so it stays in them; elsewhere it is
// written as one quoted value when it needs quotes, so no value can add
// commands, conditions or expressions to the search. $$ is a literal $.
func SubstituteMap(s string, value func(name string) (string, bool)) (string, error) {
	var b strings.Builder
	var quote byte // the quote the text is inside, or 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\\' && quote != 0 && i+1 < len(s):
			b.WriteByte(ch)
			b.WriteByte(s[i+1])
			i++
		case quote == 0 && ch == '"', quote == 0 && ch == '\'' && (i == 0 || strings.IndexByte(" \t\n\r\f\v(,=!<>+-*/%.", s[i-1]) >= 0):
			quote = ch
			b.WriteByte(ch)
		case quote != 0 && ch == quote:
			quote = 0
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
			if quote != 0 {
				b.WriteString(strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), string(quote), `\`+string(quote)))
			} else {
				b.WriteString(mapValue(v))
			}
		default:
			b.WriteByte(ch)
		}
		if b.Len() > MaxMapSearchText {
			return "", errors.New("map's search is longer than 64 KB once its values are in")
		}
	}
	return b.String(), nil
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
