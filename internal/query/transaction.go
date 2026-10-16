package query

import (
	"strconv"
	"strings"
)

// Transaction groups events that share the values of Fields into one row
// each, as in Splunk:
// transaction host, user maxspan=10m startswith="Accepted" endswith=(action=logoff).
type Transaction struct {
	Fields     []string
	MaxSpan    int64 // seconds from a transaction's first event to its last; 0 is no limit
	MaxPause   int64 // seconds between two events of a transaction; 0 is no limit
	MaxEvents  int   // events in one transaction
	StartsWith Expr  // an event that matches starts a transaction
	EndsWith   Expr  // an event that matches ends one
}

func (*Transaction) Name() string { return "transaction" }

// DefaultMaxEvents is the most events of one transaction when maxevents=
// is not given, as in Splunk.
const DefaultMaxEvents = 1000

// maxTransactionSpan bounds maxspan and maxpause: ten years.
const maxTransactionSpan = 10 * 365 * 24 * 3600

func (p *parser) parseTransaction() (Command, error) {
	c := &Transaction{MaxEvents: DefaultMaxEvents}
	for {
		t := p.peek()
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t.kind == tokString && t.text != "" {
			p.next()
			c.Fields = append(c.Fields, t.text)
			continue
		}
		if t.kind != tokWord {
			break
		}
		if p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			key := strings.ToLower(t.text)
			p.next()
			p.next()
			v := p.peek()
			var err error
			switch key {
			case "maxspan", "maxpause":
				p.next()
				n, ok := parseSpanSeconds(v.text)
				if !ok || v.kind != tokWord {
					return nil, errorf(v.pos, "%s takes a time such as 30s, 10m, 2h or 1d, got %s", key, describe(v))
				}
				if key == "maxspan" {
					c.MaxSpan = n
				} else {
					c.MaxPause = n
				}
			case "maxevents":
				n, err := p.int()
				if err != nil {
					return nil, err
				}
				if n < 1 {
					return nil, errorf(v.pos, "maxevents must be at least 1")
				}
				c.MaxEvents = n
			case "startswith", "endswith":
				var e Expr
				if e, err = p.transactionBound(key); err != nil {
					return nil, err
				}
				if key == "startswith" {
					c.StartsWith = e
				} else {
					c.EndsWith = e
				}
			default:
				return nil, errorf(t.pos, "unknown transaction option %q; transaction takes maxspan=, maxpause=, maxevents=, startswith= and endswith=", t.text)
			}
			continue
		}
		p.next()
		f := p.fieldSuffix(t.text)
		if f == "" {
			return nil, errorf(t.pos, "expected a field name")
		}
		c.Fields = append(c.Fields, f)
	}
	return c, p.endCommand()
}

// transactionBound reads startswith= or endswith=: text found in the raw
// event ("Accepted"), or a search in parentheses ((action=logoff)).
func (p *parser) transactionBound(key string) (Expr, error) {
	v := p.peek()
	switch v.kind {
	case tokString, tokWord:
		p.next()
		if v.text == "" {
			return nil, errorf(v.pos, "%s needs text to find", key)
		}
		return &Text{Value: v.text}, nil
	case tokLParen:
		e, err := p.parseUnary(true)
		if err != nil {
			return nil, err
		}
		if e == nil {
			return nil, errorf(v.pos, "%s=(*) matches every event", key)
		}
		return e, nil
	}
	return nil, errorf(v.pos, `%s takes text such as "session opened" or a search in parentheses such as (action=success)`, key)
}

// parseSpanSeconds reads 30, 30s, 10m, 2h or 1d as seconds.
func parseSpanSeconds(s string) (int64, bool) {
	s = strings.ToLower(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i > 12 {
		return 0, false
	}
	n, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return 0, false
	}
	var unit int64
	switch s[i:] {
	case "", "s", "sec", "secs", "second", "seconds":
		unit = 1
	case "m", "min", "mins", "minute", "minutes":
		unit = 60
	case "h", "hr", "hrs", "hour", "hours":
		unit = 3600
	case "d", "day", "days":
		unit = 86400
	default:
		return 0, false
	}
	if n < 1 || n > maxTransactionSpan/unit {
		return 0, false
	}
	return n * unit, true
}

func transactionString(c *Transaction) string {
	parts := []string{"transaction"}
	for _, f := range c.Fields {
		parts = append(parts, formatName(f))
	}
	if c.MaxSpan > 0 {
		parts = append(parts, "maxspan="+strconv.FormatInt(c.MaxSpan, 10)+"s")
	}
	if c.MaxPause > 0 {
		parts = append(parts, "maxpause="+strconv.FormatInt(c.MaxPause, 10)+"s")
	}
	if c.MaxEvents != DefaultMaxEvents {
		parts = append(parts, "maxevents="+strconv.Itoa(c.MaxEvents))
	}
	if c.StartsWith != nil {
		parts = append(parts, "startswith=("+topLevel(c.StartsWith, " ")+")")
	}
	if c.EndsWith != nil {
		parts = append(parts, "endswith=("+topLevel(c.EndsWith, " ")+")")
	}
	return strings.Join(parts, " ")
}
