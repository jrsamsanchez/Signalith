package query

import "strings"

// EventCount starts a search with the number of events stored in
// Indexes, all of them together (Summarize) or one row per index.
type EventCount struct {
	Indexes   []string // index= patterns; none = every index a search reads
	Summarize bool
}

func (*EventCount) Name() string { return "eventcount" }

const (
	// MaxEventCountIndexes bounds the index= options of one eventcount.
	MaxEventCountIndexes = 20

	eventCountUsage = "eventcount [index=pattern ...] [summarize=true|false]"
)

func (p *parser) parseEventCount(cmd token) (Command, error) {
	c := &EventCount{Summarize: true}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		t, key, ok := p.option()
		if !ok {
			return nil, errorf(t.pos, "unexpected %s; eventcount expects: %s", describe(t), eventCountUsage)
		}
		var err error
		switch key {
		case "index":
			if len(c.Indexes) >= MaxEventCountIndexes {
				return nil, errorf(t.pos, "eventcount takes at most %d index= options", MaxEventCountIndexes)
			}
			vt := p.peek()
			var v string
			if v, err = p.optionName("eventcount", key); err == nil {
				if err = CheckIndex(v); err != nil {
					return nil, errorf(vt.pos, "%s", err.Error())
				}
				c.Indexes = append(c.Indexes, strings.ToLower(v))
			}
		case "summarize":
			c.Summarize, err = parseBool(p.next())
		case "report_size", "list_vix":
			// Index sizes and virtual indexes are not Signalith's; only
			// false is taken, as Splunk's own default.
			vt := p.next()
			var on bool
			if on, err = parseBool(vt); err == nil && on {
				return nil, errorf(vt.pos, "eventcount %s= takes only false", key)
			}
		default:
			return nil, errorf(t.pos, "unknown eventcount option %q; eventcount expects: %s", t.text, eventCountUsage)
		}
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func eventCountString(c *EventCount) string {
	s := "eventcount"
	for _, ix := range c.Indexes {
		s += " index=" + optionValue(ix)
	}
	if !c.Summarize {
		s += " summarize=false"
	}
	return s
}
