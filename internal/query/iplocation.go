package query

import "strings"

// IPLocation adds where the address in a field is, from the GeoIP
// database: City, Region, Country, lat and lon, and with AllFields also
// Continent, MetroCode and Timezone, each name starting with Prefix.
type IPLocation struct {
	Field     string
	Prefix    string
	AllFields bool
	Lang      string // "" for English
}

func (*IPLocation) Name() string { return "iplocation" }

// MaxIPLocationPrefix bounds iplocation prefix=.
const MaxIPLocationPrefix = 100

// Fields returns the names the command adds, in order.
func (c *IPLocation) Fields() []string {
	names := []string{"City", "Region", "Country", "lat", "lon"}
	if c.AllFields {
		names = append(names, "Continent", "MetroCode", "Timezone")
	}
	for i := range names {
		names[i] = c.Prefix + names[i]
	}
	return names
}

func (p *parser) parseIPLocation(cmd token) (Command, error) {
	c := &IPLocation{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			key := strings.ToLower(t.text)
			switch key {
			case "prefix", "allfields", "lang":
			default:
				return nil, errorf(t.pos, "iplocation has no option %s; it takes prefix=, allfields= and lang=", t.text)
			}
			p.next()
			p.next()
			if key == "allfields" {
				b, err := parseBool(p.next())
				if err != nil {
					return nil, err
				}
				c.AllFields = b
				continue
			}
			vt := p.peek()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			switch key {
			case "prefix":
				if len(v) > MaxIPLocationPrefix {
					return nil, errorf(vt.pos, "iplocation prefix= is at most %d characters", MaxIPLocationPrefix)
				}
				c.Prefix = v
			case "lang":
				if !validLang(v) {
					return nil, errorf(vt.pos, "iplocation lang= takes a language code such as en, de or zh-CN, not %q", v)
				}
				if v != "en" {
					c.Lang = v
				}
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && c.Field == "" {
			p.next()
			c.Field = t.text
			// 'sourceIPs{}', a field name in eval's quotes, as Splunk's
			// content writes some.
			if n := len(c.Field); t.kind == tokWord && n > 2 && c.Field[0] == '\'' && c.Field[n-1] == '\'' {
				c.Field = c.Field[1 : n-1]
			}
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; iplocation expects: iplocation [prefix=name] [allfields=true] [lang=code] <field>", describe(t))
	}
	if c.Field == "" {
		return nil, errorf(cmd.pos, "iplocation needs a field holding an IP address, like iplocation src")
	}
	return c, nil
}

func validLang(s string) bool {
	if len(s) < 2 || len(s) > 10 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
			return false
		}
	}
	return true
}

func ipLocationString(c *IPLocation) string {
	s := "iplocation"
	if c.Prefix != "" {
		s += " prefix=" + optionValue(c.Prefix)
	}
	if c.AllFields {
		s += " allfields=true"
	}
	if c.Lang != "" {
		s += " lang=" + c.Lang
	}
	// A name that starts and ends with ' is written in double quotes, or
	// it would read back without them.
	if n := len(c.Field); n > 2 && c.Field[0] == '\'' && c.Field[n-1] == '\'' {
		return s + " " + quote(c.Field)
	}
	return s + " " + formatName(c.Field)
}
