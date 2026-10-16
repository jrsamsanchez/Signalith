package query

import (
	"regexp"
	"strconv"
	"strings"
)

// MVExpand makes one row for each value of a multivalue field, each a copy
// of the row with that one value: mvexpand user limit=100.
type MVExpand struct {
	Field string
	Limit int // values expanded per row; 0 for all
}

// MakeMV splits a field's text into a multivalue field, at Delim or at
// each match of Tokenizer: makemv delim="," recipients, or
// makemv tokenizer="(\w+@\S+)" recipients.
type MakeMV struct {
	Field      string
	Delim      string // default a space
	Tokenizer  string // a regular expression; its first group, or whole match, is a value
	AllowEmpty bool   // keep empty values between delimiters
}

// Reverse turns the rows' order around.
type Reverse struct{}

// AddTotals adds each row's numeric fields up into a Total field, and with
// Col a last row adding up each column: addtotals, addtotals fieldname=sum
// bytes_*, or addcoltotals labelfield=host.
type AddTotals struct {
	Fields     []string // fields to add up, * matching any text; all when empty
	NoRow      bool     // row=f
	Col        bool
	FieldName  string // the row total's name; "" is Total
	LabelField string // the field that labels the column totals row
	Label      string // its value; "" is Total
}

func (*MVExpand) Name() string  { return "mvexpand" }
func (*MakeMV) Name() string    { return "makemv" }
func (*Reverse) Name() string   { return "reverse" }
func (*AddTotals) Name() string { return "addtotals" }

// TotalName is the row total's field name.
func (a *AddTotals) TotalName() string {
	if a.FieldName == "" {
		return "Total"
	}
	return a.FieldName
}

// TotalLabel is the column totals row's label.
func (a *AddTotals) TotalLabel() string {
	if a.Label == "" {
		return "Total"
	}
	return a.Label
}

// MatchField reports whether a field name matches a pattern in which *
// matches any text.
func MatchField(pattern, name string) bool {
	_, ok := RenameField([2]string{pattern, pattern}, name)
	return ok
}

// MaxMVExpand caps mvexpand limit=.
const MaxMVExpand = 10000

func (p *parser) parseMVExpand(cmd token) (Command, error) {
	const usage = "mvexpand <field> [limit=<number>]"
	m := &MVExpand{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && strings.EqualFold(t.text, "limit") && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			p.next()
			p.next()
			at := p.peek().pos
			n, err := p.int()
			if err != nil {
				return nil, err
			}
			if n > MaxMVExpand {
				return nil, errorf(at, "mvexpand limit can be at most %d", MaxMVExpand)
			}
			m.Limit = n
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && m.Field == "" {
			p.next()
			m.Field = t.text
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; mvexpand expects: %s", describe(t), usage)
	}
	if m.Field == "" {
		return nil, errorf(cmd.pos, "mvexpand expects: %s", usage)
	}
	return m, nil
}

func mvExpandString(c *MVExpand) string {
	s := "mvexpand " + FormatValue(c.Field)
	if c.Limit > 0 {
		s += " limit=" + strconv.Itoa(c.Limit)
	}
	return s
}

func (p *parser) parseMakeMV(cmd token) (Command, error) {
	const usage = `makemv [delim=","] [tokenizer="<regular expression>"] [allowempty=t] <field>`
	m := &MakeMV{}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			key := strings.ToLower(t.text)
			p.next()
			p.next()
			switch key {
			case "delim", "tokenizer":
				v := p.next()
				if v.kind != tokWord && v.kind != tokString || v.text == "" {
					return nil, errorf(v.pos, "makemv %s= needs a value", key)
				}
				if len(v.text) > MaxRexPattern {
					return nil, errorf(v.pos, "makemv %s is %d characters long; the limit is %d", key, len(v.text), MaxRexPattern)
				}
				if key == "delim" {
					m.Delim = v.text
					break
				}
				re, err := regexp.Compile(v.text)
				if err != nil {
					return nil, errorf(v.pos, "makemv tokenizer: %v", err)
				}
				if re.MatchString("") {
					return nil, errorf(v.pos, "makemv tokenizer must not match empty text")
				}
				m.Tokenizer = v.text
			case "allowempty":
				b, err := parseBool(p.next())
				if err != nil {
					return nil, err
				}
				m.AllowEmpty = b
			case "setsv":
				if b, err := parseBool(p.next()); err != nil || b {
					return nil, errorf(t.pos, "makemv setsv=t is not supported")
				}
			default:
				return nil, errorf(t.pos, "unknown makemv option %q; makemv expects: %s", t.text, usage)
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" && m.Field == "" {
			p.next()
			m.Field = t.text
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; makemv expects: %s", describe(t), usage)
	}
	if m.Field == "" {
		return nil, errorf(cmd.pos, "makemv expects: %s", usage)
	}
	if m.Delim != "" && m.Tokenizer != "" {
		return nil, errorf(cmd.pos, "makemv takes delim= or tokenizer=, not both")
	}
	if m.Delim == " " {
		m.Delim = "" // the default
	}
	return m, nil
}

func makeMVString(c *MakeMV) string {
	s := "makemv"
	if c.Delim != "" {
		s += " delim=" + quote(c.Delim)
	}
	if c.Tokenizer != "" {
		s += " tokenizer=" + quote(c.Tokenizer)
	}
	if c.AllowEmpty {
		s += " allowempty=t"
	}
	return s + " " + FormatValue(c.Field)
}

func (p *parser) parseAddTotals(cmd token) (Command, error) {
	a := &AddTotals{}
	name := strings.ToLower(cmd.text)
	if name == "addcoltotals" {
		a.NoRow, a.Col = true, true
	}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t.kind == tokWord && p.peekAt(1).kind == tokOp && p.peekAt(1).text == "=" {
			key := strings.ToLower(t.text)
			p.next()
			p.next()
			switch key {
			case "row", "col":
				if name == "addcoltotals" {
					return nil, errorf(t.pos, "addcoltotals takes labelfield= and label=; use addtotals for row= and col=")
				}
				b, err := parseBool(p.next())
				if err != nil {
					return nil, err
				}
				if key == "row" {
					a.NoRow = !b
				} else {
					a.Col = b
				}
			case "fieldname", "labelfield", "label":
				if key == "fieldname" && name == "addcoltotals" {
					return nil, errorf(t.pos, "addcoltotals takes labelfield= and label=")
				}
				v, err := p.value()
				if err != nil {
					return nil, err
				}
				if v == "" || len(v) > MaxSpathPath {
					return nil, errorf(t.pos, "%s %s= needs a value of 1 to %d characters", name, key, MaxSpathPath)
				}
				switch key {
				case "fieldname":
					a.FieldName = v
				case "labelfield":
					a.LabelField = v
				default:
					a.Label = v
				}
			default:
				return nil, errorf(t.pos, "unknown %s option %q", name, t.text)
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" {
			p.next()
			f := t.text
			if t.kind == tokWord {
				f = p.fieldSuffix(f)
			}
			if strings.Count(f, "*") > MaxRenameWildcards {
				return nil, errorf(t.pos, "%s field %s has too many *", name, FormatValue(f))
			}
			a.Fields = append(a.Fields, f)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s in %s", describe(t), name)
	}
	if a.NoRow && !a.Col {
		return nil, errorf(cmd.pos, "addtotals with row=f needs col=t")
	}
	if a.FieldName == "Total" {
		a.FieldName = ""
	}
	if a.Label == "Total" {
		a.Label = ""
	}
	return a, nil
}

func addTotalsString(c *AddTotals) string {
	s := "addtotals"
	if c.NoRow {
		s += " row=f"
	}
	if c.Col {
		s += " col=t"
	}
	if c.FieldName != "" {
		s += " fieldname=" + FormatValue(c.FieldName)
	}
	if c.LabelField != "" {
		s += " labelfield=" + FormatValue(c.LabelField)
	}
	if c.Label != "" {
		s += " label=" + FormatValue(c.Label)
	}
	for _, f := range c.Fields {
		s += " " + formatName(f)
	}
	return s
}
