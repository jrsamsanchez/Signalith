package splcheck

import (
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
)

// Access masks tested bit by bit: a raw search reads a hex field as a
// number (eval x = tonumber(replace(GrantedAccess,"0x",""),16)), names
// masks (eval PROCESS_VM_READ = 16), takes bit_and of the two and keeps
// the events whose bits are set (where vm_read_set == PROCESS_VM_READ).
// Each bit is one hex digit's, so the test is a regular expression over
// the field's text (bitsPattern).
var (
	evalRe     = regexp.MustCompile(`(?is)^eval\s+(\w+)\s*=\s*(.+?)\s*$`)
	toNumberRe = regexp.MustCompile(`(?i)^tonumber\(\s*(?:replace\(\s*(\w+)\s*,\s*"0x"\s*,\s*""\s*\)|(\w+))\s*,\s*16\s*\)$`)
	bitAndRe   = regexp.MustCompile(`(?i)^bit_and\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)`)
	sumRe      = regexp.MustCompile(`^\w+(\s*\+\s*\w+)*$`)
)

// bitStages reads a raw search's bit test stages in order.
type bitStages struct {
	hex    map[string]string // number variable -> the field it reads
	consts map[string]uint64
	masked map[string]masked // bit_and variable
	tests  map[*Cmp]bitTest  // the bits each test's pattern asks for
	// unused is the first eval no where has read yet: an eval that
	// only sets values for a later stage Signalith does not run.
	unused string
}

type bitTest struct{ set, clear uint64 }

type masked struct {
	field string
	mask  uint64
}

func newBitStages() *bitStages {
	return &bitStages{hex: map[string]string{}, consts: map[string]uint64{}, masked: map[string]masked{}, tests: map[*Cmp]bitTest{}}
}

// value is a constant: a number or a name an earlier eval gave one.
func (b *bitStages) value(s string) (uint64, bool) {
	if n, err := strconv.ParseUint(s, 10, 64); err == nil {
		return n, true
	}
	n, ok := b.consts[s]
	return n, ok
}

// stage reads one stage. An eval it understands is taken (nil, true); a
// where over its bit tests becomes their expression on the field.
func (b *bitStages) stage(s string, field func(string) (string, error)) (Expr, bool, error) {
	if m := evalRe.FindStringSubmatch(s); m != nil {
		name, rhs := m[1], strings.TrimSpace(m[2])
		if b.unused == "" {
			b.unused = s
		}
		if t := toNumberRe.FindStringSubmatch(rhs); t != nil {
			f := t[1] + t[2]
			name2, err := field(f)
			if err != nil {
				return nil, true, err
			}
			b.hex[name] = name2
			return nil, true, nil
		}
		if t := bitAndRe.FindStringSubmatch(rhs); t != nil && len(t[0]) == len(rhs) {
			f, ok := b.hex[t[1]]
			mask, ok2 := b.value(t[2])
			if !ok || !ok2 {
				return nil, false, nil
			}
			b.masked[name] = masked{f, mask}
			return nil, true, nil
		}
		if sumRe.MatchString(rhs) {
			var n uint64
			for _, part := range strings.Split(rhs, "+") {
				v, ok := b.value(strings.TrimSpace(part))
				if !ok {
					return nil, false, nil
				}
				n += v
			}
			b.consts[name] = n
			return nil, true, nil
		}
		return nil, false, nil
	}
	w := whereRe.FindStringSubmatch(s)
	if w == nil || len(b.hex) == 0 {
		return nil, false, nil
	}
	p := &bitParser{b: b, rest: strings.TrimSpace(w[1])}
	e, err := p.or()
	if err != nil || strings.TrimSpace(p.rest) != "" {
		return nil, false, nil
	}
	b.unused = ""
	return e, true, nil
}

// bitParser reads a where clause of bit tests joined by AND, OR and
// parentheses.
type bitParser struct {
	b    *bitStages
	rest string
}

var (
	bitOrRe    = regexp.MustCompile(`^(?i)OR\s+`)
	bitAndOpRe = regexp.MustCompile(`^(?i)AND\s+`)
	bitCmpRe   = regexp.MustCompile(`^(\w+)\s*(==|=|!=)\s*(\w+)`)
)

func (p *bitParser) skip() { p.rest = strings.TrimSpace(p.rest) }

func (p *bitParser) or() (Expr, error) {
	e, err := p.and()
	if err != nil {
		return nil, err
	}
	kids := []Expr{e}
	for p.skip(); bitOrRe.MatchString(p.rest); p.skip() {
		p.rest = p.rest[len(bitOrRe.FindString(p.rest)):]
		k, err := p.and()
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	if len(kids) == 1 {
		return e, nil
	}
	return &Or{Kids: kids}, nil
}

func (p *bitParser) and() (Expr, error) {
	e, err := p.atom()
	if err != nil {
		return nil, err
	}
	kids := []Expr{e}
	for p.skip(); bitAndOpRe.MatchString(p.rest); p.skip() {
		p.rest = p.rest[len(bitAndOpRe.FindString(p.rest)):]
		k, err := p.atom()
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	// Tests of one field joined by AND are one pattern, which a test
	// event can match.
	var out []Expr
	merged := map[string]*Cmp{}
	for _, k := range kids {
		c, ok := k.(*Cmp)
		t, isBits := p.b.tests[c]
		if !ok || !isBits {
			out = append(out, k)
			continue
		}
		prev := merged[c.Field]
		if prev == nil {
			merged[c.Field] = c
			out = append(out, c)
			continue
		}
		u := p.b.tests[prev]
		u.set, u.clear = u.set|t.set, u.clear|t.clear
		prev.Values = []string{bitsPattern(u.set, u.clear)}
		p.b.tests[prev] = u
	}
	if len(out) == 1 {
		return out[0], nil
	}
	return &And{Kids: out}, nil
}

func (p *bitParser) atom() (Expr, error) {
	p.skip()
	if strings.HasPrefix(p.rest, "(") {
		p.rest = p.rest[1:]
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		p.skip()
		if !strings.HasPrefix(p.rest, ")") {
			return nil, fmt.Errorf("missing )")
		}
		p.rest = p.rest[1:]
		return e, nil
	}
	// bit_and(x, MASK) op K, or a variable that holds it.
	var m masked
	if t := bitAndRe.FindStringSubmatch(p.rest); t != nil {
		f, ok := p.b.hex[t[1]]
		mask, ok2 := p.b.value(t[2])
		if !ok || !ok2 {
			return nil, fmt.Errorf("unknown bit test")
		}
		m = masked{f, mask}
		p.rest = strings.TrimSpace(p.rest[len(t[0]):])
		c := regexp.MustCompile(`^(==|=|!=)\s*(\w+)`).FindStringSubmatch(p.rest)
		if c == nil {
			return nil, fmt.Errorf("not a bit test")
		}
		p.rest = p.rest[len(c[0]):]
		return p.b.test(m, c[1], c[2])
	}
	c := bitCmpRe.FindStringSubmatch(p.rest)
	if c == nil {
		return nil, fmt.Errorf("not a bit test")
	}
	m, ok := p.b.masked[c[1]]
	if !ok {
		return nil, fmt.Errorf("not a bit test")
	}
	p.rest = p.rest[len(c[0]):]
	return p.b.test(m, c[2], c[3])
}

// test is bit_and(field, mask) compared with a constant: equal to the
// mask (every bit set), equal to 0 (none set), or not 0 (one set).
func (b *bitStages) test(m masked, op, k string) (Expr, error) {
	v, ok := b.value(k)
	if !ok || m.mask == 0 {
		return nil, fmt.Errorf("not a bit test")
	}
	re := func(set, clear uint64) Expr {
		c := &Cmp{Field: m.field, Values: []string{bitsPattern(set, clear)}, Regex: true}
		b.tests[c] = bitTest{set, clear}
		return c
	}
	switch {
	case op != "!=" && v == m.mask:
		return re(m.mask, 0), nil
	case op != "!=" && v == 0:
		return re(0, m.mask), nil
	case op == "!=" && v == 0:
		var kids []Expr
		for x := m.mask; x != 0; x &= x - 1 {
			kids = append(kids, re(x&-x, 0))
		}
		if len(kids) == 1 {
			return kids[0], nil
		}
		return &Or{Kids: kids}, nil
	}
	return nil, fmt.Errorf("not a bit test")
}

// maxHexDigits is the longest number bitsPattern reads: 32 bits, as
// Windows writes access masks.
const maxHexDigits = 8

// bitsPattern matches the hex text (0x1410, 0x0001fffff, 1f) of the
// numbers whose set bits include set and none of clear. Each hex digit
// holds four bits, so it is a list of the digits those bits allow.
func bitsPattern(set, clear uint64) string {
	digits := make([]string, maxHexDigits) // least significant first
	for i := range digits {
		s, c := (set>>(4*i))&0xf, (clear>>(4*i))&0xf
		var b strings.Builder
		for d := uint64(0); d < 16; d++ {
			if d&s == s && d&c == 0 {
				b.WriteString(strconv.FormatUint(d, 16))
			}
		}
		digits[i] = "[" + b.String() + "]"
	}
	// The text has at least the digits up to set's highest; the digits
	// above are there only up to the first one written, so each is
	// optional only along with those above it. Leading zeros may come
	// before.
	low := 1
	if set != 0 {
		low = (bits.Len64(set) + 3) / 4
	}
	high := ""
	for i := maxHexDigits - 1; i >= low; i-- {
		high = "(" + high + digits[i] + ")?"
	}
	var s strings.Builder
	s.WriteString(high)
	for i := low - 1; i >= 0; i-- {
		s.WriteString(digits[i])
	}
	return `(?i)^(0x)?0*` + s.String() + `$`
}
