// Package sigmacheck evaluates Sigma rules directly, by the Sigma
// specification, and makes test events for them. It is a second,
// independent reading of a rule: the detection content checks make
// events that this package says a rule matches (and events it says the
// rule must not match), put them through Signalith's real parsers, and
// require the converted detection to agree. A rule ships only when both
// readings agree on every test event.
//
// It does not import the detect package, so a mistake in the converter
// cannot hide the same mistake here.
package sigmacheck

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"gopkg.in/yaml.v3"
)

// Rule is a parsed Sigma rule.
type Rule struct {
	Title     string
	ID        string
	Status    string
	Level     string
	Author    string
	Logsource map[string]string
	sels      map[string]*selection
	cond      node
}

type ruleYAML struct {
	Title     string            `yaml:"title"`
	ID        string            `yaml:"id"`
	Status    string            `yaml:"status"`
	Level     string            `yaml:"level"`
	Author    string            `yaml:"author"`
	Logsource map[string]string `yaml:"logsource"`
	Detection map[string]any    `yaml:"detection"`
}

// Parse reads one Sigma rule.
func Parse(src []byte) (*Rule, error) {
	var y ruleYAML
	if err := yaml.Unmarshal(src, &y); err != nil {
		return nil, err
	}
	if y.Detection == nil {
		return nil, errors.New("no detection section")
	}
	r := &Rule{Title: y.Title, ID: y.ID, Status: y.Status, Level: y.Level, Author: y.Author,
		Logsource: map[string]string{}, sels: map[string]*selection{}}
	for k, v := range y.Logsource {
		r.Logsource[k] = strings.ToLower(v)
	}
	var condStr string
	for name, v := range y.Detection {
		switch name {
		case "condition":
			switch c := v.(type) {
			case string:
				condStr = c
			case []any:
				if len(c) != 1 {
					return nil, errors.New("several conditions")
				}
				condStr = fmt.Sprint(c[0])
			}
			continue
		case "timeframe":
			continue
		}
		s, err := parseSelection(v)
		if err != nil {
			return nil, fmt.Errorf("selection %s: %w", name, err)
		}
		r.sels[name] = s
	}
	if condStr == "" {
		return nil, errors.New("no condition")
	}
	if strings.Contains(condStr, "|") {
		return nil, errors.New("aggregation condition")
	}
	n, err := parseCondition(condStr, r.sels)
	if err != nil {
		return nil, err
	}
	r.cond = n
	if r.Logsource["service"] == "security" {
		r.dropLegacyEventIDs()
	}
	return r, nil
}

// dropLegacyEventIDs leaves the Windows 2000 and XP event IDs (below
// 1000) out of an EventID list that names current ones too, so test
// events are made as the current events: the old ones never reach
// Signalith (EventIDs).
func (r *Rule) dropLegacyEventIDs() {
	legacy := func(v *string) bool {
		if v == nil {
			return false
		}
		n, err := strconv.Atoi(*v)
		return err == nil && n < 1000
	}
	for _, s := range r.sels {
		for _, alt := range s.alts {
			for _, fc := range alt {
				if fc.field != "EventID" || len(fc.mods) > 0 || !slices.ContainsFunc(fc.values, func(v *string) bool { return v != nil && !legacy(v) }) {
					continue
				}
				fc.values = slices.DeleteFunc(fc.values, legacy)
			}
		}
	}
}

// Fields returns every field name the rule's selections use.
func (r *Rule) Fields() []string {
	seen := map[string]bool{}
	for _, s := range r.sels {
		for _, alt := range s.alts {
			for _, fc := range alt {
				seen[fc.field] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// EventIDs returns the event IDs the rule's selections name (EventID
// without modifiers), in order. Windows 2000 and XP event IDs (below
// 1000, such as 517 for the log cleared) are left out when it also names
// current ones, as the converter leaves them out: those systems' events
// never reach Signalith.
func (r *Rule) EventIDs() []string {
	seen := map[string]bool{}
	for _, s := range r.sels {
		for _, alt := range s.alts {
			for _, fc := range alt {
				if fc.field != "EventID" || len(fc.mods) > 0 {
					continue
				}
				for _, v := range fc.values {
					if v != nil {
						seen[*v] = true
					}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	modern := slices.DeleteFunc(slices.Clone(out), func(id string) bool {
		n, err := strconv.Atoi(id)
		return err == nil && n < 1000
	})
	if len(modern) > 0 {
		return modern
	}
	return out
}

// HasKeywords reports whether the rule searches free text.
func (r *Rule) HasKeywords() bool {
	for _, s := range r.sels {
		if len(s.keywords) > 0 {
			return true
		}
	}
	return false
}

// Match reports whether an event (Sigma field name to value) matches. An
// empty value, or "-", counts as missing, as Signalith stores it.
func (r *Rule) Match(ev map[string]string) (bool, error) {
	return r.cond.eval(clean(ev))
}

func clean(ev map[string]string) map[string]string {
	out := make(map[string]string, len(ev))
	for k, v := range ev {
		v = strings.TrimSpace(v)
		if v == "" || v == "-" {
			continue
		}
		out[k] = v
	}
	return out
}

// ---- selections ----

type selection struct {
	// alts are alternatives (a list of maps); each is a conjunction of
	// field conditions.
	alts     [][]*fieldCond
	keywords []string
}

type fieldCond struct {
	field string
	mods  []string
	// values are alternatives unless all is set; nil means the field is
	// null (missing).
	values []*string
	all    bool
}

func parseSelection(v any) (*selection, error) {
	s := &selection{}
	switch x := v.(type) {
	case map[string]any:
		fcs, err := parseFieldMap(x)
		if err != nil {
			return nil, err
		}
		s.alts = append(s.alts, fcs)
	case []any:
		for _, item := range x {
			switch it := item.(type) {
			case map[string]any:
				fcs, err := parseFieldMap(it)
				if err != nil {
					return nil, err
				}
				s.alts = append(s.alts, fcs)
			default:
				s.keywords = append(s.keywords, fmt.Sprint(it))
			}
		}
	case string:
		s.keywords = append(s.keywords, x)
	default:
		return nil, fmt.Errorf("unsupported shape %T", v)
	}
	return s, nil
}

func parseFieldMap(m map[string]any) ([]*fieldCond, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*fieldCond
	for _, k := range keys {
		parts := strings.Split(k, "|")
		fc := &fieldCond{field: parts[0]}
		for _, mod := range parts[1:] {
			mod = strings.ToLower(mod)
			if mod == "all" {
				fc.all = true
				continue
			}
			fc.mods = append(fc.mods, mod)
		}
		switch v := m[k].(type) {
		case []any:
			for _, x := range v {
				fc.values = append(fc.values, strPtr(x))
			}
			if len(v) == 0 {
				fc.values = []*string{nil}
			}
		default:
			fc.values = []*string{strPtr(v)}
		}
		out = append(out, fc)
	}
	return out, nil
}

func strPtr(v any) *string {
	if v == nil {
		return nil
	}
	s := fmt.Sprint(v)
	if b, ok := v.(bool); ok {
		s = fmt.Sprint(b)
	}
	return &s
}

func (s *selection) eval(ev map[string]string) (bool, error) {
	for _, kw := range s.keywords {
		_ = kw
		return false, errors.New("keyword searches are not evaluated")
	}
	for _, alt := range s.alts {
		ok := true
		for _, fc := range alt {
			m, err := fc.eval(ev)
			if err != nil {
				return false, err
			}
			if !m {
				ok = false
				break
			}
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (fc *fieldCond) eval(ev map[string]string) (bool, error) {
	val, present := ev[fc.field]
	if len(fc.mods) == 1 && fc.mods[0] == "exists" {
		want := fc.values[0] != nil && strings.EqualFold(*fc.values[0], "true")
		return present == want, nil
	}
	results := 0
	for _, v := range fc.values {
		var m bool
		if v == nil {
			m = !present
		} else if present {
			var err error
			m, err = matchValue(fc.mods, *v, val)
			if err != nil {
				return false, err
			}
		} else if *v == "" {
			// An empty value matches a missing one, as stored.
			m = true
		}
		if m {
			results++
			if !fc.all {
				return true, nil
			}
		} else if fc.all {
			return false, nil
		}
	}
	return fc.all && results == len(fc.values), nil
}

// Patterns returns the candidate patterns a value turns into after the
// transforming modifiers (windash, base64, base64offset, utf16 and
// wide), and the comparison to apply: equals, contains, startswith,
// endswith, re, cidr.
func Patterns(mods []string, v string) (how string, pats []string, err error) {
	how = "equals"
	pats = []string{v}
	cased := false
	for _, m := range mods {
		switch m {
		case "contains", "startswith", "endswith":
			how = m
		case "re", "cidr":
			how = m
		case "i", "m", "s":
			// regular expression flags
		case "cased":
			cased = true
		case "windash":
			var out []string
			for _, p := range pats {
				out = append(out, windash(p)...)
			}
			pats = out
		case "utf16le", "wide":
			for i, p := range pats {
				pats[i] = utf16le(p)
			}
		case "utf16be":
			for i, p := range pats {
				pats[i] = utf16be(p)
			}
		case "utf16":
			for i, p := range pats {
				pats[i] = "\xff\xfe" + utf16le(p)
			}
		case "base64":
			for i, p := range pats {
				pats[i] = base64.StdEncoding.EncodeToString([]byte(p))
			}
		case "base64offset":
			var out []string
			for _, p := range pats {
				out = append(out, base64Offsets(p)...)
			}
			pats = out
		default:
			return "", nil, fmt.Errorf("modifier %s", m)
		}
	}
	_ = cased
	return how, pats, nil
}

func matchValue(mods []string, v, have string) (bool, error) {
	how, pats, err := Patterns(mods, v)
	if err != nil {
		return false, err
	}
	for _, p := range pats {
		var m bool
		switch how {
		case "re":
			flags := "(?"
			for _, mod := range mods {
				if mod == "i" || mod == "m" || mod == "s" {
					flags += mod
				}
			}
			expr := p
			if flags != "(?" {
				expr = flags + ")" + p
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				return false, err
			}
			m = re.MatchString(have)
		case "cidr":
			pfx, err := netip.ParsePrefix(p)
			if err != nil {
				return false, err
			}
			a, err := netip.ParseAddr(have)
			m = err == nil && pfx.Contains(a)
		default:
			m = wildcard(how, p, have)
		}
		if m {
			return true, nil
		}
	}
	return false, nil
}

// wildcard applies Sigma's value matching: case-insensitive, with * and
// ? as wildcards unless escaped by a backslash.
func wildcard(how, pattern, s string) bool {
	toks := tokens(pattern)
	switch how {
	case "contains":
		toks = append(append([]tok{{star: true}}, toks...), tok{star: true})
	case "startswith":
		toks = append(toks, tok{star: true})
	case "endswith":
		toks = append([]tok{{star: true}}, toks...)
	}
	return globTokens(toks, []rune(strings.ToLower(s)))
}

type tok struct {
	r     rune
	star  bool
	quest bool
}

func tokens(p string) []tok {
	var out []tok
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if c == '\\' && i+1 < len(rs) && (rs[i+1] == '*' || rs[i+1] == '?' || rs[i+1] == '\\') {
			out = append(out, tok{r: toLower(rs[i+1])})
			i++
			continue
		}
		switch c {
		case '*':
			out = append(out, tok{star: true})
		case '?':
			out = append(out, tok{quest: true})
		default:
			out = append(out, tok{r: toLower(c)})
		}
	}
	return out
}

func toLower(r rune) rune { return []rune(strings.ToLower(string(r)))[0] }

func globTokens(p []tok, t []rune) bool {
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && !p[pi].star && (p[pi].quest || p[pi].r == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi].star:
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi].star {
		pi++
	}
	return pi == len(p)
}

// windash expands - and / at the start of a word (after a non-word
// character or the start, before a word character) into every dash
// Windows accepts, as pySigma does (regexp \B[-/]\b).
func windash(s string) []string {
	dashes := []string{"-", "/", "–", "—", "―"}
	rs := []rune(s)
	isWord := func(r rune) bool {
		return r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range dashes {
		var b strings.Builder
		for i, r := range rs {
			if (r == '-' || r == '/') && (i == 0 || !isWord(rs[i-1])) && i+1 < len(rs) && isWord(rs[i+1]) {
				b.WriteString(d)
				continue
			}
			b.WriteRune(r)
		}
		if x := b.String(); !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func utf16le(s string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return string(b)
}

func utf16be(s string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u>>8), byte(u))
	}
	return string(b)
}

// base64Offsets returns the three base64 forms of s at each byte offset
// in a longer string, trimmed to the characters that do not depend on
// the surrounding bytes (as the Sigma specification defines it).
func base64Offsets(s string) []string {
	starts := []int{0, 2, 3}
	ends := []int{0, 3, 2}
	var out []string
	for i := 0; i < 3; i++ {
		enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(" ", i) + s))
		lo, hi := starts[i], len(enc)-ends[(len(s)+i)%3]
		if hi > lo {
			out = append(out, enc[lo:hi])
		}
	}
	return out
}

// ---- conditions ----

type node interface {
	eval(ev map[string]string) (bool, error)
}

type selNode struct {
	name string
	s    *selection
}

func (n *selNode) eval(ev map[string]string) (bool, error) { return n.s.eval(ev) }

type andNode struct{ kids []node }

func (n *andNode) eval(ev map[string]string) (bool, error) {
	for _, k := range n.kids {
		ok, err := k.eval(ev)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

type orNode struct{ kids []node }

func (n *orNode) eval(ev map[string]string) (bool, error) {
	for _, k := range n.kids {
		ok, err := k.eval(ev)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

type notNode struct{ kid node }

func (n *notNode) eval(ev map[string]string) (bool, error) {
	ok, err := n.kid.eval(ev)
	return !ok, err
}

func parseCondition(s string, sels map[string]*selection) (node, error) {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	p := &cparser{toks: strings.Fields(s), sels: sels}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.pos])
	}
	return n, nil
}

type cparser struct {
	toks []string
	pos  int
	sels map[string]*selection
}

func (p *cparser) peek() string {
	if p.pos < len(p.toks) {
		return strings.ToLower(p.toks[p.pos])
	}
	return ""
}

func (p *cparser) or() (node, error) {
	n, err := p.and()
	if err != nil {
		return nil, err
	}
	kids := []node{n}
	for p.peek() == "or" {
		p.pos++
		k, err := p.and()
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	if len(kids) == 1 {
		return n, nil
	}
	return &orNode{kids}, nil
}

func (p *cparser) and() (node, error) {
	n, err := p.not()
	if err != nil {
		return nil, err
	}
	kids := []node{n}
	for p.peek() == "and" {
		p.pos++
		k, err := p.not()
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	if len(kids) == 1 {
		return n, nil
	}
	return &andNode{kids}, nil
}

func (p *cparser) not() (node, error) {
	if p.peek() == "not" {
		p.pos++
		k, err := p.not()
		if err != nil {
			return nil, err
		}
		return &notNode{k}, nil
	}
	return p.primary()
}

func (p *cparser) primary() (node, error) {
	t := p.peek()
	switch t {
	case "":
		return nil, errors.New("condition ended early")
	case "(":
		p.pos++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("missing )")
		}
		p.pos++
		return n, nil
	case "1", "all", "any":
		p.pos++
		if p.peek() != "of" {
			return nil, fmt.Errorf("expected of after %s", t)
		}
		p.pos++
		if p.pos >= len(p.toks) {
			return nil, errors.New("of needs a name")
		}
		pat := p.toks[p.pos]
		p.pos++
		var names []string
		for name := range p.sels {
			if pat == "them" || name == pat || (strings.HasSuffix(pat, "*") && strings.HasPrefix(name, strings.TrimSuffix(pat, "*"))) {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("nothing matches %s", pat)
		}
		sort.Strings(names)
		var kids []node
		for _, n := range names {
			kids = append(kids, &selNode{n, p.sels[n]})
		}
		if len(kids) == 1 {
			return kids[0], nil
		}
		if t == "all" {
			return &andNode{kids}, nil
		}
		return &orNode{kids}, nil
	}
	name := p.toks[p.pos]
	p.pos++
	s, ok := p.sels[name]
	if !ok {
		return nil, fmt.Errorf("unknown selection %s", name)
	}
	return &selNode{name, s}, nil
}
