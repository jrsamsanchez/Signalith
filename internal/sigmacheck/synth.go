package sigmacheck

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"strings"
)

// Synthesis makes events from a rule: positives the rule matches, and
// negatives that satisfy a selection and one of its exclusion filters, so
// the rule must not match them. Every event is checked with Match.
type Synthesis struct {
	Positive []map[string]string
	Negative []map[string]string
}

// Limits on how much synthesis tries per rule.
const (
	maxTerms    = 64
	maxAttempts = 120
	maxPositive = 4
	maxNegative = 12
)

type lit struct {
	sel *selection
	neg bool
}

// dnf expands a condition into a disjunction of conjunctions of
// (possibly negated) selections.
func dnf(n node, neg bool) [][]lit {
	switch x := n.(type) {
	case *selNode:
		return [][]lit{{{x.s, neg}}}
	case *notNode:
		return dnf(x.kid, !neg)
	case *andNode:
		if neg {
			return orTerms(x.kids, true)
		}
		return andTerms(x.kids, false)
	case *orNode:
		if neg {
			return andTerms(x.kids, true)
		}
		return orTerms(x.kids, false)
	}
	return nil
}

func orTerms(kids []node, neg bool) [][]lit {
	var out [][]lit
	for _, k := range kids {
		out = append(out, dnf(k, neg)...)
		if len(out) > maxTerms {
			return out[:maxTerms]
		}
	}
	return out
}

func andTerms(kids []node, neg bool) [][]lit {
	out := [][]lit{{}}
	for _, k := range kids {
		var next [][]lit
		for _, a := range out {
			for _, b := range dnf(k, neg) {
				t := append(append([]lit{}, a...), b...)
				next = append(next, t)
				if len(next) > maxTerms {
					break
				}
			}
		}
		out = next
	}
	return out
}

// constraint is one requirement on a field's value.
type constraint struct {
	how     string // equals, contains, startswith, endswith, cidr, null, exists, absent
	pattern string
}

type constraints map[string][]constraint

// pick chooses, at random, one way to satisfy a selection: one
// alternative, one value of each field condition (all of them with
// |all), one variant of each value.
func pick(rng *rand.Rand, s *selection, into constraints) error {
	if len(s.keywords) > 0 {
		return errors.New("keyword search")
	}
	if len(s.alts) == 0 {
		return errors.New("empty selection")
	}
	alt := s.alts[rng.Intn(len(s.alts))]
	for _, fc := range alt {
		if len(fc.mods) == 1 && fc.mods[0] == "exists" {
			if fc.values[0] != nil && strings.EqualFold(*fc.values[0], "true") {
				into[fc.field] = append(into[fc.field], constraint{how: "exists"})
			} else {
				into[fc.field] = append(into[fc.field], constraint{how: "null"})
			}
			continue
		}
		values := fc.values
		if !fc.all {
			values = []*string{values[rng.Intn(len(values))]}
		}
		for _, v := range values {
			if v == nil {
				into[fc.field] = append(into[fc.field], constraint{how: "null"})
				continue
			}
			how, pats, err := Patterns(fc.mods, *v)
			if err != nil {
				return err
			}
			if how == "re" {
				return errors.New("regular expression")
			}
			into[fc.field] = append(into[fc.field], constraint{how: how, pattern: pats[rng.Intn(len(pats))]})
		}
	}
	return nil
}

// instantiateCase turns a Sigma pattern into a concrete string, keeping
// its letter case: * becomes nothing, ? becomes x, and escapes are
// resolved.
func instantiateCase(p string) string {
	var b strings.Builder
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if c == '\\' && i+1 < len(rs) && (rs[i+1] == '*' || rs[i+1] == '?' || rs[i+1] == '\\') {
			b.WriteRune(rs[i+1])
			i++
			continue
		}
		switch c {
		case '*':
		case '?':
			b.WriteByte('x')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// build makes field values that satisfy the constraints, or says a field
// must be missing. ok is false when the constraints conflict.
func build(rng *rand.Rand, cs constraints) (map[string]string, bool) {
	out := map[string]string{}
	fields := make([]string, 0, len(cs))
	for f := range cs {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, f := range fields {
		var eq, starts, ends, mids []string
		missing, present := false, false
		for _, c := range cs[f] {
			switch c.how {
			case "null":
				missing = true
			case "exists":
				present = true
			case "equals":
				eq = append(eq, c.pattern)
			case "startswith":
				starts = append(starts, c.pattern)
			case "endswith":
				ends = append(ends, c.pattern)
			case "contains":
				mids = append(mids, c.pattern)
			case "cidr":
				pfx, err := netip.ParsePrefix(c.pattern)
				if err != nil {
					return nil, false
				}
				a := pfx.Masked().Addr()
				if n := a.Next(); n.IsValid() && pfx.Contains(n) {
					a = n
				}
				eq = append(eq, a.String())
			}
		}
		if missing {
			if present || len(eq)+len(starts)+len(ends)+len(mids) > 0 {
				// A field that must be missing and set: only an empty
				// pattern can do both.
				if len(eq) == 1 && eq[0] == "" && len(starts)+len(ends)+len(mids) == 0 {
					continue
				}
				return nil, false
			}
			continue
		}
		if len(eq) > 0 {
			out[f] = instantiateCase(eq[rng.Intn(len(eq))])
			continue
		}
		sep := ""
		if rng.Intn(2) == 0 {
			sep = " "
		}
		var b strings.Builder
		if len(starts) > 0 {
			sort.Slice(starts, func(i, j int) bool { return len(starts[i]) > len(starts[j]) })
			b.WriteString(instantiateCase(starts[0]))
		}
		rng.Shuffle(len(mids), func(i, j int) { mids[i], mids[j] = mids[j], mids[i] })
		for i, m := range mids {
			if i > 0 || b.Len() > 0 {
				b.WriteString(sep)
			}
			b.WriteString(instantiateCase(m))
		}
		if len(ends) > 0 {
			sort.Slice(ends, func(i, j int) bool { return len(ends[i]) > len(ends[j]) })
			if b.Len() > 0 {
				b.WriteString(sep)
			}
			b.WriteString(instantiateCase(ends[0]))
		}
		v := b.String()
		// Stored values are trimmed, so a pattern with spaces at its ends
		// needs text around it.
		if len(starts) == 0 && strings.TrimLeft(v, " \t") != v {
			v = "x" + v
		}
		if len(ends) == 0 && strings.TrimRight(v, " \t") != v {
			v += "x"
		}
		if v == "" && present {
			v = "x"
		}
		if v == "" {
			continue
		}
		out[f] = v
	}
	return out, true
}

func merge(base, over map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func copyConstraints(c constraints) constraints {
	out := make(constraints, len(c))
	for k, v := range c {
		out[k] = append([]constraint(nil), v...)
	}
	return out
}

// Synthesize makes test events for the rule. Attempts alternate between
// the given bases (the fields a typical event of the log source has, which
// the rule's own values override), so rules that exclude events missing a
// field still get events. The seed makes the result repeatable.
func (r *Rule) Synthesize(seed int64, bases ...map[string]string) (*Synthesis, error) {
	if len(bases) == 0 {
		bases = []map[string]string{nil}
	}
	if r.HasKeywords() {
		return nil, errors.New("rule searches free text; only field rules get test events")
	}
	rng := rand.New(rand.NewSource(seed))
	terms := dnf(r.cond, false)
	out := &Synthesis{}
	seen := map[string]bool{}
	key := func(ev map[string]string) string {
		ks := make([]string, 0, len(ev))
		for k, v := range ev {
			ks = append(ks, k+"="+v)
		}
		sort.Strings(ks)
		return strings.Join(ks, "\x00")
	}
	for _, term := range terms {
		if len(out.Positive) >= maxPositive {
			break
		}
		for attempt := 0; attempt < maxAttempts; attempt++ {
			cs := constraints{}
			bad := false
			for _, l := range term {
				if !l.neg {
					if err := pick(rng, l.sel, cs); err != nil {
						bad = true
						break
					}
				}
			}
			if bad {
				break
			}
			vals, ok := build(rng, cs)
			if !ok {
				continue
			}
			base := bases[attempt%len(bases)]
			ev := merge(base, vals)
			m, err := r.Match(ev)
			if err != nil {
				return nil, err
			}
			if !m {
				continue
			}
			if k := key(ev); !seen[k] {
				seen[k] = true
				out.Positive = append(out.Positive, ev)
				r.negatives(rng, term, cs, base, out, seen, key)
				r.nearMisses(ev, vals, out, seen, key)
			}
			break
		}
	}
	if len(out.Positive) == 0 {
		return nil, errors.New("could not make an event the rule matches")
	}
	return out, nil
}

// negatives adds, for each excluded selection in a term, an event that
// satisfies the term's selections and that exclusion.
func (r *Rule) negatives(rng *rand.Rand, term []lit, pos constraints, base map[string]string, out *Synthesis, seen map[string]bool, key func(map[string]string) string) {
	for _, l := range term {
		if !l.neg || len(out.Negative) >= maxNegative {
			continue
		}
		for attempt := 0; attempt < maxAttempts/4; attempt++ {
			cs := copyConstraints(pos)
			if err := pick(rng, l.sel, cs); err != nil {
				break
			}
			vals, ok := build(rng, cs)
			if !ok {
				continue
			}
			ev := merge(base, vals)
			hit, err := l.sel.eval(clean(ev))
			if err != nil || !hit {
				continue
			}
			if m, err := r.Match(ev); err != nil || m {
				continue
			}
			if k := key(ev); !seen[k] {
				seen[k] = true
				out.Negative = append(out.Negative, ev)
			}
			break
		}
	}
}

// nearMisses adds, for each field the rule set in a positive event, the
// same event with that field changed so the rule no longer matches: the
// converted detection must need every value the rule needs.
func (r *Rule) nearMisses(ev, vals map[string]string, out *Synthesis, seen map[string]bool, key func(map[string]string) string) {
	fields := make([]string, 0, len(vals))
	for f := range vals {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, f := range fields {
		if len(out.Negative) >= maxNegative {
			return
		}
		for _, v := range []string{"", "unrelated-value"} {
			miss := merge(ev, map[string]string{f: v})
			if v == "" {
				delete(miss, f)
			}
			if m, err := r.Match(miss); err != nil || m {
				continue
			}
			if k := key(miss); !seen[k] {
				seen[k] = true
				out.Negative = append(out.Negative, miss)
			}
			break
		}
	}
}

// String shows a synthesized event, for test failures.
func String(ev map[string]string) string {
	ks := make([]string, 0, len(ev))
	for k := range ev {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		fmt.Fprintf(&b, "%s=%q ", k, ev[k])
	}
	return strings.TrimSpace(b.String())
}
