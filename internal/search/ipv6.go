package search

import (
	"fmt"
	"net/netip"
	"strings"
)

// ipv6RangePattern is a regular expression (RE2 syntax) for the text of
// the IPv6 addresses in a range such as fe80::/10, as Windows and Linux
// write them: hextets in hex without leading zeros, one run of zero
// hextets shortened to "::", and possibly a zone ("%12") after. Each
// hextet the prefix covers must have one of the prefix's values, wherever
// "::" falls; the rest may be anything.
func ipv6RangePattern(p netip.Prefix) (string, error) {
	p = p.Masked()
	bits := p.Bits()
	if bits == 0 {
		return "", fmt.Errorf("an IPv6 range of /%d is not a pattern", bits)
	}
	a := p.Addr().As16()
	n := (bits + 15) / 16 // hextets the prefix covers
	hex := make([]string, n)
	zero := make([]bool, n) // the hextet may be 0
	for i := 0; i < n; i++ {
		v := uint16(a[2*i])<<8 | uint16(a[2*i+1])
		free := 0
		if i == n-1 {
			free = n*16 - bits
		}
		hex[i] = hextetPattern(v, free)
		zero[i] = v == 0
	}
	const any = `[0-9a-f]{1,4}`
	join := func(parts []string) string { return strings.Join(parts, ":") }
	var alts []string
	// No "::" among the prefix's hextets: they are the text's first ones,
	// and the address goes on after a colon (or ends, for 8 hextets).
	if n == 8 {
		alts = append(alts, join(hex)+`(%.*)?`)
	} else {
		alts = append(alts, join(hex)+`(:.*|%.*)?`)
	}
	// "::" in place of the zero hextets c..e: the prefix's hextets before
	// c, "::", then 7-e hextets of which the first are the prefix's
	// hextets after e.
	for c := 0; c < n; c++ {
		if !zero[c] {
			continue
		}
		for e := c; e < 8; e++ {
			if e < n && !zero[e] {
				break
			}
			var after []string
			for i := e + 1; i < 8; i++ {
				if i < n {
					after = append(after, hex[i])
				} else {
					after = append(after, any)
				}
			}
			alts = append(alts, join(hex[:c])+"::"+join(after)+`(%.*)?`)
		}
	}
	return `(?i)^(` + strings.Join(alts, "|") + `)$`, nil
}

// hextetPattern matches the text of the hextets whose top 16-free bits
// are v's: hex digits without leading zeros ("0" for zero).
func hextetPattern(v uint16, free int) string {
	if free == 0 {
		return fmt.Sprintf("%x", v)
	}
	// Each of the four digits is a set of values: fixed, partly free or
	// free.
	var digits [4][2]int // lo, hi
	for d := 0; d < 4; d++ {
		shift := uint(12 - 4*d)
		lo := int(v>>shift) & 0xf
		f := free - int(shift)
		switch {
		case f <= 0:
			digits[d] = [2]int{lo, lo}
		case f >= 4:
			digits[d] = [2]int{0, 15}
		default:
			lo &^= 1<<f - 1
			digits[d] = [2]int{lo, lo | (1<<f - 1)}
		}
	}
	class := func(lo, hi int) string {
		if lo == hi {
			return fmt.Sprintf("%x", lo)
		}
		// Listed, since a range such as 8-b would span punctuation and
		// capital letters.
		var b strings.Builder
		b.WriteByte('[')
		for d := lo; d <= hi; d++ {
			fmt.Fprintf(&b, "%x", d)
		}
		b.WriteByte(']')
		return b.String()
	}
	// The text has L digits: the first 4-L are zeros and are left out,
	// the next is not zero (unless it is the last).
	var alts []string
	for l := 4; l >= 1; l-- {
		skip := 4 - l
		ok := true
		for d := 0; d < skip; d++ {
			if digits[d][0] != 0 {
				ok = false
			}
		}
		if !ok {
			continue
		}
		first := digits[skip]
		if l > 1 {
			if first[1] == 0 {
				continue
			}
			first[0] = max(first[0], 1)
		}
		s := class(first[0], first[1])
		for d := skip + 1; d < 4; d++ {
			s += class(digits[d][0], digits[d][1])
		}
		alts = append(alts, s)
	}
	if len(alts) == 1 {
		return alts[0]
	}
	return "(" + strings.Join(alts, "|") + ")"
}
