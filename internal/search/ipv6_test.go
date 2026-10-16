package search

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// Addresses in and around each range match exactly when the range holds
// them, in OpenSearch's syntax evaluated here.
func TestIPv6Range(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, r := range []string{"fe80::/10", "fc00::/7", "2603:1056::/36", "2603:1006::/40", "2620:1ec:900::/46",
		"2603:1063:2000::/38", "2a01:111:f403::/48", "2620:83:8000::/48", "::/8", "0:0:1::/48", "2001:db8::/120", "::ffff:0:0/96", "::1/128", "2620:1ec:a92::153/128", "2a01:111:f100:2002::8975:2da8/128"} {
		p := netip.MustParsePrefix(r)
		q, err := query.Parse("src=" + r)
		if err != nil {
			t.Fatal(err)
		}
		base := p.Masked().Addr().As16()
		for i := 0; i < 600; i++ {
			a := base
			// Random bits after the prefix, often zero runs, and now and
			// then a flipped prefix bit.
			for b := p.Bits(); b < 128; b++ {
				if rng.Intn(3) == 0 && (b/16)%3 != 0 {
					a[b/8] |= 1 << (7 - b%8)
				}
			}
			if rng.Intn(4) == 0 {
				b := rng.Intn(p.Bits())
				a[b/8] ^= 1 << (7 - b%8)
			}
			addr := netip.AddrFrom16(a)
			text := addr.String()
			if addr.Is4In6() {
				continue // written as ::ffff:1.2.3.4
			}
			// As written, with a zone, in capitals, and with no "::".
			var full []string
			for k := 0; k < 16; k += 2 {
				full = append(full, fmt.Sprintf("%x", uint16(a[k])<<8|uint16(a[k+1])))
			}
			for _, v := range []string{text, text + "%12", strings.ToUpper(text), strings.Join(full, ":")} {
				got, err := MatchDoc(q.Search, map[string]any{"src": v})
				if err != nil {
					t.Fatal(err)
				}
				if got != p.Contains(addr) {
					t.Fatalf("%s: %s matched %v, want %v\n%v", r, v, got, p.Contains(addr), must(ipv6RangePattern(p)))
				}
			}
		}
	}
}

func must(s string, err error) string {
	if err != nil {
		return err.Error()
	}
	return s
}

// A search's clause estimate counts what it compiles to.
func TestClauses(t *testing.T) {
	for q, want := range map[string]int{
		"a=1":                  1,
		"a=1 b IN (x, y, z)":   4,
		"src=10.0.0.0/7":       1,
		"NOT (a=1 OR b=2) c=3": 3,
	} {
		e, err := query.Parse(q)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := Clauses(e.Search); err != nil || n != want {
			t.Errorf("Clauses(%s) = %d %v, want %d", q, n, err, want)
		}
	}
}
