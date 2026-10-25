// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"strings"
	"testing"
)

func TestCompareDebian(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-1", 0},
		{"1.0", "1.0-0", 0},
		{"1.0", "1.0-", 0},
		{"1:1.0", "1.0", 1},
		{"0:1.0", "1.0", 0},
		{"2:1.0", "1:9.9", 1},
		{"1.0", "1:0.1", -1},
		// Debian policy's example order: ~~, ~~a, ~, nothing, a.
		{"1.0~~", "1.0~~a", -1},
		{"1.0~~a", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0a", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0-1", "1.0-1ubuntu1", -1},
		{"1.0-1ubuntu1", "1.0-2", -1},
		{"1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.3", 1},
		{"1:8.9p1-3ubuntu0.1", "1:8.9p1-3ubuntu0.3", -1},
		{"1:8.9p1-3ubuntu0.3", "1:8.9p1-3ubuntu0.3", 0},
		{"1:9.2p1-2+deb12u1", "1:9.2p1-2", 1},
		{"1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3", -1},
		{"2.36-9+deb12u4", "2.36-9+deb12u10", -1},
		{"3.0.11-1~deb12u2", "3.0.11-1", -1},
		{"3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1},
		{"1.2.3+dfsg-1", "1.2.3-1", 1},
		{"1.0-1+b1", "1.0-1", 1},
		{"1.0.0", "1.0", 1},
		{"1.01", "1.1", 0},
		{"1.001-1", "1.1-1", 0},
		{"10", "9", 1},
		{"1.10", "1.9", 1},
		{"1.2-3-4", "1.2-3-5", -1},
		{"1.2-3-4", "1.2-4", 1}, // upstream 1.2-3 against 1.2
		{"2.7.4+dfsg1-6", "2.7.4-6", 1},
		{"1.0+", "1.0.", -1}, // '+' sorts before '.'
		{"a", "b", -1},
		{"1a", "1b", -1},
		{"1A", "1a", -1},
		{"", "0", 0},
	} {
		if got := CompareDebian(c.a, c.b); got != c.want {
			t.Errorf("CompareDebian(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareDebian(c.b, c.a); got != -c.want {
			t.Errorf("CompareDebian(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

// The cases of rpm's own tests (tests/rpmvercmp.at).
func TestRPMVerCmp(t *testing.T) {
	cases := `1.0 1.0 0
1.0 2.0 -1
2.0 1.0 1
2.0.1 2.0.1 0
2.0 2.0.1 -1
2.0.1 2.0 1
2.0.1a 2.0.1a 0
2.0.1a 2.0.1 1
2.0.1 2.0.1a -1
5.5p1 5.5p1 0
5.5p1 5.5p2 -1
5.5p2 5.5p1 1
5.5p10 5.5p10 0
5.5p1 5.5p10 -1
5.5p10 5.5p1 1
10xyz 10.1xyz -1
10.1xyz 10xyz 1
xyz10 xyz10 0
xyz10 xyz10.1 -1
xyz10.1 xyz10 1
xyz.4 xyz.4 0
xyz.4 8 -1
8 xyz.4 1
xyz.4 2 -1
2 xyz.4 1
5.5p2 5.6p1 -1
5.6p1 5.5p2 1
5.6p1 6.5p1 -1
6.5p1 5.6p1 1
6.0.rc1 6.0 1
6.0 6.0.rc1 -1
10b2 10a1 1
10a2 10b2 -1
1.0aa 1.0aa 0
1.0a 1.0aa -1
1.0aa 1.0a 1
10.0001 10.0001 0
10.0001 10.1 0
10.1 10.0001 0
10.0001 10.0039 -1
10.0039 10.0001 1
4.999.9 5.0 -1
5.0 4.999.9 1
20101121 20101121 0
20101121 20101122 -1
20101122 20101121 1
2_0 2_0 0
2.0 2_0 0
2_0 2.0 0
a a 0
a+ a+ 0
a+ a_ 0
a_ a+ 0
+a +a 0
+a _a 0
_a +a 0
+_ +_ 0
_+ +_ 0
_+ _+ 0
+ _ 0
_ + 0
1.0~rc1 1.0~rc1 0
1.0~rc1 1.0 -1
1.0 1.0~rc1 1
1.0~rc1 1.0~rc2 -1
1.0~rc2 1.0~rc1 1
1.0~rc1~git123 1.0~rc1~git123 0
1.0~rc1~git123 1.0~rc1 -1
1.0~rc1 1.0~rc1~git123 1
1.0^ 1.0^ 0
1.0^ 1.0 1
1.0 1.0^ -1
1.0^git1 1.0^git1 0
1.0^git1 1.0 1
1.0 1.0^git1 -1
1.0^git1 1.0^git2 -1
1.0^git2 1.0^git1 1
1.0^git1 1.01 -1
1.01 1.0^git1 1
1.0^20160101 1.0^20160101 0
1.0^20160101 1.0.1 -1
1.0.1 1.0^20160101 1
1.0^20160101^git1 1.0^20160101^git1 0
1.0^20160102 1.0^20160101^git1 1
1.0^20160101^git1 1.0^20160102 -1
1.0~rc1^git1 1.0~rc1^git1 0
1.0~rc1^git1 1.0~rc1 1
1.0~rc1 1.0~rc1^git1 -1
1.0^git1~pre 1.0^git1~pre 0
1.0^git1 1.0^git1~pre 1
1.0^git1~pre 1.0^git1 -1`
	for _, line := range strings.Split(cases, "\n") {
		f := strings.Fields(line)
		want := map[string]int{"-1": -1, "0": 0, "1": 1}[f[2]]
		if got := rpmvercmp(f[0], f[1]); got != want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", f[0], f[1], got, want)
		}
	}
}

func TestCompareRPM(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"8.0p1-19.el8_8", "8.0p1-19.el8_8", 0},
		{"0:8.0p1-19.el8_8", "8.0p1-19.el8_8", 0},
		{"8.0p1-17.el8_7", "0:8.0p1-19.el8_8", -1},
		{"8.0p1-19.el8_9", "8.0p1-19.el8_8", 1},
		{"8.0p1-19.el8_8.1", "8.0p1-19.el8_8", 1},
		{"1:1.0-1.el9", "2.0-1.el9", 1},
		{"1:3.0.7-24.el9", "1:3.0.7-25.el9", -1},
		{"1:3.0.7-27.el9_4", "1:3.0.7-25.el9", 1},
		{"2.34-100.el9_4.2", "2.34-100.el9_4.12", -1},
		{"4.18.0-513.5.1.el8_9", "4.18.0-513.24.1.el8_9", -1},
		{"5.14.0-427.13.1.el9_4", "5.14.0-362.24.1.el9_3", 1},
		{"1.0", "1.0-1", 0}, // no release: only the versions compare
		{"1.0", "1.1-1", -1},
		{"7.76.1-26.el9_3.2", "7.76.1-26.el9_3.3", -1},
		{"1.0~rc1-1", "1.0-1", -1},
	} {
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareRPM(c.b, c.a); got != -c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
