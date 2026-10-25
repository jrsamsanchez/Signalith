// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"strconv"
	"strings"
)

// Distribution package versions sort by their own rules, not as upstream
// versions do: 1:8.9p1-3ubuntu0.10 (Debian, epoch:upstream-revision) and
// 0:8.0p1-19.el8_8 (RPM, epoch:version-release). A package is called
// vulnerable only when its installed version sorts before the version the
// distribution fixed (ASI-19).

// CompareDebian compares two Debian package versions as dpkg does: -1 when
// a is older, 0 when they are the same, 1 when a is newer. The epoch is a
// number; the upstream version and revision compare part by part, with ~
// sorting before anything, even the end (1.0~rc1 is older than 1.0).
func CompareDebian(a, b string) int {
	ae, au, ar := splitDebian(a)
	be, bu, br := splitDebian(b)
	if ae != be {
		if ae < be {
			return -1
		}
		return 1
	}
	if c := dpkgCompare(au, bu); c != 0 {
		return c
	}
	return dpkgCompare(ar, br)
}

// splitDebian splits [epoch:]upstream[-revision]. A missing or bad epoch
// is 0, and a missing revision is empty, which dpkg sorts as 0.
func splitDebian(v string) (epoch uint64, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, _ = strconv.ParseUint(v[:i], 10, 32)
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// dpkgOrder is a character's weight outside a run of digits: ~ first,
// then the end of the string and digits, then letters, then the rest.
func dpkgOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case c == '~':
		return -1
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	}
	return int(c) + 256
}

// dpkgCompare is dpkg's verrevcmp: runs of non-digits by dpkgOrder, then
// runs of digits as numbers, in turn.
func dpkgCompare(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := dpkgOrder(a, i), dpkgOrder(b, j)
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		first := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if first != 0 {
			return sign(first)
		}
	}
	return 0
}

// CompareRPM compares two RPM versions, [epoch:]version[-release], as rpm
// does: the epoch as a number (missing is 0), then the version and the
// release with rpmvercmp. A release is compared only when both have one,
// as rpm compares a dependency without one.
func CompareRPM(a, b string) int {
	ae, av, ar := splitRPM(a)
	be, bv, br := splitRPM(b)
	if ae != be {
		if ae < be {
			return -1
		}
		return 1
	}
	if c := rpmvercmp(av, bv); c != 0 {
		return c
	}
	if ar == "" || br == "" {
		return 0
	}
	return rpmvercmp(ar, br)
}

func splitRPM(v string) (epoch uint64, version, release string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, _ = strconv.ParseUint(v[:i], 10, 32)
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// rpmvercmp is rpm's comparison of one version or release: separators
// are skipped, ~ sorts before anything and ^ after the end but before
// anything else, and runs of digits (as numbers) beat runs of letters.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ai, bj := byteAt(a, i), byteAt(b, j)
		if ai == '~' || bj == '~' {
			if ai != '~' {
				return 1
			}
			if bj != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if ai == '^' || bj == '^' {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case ai != '^':
				return 1
			case bj != '^':
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		num := isDigit(a[i])
		if num {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		if sj == j {
			// A number beats letters; letters lose to a number.
			if num {
				return 1
			}
			return -1
		}
		x, y := a[si:i], b[sj:j]
		if num {
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				if len(x) > len(y) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
