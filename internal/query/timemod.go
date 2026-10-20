// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// timeUnits are the units of a time modifier, by their canonical letter:
// s, m (minutes), h, d, w, M (months), q (quarters), y.
var timeUnits = map[string]string{
	"s": "s", "sec": "s", "secs": "s", "second": "s", "seconds": "s",
	"m": "m", "min": "m", "mins": "m", "minute": "m", "minutes": "m",
	"h": "h", "hr": "h", "hrs": "h", "hour": "h", "hours": "h",
	"d": "d", "day": "d", "days": "d",
	"w": "w", "week": "w", "weeks": "w",
	"mon": "M", "month": "M", "months": "M",
	"q": "q", "qtr": "q", "qtrs": "q", "quarter": "q", "quarters": "q",
	"y": "y", "yr": "y", "yrs": "y", "year": "y", "years": "y",
}

// maxTimeOffset bounds the number in one offset of a time modifier.
const maxTimeOffset = 100000

// isoDate is an ISO 8601 date, optionally with a time and zone, which
// OpenSearch reads as it is.
var isoDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$`)

var isoLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04Z07:00", "2006-01-02T15:04", "2006-01-02T15:04:05Z0700", "2006-01-02"}

// ResolveTime reads a time as earliest=, latest= and relative_time take
// it, as Splunk does, with now as the current time, in UTC:
//
//   - now, or empty
//   - a chain of offsets and snaps such as -24h, -7d@d, @d-1h, -1d@d+8h,
//     -1q@q or @w1. A snap rounds down to the start of its unit; weeks
//     start on Sunday (@w or @w0), or on the day @w1 to @w6 names (@w1 is
//     Monday)
//   - an epoch time in seconds, such as 1767225600 (a number of 12 digits
//     or more is milliseconds)
//   - an ISO 8601 date and time, such as 2026-10-01 or
//     2026-10-01T08:00:00Z (UTC when it names no zone)
//   - Splunk's %m/%d/%Y:%H:%M:%S, such as 10/01/2026:08:00:00
func ResolveTime(v string, now time.Time) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "now") {
		return now.UTC(), true
	}
	if isEpoch(v) {
		return epochTime(v)
	}
	if isoDate.MatchString(v) {
		for _, l := range isoLayouts {
			if t, err := time.Parse(l, v); err == nil {
				return t.UTC(), true
			}
		}
		return time.Time{}, false
	}
	if t, err := time.Parse("01/02/2006:15:04:05", v); err == nil {
		return t.UTC(), true
	}
	return RelativeTime(now, v)
}

// isEpoch reports whether v is a number of seconds (or milliseconds).
func isEpoch(v string) bool {
	digits := 0
	for i, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.' && i > 0 && !strings.Contains(v[:i], "."):
		default:
			return false
		}
	}
	return digits > 0 && v[len(v)-1] != '.'
}

func epochTime(v string) (time.Time, bool) {
	whole, frac, _ := strings.Cut(v, ".")
	if len(whole) >= 12 {
		ms, err := strconv.ParseInt(whole, 10, 64)
		return time.UnixMilli(ms).UTC(), err == nil
	}
	sec, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	var ns int64
	if frac != "" {
		frac = (frac + "000000000")[:9]
		ns, _ = strconv.ParseInt(frac, 10, 64)
	}
	return time.Unix(sec, ns).UTC(), true
}

// RelativeTime applies a chain of offsets and snaps (-1d@d+8h, @w1, now)
// to t, in UTC; see ResolveTime.
func RelativeTime(t time.Time, spec string) (time.Time, bool) {
	spec = strings.TrimSpace(spec)
	if strings.EqualFold(spec, "now") {
		return t.UTC(), true
	}
	if spec == "" {
		return time.Time{}, false
	}
	t = t.UTC()
	for spec != "" {
		var ok bool
		switch spec[0] {
		case '+', '-':
			t, spec, ok = applyOffset(t, spec)
		case '@':
			t, spec, ok = applySnap(t, spec[1:])
		}
		if !ok {
			return time.Time{}, false
		}
	}
	return t, true
}

// leadingDigits splits s after its leading digits.
func leadingDigits(s string) (string, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

// leadingLetters splits s after its leading letters.
func leadingLetters(s string) (string, string) {
	i := 0
	for i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z') {
		i++
	}
	return s[:i], s[i:]
}

func applyOffset(t time.Time, spec string) (time.Time, string, bool) {
	sign := spec[0]
	num, rest := leadingDigits(spec[1:])
	word, rest := leadingLetters(rest)
	unit, ok := timeUnits[strings.ToLower(word)]
	if !ok {
		return t, "", false
	}
	n := 1
	if num != "" {
		var err error
		if n, err = strconv.Atoi(num); err != nil || n > maxTimeOffset {
			return t, "", false
		}
	}
	if sign == '-' {
		n = -n
	}
	switch unit {
	case "s":
		t = t.Add(time.Duration(n) * time.Second)
	case "m":
		t = t.Add(time.Duration(n) * time.Minute)
	case "h":
		t = t.Add(time.Duration(n) * time.Hour)
	case "d":
		t = t.AddDate(0, 0, n)
	case "w":
		t = t.AddDate(0, 0, 7*n)
	case "M":
		t = t.AddDate(0, n, 0)
	case "q":
		t = t.AddDate(0, 3*n, 0)
	case "y":
		t = t.AddDate(n, 0, 0)
	}
	return t, rest, true
}

func applySnap(t time.Time, spec string) (time.Time, string, bool) {
	word, rest := leadingLetters(spec)
	unit, ok := timeUnits[strings.ToLower(word)]
	if !ok {
		return t, "", false
	}
	y, mo, d := t.Date()
	switch unit {
	case "s":
		t = t.Truncate(time.Second)
	case "m":
		t = t.Truncate(time.Minute)
	case "h":
		t = t.Truncate(time.Hour)
	case "d":
		t = time.Date(y, mo, d, 0, 0, 0, 0, time.UTC)
	case "w":
		day := 0 // Sunday
		if rest != "" && rest[0] >= '0' && rest[0] <= '7' {
			day, rest = int(rest[0]-'0')%7, rest[1:]
		}
		back := (int(t.Weekday()) - day + 7) % 7
		t = time.Date(y, mo, d-back, 0, 0, 0, 0, time.UTC)
	case "M":
		t = time.Date(y, mo, 1, 0, 0, 0, 0, time.UTC)
	case "q":
		t = time.Date(y, mo-(mo-1)%3, 1, 0, 0, 0, 0, time.UTC)
	case "y":
		t = time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return t, rest, true
}

// CheckTime reports whether earliest= or latest= can take v: a time
// ResolveTime reads, 0 (all time), or OpenSearch date math that starts
// with now (now-1d/d).
func CheckTime(v string) bool {
	v = strings.TrimSpace(v)
	if v == "0" || strings.HasPrefix(strings.ToLower(v), "now") {
		return true
	}
	_, ok := ResolveTime(v, time.Now())
	return ok
}
