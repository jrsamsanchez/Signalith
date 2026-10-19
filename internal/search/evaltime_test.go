package search

import (
	"math"
	"testing"
	"time"
)

// Every % conversion strftime knows, and the unknown ones kept as written.
func TestStrftimeConversions(t *testing.T) {
	tm := time.Date(2026, 3, 7, 15, 4, 9, 123456789, time.UTC) // a Saturday
	for format, want := range map[string]string{
		"%Y-%m-%d %H:%M:%S": "2026-03-07 15:04:09",
		"%y|%e|%I|%p":       "26| 7|03|PM",
		"%N %3N":            "123456789 123",
		"%b %h %B %a %A":    "Mar Mar March Sat Saturday",
		"%j %Z %z %s":       "066 UTC +0000 " + "1772895849",
		"%T %F %D":          "15:04:09 2026-03-07 03/07/26",
		"%u %w %% %q":       "6 6 % %q",
		"trailing %":        "trailing %",
	} {
		if got := strftime(tm, format); got != want {
			t.Errorf("strftime(%q) = %q, want %q", format, got, want)
		}
	}
	// Midnight is 12 AM, and Sunday is day 7 of the ISO week.
	sun := time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)
	if got := strftime(sun, "%I %p %u %w"); got != "12 AM 7 0" {
		t.Errorf("sunday midnight = %q", got)
	}
}

// strptime reads what strftime writes, and refuses what it cannot read.
func TestStrptimeConversions(t *testing.T) {
	want := time.Date(2026, 3, 7, 15, 4, 9, 0, time.UTC)
	for s, format := range map[string]string{
		"2026-03-07 15:04:09":                 "%Y-%m-%d %H:%M:%S",
		"07/Mar/2026:15:04:09 +0000":          "%d/%b/%Y:%H:%M:%S %z",
		"Saturday, March 07 2026 03:04:09 PM": "%A, %B %d %Y %I:%M:%S %p",
		"2026-03-07T15:04:09":                 "%FT%T",
		"1772895849":                          "%s",
		" 2026-03-07 15:04:09.000 ":           "%Y-%m-%d %H:%M:%S.%3N",
		"2026-03-07 15:04:09 %":               "%Y-%m-%d %H:%M:%S %%",
	} {
		got, ok := strptime(s, format)
		if !ok || !got.Equal(want) {
			t.Errorf("strptime(%q, %q) = %v %v", s, format, got, ok)
		}
	}
	for s, format := range map[string]string{
		"x":          "%s",
		"2026":       "%Q",
		"not a date": "%Y-%m-%d",
	} {
		if got, ok := strptime(s, format); ok {
			t.Errorf("strptime(%q, %q) = %v", s, format, got)
		}
	}
}

func TestDurationAndTimes(t *testing.T) {
	for f, want := range map[float64]string{0: "00:00:00", 3725: "01:02:05", 90061: "1+01:01:01", -61: "-00:01:01"} {
		if got := duration(f); got != want {
			t.Errorf("duration(%v) = %q", f, got)
		}
	}
	if got, ok := toTime(1.5); !ok || !got.Equal(time.Unix(1, 5e8).UTC()) {
		t.Errorf("toTime(1.5) = %v %v", got, ok)
	}
	if _, ok := toTime(1e13); ok {
		t.Error("read a time too far out")
	}
	if _, ok := toTime(math.NaN()); ok {
		t.Error("read NaN as a time")
	}
	if _, ok := toTime(nil); ok {
		t.Error("read nothing as a time")
	}
	if _, ok := toTime("yesterday"); ok {
		t.Error("read words as a time")
	}
	if got, ok := toTime(" 2026-03-07T15:04:09Z "); !ok || got.Unix() != 1772895849 {
		t.Errorf("toTime(text) = %v %v", got, ok)
	}
	if got := timeNumber("2026-03-07T15:04:09.5Z"); got != 1772895849.5 {
		t.Errorf("timeNumber = %#v", got)
	}
	for _, v := range []any{"later", int64(5)} {
		if got := timeNumber(v); got != v {
			t.Errorf("timeNumber(%#v) = %#v", v, got)
		}
	}
}

// How values read as conditions, numbers and text.
func TestValueReadings(t *testing.T) {
	for _, c := range []struct {
		v    any
		want bool
	}{
		{nil, false}, {true, true}, {false, false}, {"0", false}, {"2", true}, {"", false}, {"FALSE", false},
		{"yes", true}, {[]any{}, false}, {[]any{"x"}, true}, {int64(0), false}, {3.5, true}, {struct{}{}, true},
	} {
		if got := truth(c.v); got != c.want {
			t.Errorf("truth(%#v) = %v", c.v, got)
		}
	}
	if n, ok := evNum([]any{"4"}); !ok || n != 4 {
		t.Errorf("evNum of one value = %v %v", n, ok)
	}
	if _, ok := evNum([]any{"4", "5"}); ok {
		t.Error("evNum of two values")
	}
	if _, ok := evNum(true); ok {
		t.Error("evNum of a boolean")
	}
	for _, c := range []struct {
		v    any
		want string
		ok   bool
	}{
		{nil, "", false}, {"s", "s", true}, {int64(-3), "-3", true}, {7, "7", true}, {2.5, "2.5", true},
		{true, "true", true}, {[]any{"a", nil, int64(1)}, "a\n1", true}, {struct{ A int }{1}, "{1}", true},
	} {
		if got, ok := evStr(c.v); got != c.want || ok != c.ok {
			t.Errorf("evStr(%#v) = %q %v", c.v, got, ok)
		}
	}
}
