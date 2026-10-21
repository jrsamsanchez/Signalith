// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strings"
	"testing"
	"time"
)

// Wednesday.
var modNow = time.Date(2026, 10, 14, 13, 47, 31, 0, time.UTC)

func TestResolveTime(t *testing.T) {
	for in, want := range map[string]string{
		"now":                       "2026-10-14T13:47:31Z",
		"-24h":                      "2026-10-13T13:47:31Z",
		"-7d@d":                     "2026-10-07T00:00:00Z",
		"@d-1h":                     "2026-10-13T23:00:00Z",
		"-1d@d+8h":                  "2026-10-13T08:00:00Z",
		"@w":                        "2026-10-11T00:00:00Z", // Sunday
		"@w0":                       "2026-10-11T00:00:00Z",
		"@w1":                       "2026-10-12T00:00:00Z", // Monday
		"@w3":                       "2026-10-14T00:00:00Z", // today
		"@w4":                       "2026-10-08T00:00:00Z",
		"@w7":                       "2026-10-11T00:00:00Z",
		"-1q@q":                     "2026-07-01T00:00:00Z",
		"@q":                        "2026-10-01T00:00:00Z",
		"-1mon@mon":                 "2026-09-01T00:00:00Z",
		"+2h@h":                     "2026-10-14T15:00:00Z",
		"1767225600":                "2026-01-01T00:00:00Z", // seconds
		"1767225600.5":              "2026-01-01T00:00:00Z",
		"1767225600000":             "2026-01-01T00:00:00Z", // milliseconds
		"2026-10-01":                "2026-10-01T00:00:00Z",
		"2026-10-01T08:00:00":       "2026-10-01T08:00:00Z",
		"2026-10-01T08:00:00-04:00": "2026-10-01T12:00:00Z",
		"10/01/2026:08:00:00":       "2026-10-01T08:00:00Z",
	} {
		got, ok := ResolveTime(in, modNow)
		if !ok || got.Format(time.RFC3339) != want {
			t.Errorf("ResolveTime(%q) = %v %v, want %s", in, got, ok, want)
		}
	}
	for _, bad := range []string{"yesterday", "-x", "-1d@", "@w8", "-1", "1.2.3", "2026-13-01", "-1000000d", "-1d@d+"} {
		if got, ok := ResolveTime(bad, modNow); ok {
			t.Errorf("ResolveTime(%q) = %v, want refused", bad, got)
		}
	}
}

// earliest= and latest= refuse what they cannot read, where they once
// went to OpenSearch as they were (SL-06).
func TestEarliestIsChecked(t *testing.T) {
	for _, ok := range []string{"earliest=-1d@d+8h", "earliest=@w1 latest=now", "earliest=1767225600", "earliest=0", "earliest=now-1d/d", "latest=2026-10-01T00:00:00Z"} {
		if _, err := Parse(ok + " | stats count"); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	_, err := Parse("user=bob earliest=yesterday")
	if err == nil || !strings.Contains(err.Error(), "earliest=yesterday is not a time") {
		t.Errorf("err = %v", err)
	}
}
