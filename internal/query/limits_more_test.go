// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strconv"
	"strings"
	"testing"
)

// Commands refuse input past their limits with an error that names the
// limit.
func TestCommandLimits(t *testing.T) {
	long := strings.Repeat("a", MaxRexPattern+1)
	parts := strings.Repeat(" a", MaxStrCatParts+1)
	var ranges, fields []string
	for i := 0; i <= MaxRanges; i++ {
		ranges = append(ranges, "r"+strconv.Itoa(i)+"="+strconv.Itoa(i)+"-"+strconv.Itoa(i))
	}
	for i := 0; i <= MaxForEachFields; i++ {
		fields = append(fields, "f"+strconv.Itoa(i))
	}
	for src, want := range map[string]string{
		`* | rex field=a "` + long + `"`:                                             "the rex pattern is",
		`* | regex a="` + long + `"`:                                                 "the regex pattern is",
		`* | strcat` + parts + ` out`:                                                "strcat joins at most",
		`* | rangemap field=n ` + strings.Join(ranges, " "):                          "rangemap takes at most",
		`* | foreach ` + strings.Join(fields, " ") + ` [eval x=1]`:                   "foreach takes at most",
		`* | eval x=` + strings.Repeat("(", 120) + "1" + strings.Repeat(")", 120):    "nests too deeply",
		`* | eval x=` + strings.Repeat("abs(", 120) + "1" + strings.Repeat(")", 120): "nests too deeply",
		`* | eval x=` + strings.Repeat("NOT ", 120) + "1":                            "nests too deeply",
		`* | eval x=` + strings.Repeat("-", 120) + "1":                               "nests too deeply",
	} {
		_, err := Parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.60s...: err = %v, want %q", src, err, want)
		}
	}
}
