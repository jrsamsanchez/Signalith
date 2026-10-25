// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import "testing"

func TestCVSS3Score(t *testing.T) {
	for _, c := range []struct {
		vector  string
		want    float64
		version string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "3.1"},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "3.1"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "3.1"},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5, "3.1"},
		{"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0, "3.1"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "3.1"},
		{"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.6, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.7, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, "3.1"},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "3.0"},
		// Temporal metrics after the base ones change nothing.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O", 9.8, "3.1"},
	} {
		got, v, ok := CVSS3Score(c.vector)
		if !ok || got != c.want || v != c.version {
			t.Errorf("CVSS3Score(%s) = %v %q %v, want %v %q", c.vector, got, v, ok, c.want, c.version)
		}
	}
	for _, bad := range []string{
		"", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/AH",
	} {
		if _, _, ok := CVSS3Score(bad); ok {
			t.Errorf("CVSS3Score(%q) was read", bad)
		}
	}
}
