// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sample"
)

// The command line prints a line per step, not per detection run: a small
// load used to print some 650 lines, most of them "Running detections (N
// of 640)", and end on "Done (547 of 547)".
func TestProgressPrinterIsQuiet(t *testing.T) {
	var out bytes.Buffer
	p := progressPrinter(&out)
	p(sample.Progress{Op: "load", Phase: "Generating a week of activity", Percent: 0})
	p(sample.Progress{Op: "load", Phase: "Generating a week of activity", Percent: 2})
	for i := 1; i <= 14; i++ {
		p(sample.Progress{Op: "load", Phase: "Writing events", Percent: 2 + i*23/14})
	}
	p(sample.Progress{Op: "load", Phase: "Adding threat intel", Percent: 25})
	for i := 1; i <= 640; i++ {
		p(sample.Progress{Op: "load", Phase: "Running detections", Percent: 27 + i*70/640})
	}
	p(sample.Progress{Op: "load", Phase: "Done", Percent: 100})

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Errorf("printed %d lines, want one per step:\n%s", len(lines), out.String())
	}
	if strings.Contains(out.String(), "Done") || regexp.MustCompile(`\d+ of \d+`).MatchString(out.String()) {
		t.Errorf("unexpected text:\n%s", out.String())
	}
	if lines[0] != "  Generating a week of activity (0%)" {
		t.Errorf("first line %q", lines[0])
	}
}
