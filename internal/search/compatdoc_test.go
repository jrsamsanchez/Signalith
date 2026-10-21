// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// docs/compatibility.md names every command and function the parser
// takes, and its numbers are the tests' own (SL-21).
func TestCompatibilityPage(t *testing.T) {
	b, err := os.ReadFile("../../docs/compatibility.md")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	var names []string
	names = append(names, query.Commands...)
	for _, f := range query.AggFuncs {
		if f == "perc95" {
			f = "perc1"
		}
		names = append(names, f)
	}
	for f := range query.EvalFuncs {
		names = append(names, f)
	}
	for _, n := range names {
		if !strings.Contains(page, "`"+n+"`") {
			t.Errorf("docs/compatibility.md does not list `%s`", n)
		}
	}
	semantic := len(semanticCases) + len(semanticDifferences)
	for _, want := range []string{
		fmt.Sprintf("%s of them", commas(splunkCorpusPass)),
		fmt.Sprintf("It runs %d searches", semantic),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("docs/compatibility.md should say %q", want)
		}
	}
}

func commas(n int) string {
	s := fmt.Sprint(n)
	if len(s) > 3 {
		s = s[:len(s)-3] + "," + s[len(s)-3:]
	}
	return s
}
