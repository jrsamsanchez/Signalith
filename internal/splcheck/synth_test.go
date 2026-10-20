// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"regexp"
	"testing"
)

// A regular expression with word boundaries gets a near miss that only
// its boundary rejects.
func TestBoundaryNearMiss(t *testing.T) {
	re := `(?i)\.(?:key|pem)\b`
	pos, neg := Events(&And{Kids: []Expr{
		&Cmp{Field: "process", Values: []string{"*.key*"}},
		&Cmp{Field: "process", Values: []string{re}, Regex: true},
	}})
	if len(pos) != 1 {
		t.Fatalf("positives %v", pos)
	}
	strict, loose := regexp.MustCompile(re), regexp.MustCompile(`(?i)\.(?:key|pem)`)
	found := false
	for _, ev := range neg {
		v, ok := ev["process"]
		if ok && !strict.MatchString(v) && loose.MatchString(v) && Glob("*.key*", v) && len(v) > len(pos[0]["process"]) {
			found = true
		}
	}
	if !found {
		t.Errorf("no near miss at the boundary of %v: %v", pos, neg)
	}
	if p, ok := WithoutBoundaries(`\bx\B`); !ok || !regexp.MustCompile(p).MatchString("axa") {
		t.Errorf("WithoutBoundaries = %q %v", p, ok)
	}
	if _, ok := WithoutBoundaries(`x`); ok {
		t.Error("x has boundaries")
	}
}
