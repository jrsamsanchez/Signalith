// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package datamodel

import (
	"slices"
	"testing"
)

func TestFieldsFor(t *testing.T) {
	names := func(fs []Field) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.Name)
		}
		return out
	}
	m, ok := Get(RiskModel)
	if !ok {
		t.Fatal("no Risk model")
	}
	one := names(FieldsFor("risk"))
	if len(one) == 0 || one[0] != "_time" || !slices.IsSorted(one[1:]) {
		t.Errorf("risk fields = %v", one)
	}
	for _, f := range m.Fields {
		if !slices.Contains(one, f.Name) {
			t.Errorf("risk lacks its own %s", f.Name)
		}
	}
	all := names(FieldsFor(""))
	if len(all) <= len(one) || all[0] != "_time" || !slices.IsSorted(all[1:]) {
		t.Errorf("all fields = %d, first %v", len(all), all[:1])
	}
	seen := map[string]bool{}
	for _, n := range all {
		if seen[n] {
			t.Errorf("%s listed twice", n)
		}
		seen[n] = true
	}
	if _, ok := Get("no-such-model"); ok {
		t.Error("an unknown model was found")
	}
}
