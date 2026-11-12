// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"strings"
	"testing"
)

// A where clause ParseWhere cannot read is refused with what is wrong:
// macros it cannot expand, unclosed quotes and lists, and terms that are
// not comparisons.
func TestParseWhereErrors(t *testing.T) {
	macros := map[string]*Macro{
		"loop":  {Name: "loop", Definition: "`loop`"},
		"wraps": {Name: "wraps", Definition: "`nosuch`"},
		"names": {Name: "names", Definition: "a.exe, b.exe"},
	}
	for _, c := range []struct{ where, want string }{
		{"Processes.process_name=a )", `unexpected ")" in the where clause`},
		{"`loop`", "macros nest too deep"},
		{"Processes.process_name=a `loop", "unclosed macro"},
		{"`m(x)`", "macro with arguments m(x) is not supported"},
		{"`wraps`", "macro wraps: macro nosuch is not defined"},
		{"`nosuch`", "macro nosuch is not defined"},
		{`Processes.process_name="a`, "unclosed quote"},
		{"NOT (Processes.process_name=a", "missing )"},
		{"(Processes.process_name=a", "missing )"},
		{"= a", `expected a field, found "="`},
		{"Processes.process_name= )", "Processes.process_name = needs a value"},
		{"Processes.process_name!=", "Processes.process_name != needs a value"},
		{"Processes.process_name IN a", "Processes.process_name IN needs a list"},
		{"Processes.process_name IN (a", "Processes.process_name IN: missing )"},
		{"Processes.process_name IN (a b)", "no comma between two values"},
		{"Processes.process_name IN (=)", `Processes.process_name IN: expected a value, found "="`},
		{"Processes.process_name", "a bare term Processes.process_name is not supported"},
		{"Processes.process_name IN (`names`)", ""},
		{"Processes.process_name IN (,a, b,)", ""},
	} {
		e, err := ParseWhere(c.where, "Processes", macros)
		if c.want == "" {
			if err != nil || e == nil {
				t.Errorf("%s: %v %v", c.where, e, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.where, err, c.want)
		}
	}
}
