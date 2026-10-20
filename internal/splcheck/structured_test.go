// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"strings"
	"testing"
)

// TestStructuredCases checks a rule whose later stages read one entry of
// a record's list and a pattern in it gets a test event whose list has
// that value at that place, kept by the stages, and near misses that are
// not.
func TestStructuredCases(t *testing.T) {
	r, err := Parse(rule("`o365_management_activity` Workload=AzureActiveDirectory Operation=\"Consent to application.\" ResultStatus=Success\n"+
		"| eval admin_consent=mvindex('ModifiedProperties{}.NewValue',0)\n| search admin_consent=False\n"+
		"| eval permissions=mvindex('ModifiedProperties{}.NewValue',4)\n| rex field=permissions \"Scope:(?<Scope>[^,]+)\"\n"+
		"| search Scope=\"Mail.Read\"\n| fillnull\n| stats count by user src Scope"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pos, neg := 0, 0
	for _, c := range Cases(r) {
		list := c.Data["ModifiedProperties"]
		if list == "" {
			continue
		}
		doc, _ := Stored(c)
		if kept := Eval(r.Where, View(doc)) && r.Keeps(doc); kept != c.Expect {
			t.Errorf("expect %v, kept %v: %s", c.Expect, kept, list)
		}
		if c.Expect {
			pos++
			if !strings.HasPrefix(list, `[{"NewValue":"False"}`) || !strings.Contains(list, `"Scope:Mail.Read"`) {
				t.Errorf("positive list %s", list)
			}
		} else {
			neg++
		}
	}
	if pos == 0 || neg == 0 {
		t.Errorf("%d positive and %d negative structured cases", pos, neg)
	}
}

// TestEvalMultivalue checks a comparison with a field of several values
// holds when any of them matches, as in Splunk.
func TestEvalMultivalue(t *testing.T) {
	cmp := &Cmp{Field: "role", Values: []string{"Global Administrator"}}
	doc := map[string]any{"role": []any{"62e90394", "Global Administrator"}}
	if !Eval(cmp, View(doc)) {
		t.Errorf("the second value does not match: %q", View(doc))
	}
	doc["role"] = []any{"62e90394", "Reader"}
	if Eval(cmp, View(doc)) {
		t.Error("no value matches, but the comparison holds")
	}
	if cmp.Neg = true; !Eval(cmp, View(doc)) {
		t.Error("no value matches, but != does not hold")
	}
}
