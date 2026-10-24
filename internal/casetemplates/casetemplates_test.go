// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package casetemplates

import (
	"context"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cases"
)

func TestBuiltinTemplatesAreValid(t *testing.T) {
	for _, b := range Builtin {
		if !idPattern.MatchString(b.ID) || !b.Builtin || b.Name == "" || len(b.Tasks) == 0 {
			t.Errorf("template %+v", b)
		}
		for _, task := range b.Tasks {
			if _, err := cases.CleanTaskTitle(task); err != nil {
				t.Errorf("%s: %v", b.ID, err)
			}
		}
	}
}

func TestValidateAndFind(t *testing.T) {
	ts, err := Validate([]Template{{ID: "ot", Name: " OT ", Builtin: true, Tasks: []string{" Call the plant "}}})
	if err != nil || ts[0].Name != "OT" || ts[0].Builtin || ts[0].Tasks[0] != "Call the plant" {
		t.Fatalf("%+v %v", ts, err)
	}
	if _, err := Validate([]Template{{ID: "ot", Name: "a"}, {ID: "ot", Name: "b"}}); err == nil {
		t.Error("duplicate IDs accepted")
	}
	m := &Memory{}
	_ = m.Put(context.Background(), ts)
	got, _ := m.Get(context.Background())
	f, ok := Find(got, "ot")
	if !ok || f.Name != "OT" {
		t.Fatalf("find %+v", f)
	}
	// What Find returns is a copy.
	f.Tasks[0] = "changed"
	if again, _ := Find(got, "ot"); again.Tasks[0] != "Call the plant" {
		t.Error("Find shares its tasks")
	}
	if p, ok := Find(nil, "phishing"); !ok || !p.Builtin {
		t.Error("built-in not found")
	}
}
