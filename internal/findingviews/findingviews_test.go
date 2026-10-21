// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package findingviews

import (
	"context"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestValidate(t *testing.T) {
	got, err := Validate([]View{{ID: "my-crit", Name: "  My critical ", Query: "urgency=critical&owner=__me"}})
	if err != nil || got[0].Name != "My critical" || got[0].Query != "owner=__me&urgency=critical" {
		t.Fatalf("%+v %v", got, err)
	}
	many := make([]View, MaxViews+1)
	for _, c := range []struct {
		vs   []View
		want string
	}{
		{many, "at most"},
		{[]View{{ID: "A B", Name: "x"}}, "ID"},
		{[]View{{ID: "a", Name: "x"}, {ID: "a", Name: "y"}}, "same ID"},
		{[]View{{ID: "a", Name: ""}}, "name"},
		{[]View{{ID: "a", Name: strings.Repeat("n", MaxName+1)}}, "name"},
		{[]View{{ID: "a", Name: "bad\nname"}}, "name"},
		{[]View{{ID: "a", Name: "x"}, {ID: "b", Name: "X"}}, "already"},
		{[]View{{ID: "a", Name: "x", Query: "password=1"}}, "not a queue filter"},
		{[]View{{ID: "a", Name: "x", Query: "q=1&q=2"}}, "not a queue filter"},
		{[]View{{ID: "a", Name: "x", Query: "q=%zz"}}, "cannot be read"},
		{[]View{{ID: "a", Name: "x", Query: strings.Repeat("q", MaxQuery+1)}}, "too long"},
	} {
		if _, err := Validate(c.vs); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.vs, err, c.want)
		}
	}
}

func TestOpenSearch(t *testing.T) {
	fake := ostest.New(t)
	o := &OpenSearch{Docs: store.New(store.Config{URL: fake.URL}), Prefix: "fv"}
	ctx := context.Background()
	if got, err := o.Get(ctx, "ana@acme"); err != nil || len(got) != 0 {
		t.Fatalf("Get before any view = %+v, %v", got, err)
	}
	if err := o.Put(ctx, "Ana@Acme", []View{{ID: "a", Name: "Mine", Query: "owner=__me"}}); err != nil {
		t.Fatal(err)
	}
	if err := o.Put(ctx, "ana@acme", []View{{ID: "b", Name: "Unowned", Query: "owner=__none"}, {ID: "a", Name: "Mine", Query: "owner=__me"}}); err != nil {
		t.Fatal(err)
	}
	got, err := o.Get(ctx, "ana@acme")
	if err != nil || len(got) != 2 || got[0].ID != "b" || got[1].Query != "owner=__me" {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if src := fake.Source("fv_runtime", "findingviews:ana@acme"); src["kind"] != kind || src["user"] != "ana@acme" {
		t.Errorf("stored document = %v", src)
	}
	if got, _ := o.Get(ctx, "ana"); len(got) != 0 {
		t.Errorf("another user's Get = %+v", got)
	}
}

func TestMemory(t *testing.T) {
	var m Memory
	ctx := context.Background()
	if err := m.Put(ctx, "Bo", []View{{ID: "a", Name: "x"}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Get(ctx, "bo"); len(got) != 1 {
		t.Errorf("Get = %+v", got)
	}
}
