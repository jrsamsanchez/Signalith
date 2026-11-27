// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A document signed for its place but naming another id, or without a
// format, is tampered with; a document that is not one at all too.
func TestHubOpenRefusals(t *testing.T) {
	e := newEnv(t)
	put := func(id string, env *Envelope) {
		t.Helper()
		if err := Sign(e.key, id, env); err != nil {
			t.Fatal(err)
		}
		e.os.Put(testIndex, id, sourceOf(t, env, nil))
	}
	at := "2026-10-12T09:00:00Z"
	put("users", &Envelope{Kind: "users", ID: "other", Format: 1, Rev: 1, UpdatedAt: at, Body: `{"name":"x"}`})
	put("groups", &Envelope{Kind: "groups", ID: "groups", Format: 0, Rev: 1, UpdatedAt: at, Body: `{"name":"x"}`})
	h, _ := e.hub("siem-a")
	users := NewDoc[testBody](h, "users", "users", 1)
	groups := NewDoc[testBody](h, "groups", "groups", 1)
	cycle(t, h)
	reasons := map[string]string{}
	for _, p := range h.Problems() {
		reasons[p.ID] = p.Reason
	}
	if !strings.Contains(reasons["users"], "it holds the id other") {
		t.Errorf("users problem = %q", reasons["users"])
	}
	if !strings.Contains(reasons["groups"], "it has no format") {
		t.Errorf("groups problem = %q", reasons["groups"])
	}
	if _, ok := users.Get(); ok {
		t.Error("a document naming another id was used")
	}
	if _, ok := groups.Get(); ok {
		t.Error("a document without a format was used")
	}

	// A server without the cluster key reads nothing as good.
	nokey := NewHub(Options{NodeName: "siem-z", Clock: e.clock})
	nokey.Use(e.c, testPrefix)
	if _, p := nokey.open("users", "users", 1, json.RawMessage(`{}`)); p == nil || p.Kind != ProblemKeyMissing {
		t.Errorf("open without a key = %+v", p)
	}
	if _, p := h.open("users", "users", 1, json.RawMessage(`[`)); p == nil || p.Kind != ProblemTamper {
		t.Errorf("open of broken JSON = %+v", p)
	}
	// A hub not pointed at OpenSearch cannot cycle.
	none := NewHub(Options{NodeName: "siem-y", Clock: e.clock})
	if err := none.Cycle(context.Background()); err == nil {
		t.Error("Cycle without OpenSearch")
	}
}

func TestRequestRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	r := NewRequests(a, "n_a")
	if _, err := r.Submit(ctx, "test", TargetLeader, func() {}, "sam"); err == nil {
		t.Error("a request with arguments that are not JSON")
	}
	if _, err := r.Submit(ctx, "test", TargetLeader, nil, "s\x00m"); err == nil || !strings.Contains(err.Error(), "zero byte") {
		t.Errorf("a request by a name with a zero byte = %v", err)
	}
	nokey := NewHub(Options{NodeName: "siem-z", Clock: e.clock})
	nokey.Use(e.c, testPrefix)
	if _, err := NewRequests(nokey, "n_z").Submit(ctx, "test", TargetLeader, nil, "sam"); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("a request without a key = %v", err)
	}
	// A stored request that is not one is damaged.
	if _, err := e.c.Create(ctx, r.index(), requestDocID("rq_bad"), map[string]any{"targets": "not a list"}, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Get(ctx, "rq_bad"); err == nil || !strings.Contains(err.Error(), "is damaged") {
		t.Errorf("Get of a damaged request = %v", err)
	}
	if _, found, err := r.Get(ctx, "rq_none"); found || err != nil {
		t.Errorf("Get of no request = %v %v", found, err)
	}
	// Arguments are covered as decoded: a request with broken ones
	// cannot be signed.
	if _, err := requestText(&Request{Args: json.RawMessage(`{`)}); err == nil {
		t.Error("requestText of broken arguments")
	}
	req := &Request{}
	if err := req.SetResult(func() {}); err == nil {
		t.Error("SetResult of a func")
	}
}
