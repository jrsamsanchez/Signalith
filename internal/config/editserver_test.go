// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// An edit of another server's own settings is checked value by value:
// settings of another scope, unknown ones and those its environment sets
// are refused, and the layer passed in is not changed.
func TestEditServer(t *testing.T) {
	sh := &Shared{}
	at := time.Now().Add(-time.Hour)
	res := EditServer(sh, Edit{Values: map[string]any{
		"server.max_connections": float64(500),
		"detections.scheduler":   false,
		"auth.session_timeout":   "8h",
		"no.such.setting":        1,
		"ingest.max_concurrent":  float64(-5),
		"server.listen":          ":8443",
	}, Clear: []string{"server.max_connections"}, By: "ann", At: at},
		map[string]string{"server.listen": "SIGNALITH_LISTEN"})
	if res.Scope != ScopeServer || res.Config != nil {
		t.Fatalf("result %+v", res)
	}
	for key, want := range map[string]string{
		"auth.session_timeout":   "This setting is one of",
		"no.such.setting":        "There is no setting called no.such.setting",
		"ingest.max_concurrent":  "",
		"server.listen":          "SIGNALITH_LISTEN environment variable",
		"server.max_connections": "Only passwords and keys can be cleared",
	} {
		got, ok := res.Fields[key]
		if !ok || !strings.Contains(got, want) {
			t.Errorf("%s: %q", key, got)
		}
	}
	if got := res.Touched; !slices.Equal(got, []string{"cluster.leader_eligible", "server.max_connections"}) {
		t.Errorf("touched %v", got)
	}
	if !slices.Contains(res.Changed, "server.max_connections") {
		t.Errorf("changed %v", res.Changed)
	}
	en := res.Shared.Server["server.max_connections"]
	if en == nil || en.ChangedBy != "ann" || !en.ChangedAt.Equal(at.UTC()) {
		t.Fatalf("entry %+v", en)
	}
	if len(sh.Server) != 0 {
		t.Error("the layer passed in was changed")
	}

	// The same value again touches nothing.
	again := EditServer(res.Shared, Edit{Values: map[string]any{"server.max_connections": float64(500)}, By: "bob"}, nil)
	if len(again.Touched) != 0 || len(again.Fields) != 0 {
		t.Errorf("same value: touched %v, fields %v", again.Touched, again.Fields)
	}

	// A change a restart set aside is used again on Retry; Reset takes a
	// setting off, ResetAll all of them.
	set := res.Shared.Clone()
	set.Server["server.max_connections"].Refused = "it did not start"
	set.Server["server.max_connections"].RefusedAt = at
	retried := EditServer(set, Edit{Retry: []string{"server.max_connections", "no.such.setting"}}, nil)
	if en := retried.Shared.Server["server.max_connections"]; en.Refused != "" || !en.RefusedAt.IsZero() {
		t.Errorf("after Retry %+v", en)
	}
	if retried.Fields["no.such.setting"] == "" {
		t.Error("Retry of an unknown setting was not refused")
	}
	// A value refused is written again even when it is the same.
	same := EditServer(set, Edit{Values: map[string]any{"server.max_connections": float64(500)}}, nil)
	if en := same.Shared.Server["server.max_connections"]; en.Refused != "" {
		t.Errorf("saved again: %+v", en)
	}
	reset := EditServer(res.Shared, Edit{Reset: []string{"server.max_connections"}}, nil)
	if _, ok := reset.Shared.Server["server.max_connections"]; ok || !slices.Contains(reset.Touched, "server.max_connections") {
		t.Errorf("after Reset %v, touched %v", reset.Shared.Server, reset.Touched)
	}
	all := EditServer(res.Shared, Edit{ResetAll: true}, nil)
	if len(all.Shared.Server) != 0 || len(all.Touched) != 2 {
		t.Errorf("after ResetAll %v, touched %v", all.Shared.Server, all.Touched)
	}
}
