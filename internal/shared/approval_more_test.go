// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Without a cluster document, or with one the key does not sign, a key
// does not verify the cluster, and the cluster has no name to show.
func TestVerifiesClusterForms(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := e.server("siem-a", nil)
	k, _ := NewClusterKey()
	if err := s.rt.verifiesCluster(ctx, k); err == nil || !strings.Contains(err.Error(), "not there") {
		t.Errorf("no cluster document = %v", err)
	}
	if name, ok := s.rt.peekClusterName(ctx); ok {
		t.Errorf("a name without a cluster document: %q", name)
	}
	e.os.Put(ConfigIndex(testPrefix), ClusterDocID, map[string]any{"kind": "cluster", "id": ClusterDocID, "body": "not json"})
	if err := s.rt.verifiesCluster(ctx, k); !errors.Is(err, errNotThisCluster) {
		t.Errorf("an unsigned cluster document = %v", err)
	}
	if name, ok := s.rt.peekClusterName(ctx); ok {
		t.Errorf("a name from a damaged cluster document: %q", name)
	}
	if got := cmpOr("", "b"); got != "b" {
		t.Errorf("cmpOr = %q", got)
	}
}

// A runtime not pointed at OpenSearch lists no approvals or waiting
// servers.
func TestApprovalListsWithoutOpenSearch(t *testing.T) {
	rt := NewRuntime(RuntimeOptions{StateDir: t.TempDir(), Self: Self{NodeID: "n_x", Name: "x"}})
	ctx := context.Background()
	if _, err := rt.Approved(ctx); err == nil {
		t.Error("Approved without OpenSearch")
	}
	if _, err := rt.Pending(ctx); err == nil {
		t.Error("Pending without OpenSearch")
	}
	e := newEnv(t)
	s := e.server("siem-a", nil)
	if got, err := s.rt.Approved(ctx); err != nil || len(got) != 0 {
		t.Errorf("Approved = %v %v", got, err)
	}
	if got, err := s.rt.Pending(ctx); err != nil || len(got) != 0 {
		t.Errorf("Pending = %v %v", got, err)
	}
}
