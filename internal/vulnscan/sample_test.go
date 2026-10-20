// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
)

// The sample data's scan results stay when the networks are saved, and no
// network can take their ID.
func TestSampleTargetIsTheSampleDatas(t *testing.T) {
	ctx := context.Background()
	st := NewStore(endpoint.NewMemoryDocs(), "signalith")
	for _, target := range []string{SampleTarget, "office"} {
		h := &Host{ID: HostID(target, "10.0.0.5"), TargetID: target, Address: "10.0.0.5"}
		if err := st.SaveHosts(ctx, target, []*Host{h}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.DropHosts(ctx, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	hosts, err := st.Hosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].TargetID != SampleTarget {
		t.Errorf("hosts after dropping every network: %+v", hosts)
	}

	tg := target("10.0.0.0/24")
	if err := tg.Validate(); err != nil {
		t.Fatalf("a plain network: %v", err)
	}
	tg = target("10.0.0.0/24")
	tg.ID = SampleTarget
	if err := tg.Validate(); err == nil {
		t.Error("a network with the sample data's ID was accepted")
	}
}
