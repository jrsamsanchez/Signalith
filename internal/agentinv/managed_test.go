// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentinv

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A Signalith Agent's status and its Fluent Bit's batches share the
// computer's row: the status does not wipe what the batches say (its
// tag, configuration, CA), the batches do not wipe the status. Across
// servers the newest status wins, and a computer the agent runs is silent
// after SensorSilentAfter.
func TestManagedStatusSharesTheRow(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	n1, n2 := newInv(c, "n1", clk, pinA), newInv(c, "n2", clk, pinA)
	ctx := context.Background()

	batch := Contact{Name: "web-01", Address: "192.0.2.30", Tag: "linux.auth", Intake: "agent", TLS: true, TokenID: "tok1", TokenName: "line 1", Events: 10}
	n1.Note(batch)
	st := &agentproto.Status{Version: "0.4.0", OS: "linux", Components: []agentproto.Component{{Name: "fluentbit", State: agentproto.StateRunning}}}
	n1.Note(Contact{Name: "web-01", Address: "192.0.2.30", Intake: "agent", TLS: true, TokenID: "tok1", Managed: st})
	a := list(t, n1)
	if len(a) != 1 || a[0].Managed == nil || a[0].Managed.Version != "0.4.0" || a[0].Tag != "linux.auth" || a[0].Managed.Token != "tok1" {
		t.Fatalf("after status: %+v", a)
	}
	clk.add(time.Minute)
	n1.Note(batch)
	if a := list(t, n1); a[0].Managed == nil {
		t.Errorf("a batch wiped the status: %+v", a[0])
	}

	// A newer status on n2.
	clk.add(time.Minute)
	newer := &agentproto.Status{Version: "0.4.1", OS: "linux", Components: []agentproto.Component{{Name: "fluentbit", State: agentproto.StateFailed}}}
	n2.Note(Contact{Name: "web-01", Address: "192.0.2.30", Intake: "agent", TLS: true, TokenID: "tok1", Managed: newer})
	n1.FlushNow(ctx)
	n2.FlushNow(ctx)
	a = list(t, newInv(c, "n3", clk, pinA))
	if len(a) != 1 || a[0].Managed == nil || a[0].Managed.Version != "0.4.1" {
		t.Fatalf("merged: %+v", a)
	}
	if !Silent(a[0], clk.now().Add(SensorSilentAfter+time.Second)) {
		t.Error("a computer the agent runs is silent after SensorSilentAfter")
	}
	if Silent(a[0], clk.now().Add(SensorSilentAfter-time.Second)) {
		t.Error("silent too soon")
	}
}
