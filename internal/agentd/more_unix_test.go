// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agentd

import (
	"context"
	"errors"
	"testing"
)

func TestSystemdState(t *testing.T) {
	ctx := context.Background()
	var m map[string]string
	var err error
	svc := SystemdService{Unit: "signalith-agent.service", Show: func(_ context.Context, unit string) (map[string]string, error) {
		if unit != "signalith-agent.service" {
			t.Errorf("unit %q", unit)
		}
		return m, err
	}}
	m = map[string]string{"ActiveState": "active", "NRestarts": "4"}
	if running, run, e := svc.State(ctx); !running || run != "4" || e != nil {
		t.Errorf("active = %v %q %v", running, run, e)
	}
	m = map[string]string{"ActiveState": "failed", "NRestarts": "5"}
	if running, _, e := svc.State(ctx); running || e != nil {
		t.Errorf("failed = %v %v", running, e)
	}
	err = errors.New("no bus")
	if _, _, e := svc.State(ctx); !errors.Is(e, err) {
		t.Errorf("error = %v", e)
	}
	if svc.Stop(ctx) != nil || (LaunchdService{}).Stop(ctx) != nil {
		t.Error("Stop is not a no-op")
	}
	ls := LaunchdService{Label: "io.signalith.agent", Print: func(context.Context, string) (string, error) { return "", errors.New("no such service") }}
	if _, _, e := ls.State(ctx); e == nil {
		t.Error("launchd error dropped")
	}
}
