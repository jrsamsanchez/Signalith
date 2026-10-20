// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agentd

import (
	"context"
	"testing"
)

func TestLaunchdState(t *testing.T) {
	out := "system/io.signalith.agent = {\n\tactive count = 1\n\tpath = /Library/LaunchDaemons/io.signalith.agent.plist\n\tstate = running\n\n" +
		"\tprogram = /opt/signalith-agent/bin/signalith-agent\n\tendpoints = {\n\t\tstate = waiting\n\t\tpid = 9\n\t}\n\tpid = 412\n}\n"
	svc := LaunchdService{Label: "io.signalith.agent", Print: func(_ context.Context, target string) (string, error) {
		if target != "system/io.signalith.agent" {
			t.Errorf("target %q", target)
		}
		return out, nil
	}}
	running, run, err := svc.State(context.Background())
	if err != nil || !running || run != "412" {
		t.Errorf("state: %v %q %v", running, run, err)
	}
	out = "system/io.signalith.agent = {\n\tstate = not running\n\tlast exit code = 1\n}\n"
	if running, _, err := svc.State(context.Background()); err != nil || running {
		t.Errorf("stopped: %v %v", running, err)
	}
	out = "nothing"
	if _, _, err := svc.State(context.Background()); err == nil {
		t.Error("no state, no error")
	}
}
