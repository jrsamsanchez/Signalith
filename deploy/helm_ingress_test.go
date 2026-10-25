// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os/exec"
	"runtime"
	"testing"
)

// The Helm chart's Ingress (ingress.*) is off by default and carries the
// web port only, over HTTPS; agents get a Service of their own
// (server.agentService.*). helm/ci/ingress.sh renders the chart to check;
// it needs helm and a POSIX shell, and is skipped without them.
func TestHelmIngress(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	out, err := exec.Command("sh", "helm/ci/ingress.sh", "helm/signalith").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Logf("%s", out)
}
