// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os/exec"
	"runtime"
	"testing"
)

// The Helm chart takes syslog over TLS only on a new install, and plain
// syslog over UDP and TCP only with server.syslog.plain (or, on an upgrade,
// when the release had it: see signalith.plainSyslog in _helpers.tpl).
// helm/ci/syslog-plain.sh renders the chart to check; it needs helm and a
// POSIX shell, and is skipped without them.
func TestHelmPlainSyslog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	out, err := exec.Command("sh", "helm/ci/syslog-plain.sh", "helm/signalith").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Logf("%s", out)
}
