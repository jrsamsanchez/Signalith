// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentproto

import "testing"

// TestSecretPath: paths that hold secrets, or could name one other than
// as written, count as secret (ASI-03).
func TestSecretPath(t *testing.T) {
	for _, c := range []struct {
		p, goos string
		want    bool
	}{
		{"/var/log/syslog", "linux", false},
		{"/var/log/*.log", "linux", false},
		{"/etc/shadow", "linux", true},
		{"/etc/signalith-agent/token", "linux", true},
		{"/var/log/../../etc/shadow", "linux", true},
		{"etc/shadow", "linux", true},
		{"~/.ssh/id_rsa", "linux", true},
		{"/home/x/.kdbx/a.kdbx", "linux", true},
		{`C:\Logs\app.log`, "windows", false},
		{`C:\ProgramData\Signalith Agent\token`, "windows", true},
		{`C:\PROGRA~3\Signalith Agent\token`, "windows", true},
		{`C:\WINDOWS\SYSTEM~1\config\SAM`, "windows", true},
		{`C:\x.log:stream`, "windows", true},
		{`\\server\share\x.log`, "windows", true},
	} {
		if got := SecretPath(c.p, c.goos); got != c.want {
			t.Errorf("SecretPath(%q, %s) = %v", c.p, c.goos, got)
		}
	}
}
