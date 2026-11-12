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

		// Credential files of users and services (ING-217).
		{"/home/alice/.aws/credentials", "linux", true},
		{"/home/*/.aws/credentials", "linux", true},
		{"/home/*/.netrc", "linux", true},
		{"/home/bob/.netrc", "linux", true},
		{"/home/*/.ssh/*", "linux", true},
		{"/home/*/.kube/config", "linux", true},
		{"/home/bob/.bash_history", "linux", true},
		{"/etc/krb5.keytab", "linux", true},
		{"/etc/wireguard/wg0.conf", "linux", true},
		{"/etc/wireguard/*.conf", "linux", true},
		{"/etc/kubernetes/admin.conf", "linux", true},
		{"/etc/letsencrypt/live/*/privkey.pem", "linux", true},
		{"/etc/sssd/sssd.conf", "linux", true},
		{"/var/lib/samba/private/secrets.tdb", "linux", true},
		{"/etc/mysql/debian.cnf", "linux", true},
		{"/etc/openvpn/*", "linux", true},
		{"/srv/vpn/client.ovpn", "linux", true},
		{"/home/app/logs/app.log", "linux", false},
		{"/var/log/openvpn.log", "linux", false},
		{`C:\Users\*\.aws\credentials`, "windows", true},
		{`C:\Users\bob\AppData\Roaming\Microsoft\Credentials\*`, "windows", true},
		{`C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data`, "windows", true},
		{`C:\inetpub\wwwroot\web.config`, "windows", true},
		{`C:\inetpub\logs\LogFiles\W3SVC1\*.log`, "windows", false},
		{`C:\Users\bob\AppData\Local\App\app.log`, "windows", false},
	} {
		if got := SecretPath(c.p, c.goos); got != c.want {
			t.Errorf("SecretPath(%q, %s) = %v", c.p, c.goos, got)
		}
	}
}
