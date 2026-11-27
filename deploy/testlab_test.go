// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The public test lab's setup script (deploy/testlab) builds a server
// anyone can reach, so it is checked here: it parses, shellcheck finds
// nothing, and the controls its security review asked for are still in it.
func TestTestLabSetupScript(t *testing.T) {
	const path = "testlab/testlab-setup.sh"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := lf(b)

	if runtime.GOOS != "windows" {
		if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", path, err, out)
		}
		if _, err := exec.LookPath("shellcheck"); err == nil {
			// Warnings and errors only: info notes such as SC2012 are not
			// defects.
			if out, err := exec.Command("shellcheck", "-s", "bash", "-S", "warning", path).CombinedOutput(); err != nil {
				t.Errorf("shellcheck %s: %v\n%s", path, err, out)
			}
		}
	}

	for _, want := range []string{
		// Caddy's admin API off: nothing on the server can rewrite its rules.
		"\tadmin off\n",
		// No single sign-on on the lab, so its links are closed with the
		// token routes.
		"/api/auth/oidc/* /api/auth/saml/*",
		"/api/ingest* ",
		"header_up X-Forwarded-For {remote_host}",
		"header_up Host {host}",
		// OpenSearch's folders closed to the server's other accounts.
		`install -d -m 0750 -o opensearch -g opensearch "$DATA/opensearch" "$DATA/snapshots"`,
		// The CA's key is not left on the server.
		`"$LAB/pki/ca/root-ca-key.pem"`,
		// A host firewall for what comes in.
		"type filter hook input priority 0; policy drop;",
		"IPAddressDeny=any",
		"OnFailure=testlab-backup-failed.service",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("%s no longer has %q", path, want)
		}
	}
	for _, bad := range []string{
		// The web page reloads after an upgrade by this header.
		"-X-Signalith-Version",
		// With the admin API off, Caddy cannot reload.
		"reload-or-restart caddy",
	} {
		if strings.Contains(s, bad) {
			t.Errorf("%s has %q again", path, bad)
		}
	}
}
