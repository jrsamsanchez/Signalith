// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// validate counts what is turned on in the pages' files, and says when
// the server was a member of a cluster.
func TestValidateCountsWhatIsOn(t *testing.T) {
	path, c := validateConfig(t, "http://127.0.0.1:1", "")
	writeTestFile(t, c.NotifyFile(), `channels:
  - id: hook
    name: SOAR
    type: webhook
    url: https://soar.example.test/hook
rules:
  - id: r1
    name: High
    enabled: true
    channels: [hook]
`)
	writeTestFile(t, c.PlaybooksFile(), "playbooks:\n  - id: a\n    name: A\n    enabled: true\n  - id: b\n    name: B\n")
	writeTestFile(t, c.TicketingFile(), "connections:\n  - id: j\n    name: Jira\n    type: jira\n    url: https://example.atlassian.net\n")
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	cache := shared.CachePath(state)
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(cache, []byte("{}"), 0o600)
	out, err := capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"1 notification channels and 1 rules (1 on)",
		"This server is a member of a cluster",
		"2 playbooks (1 on), set on the Playbooks page.",
		"1 ticketing connections (Jira or ServiceNow)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate lacks %q:\n%s", want, out)
		}
	}
}
