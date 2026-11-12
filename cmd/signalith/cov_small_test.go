// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// README.txt lists the files outside the export's folders one by one,
// with the platform's command.
func TestExportReadmeLooseFiles(t *testing.T) {
	m := &exportManifest{Server: "siem-a", NodeID: "n_a", Version: "1.6.0", ClusterID: "c1",
		Folders: []manifestFolder{{Path: "state", Dest: "/var/lib/signalith"}},
		Files: []manifestFile{{Name: "users", Path: "state/users.json", Dest: "/var/lib/signalith/users.json"},
			{Name: "tls", Path: "tls/server.pem", Dest: "/etc/signalith/server.pem"}}}
	for platform, want := range map[string]string{
		"linux":   `sudo install -D -o signalith -g signalith -m 0600 "` + filepath.Join("/x", "tls", "server.pem"),
		"windows": `Copy-Item -Path "`,
		"docker":  "-> what your compose file mounts at /etc/signalith/server.pem",
	} {
		got := exportReadme(m, "/x", readmeEnv{platform: platform, state: "/var/lib/signalith"})
		if !strings.Contains(got, "Files outside those folders, one by one:") || !strings.Contains(got, want) {
			t.Errorf("%s: no %q in\n%s", platform, want, got)
		}
	}
	// With no config file named, the commands name none.
	if got := exportReadme(m, "/x", readmeEnv{platform: "linux"}); strings.Contains(got, ` -c "`) {
		t.Errorf("a config file is named:\n%s", got)
	}
}

// signalith opensearch needs a command and a heap it understands, before
// it looks at the system.
func TestOpenSearchCommandArguments(t *testing.T) {
	if _, err := capture(t, func() error { return cmdOpenSearch(nil) }); err == nil || !strings.Contains(err.Error(), "an opensearch command is required") {
		t.Errorf("no command: %v", err)
	}
	if _, err := capture(t, func() error { return cmdOpenSearch([]string{"install", "-heap", "lots"}) }); err == nil {
		t.Error("a heap of lots was taken")
	}
}

// A runner with no shared settings has no cluster key, and an agent port
// that stopped on an error says so.
func TestRunnerWithoutCluster(t *testing.T) {
	var logs bytes.Buffer
	r := &runner{log: slog.New(slog.NewTextHandler(&logs, nil))}
	if r.clusterKey() != nil {
		t.Error("a cluster key without a cluster")
	}
	r.agentServeEnded(&agentServer{bound: "127.0.0.1:1"}, errors.New("accept failed"))
	if !strings.Contains(logs.String(), "the agent port stopped") {
		t.Errorf("log: %s", logs.String())
	}
	logs.Reset()
	r.agentServeEnded(&agentServer{bound: "127.0.0.1:1"}, nil)
	if logs.Len() != 0 {
		t.Errorf("a clean stop was logged: %s", logs.String())
	}
	archiveCrypto(nil, nil, nil)
	if err := recordLegacyArchives(nil, nil); err != nil {
		t.Errorf("no archive: %v", err)
	}
}
