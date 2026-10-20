// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterarchive

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// historyFile is retention_history.json as a server on its own keeps it
// (retention.ReadHistoryFile reads it).
type historyFile struct {
	LastRun *retention.Run     `json:"last_run,omitempty"`
	Actions []retention.Action `json:"actions"`
}

// HistoryExporter is the exporter of the retention history (signalith
// cluster export --to-files), the inverse of the importer named
// shared.ImportRetentionHistory: the last run and the latest
// retention.MaxActions actions of every server, from the audit records,
// written as the history file a server on its own keeps (historyFile,
// this server's path for it). The archive manifests have no exporter:
// they are files in the archive folder already.
func HistoryExporter(client func() (Client, string), historyFile string) shared.Exporter {
	return shared.Exporter{Name: shared.ImportRetentionHistory, Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
		cl, prefix := client()
		run, acts, err := (&History{Client: cl, Prefix: prefix}).Recent(ctx)
		if err != nil {
			return nil, err
		}
		if run == nil && len(acts) == 0 {
			return nil, nil
		}
		return writeHistory(t, historyFile, run, acts)
	}}
}

func writeHistory(t shared.ExportTarget, dest string, run *retention.Run, acts []retention.Action) ([]shared.ExportedFile, error) {
	if acts == nil {
		acts = []retention.Action{}
	}
	data, err := json.MarshalIndent(historyFile{LastRun: run, Actions: acts}, "", "  ")
	if err != nil {
		return nil, err
	}
	p := t.Under(dest)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return nil, err
	}
	if err := securefile.WriteFile(p, data); err != nil {
		return nil, err
	}
	return []shared.ExportedFile{{Path: p, Dest: dest}}, nil
}
