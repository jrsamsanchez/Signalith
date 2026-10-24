// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"

	"github.com/jrsamsanchez/signalith/internal/snapshots"
)

// BackupStatus says how the scheduled OpenSearch snapshots go;
// *snapshots.Manager is one.
type BackupStatus interface {
	Status(ctx context.Context, fresh bool) *snapshots.Status
}

// backupHealth is the Backups card of the Health page, for admins of the
// server (api/health has it only for them): the scheduled snapshots, and
// the last signalith backup of this server's own files. A late or failing
// snapshot is a red item there.
func (s *Server) backupHealth(ctx context.Context) map[string]any {
	if s.TenantID != "" {
		return nil
	}
	out := map[string]any{}
	if s.Snapshots != nil {
		st := s.Snapshots.Status(ctx, false)
		out["snapshots"] = st
		if a := st.Alert(); a != "" {
			out["alert"] = a
		}
	}
	if r := snapshots.ReadFilesBackup(s.conf().StateDir()); r != nil {
		out["files"] = r
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
