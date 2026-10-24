// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package snapshots

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// FilesBackupName is the file in the state folder where signalith backup
// records the last backup of this server's own files. A backup leaves it
// out, so a restore does not bring back an older record.
const FilesBackupName = "last-backup.json"

// FilesBackup is what signalith backup records about the last backup it
// made of this server's files: never the backup itself, nor where its
// master key went.
type FilesBackup struct {
	At      time.Time `json:"at"`
	File    string    `json:"file"`
	Files   int       `json:"files"`
	Archive bool      `json:"archive,omitempty"`
	Version string    `json:"version,omitempty"`
}

// ReadFilesBackup returns the record in stateDir, or nil when there is
// none (or it cannot be read).
func ReadFilesBackup(stateDir string) *FilesBackup {
	b, err := os.ReadFile(filepath.Join(stateDir, FilesBackupName))
	if err != nil {
		return nil
	}
	var r FilesBackup
	if json.Unmarshal(b, &r) != nil || r.At.IsZero() {
		return nil
	}
	return &r
}

// WriteFilesBackup records r in stateDir: written to a temporary file,
// synced to disk and renamed into place, readable by its owner only.
// Run as root (signalith backup may be), a new record is given the
// state folder's owner, the server's account.
func WriteFilesBackup(stateDir string, r FilesBackup) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	p, err := securefile.PreparePrivate(filepath.Join(stateDir, FilesBackupName), append(b, '\n'))
	if err != nil {
		return err
	}
	return p.Commit()
}
