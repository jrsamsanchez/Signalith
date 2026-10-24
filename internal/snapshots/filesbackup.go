// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package snapshots

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
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

// WriteFilesBackup records r in stateDir through a temporary file renamed
// into place. own, when set, gives the temporary file to the server's
// account first (signalith backup may run as root).
func WriteFilesBackup(stateDir string, r FilesBackup, own func(path string)) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, "."+FilesBackupName+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if own != nil {
		own(tmp.Name())
	}
	return os.Rename(tmp.Name(), filepath.Join(stateDir, FilesBackupName))
}
