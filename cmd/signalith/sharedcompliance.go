// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/clustercomp"
	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// complianceImporter moves the notes on compliance controls from this
// server's state folder into the shared settings when it founds or joins
// a cluster.
func complianceImporter(n *clustercomp.Notes, f clustercfg.Files) shared.Importer {
	return clustercomp.Importer(n, complianceNotesPath(f))
}

// complianceExporter writes them back there for signalith cluster export.
func complianceExporter(n *clustercomp.Notes, f clustercfg.Files) shared.Exporter {
	return clustercomp.Exporter(n, complianceNotesPath(f))
}

// complianceNotesPath is where this server keeps its own notes.
func complianceNotesPath(f clustercfg.Files) func() string {
	return func() string {
		if f.Config == nil {
			return ""
		}
		dir := f.Config().StateDir()
		if dir == "" {
			return ""
		}
		return filepath.Join(dir, compliance.NotesFile)
	}
}
