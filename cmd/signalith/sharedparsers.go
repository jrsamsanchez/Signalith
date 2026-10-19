// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/clusterparsers"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/onboard"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// parsersImporter moves the custom parsers from this server's state
// folder into the shared settings when it founds or joins a cluster.
func parsersImporter(p *clusterparsers.Parsers, f clustercfg.Files) shared.Importer {
	return clusterparsers.Importer(p, parsersPath(f))
}

// parsersExporter writes them back there for signalith cluster export.
func parsersExporter(p *clusterparsers.Parsers, f clustercfg.Files) shared.Exporter {
	return clusterparsers.Exporter(p, parsersPath(f))
}

// parsersPath is where this server keeps its own custom parsers.
func parsersPath(f clustercfg.Files) func() string {
	return func() string {
		if f.Config == nil {
			return ""
		}
		return parsersFile(f.Config())
	}
}

func parsersFile(c *config.Config) string {
	if c == nil || c.StateDir() == "" {
		return ""
	}
	return filepath.Join(c.StateDir(), onboard.File)
}

// parsersRegistry runs the custom parsers on what arrives: the shared
// ones while this server takes its content from the shared settings, so
// every server parses alike, else its own file's.
func (r *runner) parsersRegistry(c *config.Config, sharedOn bool) *onboard.Registry {
	if sharedOn && r.shared != nil && r.sharedContent != nil {
		return onboard.NewRegistry(r.sharedContent.parsers)
	}
	return onboard.NewRegistry(onboard.NewFileStore(parsersFile(c)))
}
