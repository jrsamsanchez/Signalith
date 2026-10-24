// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// reportKeysImporter copies this server's own case report keys into the
// shared settings, as retired, when it founds or joins a cluster.
func reportKeysImporter(s *reportkeys.Shared, f clustercfg.Files) shared.Importer {
	return reportkeys.Importer(s, reportKeysPath(f))
}

// reportKeysExporter writes the cluster's keys back there for signalith
// cluster export.
func reportKeysExporter(s *reportkeys.Shared, f clustercfg.Files) shared.Exporter {
	return reportkeys.Exporter(s, reportKeysPath(f))
}

func reportKeysPath(f clustercfg.Files) func() string {
	return func() string {
		if f.Config == nil {
			return ""
		}
		dir := f.Config().StateDir()
		if dir == "" {
			return ""
		}
		return filepath.Join(dir, reportkeys.FileName)
	}
}

// reportSigning returns what signs the server's case reports and the list
// of their keys: the cluster key's report key and the shared list on a
// member of a cluster, the master key's and report-keys.json otherwise.
func reportSigning(c *config.Config, rt *shared.Runtime, sh *reportkeys.Shared) (func() (ed25519.PrivateKey, string, error), reportkeys.Registry) {
	clustered := clusteredRuntime(rt)
	reg := &reportkeys.Switch{Clustered: clustered, Shared: sh, File: &reportkeys.File{Path: filepath.Join(c.StateDir(), reportkeys.FileName)}}
	signer := func() (ed25519.PrivateKey, string, error) {
		if clustered() {
			if sh == nil {
				return nil, "", errors.New("the shared settings are not open")
			}
			k := rt.Hub().Keys().Active()
			if k == nil {
				return nil, "", errors.New("this server does not hold the cluster key")
			}
			return k.ReportKey(), reportkeys.FromCluster, nil
		}
		key, err := c.Keyring().ReportKey()
		return key, reportkeys.FromMaster, err
	}
	return signer, reg
}
