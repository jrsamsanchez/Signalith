// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterlib

import (
	"context"
	"os"
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Exporters return the exporters of the library (signalith cluster
// export --to-files), the inverse of Importers and LookupImporters: the
// custom detections and the state chosen for shipped ones, one YAML file
// each in the detections folder and its state folder; the custom
// dashboards, one YAML file each; and the asset and identity lists of the
// lookups folder. The files are what the folders of a server on its own
// hold, as the inbox writes them back.
func Exporters(d *Docs, f Files) []shared.Exporter {
	return []shared.Exporter{
		{Name: shared.ImportDetections, Run: func(_ context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
			return exportDetections(d, f, t)
		}},
		{Name: shared.ImportDashboards, Run: func(_ context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
			return exportDashboards(d, f, t)
		}},
		{Name: shared.ImportLookups, Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
			return exportLookups(ctx, d, f, t)
		}},
	}
}

// writeExport writes data as the file this server keeps at dest, in the
// export, and lists it in out.
func writeExport(t shared.ExportTarget, dest string, data []byte, out []shared.ExportedFile) ([]shared.ExportedFile, error) {
	p := t.Under(dest)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return out, err
	}
	if err := writeFileAtomic(p, data); err != nil {
		return out, err
	}
	return append(out, shared.ExportedFile{Path: p, Dest: dest}), nil
}

func exportDetections(d *Docs, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	dir := dirOf(f.DetectionsDir)
	if dir == "" {
		return nil, nil
	}
	var out []shared.ExportedFile
	for _, it := range d.Detections().List() {
		if it.Value == nil {
			continue
		}
		det, st, err := it.Value.decode(it.Name)
		if err != nil {
			t.Logger().Warn("a shared detection cannot be read, so it is left out", "detection", it.Name, "err", err)
			continue
		}
		if det != nil {
			if out, err = writeExport(t, filepath.Join(dir, it.Name+".yaml"), []byte(it.Value.YAML), out); err != nil {
				return out, err
			}
		}
		if st != nil {
			data, err := detect.EncodeState(st)
			if err != nil {
				return out, err
			}
			if out, err = writeExport(t, filepath.Join(dir, detect.StateDir, it.Name+".yaml"), data, out); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func exportDashboards(d *Docs, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	dir := dirOf(f.DashboardsDir)
	if dir == "" {
		return nil, nil
	}
	var out []shared.ExportedFile
	for _, it := range d.Dashboards().List() {
		if it.Value == nil {
			continue
		}
		if _, err := it.Value.decode(it.Name); err != nil {
			t.Logger().Warn("a shared dashboard cannot be read, so it is left out", "dashboard", it.Name, "err", err)
			continue
		}
		var err error
		if out, err = writeExport(t, filepath.Join(dir, it.Name+".yaml"), []byte(it.Value.YAML), out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func exportLookups(ctx context.Context, d *Docs, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	dir := dirOf(f.LookupsDir)
	if dir == "" {
		return nil, nil
	}
	b := &Lookups{Docs: d, Node: f.Node}
	var out []shared.ExportedFile
	for _, kind := range LookupNames {
		data, h, err := b.Read(ctx, kind)
		if err != nil {
			return out, err
		}
		if h == nil {
			continue
		}
		if out, err = writeExport(t, listFile(dir, kind), data, out); err != nil {
			return out, err
		}
	}
	return out, nil
}
