// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterlib

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// exportTo returns an export target that writes under root what a
// server keeps under base.
func exportTo(t *testing.T, base, root string) shared.ExportTarget {
	t.Helper()
	return shared.ExportTarget{Under: func(p string) string {
		rel, err := filepath.Rel(base, p)
		if err != nil || !filepath.IsLocal(rel) {
			t.Fatalf("%s is not under %s", p, base)
		}
		return filepath.Join(root, rel)
	}}
}

// sameText compares two texts whatever their line ends.
func sameText(a, b []byte) bool {
	return bytes.Equal(bytes.ReplaceAll(a, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
}

func TestExportIsTheInverseOfImport(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	id, on := builtinID(t)
	files := map[string][]byte{
		filepath.Join(a.detDir, "my-rule.yaml"):              encodeDet(t, custom("my-rule", "Mine")),
		filepath.Join(a.detDir, detect.StateDir, id+".yaml"): []byte("enabled: " + map[bool]string{true: "false", false: "true"}[on] + "\n"),
		filepath.Join(a.dbDir, "ops.yaml"):                   encodeBoard(t, board("ops", "Ops")),
		filepath.Join(a.lkDir, assets.AssetsFile):            assetsCSV("web1"),
		filepath.Join(a.lkDir, assets.IdentitiesFile):        []byte("identity\nbob\n"),
	}
	for p, data := range files {
		writeFile(t, p, data)
	}
	runImporter(t, a, "detections")
	runImporter(t, a, "dashboards")
	for _, im := range LookupImporters(a.docs, a.files()) {
		if err := im.Run(ctx, "signalith"); err != nil {
			t.Fatal(err)
		}
	}

	root := t.TempDir()
	target := exportTo(t, a.state, root)
	var written []shared.ExportedFile
	for _, ex := range Exporters(a.docs, a.files()) {
		list, err := ex.Run(ctx, target)
		if err != nil {
			t.Fatalf("%s: %v", ex.Name, err)
		}
		written = append(written, list...)
	}
	if len(written) != len(files) {
		t.Fatalf("%d files written, want %d: %+v", len(written), len(files), written)
	}
	for _, f := range written {
		want, ok := files[f.Dest]
		if !ok {
			t.Fatalf("an unexpected file %s", f.Dest)
		}
		got, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(f.Dest, string(filepath.Separator)+detect.StateDir+string(filepath.Separator)) {
			// The state is written as detect.EncodeState writes it.
			st, err := decodeStateFile(id, got)
			if err != nil || st == nil || st.Enabled == nil || *st.Enabled == on {
				t.Fatalf("the state written: %v %+v", err, st)
			}
			continue
		}
		if !sameText(got, want) {
			t.Errorf("%s:\n%s\nwant\n%s", f.Dest, got, want)
		}
	}

	// Imported again by a new cluster, from the files written, the
	// library is the same.
	o2 := newOS(t)
	b := newServer(t, o2, "siem-b", nil)
	b.detDir, b.dbDir, b.lkDir = filepath.Join(root, "detections"), filepath.Join(root, "dashboards"), filepath.Join(root, "lookups")
	runImporter(t, b, "detections")
	runImporter(t, b, "dashboards")
	for _, im := range LookupImporters(b.docs, b.files()) {
		if err := im.Run(ctx, "signalith"); err != nil {
			t.Fatal(err)
		}
	}
	for _, it := range a.docs.Detections().List() {
		v, _, ok := b.docs.Detections().Get(it.Name)
		if !ok || v.YAML != it.Value.YAML || (v.State == nil) != (it.Value.State == nil) {
			t.Errorf("detection %s: %+v, want %+v", it.Name, v, it.Value)
		}
	}
	if n, m := len(b.docs.Dashboards().List()), len(a.docs.Dashboards().List()); n != m || n != 1 {
		t.Errorf("%d dashboards, want %d", n, m)
	}
	for _, kind := range LookupNames {
		ha, hb := a.lk.Head(kind), b.lk.Head(kind)
		if ha == nil || hb == nil || ha.SHA256 != hb.SHA256 {
			t.Errorf("list %s: %+v, want %+v", kind, hb, ha)
		}
	}
}
