// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sourceExts are the files that carry a copyright and SPDX line;
// .github/scripts/add-license-headers.py adds them.
var sourceExts = map[string]bool{".go": true, ".js": true, ".css": true, ".sh": true, ".ps1": true, ".py": true, ".tf": true}

// skipDirs are folders that are not this project's source.
var skipDirs = map[string]bool{".git": true, ".claude": true, "testdata": true, "node_modules": true, "dist": true}

func TestEverySourceFileHasALicenseHeader(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceExts[filepath.Ext(path)] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		head := string(data)
		if len(head) > 2000 {
			head = head[:2000]
		}
		checked++
		if !strings.Contains(head, "SPDX-License-Identifier: Apache-2.0") || !strings.Contains(head, "Copyright") {
			rel, _ := filepath.Rel(root, path)
			missing = append(missing, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 1000 {
		t.Fatalf("checked only %d files; is the repository root %s?", checked, root)
	}
	if len(missing) > 0 {
		t.Errorf("%d source files lack the license header; run python3 .github/scripts/add-license-headers.py:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}
