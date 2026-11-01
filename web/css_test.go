// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"io/fs"
	"strings"
	"testing"
)

// TestStylesheetBracesBalance checks that every block in the stylesheets
// is closed: a media query left open swallows every rule after it, which
// then applies only at that screen width.
func TestStylesheetBracesBalance(t *testing.T) {
	err := fs.WalkDir(FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".css") {
			return err
		}
		b, err := fs.ReadFile(FS(), path)
		if err != nil {
			return err
		}
		depth, line, opened := 0, 1, []int{}
		s := string(b)
		for i := 0; i < len(s); i++ {
			switch c := s[i]; {
			case c == '\n':
				line++
			case c == '/' && i+1 < len(s) && s[i+1] == '*':
				end := strings.Index(s[i+2:], "*/")
				if end < 0 {
					t.Errorf("%s:%d: comment never closed", path, line)
					return nil
				}
				line += strings.Count(s[i:i+2+end+2], "\n")
				i += 2 + end + 1
			case c == '"' || c == '\'':
				end := strings.IndexByte(s[i+1:], c)
				if end < 0 {
					t.Errorf("%s:%d: string never closed", path, line)
					return nil
				}
				i += end + 1
			case c == '{':
				depth++
				opened = append(opened, line)
			case c == '}':
				depth--
				if depth < 0 {
					t.Errorf("%s:%d: } closes nothing", path, line)
					return nil
				}
				opened = opened[:len(opened)-1]
			}
		}
		if depth != 0 {
			t.Errorf("%s: the block opened on line %d is never closed", path, opened[0])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
