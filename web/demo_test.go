// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"io/fs"
	"strings"
	"testing"
)

// In demo mode the server shows the demo's banner and its sign-in box by
// replacing these exact attributes (internal/api: configtoken.go and
// login.go), so the pages must carry them just so.
func TestDemoMarkers(t *testing.T) {
	for page, want := range map[string]string{
		"index.html": `id="demo-banner" hidden`,
		"login.html": `id="demo" hidden`,
	} {
		b, err := fs.ReadFile(FS(), page)
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(b), want); n != 1 {
			t.Errorf("%s has %q %d times, want once", page, want, n)
		}
	}
}
