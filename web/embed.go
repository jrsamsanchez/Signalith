// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package web embeds the browser UI into the server binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// FS returns the UI files rooted at the static directory.
func FS() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
