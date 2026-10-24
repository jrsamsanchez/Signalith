// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux

package main

import (
	"errors"
	"io"

	"github.com/jrsamsanchez/signalith/internal/oslocal"
)

func newLocalOpenSearch() (localOpenSearch, error) {
	return nil, errors.New("the opensearch command is for Windows and Linux; here, install OpenSearch from its own packages (docs/install-packages.md)")
}

func afterOpenSearchInstall(io.Writer, oslocal.Layout) error { return nil }
