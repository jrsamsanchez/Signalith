// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package packs holds the detection packs' test events, for tools that
// send them as an agent would (the load generator's replay). The server
// does not import it, so its binary does not carry them.
package packs

import "embed"

// Tests are every pack's tests/*.json files, by their path from this
// folder (sigmahq/tests/<rule>.json).
//
//go:embed */tests/*.json
var Tests embed.FS
