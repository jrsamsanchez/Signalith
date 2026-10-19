// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// TestMain gives the tests a master key of their own, in a temporary
// folder, for the secrets saved on the Settings page.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "signalith-test-keys-")
	if err != nil {
		panic(err)
	}
	secrets.SetDefault(secrets.NewKeyring(dir))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
