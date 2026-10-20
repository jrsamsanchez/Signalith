// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"os"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// TestMain gives the tests a master key of their own, in a temporary
// folder, for the files that keep passwords and keys encrypted. It also
// makes password hashes cheap: these tests create hundreds of users, and
// at bcrypt's production cost the package runs past CI's 30 minute race
// timeout. internal/users tests the production cost.
func TestMain(m *testing.M) {
	users.UseFastHashesInTests()
	dir, err := os.MkdirTemp("", "signalith-test-keys-")
	if err != nil {
		panic(err)
	}
	secrets.SetDefault(secrets.NewKeyring(dir))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
