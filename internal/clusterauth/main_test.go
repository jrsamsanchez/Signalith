// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterauth

import (
	"os"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// TestMain makes password hashes cheap: internal/users checks the
// production cost.
func TestMain(m *testing.M) {
	users.UseFastHashesInTests()
	os.Exit(m.Run())
}
