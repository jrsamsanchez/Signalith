// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/jrsamsanchez/signalith/internal/retention"
)

func TestJobsBusy(t *testing.T) {
	if got := jobsBusy(nil, nil)(); got != "" {
		t.Errorf("no retention: %q", got)
	}
	if got := jobsBusy(&retention.Manager{}, nil)(); got != "" {
		t.Errorf("idle retention: %q", got)
	}
}
