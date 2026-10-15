package main

import (
	"testing"

	"github.com/jrsamsanchez/signalith/internal/retention"
)

func TestJobsBusy(t *testing.T) {
	if got := jobsBusy(nil)(); got != "" {
		t.Errorf("no retention: %q", got)
	}
	if got := jobsBusy(&retention.Manager{})(); got != "" {
		t.Errorf("idle retention: %q", got)
	}
}
