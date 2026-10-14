package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
)

// The job holder adds new fields and the replicas setting to each index
// that is there; one step failing does not stop the others.
func TestUpgradeIndices(t *testing.T) {
	var ran []string
	step := func(name string, err error) func(context.Context) error {
		return func(context.Context) error { ran = append(ran, name); return err }
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	list := []indexUpgrade{
		{true, "findings", step("findings fields", errors.New("blocked")), step("findings replicas", nil)},
		{false, "cases", step("cases fields", nil), step("cases replicas", nil)},
		{true, "notify", nil, step("notify replicas", nil)},
	}
	upgradeIndices(context.Background(), log, func() bool { return true }, list)
	if want := []string{"findings fields", "findings replicas", "notify replicas"}; !reflect.DeepEqual(ran, want) {
		t.Errorf("ran %v, want %v", ran, want)
	}
	ran = nil
	upgradeIndices(context.Background(), log, func() bool { return false }, list)
	if len(ran) != 0 {
		t.Errorf("a server that does not run the jobs ran %v", ran)
	}
}
