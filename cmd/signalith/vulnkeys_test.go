package main

import (
	"path/filepath"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Scan logins are encrypted with the cluster key when there is one, so
// every server of the cluster opens them, and with the master key when
// there is not.
func TestLoginKeys(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	c := config.Default()
	ck, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	var active *secrets.Key
	k := newLoginKeys(c, func() *secrets.Key { return active })
	alone, err := k.Seal("f", "pw")
	if err != nil || !secrets.IsSealed(alone) {
		t.Fatalf("sealed alone: %q %v", alone, err)
	}
	active = ck.SecretsKey()
	joined, err := k.Seal("f", "pw")
	if err != nil || secrets.KeyID(joined) != ck.SecretsKey().ID() {
		t.Fatalf("sealed in a cluster: %q %v", joined, err)
	}
	for _, v := range []string{alone, joined} {
		if got, err := k.Open("f", v); err != nil || got != "pw" {
			t.Errorf("open %q = %q %v", v, got, err)
		}
		if _, err := k.Open("g", v); err == nil {
			t.Errorf("%q opened as another field", v)
		}
	}
	// Another server of the cluster opens the cluster's value only.
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	other := newLoginKeys(config.Default(), func() *secrets.Key { return ck.SecretsKey() })
	if got, err := other.Open("f", joined); err != nil || got != "pw" {
		t.Errorf("another server: %q %v", got, err)
	}
	if _, err := other.Open("f", alone); err == nil {
		t.Error("another server opened this server's master key value")
	}
}
