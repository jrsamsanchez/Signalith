package clusterpki

import (
	"context"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// A key rotation seals the certificate authority's key again: once the
// old cluster key is retired, the new one alone opens it.
func TestResealerAfterKeyRotation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.server("a", true)
	if err := o.Resealer()(ctx); err != nil {
		t.Fatalf("with no certificate authority kept: %v", err)
	}
	ca := newCA(t)
	if err := o.Import(ctx, "admin", "a", ca.CertPEM(), ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	h, _, _ := o.parts()
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	// The rotation's switch: the new key signs, the old one still opens.
	h.SetKeys(shared.NewKeySet(k2, e.key))
	if err := o.Resealer()(ctx); err != nil {
		t.Fatal(err)
	}
	// The old key retired.
	h.SetKeys(shared.NewKeySet(k2))
	if err := h.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := o.Opens(); err != nil {
		t.Fatalf("after the rotation: %v", err)
	}
	b, _ := o.Get()
	before := b.CAKey
	if err := o.Resealer()(ctx); err != nil {
		t.Fatal(err)
	}
	if b, _ := o.Get(); b.CAKey != before {
		t.Error("a key already sealed with the active cluster key was sealed again")
	}
	if (*OSCA)(nil).Resealer()(ctx) != nil {
		t.Error("a nil holder failed")
	}
}
