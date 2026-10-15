package clustertls

import (
	"context"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Resealer seals the cluster certificate authority's key again with the
// active cluster key, for a key rotation.
func (t *TLS) Resealer() shared.Resealer {
	return func(ctx context.Context) error {
		h, d, err := t.parts()
		if err != nil {
			return nil
		}
		if _, ok := d.Get(); !ok {
			return nil
		}
		_, err = d.Mutate(ctx, "signalith", func(b *Body) error {
			sealed, err := shared.Reseal(h.Keys(), keyField(b.CASHA256), b.CAKey)
			if err != nil {
				return err
			}
			b.CAKey = sealed
			return nil
		})
		return err
	}
}
