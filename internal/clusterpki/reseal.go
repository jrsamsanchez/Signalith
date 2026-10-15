package clusterpki

import (
	"context"
	"errors"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Resealer seals OpenSearch's certificate authority key again with the
// active cluster key, for a key rotation.
func (o *OSCA) Resealer() shared.Resealer {
	return func(ctx context.Context) error {
		if o == nil {
			return nil
		}
		h, d, err := o.parts()
		if err != nil {
			return nil
		}
		if _, ok := d.Get(); !ok {
			return nil
		}
		_, err = d.Mutate(ctx, systemUser, func(b *Body) error {
			sealed, err := shared.Reseal(h.Keys(), keyField(b.CASHA256), b.CAKey)
			if err != nil {
				return err
			}
			if sealed == b.CAKey {
				return errUnchanged
			}
			b.CAKey = sealed
			return nil
		})
		if errors.Is(err, errUnchanged) {
			return nil
		}
		return err
	}
}
