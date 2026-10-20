// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

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
		_, err = d.Mutate(ctx, systemUser, func(b *Body) error {
			sealed, err := shared.Reseal(h.Keys(), keyField(b.CASHA256), b.CAKey)
			if err != nil {
				return err
			}
			b.CAKey = sealed
			// The next or previous certificate authority's key too.
			for _, o := range []*OtherCA{b.Next, b.Previous} {
				if o == nil {
					continue
				}
				if o.CAKey, err = shared.Reseal(h.Keys(), keyField(o.CASHA256), o.CAKey); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	}
}
