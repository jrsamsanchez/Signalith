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
			// The next or previous certificate authority's key too. One
			// that cannot be resealed keeps its old sealed value, never an
			// empty one, and says so: it opens again once this server has
			// the key it was sealed with.
			for _, o := range []*OtherCA{b.Next, b.Previous} {
				if o == nil {
					continue
				}
				resealed, err := shared.Reseal(h.Keys(), keyField(o.CASHA256), o.CAKey)
				if err != nil || (resealed == "" && o.CAKey != "") {
					t.logger().Error("could not seal the key of the cluster's next or previous certificate authority with the new cluster key; its old sealed value is kept",
						"audit", true, "ca_sha256", o.CASHA256, "err", err)
					continue
				}
				o.CAKey = resealed
			}
			return nil
		})
		return err
	}
}
