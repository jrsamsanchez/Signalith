package clustercfg

import (
	"context"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Resealer seals the passwords and keys of the shared settings and of the
// feeds again with the active cluster key, for a key rotation. Each
// document is changed only when one of its values was sealed with
// another key.
func Resealer(d *Docs) shared.Resealer {
	return func(ctx context.Context) error {
		h := d.Hub()
		if h == nil || d.Settings() == nil || d.Feeds() == nil {
			return nil
		}
		keys := h.Keys()
		if _, ok := d.Settings().Get(); ok {
			if _, err := d.Settings().Mutate(ctx, "signalith", func(b *SettingsBody) error {
				for k, v := range b.Values {
					sealed, err := shared.Reseal(keys, config.SharedField(k, v.SentTo), v.Secret)
					if err != nil {
						return err
					}
					v.Secret = sealed
					b.Values[k] = v
				}
				for i, t := range b.IngestTokens {
					sealed, err := shared.Reseal(keys, config.SharedField("ingest.tokens", ""), t.Secret)
					if err != nil {
						return err
					}
					b.IngestTokens[i].Secret = sealed
				}
				return nil
			}); err != nil {
				return err
			}
		}
		if _, ok := d.Feeds().Get(); ok {
			if _, err := d.Feeds().Mutate(ctx, "signalith", func(b *FeedsBody) error {
				for i := range b.Feeds {
					e := &b.Feeds[i]
					if err := eachSecret(e, func(part, v string) (string, error) {
						return shared.Reseal(keys, SecretField(e.Name, part, e.URL), v)
					}); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}
}
