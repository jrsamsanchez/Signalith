package clusterauth

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Resealer seals the directory's service account password again with
// the active cluster key, and signs every session again with it, for a
// key rotation: a signed-in user stays signed in.
func Resealer(d *Docs, client func() (*store.Client, string)) shared.Resealer {
	return func(ctx context.Context) error {
		h := d.Hub()
		if h == nil {
			return nil
		}
		keys := h.Keys()
		if dir := d.Directory(); dir != nil {
			if b, ok := dir.Get(); ok && b.BindPassword != "" {
				if _, err := dir.Mutate(ctx, "signalith", func(b *DirectoryBody) error {
					s := b.Settings.Clone()
					s.BindPassword = ""
					sealed, err := shared.Reseal(keys, users.BindField(s), b.BindPassword)
					if err != nil {
						return err
					}
					b.BindPassword = sealed
					return nil
				}); err != nil {
					return err
				}
			}
		}
		return resignSessions(ctx, client, keys)
	}
}

// resignSessions signs every session whose MAC verifies with a key of
// keys, but not the active one, again with the active key. A session
// changed meanwhile (its last use written) is read again.
func resignSessions(ctx context.Context, client func() (*store.Client, string), keys *shared.KeySet) error {
	active := keys.Active()
	if client == nil || active == nil {
		return nil
	}
	cl, prefix := client()
	if cl == nil {
		return nil
	}
	index := shared.SessionsIndex(prefix)
	var last error
	for range store.ModifyTries {
		docs, err := cl.SearchDocs(ctx, index, nil)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		last = nil
		for _, doc := range docs {
			var sd sessionDoc
			if json.Unmarshal(doc.Source, &sd) != nil || !sd.verify(keys, doc.ID) {
				continue
			}
			if kid := macKeyID(sd.MAC); kid == active.ID() {
				continue
			}
			sd.sign(active, doc.ID)
			if _, err := cl.PutIf(ctx, index, doc.ID, &sd, doc.Version, false); err != nil {
				if store.IsConflict(err) || errors.Is(err, store.ErrNotFound) {
					last = err
					continue
				}
				return err
			}
		}
		if last == nil {
			return nil
		}
	}
	return nil
}

// macKeyID is the id of the key in a session's MAC, m1:<kid>:<sum>.
func macKeyID(mac string) string {
	var kid string
	if len(mac) > 3 && mac[:3] == "m1:" {
		rest := mac[3:]
		for i := 0; i < len(rest); i++ {
			if rest[i] == ':' {
				kid = rest[:i]
				break
			}
		}
	}
	return kid
}
