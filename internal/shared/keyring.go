package shared

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
)

// The keyring document, <prefix>_config/keyring, lists the cluster keys
// and the member servers with their node public keys. It holds no usable
// key material: a key is handed to a server sealed to its node key, and
// the keyring only says which keys exist, which one signs, and who may
// be given one.

// How a server became a member, in KeyringMember.AddedBy.
const (
	AddedByFounder = "founder"
	AddedByKeyFile = "key-file"
	AddedByImport  = "import-key"
)

// KeyInfo is one cluster key in the keyring.
type KeyInfo struct {
	KID       string `json:"kid"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

// KeyringMember is a member server in the keyring.
type KeyringMember struct {
	Name        string `json:"name"`
	NodePub     string `json:"node_pub"`
	Fingerprint string `json:"fingerprint"`
	AddedAt     string `json:"added_at"`
	AddedBy     string `json:"added_by"`
}

// KeyringBody is the body of the keyring document.
type KeyringBody struct {
	// Active is the id of the key that signs.
	Active  string                   `json:"active"`
	Keys    []KeyInfo                `json:"keys"`
	Members map[string]KeyringMember `json:"members"`
	// Next is a key rotation in progress (a RotationNext), null when none
	// is: raw, so a version before rotations keeps it as it was.
	Next json.RawMessage `json:"next"`
	// CatchUp keeps the last rotation's copies of the new key for 7 days,
	// for a member that was offline during it.
	CatchUp *CatchUp `json:"catch_up,omitempty"`
	Extra   `json:"-"`
}

// KIDs lists the ids of the keys the keyring names: the active one and,
// during a rotation, the one it moves to.
func (k *KeyringBody) KIDs() []string {
	var out []string
	for _, ki := range k.Keys {
		out = append(out, ki.KID)
	}
	if k.Active != "" && !slices.Contains(out, k.Active) {
		out = append(out, k.Active)
	}
	slices.Sort(out)
	return out
}

// member returns this server's entry for the keyring.
func (rt *Runtime) member(addedBy string) (KeyringMember, error) {
	nk, err := rt.nodeKey()
	if err != nil {
		return KeyringMember{}, err
	}
	return KeyringMember{Name: rt.opts.Self.Name, NodePub: nk.PublicText(), Fingerprint: nk.Fingerprint(),
		AddedAt: rt.Hub().now(), AddedBy: addedBy}, nil
}

// AddSelf adds this server to the keyring when it is not listed with its
// current node key, as a server that got the cluster key from a key file
// does at its first start as a member. A keyring that is not there yet (a
// founding cut short) is made, with this server's key as the active one.
func (rt *Runtime) AddSelf(ctx context.Context, addedBy string) error {
	m, err := rt.member(addedBy)
	if err != nil {
		return err
	}
	h, kdoc := rt.Hub(), rt.Keyring()
	cur, ok := kdoc.Get()
	if old, there := cur.Members[rt.opts.Self.NodeID]; ok && there && old.NodePub == m.NodePub {
		return nil
	}
	active := h.Keys().Active()
	if active == nil {
		return errors.New("this server has no cluster key")
	}
	_, err = kdoc.Mutate(ctx, "signalith", func(b *KeyringBody) error {
		if b.Active == "" {
			b.Active = active.ID()
			b.Keys = []KeyInfo{{KID: active.ID(), CreatedAt: m.AddedAt, CreatedBy: rt.opts.Self.Name}}
		}
		if old, there := b.Members[rt.opts.Self.NodeID]; there && old.NodePub == m.NodePub {
			return nil
		}
		if b.Members == nil {
			b.Members = map[string]KeyringMember{}
		}
		b.Members[rt.opts.Self.NodeID] = m
		return nil
	})
	if err == nil {
		rt.log.Info("this server added itself to the cluster's keyring", "audit", true, "fingerprint", m.Fingerprint, "added_by", addedBy)
	}
	return err
}
