package shared

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"time"
)

// Removing a server takes it out of the keyring, so no rotation hands it
// a new key, and records it in the cluster document's removed list, so a
// copy of it that still runs with the cluster key does not add itself
// back. Rotating the key afterwards (the default) is what makes its copy
// of the key useless.

// RemovedServer is a server removed from the cluster.
type RemovedServer struct {
	NodeID string    `json:"node_id"`
	Name   string    `json:"name"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
	// Fingerprint is its node key's, as the keyring had it.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Rotated is true once a key rotation followed its removal: its copy
	// of the cluster key opens nothing new.
	Rotated bool `json:"rotated,omitempty"`
}

// removedKept bounds the removed list.
const removedKept = 50

// ErrLastMember is a removal of the only member of the keyring.
var ErrLastMember = errors.New("a cluster's last server cannot be removed")

// RemoveMember removes the server nodeID (named name, for a server the
// keyring does not list) from the keyring and records it as removed, for
// the user by.
func (rt *Runtime) RemoveMember(ctx context.Context, nodeID, name, by string) (RemovedServer, error) {
	if err := rt.Writable(); err != nil {
		return RemovedServer{}, err
	}
	rec := RemovedServer{NodeID: nodeID, Name: name, At: rt.clock.Now().UTC(), By: by}
	_, err := rt.Keyring().Mutate(ctx, "signalith", func(b *KeyringBody) error {
		m, ok := b.Members[nodeID]
		if ok {
			if len(b.Members) == 1 {
				return ErrLastMember
			}
			rec.Name, rec.Fingerprint = cmp.Or(m.Name, rec.Name), m.Fingerprint
			delete(b.Members, nodeID)
		}
		if n, err := b.Rotation(); err == nil && n != nil {
			// A rotation in progress hands it no copy.
			delete(n.Copies, nodeID)
			if err := b.setRotation(n); err != nil {
				return err
			}
		}
		if b.CatchUp != nil {
			delete(b.CatchUp.Copies, nodeID)
		}
		return nil
	})
	if err != nil {
		return RemovedServer{}, err
	}
	rec.Name = cmp.Or(rec.Name, nodeID)
	if _, err := rt.Cluster().Mutate(ctx, "signalith", func(b *ClusterBody) error {
		out := make([]RemovedServer, 0, len(b.Removed)+1)
		for _, r := range b.Removed {
			if r.NodeID != nodeID {
				out = append(out, r)
			}
		}
		out = append(out, rec)
		if len(out) > removedKept {
			out = out[len(out)-removedKept:]
		}
		b.Removed = out
		return nil
	}); err != nil {
		return rec, fmt.Errorf("%s left the keyring, but the list of removed servers could not be written: %w", rec.Name, err)
	}
	rt.log.Info("removed a server from the cluster", "audit", true, "by", by, "server", rec.Name, "node_id", nodeID)
	return rec, nil
}

// MarkRotated records that a key rotation followed the removal of the
// servers nodeIDs.
func (rt *Runtime) MarkRotated(ctx context.Context, nodeIDs ...string) error {
	_, err := rt.Cluster().Mutate(ctx, "signalith", func(b *ClusterBody) error {
		for i := range b.Removed {
			for _, id := range nodeIDs {
				if b.Removed[i].NodeID == id {
					b.Removed[i].Rotated = true
				}
			}
		}
		return nil
	})
	return err
}

// MarkAllRotated records that a key rotation followed every removal so
// far.
func (rt *Runtime) MarkAllRotated(ctx context.Context) error {
	b, ok := rt.Cluster().Get()
	if !ok {
		return nil
	}
	var ids []string
	for _, r := range b.Removed {
		if !r.Rotated {
			ids = append(ids, r.NodeID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return rt.MarkRotated(ctx, ids...)
}

// Removed lists the servers removed from the cluster, newest last.
func (rt *Runtime) Removed() []RemovedServer {
	b, ok := rt.Cluster().Get()
	if !ok {
		return nil
	}
	return b.Removed
}

// RemovedSelf reports whether this server was removed from the cluster.
func (rt *Runtime) RemovedSelf() bool {
	_, ok := rt.removedSelf()
	return ok
}

func (rt *Runtime) removedSelf() (RemovedServer, bool) {
	for _, r := range rt.Removed() {
		if r.NodeID == rt.opts.Self.NodeID {
			return r, true
		}
	}
	return RemovedServer{}, false
}

// ForgetRemoved takes the server nodeID off the removed list, for a
// server given the cluster key again on purpose (signalith cluster
// import-key).
func (rt *Runtime) ForgetRemoved(ctx context.Context, nodeID string) error {
	b, ok := rt.Cluster().Get()
	if !ok {
		return nil
	}
	found := false
	for _, r := range b.Removed {
		found = found || r.NodeID == nodeID
	}
	if !found {
		return nil
	}
	_, err := rt.Cluster().Mutate(ctx, "signalith", func(b *ClusterBody) error {
		out := b.Removed[:0]
		for _, r := range b.Removed {
			if r.NodeID != nodeID {
				out = append(out, r)
			}
		}
		b.Removed = out
		return nil
	})
	return err
}
