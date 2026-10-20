// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterpki

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

// RevokeNode ends the OpenSearch access of the server nodeID at once,
// by the user by: every certificate the cluster issued it that has not
// expired goes on the revocation list each server writes for OpenSearch
// (opensearch.crl_file, WriteCRL), and it is issued none again unless it
// joins the cluster anew. It returns the certificates it revoked now.
// Without an osca document it returns ErrShared: the servers share one
// credential, which a revocation would take from all of them.
func (o *OSCA) RevokeNode(ctx context.Context, by, nodeID string) ([]Revoked, error) {
	_, d, err := o.parts()
	if err != nil {
		return nil, err
	}
	if nodeID == "" {
		return nil, errors.New("no server to revoke")
	}
	if _, ok := d.Get(); !ok {
		return nil, ErrShared
	}
	var out []Revoked
	_, err = d.Mutate(ctx, by, func(b *Body) error {
		now := time.Now().UTC()
		out = nil
		for _, name := range slices.Sorted(maps.Keys(b.Issued)) {
			is := b.Issued[name]
			if is.NodeID != nodeID {
				continue
			}
			for _, e := range append(slices.Clone(is.Previous), Earlier{Serial: is.Serial, NotAfter: is.NotAfter}) {
				if now.Before(e.NotAfter) && !slices.ContainsFunc(b.Revoked, func(r Revoked) bool { return r.Serial == e.Serial }) {
					out = append(out, Revoked{Serial: e.Serial, Name: name, NodeID: nodeID, NotAfter: e.NotAfter, RevokedAt: now})
				}
			}
			// The name is free again: its certificates are revoked.
			delete(b.Issued, name)
		}
		_, known := b.RevokedNodes[nodeID]
		if len(out) == 0 && known {
			return errUnchanged
		}
		list, err := pruneRevoked(append(b.Revoked, out...), now)
		if err != nil {
			return err
		}
		b.Revoked = list
		if b.RevokedNodes == nil {
			b.RevokedNodes = map[string]time.Time{}
		}
		if !known {
			b.RevokedNodes[nodeID] = now
		}
		pruneRevokedNodes(b.RevokedNodes)
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readmit lets the server nodeID be issued certificates again, as it
// joins the cluster anew.
func (o *OSCA) readmit(ctx context.Context, nodeID string) error {
	_, d, err := o.parts()
	if err != nil {
		return err
	}
	if b, ok := d.Get(); !ok || !hasKey(b.RevokedNodes, nodeID) {
		return nil
	}
	_, err = d.Mutate(ctx, systemUser, func(b *Body) error {
		if !hasKey(b.RevokedNodes, nodeID) {
			return errUnchanged
		}
		delete(b.RevokedNodes, nodeID)
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

func hasKey(m map[string]time.Time, k string) bool {
	_, ok := m[k]
	return ok
}

// pruneRevoked drops the revoked certificates that expired anyway. One
// that has not expired is never dropped, since that would let it in
// again: past MaxRevoked, it refuses.
func pruneRevoked(list []Revoked, now time.Time) ([]Revoked, error) {
	list = slices.DeleteFunc(list, func(r Revoked) bool { return !now.Before(r.NotAfter) })
	if len(list) > MaxRevoked {
		return nil, fmt.Errorf("the revocation list would name %d certificates that have not expired, more than the %d it holds, so this server's are not revoked; make OpenSearch's certificates again from a new certificate authority to end its access (bootstrap-docker -new-ca in Docker)", len(list), MaxRevoked)
	}
	return list, nil
}

// pruneRevokedNodes drops the servers over MaxRevoked revoked longest
// ago.
func pruneRevokedNodes(m map[string]time.Time) {
	if len(m) <= MaxRevoked {
		return
	}
	ids := slices.Collect(maps.Keys(m))
	slices.SortFunc(ids, func(a, b string) int { return m[a].Compare(m[b]) })
	for _, id := range ids[:len(m)-MaxRevoked] {
		delete(m, id)
	}
}

// RevokedSerials returns the serial numbers of b's revoked certificates
// that have not expired at now, in hex, sorted.
func (b *Body) RevokedSerials(now time.Time) []string {
	var out []string
	for _, r := range b.Revoked {
		if now.Before(r.NotAfter) {
			out = append(out, r.Serial)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// CRL signs the revocation list of the certificates revoked under the
// certificate authority the cluster keeps, valid until it expires.
func (o *OSCA) CRL(now time.Time) ([]byte, error) {
	b, ok := o.Get()
	if !ok {
		return nil, ErrNoCA
	}
	ca, err := o.open(b)
	if err != nil {
		return nil, err
	}
	var serials []*big.Int
	for _, s := range b.RevokedSerials(now) {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			return nil, errors.New("the osca document lists a revoked certificate with a serial number that cannot be read: " + s)
		}
		serials = append(serials, n)
	}
	return ospki.MakeCRL(ca, serials, big.NewInt(now.Unix()), now)
}
