// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// loginKeys encrypts the scan logins OpenVAS signs in to hosts with
// (Settings > Scanners). They are kept in OpenSearch, so on servers that
// share their settings they are encrypted with the cluster key, which
// every server of the cluster has, and otherwise with this server's
// master key. They are read with every key this server has, as the
// archives are. A rotation of the cluster key seals them again
// (vulnLoginsResealer).
type loginKeys struct {
	keys    *secrets.Keyring
	store   shared.KeyStore
	cluster func() *secrets.Key
	// clustered reports whether this server is, or may be about to be,
	// one of a cluster's: a login sealed with its master key then would
	// open on this server alone, so none is saved until it has the
	// cluster key.
	clustered func() bool
}

func newLoginKeys(c *config.Config, cluster func() *secrets.Key, clustered func() bool) *loginKeys {
	keys := c.Keyring()
	return &loginKeys{keys: keys, store: shared.KeyStore{Dir: c.StateDir(), Master: keys}, cluster: cluster, clustered: clustered}
}

// clusteredRuntime reports whether rt's server shares, or may be about to
// share, its settings: anything but a single server on its own.
func clusteredRuntime(rt *shared.Runtime) func() bool {
	return func() bool {
		if rt == nil {
			return false
		}
		m, _ := rt.Mode()
		return m != shared.ModeLegacyA && m != shared.ModeLegacyC
	}
}

func (l *loginKeys) active() *secrets.Key {
	if l.cluster == nil {
		return nil
	}
	return l.cluster()
}

func (l *loginKeys) Seal(field, plain string) (string, error) {
	if k := l.active(); k != nil {
		return k.Seal(field, plain)
	}
	if l.clustered != nil && l.clustered() {
		return "", fmt.Errorf("%w yet: it has not picked up the cluster's key, which every scanner needs to read the login; try again in a minute", vulnscan.ErrNoKeys)
	}
	return l.keys.Seal(field, plain)
}

func (l *loginKeys) Open(field, stored string) (string, error) {
	openers := []secrets.Opener{l.keys}
	if k := l.active(); k != nil {
		openers = append(openers, k)
	}
	// Cluster keys this server joined with earlier, still kept.
	if saved, err := l.store.ClusterKeys(); err == nil {
		for _, k := range saved {
			openers = append(openers, k.SecretsKey())
		}
	}
	return secrets.Chain(openers...).Open(field, stored)
}

// vulnLoginsResealer seals the scan logins again with the new cluster key
// when it rotates, so a removed server's copy of the old key opens none,
// and a server that joins later can read them. A login sealed with a
// single server's own key, before it joined, is left as it is: the
// Settings page asks for it again.
func vulnLoginsResealer(d *clustercfg.Docs, client func() (*store.Client, string)) shared.Resealer {
	return func(ctx context.Context) error {
		h := d.Hub()
		cl, prefix := client()
		if h == nil || cl == nil {
			return nil
		}
		keys := h.Keys()
		st := vulnscan.NewStore(cl, prefix)
		return st.ResealLogins(ctx, func(field, sealed string) (string, error) {
			if sealed == "" || keys.Get(secrets.KeyID(sealed)) == nil {
				return sealed, nil
			}
			return shared.Reseal(keys, field, sealed)
		})
	}
}
