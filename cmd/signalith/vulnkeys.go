package main

import (
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// loginKeys encrypts the scan logins OpenVAS signs in to hosts with
// (Settings > Scanners). They are kept in OpenSearch, so on servers that
// share their settings they are encrypted with the cluster key, which
// every server of the cluster has, and otherwise with this server's
// master key. They are read with every key this server has, as the
// archives are.
type loginKeys struct {
	keys    *secrets.Keyring
	store   shared.KeyStore
	cluster func() *secrets.Key
}

func newLoginKeys(c *config.Config, cluster func() *secrets.Key) *loginKeys {
	keys := c.Keyring()
	return &loginKeys{keys: keys, store: shared.KeyStore{Dir: c.StateDir(), Master: keys}, cluster: cluster}
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
