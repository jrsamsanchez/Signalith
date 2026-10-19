// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tlsauto

import (
	"crypto/tls"
	"os"
)

// Inspect reads what a Manager for o would serve, without making,
// renewing or changing anything, for "signalith security", which runs
// beside the server. Its accessors (CAInfo, Next, Previous, Leaf,
// Outside, WouldCover, WouldAllow, CAPEM, PublicCA, Covers) answer from
// the files. In auto mode it returns an error wrapping fs.ErrNotExist
// when the server has made no certificate authority yet. The Manager it
// returns must not serve HTTPS or change certificate authority.
func Inspect(o Options) (*Manager, error) {
	m := &Manager{opts: o}
	if o.CertFile != "" {
		if err := m.loadFiles(true); err != nil {
			return nil, err
		}
		return m, nil
	}
	b, err := os.ReadFile(m.path(CAFile))
	if err != nil {
		return nil, err
	}
	ca, err := parseCert(b)
	if err != nil {
		return nil, err
	}
	m.added = m.readNames()
	m.mu.Lock()
	m.ca = ca
	m.wantNames() // works out Outside
	m.mu.Unlock()
	if b, err := os.ReadFile(m.path(certFile)); err == nil {
		if leaf, err := parseCert(b); err == nil {
			m.cert.Store(&tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf})
		}
	}
	m.switchedAt = readStamp(m.path(previousDir, stampSwitched))
	return m, nil
}
