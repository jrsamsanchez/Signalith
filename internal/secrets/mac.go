// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// A MAC authenticates a record that is not secret but must not be changed
// without a key, such as an archive's manifest: HMAC-SHA256 under a key
// derived (HKDF, its own info) from the master key or the cluster key,
// over the name of what is authenticated and the record. It looks like
//
//	mac:v1:<key id>:<HMAC, base64url>
//
// so a reader knows which of its keys to check it with.

const macPrefix = "mac:v1:"

var (
	// ErrMACKey means a MAC was made with a key that is not this one, or
	// not one of this keyring's.
	ErrMACKey = errors.New("the MAC was made with another key")
	// ErrMACMismatch means a MAC of this key does not match: the record
	// was changed, or the MAC was copied from another record.
	ErrMACMismatch = errors.New("the record was changed after it was authenticated")
)

func (m *masterKey) sum(field string, msg []byte) []byte {
	h := hmac.New(sha256.New, m.mac)
	h.Write([]byte(field))
	h.Write([]byte{0})
	h.Write(msg)
	return h.Sum(nil)
}

func (m *masterKey) makeMAC(field string, msg []byte) string {
	return macPrefix + m.id + ":" + base64.RawURLEncoding.EncodeToString(m.sum(field, msg))
}

// MACKeyID returns the id of the key a MAC was made with, or "".
func MACKeyID(tag string) string {
	rest, ok := strings.CutPrefix(tag, macPrefix)
	if !ok {
		return ""
	}
	id, _, ok := strings.Cut(rest, ":")
	if !ok || len(id) != 8 {
		return ""
	}
	return id
}

// checkMAC checks tag, which MACKeyID says m made.
func (m *masterKey) checkMAC(field string, msg []byte, tag string) error {
	_, data, _ := strings.Cut(strings.TrimPrefix(tag, macPrefix), ":")
	got, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil || !hmac.Equal(got, m.sum(field, msg)) {
		return ErrMACMismatch
	}
	return nil
}

// MAC authenticates msg for field (what msg is, so that a MAC of one kind
// of record does not pass for another).
func (k *Key) MAC(field string, msg []byte) string { return k.m.makeMAC(field, msg) }

// CheckMAC checks a MAC made by MAC: nil when it matches, ErrMACKey when
// another key made it, and ErrMACMismatch when it does not match.
func (k *Key) CheckMAC(field string, msg []byte, tag string) error {
	if MACKeyID(tag) != k.m.id {
		return ErrMACKey
	}
	return k.m.checkMAC(field, msg, tag)
}

// MAC authenticates msg for field with the master key in use. It never
// makes a master key: without one it returns an error that is ErrNoKey.
func (k *Keyring) MAC(field string, msg []byte) (string, error) {
	k.mu.Lock()
	err := k.ensure()
	cur := k.cur
	k.mu.Unlock()
	if err != nil {
		return "", err
	}
	return cur.makeMAC(field, msg), nil
}

// CheckMAC is Key.CheckMAC with the master key in use or the previous
// one.
func (k *Keyring) CheckMAC(field string, msg []byte, tag string) error {
	id := MACKeyID(tag)
	if id == "" {
		return ErrMACKey
	}
	k.mu.Lock()
	err := k.ensure()
	if err == nil && !k.has(id) {
		// The key file may have changed since it was read.
		k.reset()
		err = k.ensure()
	}
	var key *masterKey
	if err == nil {
		switch {
		case k.cur.id == id:
			key = k.cur
		case k.old != nil && k.old.id == id:
			key = k.old
		}
	}
	k.mu.Unlock()
	if key == nil {
		return ErrMACKey
	}
	return key.checkMAC(field, msg, tag)
}
