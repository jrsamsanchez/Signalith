package secrets

import (
	"errors"
	"fmt"
	"os"
)

// Key is a key other than the master key that encrypts values the same
// way: enc:v1:<key id>:..., bound to the setting with the same associated
// data, and its id the same kind of fingerprint. The shared configuration
// of several servers uses one, the cluster key, for the secrets every
// server must read. It is never read from a file by itself: whoever has
// the 32 bytes makes one with NewKey.
type Key struct {
	m    *masterKey
	name string
}

// NewKey returns a key made from 32 random bytes. name says what kind of
// key it is, such as "cluster key", in errors. The caller may clear raw
// afterwards.
func NewKey(raw []byte, name string) (*Key, error) {
	if name == "" {
		return nil, errors.New("secrets: a key needs a name")
	}
	m, err := newMasterKey(raw)
	if err != nil {
		return nil, fmt.Errorf("a %s: %w", name, err)
	}
	return &Key{m: m, name: name}, nil
}

// ID returns the key's id, as in the values it encrypts.
func (k *Key) ID() string { return k.m.id }

// Seal encrypts plain for the setting field. Empty values are returned as
// they are, and so are values already encrypted, with this key or another.
func (k *Key) Seal(field, plain string) (string, error) {
	if plain == "" || IsSealed(plain) {
		return plain, nil
	}
	return k.m.seal(field, plain)
}

// Open decrypts a value stored for the setting field. Plain text is
// returned as it is. A value this key did not encrypt, or that was
// changed, gives an *OpenError.
func (k *Key) Open(field, stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	id, blob, err := parse(stored)
	if err != nil {
		return "", &OpenError{Field: field, Reason: err.Error(), Key: k.name}
	}
	if id != k.m.id {
		return "", &OpenError{Field: field, KeyID: id, Have: k.m.id, Key: k.name}
	}
	plain, ok := k.m.open(field, blob)
	if !ok {
		return "", &OpenError{Field: field, KeyID: id, Reason: "it was changed, or copied from another setting", Key: k.name}
	}
	return plain, nil
}

// Holds reports whether the key's id is id.
func (k *Key) Holds(id string) bool { return k.m.id == id }

// KeyFileWarning says what is wrong with who may use a key file other
// than the master key's, such as the cluster key file, which what names
// ("The cluster key file"): "" when nothing is, when it cannot be read,
// and on Windows, where the file's access list is set when it is made.
func KeyFileWarning(what, path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fileWarning(what, path, st)
}

// Opener decrypts stored values; *Keyring and *Key are openers.
type Opener interface {
	Open(field, stored string) (string, error)
}

// holder is an opener that can tell which key ids it holds without
// reading anything, as *Key can.
type holder interface {
	Holds(id string) bool
}

// Chain returns an opener that opens a value by its key id: with the
// opener that holds that key (a *Key), and otherwise with the others in
// order, such as the master Keyring, which reads its key files to know.
// So a value of the cluster key opens with it even when the master key
// file cannot be read. A value one of them holds the key for but cannot
// open (changed, or copied from another setting) is not tried with the
// others.
func Chain(openers ...Opener) Opener { return chain(openers) }

type chain []Opener

func (c chain) Open(field, stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	id := KeyID(stored)
	for _, o := range c {
		if h, ok := o.(holder); ok && h.Holds(id) {
			return o.Open(field, stored)
		}
	}
	var last error = &OpenError{Field: field, KeyID: id}
	for _, o := range c {
		if _, ok := o.(holder); ok {
			// It does not hold the key.
			continue
		}
		plain, err := o.Open(field, stored)
		if err == nil {
			return plain, nil
		}
		last = err
		var oe *OpenError
		if !errors.As(err, &oe) || oe.Reason != "" {
			return "", err
		}
	}
	return "", last
}
