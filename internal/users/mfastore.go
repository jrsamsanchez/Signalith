package users

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// StoredMFA is a two-step sign-in as a file or document keeps it, with
// the authenticator key encrypted.
type StoredMFA struct {
	// Secret is the key, encrypted (enc:v1:...) for MFAField or
	// BuiltinMFAField.
	Secret   string    `json:"secret"`
	Pending  bool      `json:"pending,omitempty"`
	Recovery []string  `json:"recovery,omitempty"`
	Since    time.Time `json:"since"`
	LastStep int64     `json:"last_step,omitempty"`
}

// MFAKeys encrypts and decrypts authenticator keys: the master key for
// the users file, the cluster key for the shared settings.
type MFAKeys interface {
	Seal(field, plain string) (string, error)
	Open(field, stored string) (string, error)
	// Current reports whether stored was encrypted with the key Seal
	// uses now.
	Current(stored string) bool
}

// keyringKeys are the MFAKeys of a secrets.Keyring.
type keyringKeys struct{ k *secrets.Keyring }

func (k keyringKeys) Seal(field, plain string) (string, error)  { return k.k.Seal(field, plain) }
func (k keyringKeys) Open(field, stored string) (string, error) { return k.k.Open(field, stored) }
func (k keyringKeys) Current(stored string) bool {
	id := secrets.KeyID(stored)
	return id != "" && id == k.k.KeyID()
}

// fileKeys are the keys of the users file: the master key.
func fileKeys() MFAKeys { return keyringKeys{secrets.Default()} }

// Open returns the two-step sign-in m keeps, with its key decrypted for
// field; one that cannot be decrypted says why in Problem. nil is nil.
func (m *StoredMFA) Open(keys MFAKeys, field string) *MFA {
	if m == nil {
		return nil
	}
	out := &MFA{Pending: m.Pending, Recovery: slices.Clone(m.Recovery), Since: m.Since, LastStep: m.LastStep}
	if secrets.IsSealed(m.Secret) {
		out.Sealed = m.Secret
	}
	plain, err := keys.Open(field, m.Secret)
	if err != nil {
		out.Problem = err.Error()
		return out
	}
	out.Secret = plain
	return out
}

// SealMFA returns m as it is stored, its key encrypted for field: the
// value stored before when it was encrypted with the current key, else
// encrypted again. A key that could not be decrypted (Problem) is kept
// as it was stored. nil is nil.
func SealMFA(keys MFAKeys, field string, m *MFA) (*StoredMFA, error) {
	if m == nil {
		return nil, nil
	}
	out := &StoredMFA{Pending: m.Pending, Recovery: slices.Clone(m.Recovery), Since: m.Since.UTC(), LastStep: m.LastStep}
	switch {
	case m.Secret == "":
		out.Secret = m.Sealed
	case m.Sealed != "" && keys.Current(m.Sealed):
		out.Secret = m.Sealed
	default:
		sealed, err := keys.Seal(field, m.Secret)
		if err != nil {
			return nil, err
		}
		out.Secret = sealed
	}
	return out, nil
}

// ResealUsersFile passes the authenticator keys in the users file text
// data through fn and returns the file with what fn returned, and how
// many changed.
func ResealUsersFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, 0, fmt.Errorf("not valid JSON: %w", err)
	}
	n := 0
	reseal := func(m *StoredMFA, field, label string) error {
		if m == nil || m.Secret == "" {
			return nil
		}
		v, err := fn(secrets.Stored{Field: field, Label: label, Value: m.Secret})
		if err != nil {
			return err
		}
		if v != m.Secret {
			m.Secret = v
			n++
		}
		return nil
	}
	if err := reseal(f.BuiltinMFA, BuiltinMFAField, "two-step sign-in key of the built-in admin"); err != nil {
		return nil, 0, err
	}
	for i := range f.Users {
		u := &f.Users[i]
		if err := reseal(u.MFA, MFAField(u.Username), "two-step sign-in key of user "+NormalizeUsername(u.Username)); err != nil {
			return nil, 0, err
		}
	}
	if n == 0 {
		return data, 0, nil
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	return append(out, '\n'), n, nil
}
