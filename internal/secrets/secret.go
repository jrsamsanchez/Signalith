// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"errors"
	"log/slog"

	"gopkg.in/yaml.v3"
)

// Redacted is how a Secret shows itself.
const Redacted = "[redacted]"

// Secret is a password or key that hides itself: printed, logged or turned
// into JSON it shows as [redacted], and only Reveal returns it. Read from
// YAML it accepts plain text or an encrypted value (Open then decrypts
// it); written to YAML it is encrypted with the default keyring.
type Secret struct {
	plain  string
	stored string
	field  string
}

// New returns a Secret holding plain, the value of the setting field.
func New(field, plain string) Secret { return Secret{plain: plain, field: field} }

// Reveal returns the value itself.
func (s Secret) Reveal() string { return s.plain }

// IsSet reports whether there is a value, even one that could not be
// decrypted.
func (s Secret) IsSet() bool { return s.plain != "" || s.stored != "" }

// Encrypted reports whether the value was encrypted where it was read.
func (s Secret) Encrypted() bool { return IsSealed(s.stored) }

// String returns [redacted].
func (s Secret) String() string { return Redacted }

// GoString returns a redacted form for %#v.
func (s Secret) GoString() string { return "secrets.Secret{" + Redacted + "}" }

// MarshalJSON writes "[redacted]", so the value never reaches an API reply
// or a JSON log.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// LogValue keeps the value out of slog output.
func (s Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// UnmarshalYAML keeps the value as written: plain text, which is ready to
// use, or an encrypted value, which Open decrypts.
func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	var v string
	if err := n.Decode(&v); err != nil {
		return err
	}
	*s = Secret{stored: v}
	if !IsSealed(v) {
		s.plain = v
	}
	return nil
}

// Open decrypts a value read from YAML as the setting field, with the
// default keyring. Plain text is kept as it is. When it fails, the value
// stays encrypted (Reveal returns "") and is written back unchanged.
func (s *Secret) Open(field string) error {
	s.field = field
	if !IsSealed(s.stored) {
		return nil
	}
	plain, err := Open(field, s.stored)
	if err != nil {
		return err
	}
	s.plain = plain
	return nil
}

// MarshalYAML writes the value encrypted with the default keyring, or, if
// it could not be decrypted when read, as it was read.
func (s Secret) MarshalYAML() (any, error) {
	if s.plain == "" {
		return s.stored, nil
	}
	if s.field == "" {
		return nil, errors.New("secrets: a Secret needs the name of its setting before it is written; make it with secrets.New or call Open")
	}
	return Seal(s.field, s.plain)
}
