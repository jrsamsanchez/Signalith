// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"gopkg.in/yaml.v3"
)

// The connections set on the Ticketing page are kept in a YAML file
// (default tickets.yaml in the lookups folder). Signalith rewrites it
// whole on each change, through a temporary file and a rename, so a crash
// never leaves half a file. It holds API tokens and passwords, so only the
// server's own account may read it, and each of them is encrypted with the
// master key (package secrets) for its connection and setting (see
// FileField). One that cannot be decrypted is kept as it is, and the
// connection shows a problem until it is entered again.

const fileHeader = `# Jira and ServiceNow connections set on the Ticketing page of
# Signalith. Signalith rewrites this file when they change there; to
# change them, use the page. It holds API tokens and passwords, so keep it
# private.
`

// FileError is a ticketing file that cannot be read.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string {
	return fmt.Sprintf("The ticketing file %s could not be read (%v). Fix or delete it, then reload this page.", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// ErrChanged is a save based on settings that changed since they were
// read, on another tab or by another admin.
var ErrChanged = errors.New("the ticketing connections were changed since this page loaded them; reload the page and make your change again")

// Manager keeps the connections: it reads the file once, and writes it on
// each change.
type Manager struct {
	// File is the ticketing file; "" keeps the settings in memory only.
	File string
	Log  *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	read    bool
	fileErr error
	cur     Settings
	rev     string
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// FileField is the setting a secret in the ticketing file is encrypted
// for: part is token, password or client_secret, as in
// ticketing_connections[a1b2c3].token. A value copied to another
// connection or setting cannot be decrypted there.
func FileField(connID, part string) string { return "ticketing_connections[" + connID + "]." + part }

// eachSecret replaces each secret of c with what fn returns for it. part
// names it as FileField does, label for people.
func (c *Connection) eachSecret(fn func(part, label, v string) (string, error)) error {
	for _, s := range []struct {
		dst         *string
		part, label string
	}{{&c.Token, "token", "API token"}, {&c.Password, "password", "password"}, {&c.ClientSecret, "client_secret", "client secret"}} {
		if *s.dst == "" {
			continue
		}
		v, err := fn(s.part, s.label, *s.dst)
		if err != nil {
			return err
		}
		*s.dst = v
	}
	return nil
}

// Undecrypted lists the secrets of c still encrypted after loading,
// because they could not be decrypted (the master key changed).
func (c Connection) Undecrypted() []string {
	var out []string
	cc := c.clone()
	_ = cc.eachSecret(func(_, label, v string) (string, error) {
		if secrets.IsSealed(v) {
			out = append(out, label)
		}
		return v, nil
	})
	return out
}

// Load reads the file. A file that could not be read is read again on
// each call, so fixing it takes effect without a restart; until then the
// connections cannot be changed on the page, so a bad file is never
// overwritten, and nothing is synced.
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	return m.fileErr
}

// load reads the file if it was not read, or could not be; the caller
// holds m.mu.
func (m *Manager) load() {
	if m.read && m.fileErr == nil {
		return
	}
	m.read, m.fileErr, m.cur, m.rev = true, nil, Settings{}, ""
	if m.File == "" {
		return
	}
	data, err := os.ReadFile(m.File)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		m.fileErr = &FileError{Path: m.File, Err: err}
		return
	}
	var s Settings
	if err := yaml.Unmarshal(data, &s); err != nil {
		m.fileErr = &FileError{Path: m.File, Err: err}
		return
	}
	for i := range s.Connections {
		c := &s.Connections[i]
		_ = c.eachSecret(func(part, label, v string) (string, error) {
			plain, err := secrets.Open(FileField(c.ID, part), v)
			if err != nil {
				m.log().Warn("a saved secret of a ticketing connection cannot be decrypted; edit the connection and enter it again",
					"connection", c.Name, "secret", label, "file", m.File, "err", err)
				return v, nil
			}
			return plain, nil
		})
	}
	m.cur, m.rev = s, revision(data)
}

func revision(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:12])
}

// Settings returns a copy of the connections, with their secrets, and the
// file's problem when it cannot be read (the settings are then empty).
func (m *Manager) Settings() (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	return m.cur.clone(), m.fileErr
}

// Revision identifies the saved settings; a save names the revision it
// started from (see Input.Revision).
func (m *Manager) Revision() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	return m.rev
}

// Fingerprint is a hash of the connections without their secrets, so
// servers that share one OpenSearch can tell whether theirs differ: the
// one that takes the background jobs over syncs with its own. It is ""
// when there are none, so servers that do not use ticketing compare
// equal.
func (m *Manager) Fingerprint() string {
	m.mu.Lock()
	m.load()
	s, fileErr := m.cur.clone(), m.fileErr
	m.mu.Unlock()
	if fileErr == nil && len(s.Connections) == 0 {
		return ""
	}
	// The settings as the file writes them, so settings saved here and
	// read from the file elsewhere compare equal, with each secret replaced
	// by whether it is set.
	for i := range s.Connections {
		_ = s.Connections[i].eachSecret(func(_, _, _ string) (string, error) { return "set", nil })
	}
	text, _ := encode(s)
	b, _ := json.Marshal(map[string]any{"settings": string(text), "file_ok": fileErr == nil})
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Reseal passes every secret in the ticketing file text data through fn
// and returns the file with what fn returned, and how many values that
// changed. The file is written again whole, as Signalith always writes
// it. It is the file's config.SecretFile.Reseal, for "signalith secrets"
// and the Security page.
func Reseal(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	var s Settings
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, 0, fmt.Errorf("not valid YAML: %w", err)
	}
	n := 0
	for i := range s.Connections {
		c := &s.Connections[i]
		err := c.eachSecret(func(part, label, v string) (string, error) {
			nv, err := fn(secrets.Stored{Field: FileField(c.ID, part), Label: "connections[" + c.Name + "] " + label, Value: v})
			if err == nil && nv != v {
				n++
			}
			return nv, err
		})
		if err != nil {
			return nil, 0, err
		}
	}
	if n == 0 {
		return data, 0, nil
	}
	out, err := encode(s)
	return out, n, err
}

// encode writes the file's text.
func encode(s Settings) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(fileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// save writes s, with its secrets encrypted, and makes it current; the
// caller holds m.mu.
func (m *Manager) save(s Settings) error {
	if m.File == "" {
		m.cur, m.rev = s.clone(), newID()
		return nil
	}
	sealed := s.clone()
	for i := range sealed.Connections {
		c := &sealed.Connections[i]
		err := c.eachSecret(func(part, _, v string) (string, error) {
			if secrets.IsSealed(v) {
				// Could not be decrypted when read: kept as it was.
				return v, nil
			}
			return secrets.Seal(FileField(c.ID, part), v)
		})
		if err != nil {
			return fmt.Errorf("could not save %s: %w", m.File, err)
		}
	}
	data, err := encode(sealed)
	if err != nil {
		return err
	}
	if err := securefile.WriteFile(m.File, data); err != nil {
		return fmt.Errorf("could not save %s: %s", m.File, strings.TrimPrefix(err.Error(), "open "))
	}
	m.cur, m.rev = s.clone(), revision(data)
	return nil
}
