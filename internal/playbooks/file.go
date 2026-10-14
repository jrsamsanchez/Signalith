package playbooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
	"gopkg.in/yaml.v3"
)

// The playbooks set on the Playbooks page are kept in a YAML file
// (default playbooks.yaml in the lookups folder). Signalith rewrites it
// whole on each change, through a temporary file and a rename, so a crash
// never leaves half a file. It holds no secrets, but it decides what
// Signalith changes by itself, so only the server's own account may write
// it.

const fileHeader = `# Playbooks set on the Playbooks page of Signalith. Signalith rewrites
# this file when they change there; to change them, use the page.
`

// playbooksFile is the file's content.
type playbooksFile struct {
	Playbooks []Playbook `yaml:"playbooks"`
}

// FileError is a playbooks file that cannot be read.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string {
	return fmt.Sprintf("The playbooks file %s could not be read (%v). Fix or delete it, then reload this page.", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// ErrChanged is a save based on playbooks that changed since they were
// read, on another tab or by another admin.
var ErrChanged = errors.New("the playbooks were changed since this page loaded them; reload the page and make your change again")

// Manager keeps the playbooks: it reads the file once, and writes it on
// each change.
type Manager struct {
	// File is the playbooks file; "" keeps them in memory only.
	File string
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	read    bool
	fileErr error
	cur     []Playbook
	rev     string
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Load reads the file. A file that could not be read is read again on
// each call, so fixing it takes effect without a restart; until then the
// playbooks cannot be changed on the page, so a bad file is never
// overwritten, and no playbook starts.
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
	m.read, m.fileErr, m.cur, m.rev = true, nil, nil, ""
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
	var f playbooksFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		m.fileErr = &FileError{Path: m.File, Err: err}
		return
	}
	m.cur, m.rev = f.Playbooks, revision(data)
}

func revision(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:12])
}

// List returns a copy of the playbooks, and the file's problem when it
// cannot be read (the list is then empty).
func (m *Manager) List() ([]Playbook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	out := make([]Playbook, len(m.cur))
	for i, p := range m.cur {
		out[i] = p.clone()
	}
	return out, m.fileErr
}

// Revision identifies the saved playbooks; a save names the revision it
// started from (see Input.Revision).
func (m *Manager) Revision() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	return m.rev
}

// Save checks in against the channels and actions in refs and writes it
// as the new list. It returns *InputError for settings to fix,
// ErrChanged when the playbooks changed since in.Revision, and the
// file's error when it cannot be read.
func (m *Manager) Save(in Input, refs Refs) ([]Playbook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	if m.fileErr != nil {
		return nil, m.fileErr
	}
	if in.Revision != "" && in.Revision != m.rev {
		return nil, ErrChanged
	}
	list, probs := merge(m.cur, in.Playbooks, refs, m.now())
	if len(probs) > 0 {
		return nil, &InputError{Problems: probs}
	}
	if err := m.save(list); err != nil {
		return nil, err
	}
	out := make([]Playbook, len(list))
	for i, p := range list {
		out[i] = p.clone()
	}
	return out, nil
}

// save writes list and makes it current; the caller holds m.mu.
func (m *Manager) save(list []Playbook) error {
	if m.File == "" {
		m.cur, m.rev = list, newID()
		return nil
	}
	data, err := encode(list)
	if err != nil {
		return err
	}
	if err := securefile.WriteFile(m.File, data); err != nil {
		return fmt.Errorf("could not save %s: %s", m.File, strings.TrimPrefix(err.Error(), "open "))
	}
	m.cur, m.rev = list, revision(data)
	return nil
}

// encode writes the file's text.
func encode(list []Playbook) ([]byte, error) {
	if list == nil {
		list = []Playbook{}
	}
	var buf bytes.Buffer
	buf.WriteString(fileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(playbooksFile{Playbooks: list}); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Fingerprint is a hash of the playbooks, so servers that share one
// OpenSearch can tell whether theirs differ: the one that takes the
// background jobs over runs its own. It is "" when there are none, so
// servers that do not use playbooks compare equal.
func (m *Manager) Fingerprint() string {
	m.mu.Lock()
	m.load()
	list, fileErr := make([]Playbook, len(m.cur)), m.fileErr
	for i, p := range m.cur {
		list[i] = p.clone()
		// When it was turned on differs by a moment between servers
		// whose files were copied, and does not change what it does.
		list[i].Since = time.Time{}
	}
	m.mu.Unlock()
	if fileErr == nil && len(list) == 0 {
		return ""
	}
	b, _ := json.Marshal(map[string]any{"playbooks": list, "file_ok": fileErr == nil})
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
