package respond

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"gopkg.in/yaml.v3"
)

// The actions set up on the Response actions page are kept in a YAML
// file (default response.yaml in the lookups folder). Signalith rewrites
// it whole on each change, through a temporary file and a rename, so a
// crash never leaves half a file. It holds passwords and API keys, so
// only the server's own account may read it, and each one is encrypted
// with the master key (package secrets) for its action and setting (see
// FileField). One that cannot be decrypted is kept as it is, and the
// action cannot run until it is entered again. A change made to the file
// by hand is read again at the next use.

// actionsFile is the file's content.
type actionsFile struct {
	Actions []Connector `yaml:"actions"`
}

const fileHeader = `# Response actions set up on the Response actions page of Signalith.
# Signalith rewrites this file when actions change there; to change one,
# use the page. It holds passwords and API keys, so keep it private.
`

// FileField is the setting a secret in the actions file is encrypted
// for: part is password, bind_password or headers.<header name>, as in
// response[block-ip].headers.X-Api-Key. A value copied to another action
// or setting cannot be decrypted there.
func FileField(action, part string) string { return "response[" + action + "]." + part }

// FileError is an actions file that cannot be read.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string {
	return fmt.Sprintf("The response actions file %s could not be read (%v). Fix or delete it, then reload this page.", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// Actions keeps the response actions: in File, or in memory when File is
// empty.
type Actions struct {
	File string
	Log  *slog.Logger

	mu      sync.Mutex
	list    []Connector
	locked  map[string][]string // secrets that could not be decrypted, by action
	read    bool
	stamp   fileStamp
	fileErr error
}

// fileStamp tells whether the file changed since it was read.
type fileStamp struct {
	mod  time.Time
	size int64
}

func (a *Actions) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

// load reads the file when it was not read yet or changed since; the
// caller holds a.mu.
func (a *Actions) load() {
	if a.File == "" {
		a.read = true
		return
	}
	st, err := os.Stat(a.File)
	if errors.Is(err, os.ErrNotExist) {
		if a.read && a.stamp == (fileStamp{}) {
			return
		}
		a.list, a.locked, a.fileErr, a.stamp, a.read = nil, nil, nil, fileStamp{}, true
		return
	}
	var stamp fileStamp
	if err == nil {
		stamp = fileStamp{mod: st.ModTime(), size: st.Size()}
		if a.read && a.fileErr == nil && stamp == a.stamp {
			return
		}
	}
	a.read = true
	data, err := os.ReadFile(a.File)
	if err != nil {
		a.fileErr = &FileError{Path: a.File, Err: err}
		return
	}
	var f actionsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		a.fileErr = &FileError{Path: a.File, Err: err}
		return
	}
	locked := map[string][]string{}
	for i := range f.Actions {
		c := &f.Actions[i]
		c.Normalize()
		_ = c.eachSecret(func(part, label, v string) (string, error) {
			plain, err := secrets.Open(FileField(c.Name, part), v)
			if err != nil {
				a.log().Warn("a saved secret of a response action cannot be decrypted; edit the action and enter it again",
					"action", c.Name, "secret", label, "file", a.File, "err", err)
				locked[c.Name] = append(locked[c.Name], label)
				return v, nil
			}
			return plain, nil
		})
	}
	a.list, a.locked, a.fileErr, a.stamp = f.Actions, locked, nil, stamp
}

// List returns every action, with its secrets, and the file's problem if
// it cannot be read.
func (a *Actions) List() ([]Connector, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.load()
	out := make([]Connector, len(a.list))
	for i, c := range a.list {
		out[i] = c.Clone()
	}
	return out, a.fileErr
}

// Get returns one action by name.
func (a *Actions) Get(name string) (Connector, bool, error) {
	list, err := a.List()
	if err != nil {
		return Connector{}, false, err
	}
	for _, c := range list {
		if c.Name == name {
			return c, true, nil
		}
	}
	return Connector{}, false, nil
}

// Locked lists the secrets of an action that could not be decrypted.
func (a *Actions) Locked(name string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.load()
	return slices.Clone(a.locked[name])
}

// SettingsError lists the settings that need fixing, by action.
type SettingsError struct {
	Action   string
	Problems []Problem
}

func (e *SettingsError) Error() string {
	msgs := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		msgs[i] = p.Field + ": " + p.Message
	}
	who := "the action"
	if e.Action != "" {
		who = e.Action
	}
	return "fix these settings of " + who + ": " + strings.Join(msgs, "; ")
}

// MaxActions is how many actions the file may hold.
const MaxActions = 100

// Save checks and stores a whole new list of actions, with their secrets
// in plain text (they are encrypted in the file).
func (a *Actions) Save(list []Connector) error {
	if len(list) > MaxActions {
		return fmt.Errorf("at most %d response actions", MaxActions)
	}
	seen := map[string]bool{}
	clean := make([]Connector, len(list))
	for i, c := range list {
		c = c.Clone()
		c.Normalize()
		if p := c.Problems(); len(p) > 0 {
			return &SettingsError{Action: c.Name, Problems: p}
		}
		if seen[c.Name] {
			return &SettingsError{Action: c.Name, Problems: []Problem{{Field: "name", Message: "another action has this name"}}}
		}
		seen[c.Name] = true
		clean[i] = c
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.load()
	if a.fileErr != nil {
		return a.fileErr
	}
	if a.File != "" {
		sealed := make([]Connector, len(clean))
		for i, c := range clean {
			s := c.Clone()
			err := s.eachSecret(func(part, _, v string) (string, error) {
				return secrets.Seal(FileField(s.Name, part), v)
			})
			if err != nil {
				return fmt.Errorf("could not save %s: %w", a.File, err)
			}
			sealed[i] = s
		}
		data, err := encodeFile(actionsFile{Actions: sealed})
		if err != nil {
			return err
		}
		if err := securefile.WriteFile(a.File, data); err != nil {
			return fmt.Errorf("could not save %s: %w", a.File, err)
		}
		if st, err := os.Stat(a.File); err == nil {
			a.stamp = fileStamp{mod: st.ModTime(), size: st.Size()}
		}
	}
	a.list, a.locked, a.read = clean, map[string][]string{}, true
	return nil
}

// encodeFile writes the file's text.
func encodeFile(f actionsFile) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(fileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ResealFile passes every secret in the actions file text data through fn
// and returns the file with what fn returned, and how many values that
// changed. The file is written again whole, as Signalith always writes
// it.
func ResealFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	var f actionsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, 0, fmt.Errorf("not valid YAML: %w", err)
	}
	n := 0
	for i := range f.Actions {
		c := &f.Actions[i]
		// Named as the server reads them back (see load).
		c.Normalize()
		name := c.Name
		err := c.eachSecret(func(part, label, v string) (string, error) {
			nv, err := fn(secrets.Stored{Field: FileField(name, part), Label: "actions[" + name + "] " + label, Value: v})
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
	out, err := encodeFile(f)
	return out, n, err
}
