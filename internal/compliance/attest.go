package compliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Attestation is an admin's note on a control that Signalith cannot show
// evidence for: it is handled outside Signalith, or does not apply.
type Attestation struct {
	Status Status    `json:"status"` // External or NotApplicable
	Note   string    `json:"note"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

// MaxNote is the longest note, in characters.
const MaxNote = 2000

// Key identifies a control across frameworks.
func Key(framework, control string) string { return framework + "/" + control }

// Notes keeps the admins' notes on controls in a file. It is safe for
// concurrent use.
type Notes struct {
	path string
	mu   sync.Mutex
	m    map[string]Attestation
	err  error
}

// NewNotes reads the notes from path; "" keeps them in memory only. A
// missing file is no notes.
func NewNotes(path string) *Notes {
	n := &Notes{path: path, m: map[string]Attestation{}}
	if path == "" {
		return n
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		n.err = err
	default:
		var f notesFile
		if err := json.Unmarshal(b, &f); err != nil {
			n.err = fmt.Errorf("%s: %w", path, err)
		} else if f.Notes != nil {
			n.m = f.Notes
		}
	}
	return n
}

type notesFile struct {
	Notes map[string]Attestation `json:"notes"`
}

// All returns a copy of every note, keyed by Key.
func (n *Notes) All() map[string]Attestation {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make(map[string]Attestation, len(n.m))
	for k, v := range n.m {
		out[k] = v
	}
	return out
}

// Err is why the notes file could not be read, if it could not.
func (n *Notes) Err() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.err
}

// InputError is a problem with what was asked.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

// Set saves a note on a control, or removes it when status is empty.
func (n *Notes) Set(framework, control string, status Status, note, by string, now time.Time) (*Attestation, error) {
	f, ok := FrameworkByID(framework)
	if !ok {
		return nil, &InputError{"There is no framework " + framework + "."}
	}
	found := false
	for _, c := range f.Controls {
		if c.ID == control {
			found = true
			break
		}
	}
	if !found {
		return nil, &InputError{fmt.Sprintf("%s has no control %s that Signalith maps.", f.Name, control)}
	}
	note = strings.TrimSpace(note)
	switch status {
	case "":
	case External, NotApplicable:
		if note == "" {
			return nil, &InputError{"Say how the control is handled, or why it does not apply, so an auditor can follow it."}
		}
		if utf8.RuneCountInString(note) > MaxNote {
			return nil, &InputError{fmt.Sprintf("The note can be at most %d characters.", MaxNote)}
		}
	default:
		return nil, &InputError{`status must be "external", "na" or empty`}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return nil, fmt.Errorf("the notes file could not be read, so it is not changed: %w", n.err)
	}
	next := make(map[string]Attestation, len(n.m)+1)
	for k, v := range n.m {
		next[k] = v
	}
	k := Key(framework, control)
	var a *Attestation
	if status == "" {
		delete(next, k)
	} else {
		a = &Attestation{Status: status, Note: note, By: by, At: now.UTC()}
		next[k] = *a
	}
	if n.path != "" {
		b, err := json.MarshalIndent(notesFile{Notes: next}, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := securefile.WriteFile(n.path, append(b, '\n')); err != nil {
			return nil, err
		}
	}
	n.m = next
	return a, nil
}
