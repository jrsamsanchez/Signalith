// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
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

// NotesFile keeps a server's notes in its state folder.
const NotesFile = "compliance-notes.json"

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

// NoteStore keeps the admins' notes on controls: Notes in a file on this
// server, or the shared settings of a cluster (internal/clustercomp).
type NoteStore interface {
	// All returns every note, keyed by Key.
	All() map[string]Attestation
	// Err is why the notes could not be read, if they could not.
	Err() error
	// Set saves a note on a control, or removes it when status is empty.
	Set(ctx context.Context, framework, control string, status Status, note, by string, now time.Time) (*Attestation, error)
}

// CheckNote checks a note an admin asks to save and returns its text
// trimmed: the control must be one Signalith maps, and a note needs words.
func CheckNote(framework, control string, status Status, note string) (string, error) {
	f, ok := FrameworkByID(framework)
	if !ok {
		return "", &InputError{"There is no framework " + framework + "."}
	}
	if !slices.ContainsFunc(f.Controls, func(c Control) bool { return c.ID == control }) {
		return "", &InputError{fmt.Sprintf("%s has no control %s that Signalith maps.", f.Name, control)}
	}
	note = strings.TrimSpace(note)
	switch status {
	case "":
	case External, NotApplicable:
		if note == "" {
			return "", &InputError{"Say how the control is handled, or why it does not apply, so an auditor can follow it."}
		}
		if utf8.RuneCountInString(note) > MaxNote {
			return "", &InputError{fmt.Sprintf("The note can be at most %d characters.", MaxNote)}
		}
	default:
		return "", &InputError{`status must be "external", "na" or empty`}
	}
	return note, nil
}

// Set saves a note on a control, or removes it when status is empty.
func (n *Notes) Set(_ context.Context, framework, control string, status Status, note, by string, now time.Time) (*Attestation, error) {
	note, err := CheckNote(framework, control, status, note)
	if err != nil {
		return nil, err
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
		if err := WriteNotesFile(n.path, next); err != nil {
			return nil, err
		}
	}
	n.m = next
	return a, nil
}

// WriteNotesFile writes notes, keyed by Key, as a server keeps them in
// its state folder (NotesFile).
func WriteNotesFile(path string, notes map[string]Attestation) error {
	b, err := json.MarshalIndent(notesFile{Notes: notes}, "", "  ")
	if err != nil {
		return err
	}
	return securefile.WriteFile(path, append(b, '\n'))
}
