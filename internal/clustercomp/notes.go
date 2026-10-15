// Package clustercomp keeps the admins' notes on compliance controls in
// the shared settings of a cluster, so every server shows the same notes
// on the Compliance page and in its reports. A server that is not a member
// keeps them in its state folder (compliance.Notes).
package clustercomp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The notes' documents: one per control, compnote:<framework>.<control>.
// Framework ids hold no dot, so the name reads back unambiguously.
const (
	Kind   = "compnote"
	Watch  = "compnotes"
	Format = 1
	// ImportName names the importer and exporter of the notes.
	ImportName = "compliance-notes"
)

// NoteBody is a note on one control.
type NoteBody struct {
	Framework    string            `json:"framework"`
	Control      string            `json:"control"`
	Status       compliance.Status `json:"status"`
	Note         string            `json:"note"`
	By           string            `json:"by"`
	At           time.Time         `json:"at"`
	shared.Extra `json:"-"`
}

// Name is the item name of the note on a control.
func Name(framework, control string) string { return framework + "." + control }

func validate(b *NoteBody) error {
	if b.Status != compliance.External && b.Status != compliance.NotApplicable {
		return fmt.Errorf("a note's status is external or na, not %q", b.Status)
	}
	if _, err := compliance.CheckNote(b.Framework, b.Control, b.Status, b.Note); err != nil {
		return err
	}
	return nil
}

func validateItem(name string, b *NoteBody) error {
	if name != Name(b.Framework, b.Control) {
		return fmt.Errorf("the note %q is filed under the wrong control", name)
	}
	return nil
}

// Notes holds the notes' documents, made again on each hub the runtime
// builds (Track). It is a compliance.NoteStore.
type Notes struct {
	// Writable says why the shared settings cannot be changed on this
	// server now (shared.Runtime.Writable); nil allows changes.
	Writable func() error

	mu sync.Mutex
	c  *shared.Collection[NoteBody]
}

// New returns the holder; Track makes the collection.
func New(writable func() error) *Notes { return &Notes{Writable: writable} }

// Track makes the collection on h.
func (n *Notes) Track(h *shared.Hub) {
	c := shared.NewCollection[NoteBody](h, Kind, Watch, Format)
	c.Validate, c.ValidateItem = validate, validateItem
	n.mu.Lock()
	n.c = c
	n.mu.Unlock()
}

// Reset is for the sharedTracker interface: the holder keeps no
// subscribers.
func (n *Notes) Reset() {}

var errClosed = errors.New("the shared settings are not open")

func (n *Notes) coll() (*shared.Collection[NoteBody], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.c == nil {
		return nil, errClosed
	}
	return n.c, nil
}

// All returns every note, keyed by compliance.Key.
func (n *Notes) All() map[string]compliance.Attestation {
	out := map[string]compliance.Attestation{}
	c, err := n.coll()
	if err != nil {
		return out
	}
	for _, it := range c.List() {
		b := it.Value
		out[compliance.Key(b.Framework, b.Control)] = compliance.Attestation{Status: b.Status, Note: b.Note, By: b.By, At: b.At}
	}
	return out
}

// Err says why the notes cannot be read, if they cannot.
func (n *Notes) Err() error {
	_, err := n.coll()
	return err
}

// Set saves a note on a control, or removes it when status is empty. A
// note someone changed meanwhile is written over: the last admin to save
// wins, as with the file.
func (n *Notes) Set(ctx context.Context, framework, control string, status compliance.Status, note, by string, now time.Time) (*compliance.Attestation, error) {
	note, err := compliance.CheckNote(framework, control, status, note)
	if err != nil {
		return nil, err
	}
	if n.Writable != nil {
		if err := n.Writable(); err != nil {
			return nil, err
		}
	}
	c, err := n.coll()
	if err != nil {
		return nil, err
	}
	name := Name(framework, control)
	var body *NoteBody
	if status != "" {
		body = &NoteBody{Framework: framework, Control: control, Status: status, Note: note, By: by, At: now.UTC().Truncate(time.Second)}
	}
	for try := 0; ; try++ {
		err = n.write(ctx, c, by, name, body)
		var stale *shared.StaleError
		if try < 2 && (errors.As(err, &stale) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrNotFound)) {
			// Another server wrote the note in between: read it and go again.
			if err := c.Refresh(ctx, name); err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	if err != nil || body == nil {
		return nil, err
	}
	return &compliance.Attestation{Status: body.Status, Note: body.Note, By: body.By, At: body.At}, nil
}

func (n *Notes) write(ctx context.Context, c *shared.Collection[NoteBody], by, name string, body *NoteBody) error {
	it, ok := c.Item(name)
	var err error
	switch {
	case body == nil && !ok:
		return nil
	case body == nil:
		_, err = c.Delete(ctx, by, name, it.ETag)
	case ok:
		_, err = c.SaveIf(ctx, by, name, body, it.ETag)
	default:
		_, err = c.Create(ctx, by, name, body)
	}
	return err
}

// Importer moves the notes of this server's file (path, read when it
// runs) into the shared settings when the server founds or joins a
// cluster. A control that already has a shared note keeps it.
func Importer(n *Notes, path func() string) shared.Importer {
	read := func() (map[string]compliance.Attestation, []byte, error) {
		p := path()
		if p == "" {
			return nil, nil, nil
		}
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		var f struct {
			Notes map[string]compliance.Attestation `json:"notes"`
		}
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		return f.Notes, b, nil
	}
	return shared.Importer{
		Name: ImportName,
		Source: func() (string, error) {
			notes, raw, err := read()
			if err != nil || len(notes) == 0 {
				return "", err
			}
			sum := sha256.Sum256(raw)
			return "sha256:" + hex.EncodeToString(sum[:]), nil
		},
		Run: func(ctx context.Context, by string) error {
			notes, _, err := read()
			if err != nil {
				return err
			}
			c, err := n.coll()
			if err != nil {
				return err
			}
			keys := make([]string, 0, len(notes))
			for k := range notes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				a := notes[k]
				fw, ctl, ok := strings.Cut(k, "/")
				if !ok {
					continue
				}
				body := &NoteBody{Framework: fw, Control: ctl, Status: a.Status, Note: a.Note, By: a.By, At: a.At.UTC()}
				if validate(body) != nil {
					// A control the mapping no longer lists, or a note an
					// older version took: left in the file.
					continue
				}
				_, err := c.Create(ctx, by, Name(fw, ctl), body)
				if err != nil && !errors.Is(err, store.ErrExists) {
					return fmt.Errorf("the note on %s %s: %w", fw, ctl, err)
				}
			}
			return nil
		},
	}
}

// Exporter writes the shared notes back as the file a server on its own
// keeps (path, its own), for signalith cluster export.
func Exporter(n *Notes, path func() string) shared.Exporter {
	return shared.Exporter{Name: ImportName, Run: func(_ context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
		dest := path()
		notes := n.All()
		if dest == "" || len(notes) == 0 {
			return nil, nil
		}
		out := t.Under(dest)
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return nil, err
		}
		if err := compliance.WriteNotesFile(out, notes); err != nil {
			return nil, err
		}
		return []shared.ExportedFile{{Path: out, Dest: dest}}, nil
	}}
}
