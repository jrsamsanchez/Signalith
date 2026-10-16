// Package clusterparsers keeps the custom parsers in the shared settings
// of a cluster, so every server parses alike whichever one an agent sends
// to. A server that is not a member keeps them in its state folder
// (onboard.FileStore).
package clusterparsers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/onboard"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The parsers' documents: one per parser, parser:<name>.
const (
	Kind   = "parser"
	Watch  = "parsers"
	Format = 1
	// ImportName names the importer and exporter of the parsers.
	ImportName = "custom-parsers"
)

// ParserBody is one parser.
type ParserBody struct {
	onboard.Parser
	shared.Extra `json:"-"`
}

func validate(b *ParserBody) error { return b.Validate() }

func validateItem(name string, b *ParserBody) error {
	if name != b.Name {
		return fmt.Errorf("the parser %q is filed under the wrong name", name)
	}
	return nil
}

// Parsers holds the parsers' documents, made again on each hub the
// runtime builds (Track). It is an onboard.Store.
type Parsers struct {
	// Writable says why the shared settings cannot be changed on this
	// server now (shared.Runtime.Writable); nil allows changes.
	Writable func() error

	mu  sync.Mutex
	c   *shared.Collection[ParserBody]
	gen atomic.Uint64
}

// New returns the holder; Track makes the collection.
func New(writable func() error) *Parsers { return &Parsers{Writable: writable} }

// Track makes the collection on h.
func (p *Parsers) Track(h *shared.Hub) {
	c := shared.NewCollection[ParserBody](h, Kind, Watch, Format)
	c.Validate, c.ValidateItem = validate, validateItem
	c.OnChange(func() { p.gen.Add(1) })
	p.mu.Lock()
	p.c = c
	p.mu.Unlock()
	p.gen.Add(1)
}

// Reset is for the sharedTracker interface: the holder keeps no
// subscribers.
func (p *Parsers) Reset() {}

var errClosed = errors.New("the shared settings are not open")

func (p *Parsers) coll() (*shared.Collection[ParserBody], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c == nil {
		return nil, errClosed
	}
	return p.c, nil
}

// List returns every parser, by name.
func (p *Parsers) List() []onboard.Parser {
	c, err := p.coll()
	if err != nil {
		return nil
	}
	var out []onboard.Parser
	for _, it := range c.List() {
		if it.Value != nil {
			out = append(out, it.Value.Parser)
		}
	}
	return out
}

// Get returns a parser.
func (p *Parsers) Get(name string) (onboard.Parser, bool) {
	c, err := p.coll()
	if err != nil {
		return onboard.Parser{}, false
	}
	v, _, ok := c.Get(name)
	if !ok {
		return onboard.Parser{}, false
	}
	return v.Parser, true
}

// Gen changes whenever the parsers change, on any server.
func (p *Parsers) Gen() uint64 { return p.gen.Load() }

// Err says why the parsers cannot be read, if they cannot.
func (p *Parsers) Err() error {
	_, err := p.coll()
	return err
}

// Put saves a parser. A parser someone changed meanwhile is written over:
// the last admin to save wins.
func (p *Parsers) Put(ctx context.Context, parser onboard.Parser, by string) error {
	if err := p.writable(); err != nil {
		return err
	}
	c, err := p.coll()
	if err != nil {
		return err
	}
	parser.UpdatedBy, parser.UpdatedAt = by, time.Now().UTC().Truncate(time.Second)
	body := &ParserBody{Parser: parser}
	return p.retry(ctx, c, parser.Name, func() error {
		it, ok := c.Item(parser.Name)
		if ok {
			_, err := c.SaveIf(ctx, by, parser.Name, body, it.ETag)
			return err
		}
		if n := len(c.List()); n >= onboard.MaxParsers {
			return &onboard.InputError{Msg: fmt.Sprintf("There are %d custom parsers already, the most Signalith keeps.", n)}
		}
		_, err := c.Create(ctx, by, parser.Name, body)
		return err
	})
}

// Delete removes a parser.
func (p *Parsers) Delete(ctx context.Context, name, by string) error {
	if err := p.writable(); err != nil {
		return err
	}
	c, err := p.coll()
	if err != nil {
		return err
	}
	return p.retry(ctx, c, name, func() error {
		it, ok := c.Item(name)
		if !ok {
			return onboard.ErrNotFound
		}
		_, err := c.Delete(ctx, by, name, it.ETag)
		return err
	})
}

func (p *Parsers) writable() error {
	if p.Writable != nil {
		return p.Writable()
	}
	return nil
}

// retry runs write again, after reading the item afresh, when another
// server wrote it in between.
func (p *Parsers) retry(ctx context.Context, c *shared.Collection[ParserBody], name string, write func() error) error {
	for try := 0; ; try++ {
		err := write()
		var stale *shared.StaleError
		if try < 2 && (errors.As(err, &stale) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrNotFound)) {
			if err := c.Refresh(ctx, name); err != nil {
				return err
			}
			continue
		}
		if err == nil {
			p.gen.Add(1)
		}
		return err
	}
}

// Importer moves the parsers of this server's file (path, read when it
// runs) into the shared settings when the server founds or joins a
// cluster. A parser the cluster already has keeps the cluster's.
func Importer(p *Parsers, path func() string) shared.Importer {
	read := func() ([]onboard.Parser, []byte, error) {
		f := path()
		if f == "" {
			return nil, nil, nil
		}
		raw, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		ps, err := onboard.ReadFile(f)
		return ps, raw, err
	}
	return shared.Importer{
		Name: ImportName,
		Source: func() (string, error) {
			ps, raw, err := read()
			if err != nil || len(ps) == 0 {
				return "", err
			}
			sum := sha256.Sum256(raw)
			return "sha256:" + hex.EncodeToString(sum[:]), nil
		},
		Run: func(ctx context.Context, by string) error {
			ps, _, err := read()
			if err != nil {
				return err
			}
			c, err := p.coll()
			if err != nil {
				return err
			}
			for _, parser := range ps {
				_, err := c.Create(ctx, by, parser.Name, &ParserBody{Parser: parser})
				if err != nil && !errors.Is(err, store.ErrExists) {
					return fmt.Errorf("the custom parser %s: %w", parser.Name, err)
				}
			}
			p.gen.Add(1)
			return nil
		},
	}
}

// Exporter writes the shared parsers back as the file a server on its own
// keeps (path, its own), for signalith cluster export.
func Exporter(p *Parsers, path func() string) shared.Exporter {
	return shared.Exporter{Name: ImportName, Run: func(_ context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
		dest := path()
		ps := p.List()
		if dest == "" || len(ps) == 0 {
			return nil, nil
		}
		out := t.Under(dest)
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return nil, err
		}
		if err := onboard.WriteFile(out, ps); err != nil {
			return nil, err
		}
		return []shared.ExportedFile{{Path: out, Dest: dest}}, nil
	}}
}
