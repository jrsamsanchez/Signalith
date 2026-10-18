// Package setupguide keeps what each user chose about the setup guide,
// the walkthrough Signalith offers on first use: whether to show it, when
// to ask again, and which steps they skipped or opened.
//
// A choice belongs to one user and follows them from browser to browser,
// so it lives in OpenSearch, in one document of the runtime index
// (<prefix>_runtime/setupguide:<user>). A tenant's server has its own
// prefix, so a tenant's users keep theirs with the tenant's data.
package setupguide

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// States of the guide.
const (
	// New is a user who has not answered yet: the guide opens on its own.
	New = ""
	// Started is a user who began the guide: it stays one click away at
	// the top of the page, and does not open on its own again.
	Started = "started"
	// Later is "Ask me later": it opens on its own again at Until.
	Later = "later"
	// Never is "Don't ask again": it never opens on its own, and is still
	// in the account menu.
	Never = "never"
	// Done is a user who finished or skipped every step.
	Done = "done"
)

// LaterFor is how long "Ask me later" waits.
const LaterFor = 24 * time.Hour

// MaxSteps bounds the step IDs a choice keeps; IDs are short words.
const (
	MaxSteps  = 32
	maxStepID = 32
)

// ErrBadChoice is a choice with an unknown state or a malformed step.
var ErrBadChoice = errors.New("unknown setup guide choice")

// Choice is what a user chose.
type Choice struct {
	State string `json:"state"`
	// Until is when "Ask me later" asks again.
	Until *time.Time `json:"until,omitempty"`
	// Skipped are the steps they skipped, and Opened those whose page
	// they opened from the guide (for steps Signalith cannot check).
	Skipped []string  `json:"skipped,omitempty"`
	Opened  []string  `json:"opened,omitempty"`
	At      time.Time `json:"at"`
}

// Ask reports whether the guide should open on its own at now.
func (c Choice) Ask(now time.Time) bool {
	switch c.State {
	case New:
		return true
	case Later:
		return c.Until == nil || !now.Before(*c.Until)
	}
	return false
}

// Validate checks a choice a user sent and tidies its step lists.
func (c *Choice) Validate() error {
	switch c.State {
	case New, Started, Later, Never, Done:
	default:
		return ErrBadChoice
	}
	var err error
	if c.Skipped, err = steps(c.Skipped); err != nil {
		return err
	}
	c.Opened, err = steps(c.Opened)
	return err
}

func steps(in []string) ([]string, error) {
	if len(in) > MaxSteps {
		return nil, ErrBadChoice
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || len(s) > maxStepID || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz-") != "" {
			return nil, ErrBadChoice
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// Store keeps the users' choices.
type Store interface {
	// Get returns user's choice; a user with none has the zero Choice.
	Get(ctx context.Context, user string) (Choice, error)
	// Put saves user's choice.
	Put(ctx context.Context, user string, c Choice) error
}

// Memory keeps the choices in memory, for a server without OpenSearch and
// for tests.
type Memory struct {
	mu sync.Mutex
	m  map[string]Choice
}

func (m *Memory) Get(_ context.Context, user string) (Choice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.m[key(user)], nil
}

func (m *Memory) Put(_ context.Context, user string, c Choice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]Choice{}
	}
	m.m[key(user)] = c
	return nil
}

func key(user string) string { return strings.ToLower(user) }

// Docs reads and writes a document with its version. *store.Client has
// it.
type Docs interface {
	cluster.Doer
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
}

// OpenSearch keeps the choices in the runtime index.
type OpenSearch struct {
	Docs   Docs
	Prefix string

	mu    sync.Mutex
	ready bool // the runtime index is known to be there
}

const kind = "setup_guide"

// doc is a choice as the runtime index keeps it: the fields the index
// maps (kind, user, state, until, at), the step lists in body, which it
// keeps without indexing.
type doc struct {
	Kind  string     `json:"kind"`
	User  string     `json:"user"`
	State string     `json:"state"`
	Until *time.Time `json:"until,omitempty"`
	At    time.Time  `json:"at"`
	Body  struct {
		Skipped []string `json:"skipped,omitempty"`
		Opened  []string `json:"opened,omitempty"`
	} `json:"body"`
}

func docID(user string) string { return "setupguide:" + key(user) }

func (o *OpenSearch) index() string { return cluster.RuntimeIndex(o.Prefix) }

func (o *OpenSearch) Get(ctx context.Context, user string) (Choice, error) {
	c, _, err := o.read(ctx, user)
	return c, err
}

func (o *OpenSearch) read(ctx context.Context, user string) (Choice, store.Version, error) {
	raw, v, found, err := o.Docs.Get(ctx, o.index(), docID(user))
	if err != nil || !found {
		return Choice{}, v, err
	}
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return Choice{}, v, err
	}
	return Choice{State: d.State, Until: d.Until, Skipped: d.Body.Skipped, Opened: d.Body.Opened, At: d.At}, v, nil
}

// Put writes the choice over whatever is there: the user's latest
// answer wins. A write that races another (the same user in two
// browsers) reads again and tries once more.
func (o *OpenSearch) Put(ctx context.Context, user string, c Choice) error {
	d := doc{Kind: kind, User: key(user), State: c.State, Until: c.Until, At: c.At}
	d.Body.Skipped, d.Body.Opened = c.Skipped, c.Opened
	var err error
	for range 3 {
		var v store.Version
		if _, v, err = o.read(ctx, user); err != nil {
			return err
		}
		if v.IsZero() {
			if err = o.ensure(ctx); err != nil {
				return err
			}
			_, err = o.Docs.Create(ctx, o.index(), docID(user), d, false)
		} else {
			_, err = o.Docs.PutIf(ctx, o.index(), docID(user), d, v, false)
		}
		if !errors.Is(err, store.ErrExists) && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

// ensure makes the runtime index once, so the first choice on a new
// install does not land in an index OpenSearch guessed the fields of.
func (o *OpenSearch) ensure(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ready {
		return nil
	}
	if err := cluster.EnsureRuntime(ctx, o.Docs, o.Prefix); err != nil {
		return err
	}
	o.ready = true
	return nil
}
