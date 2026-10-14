// Package clusterauth keeps the users, the directory sign-in settings and
// the sign-in sessions of the servers of a cluster in OpenSearch, so a
// person signs in once and is known on every server: the users as signed
// documents of the shared settings (internal/shared), with the backends
// the users package's Store and Directory work over; the sessions in the
// <prefix>_sessions index, behind cookies tagged with the cluster key;
// the sign-in lockouts and last sign-ins in the runtime index; and the
// leader's job that checks signed-in directory users again.
//
// It imports no configuration, so it can be tested on its own and the API
// can use it.
package clusterauth

import (
	"context"
	"encoding/json"
	"slices"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Document kinds, ids and watch documents.
const (
	UserKind      = "user"
	UsersWatch    = "users"
	DirectoryID   = "directory"
	SessionsWatch = "sessions"
	LocksWatch    = "locks"
)

// Docs holds the shared documents of the users and the directory sign-in
// settings, made again on each hub the runtime builds (Track is part of
// its RuntimeOptions.Content), and passes their changes, and those of the
// watch documents of the sessions and the lockouts, to whoever uses them
// now. Each start of the server's components subscribes again after
// Reset, as clustercfg.Docs.
type Docs struct {
	// Cluster returns the cluster document, which names the built-in
	// admin (ClusterBody.Builtin) and the cluster's id. Set it before
	// Track.
	Cluster func() *shared.Doc[shared.ClusterBody]

	mu        sync.Mutex
	hub       *shared.Hub
	users     *shared.Collection[UserBody]
	directory *shared.Doc[DirectoryBody]
	subs      map[string][]func()
	sessions  []func(ctx context.Context, raw json.RawMessage, v store.Version)
}

// Kinds of change subscribers hear of.
const (
	changeUsers     = "users"
	changeDirectory = "directory"
	changeLocks     = "locks"
)

// NewDocs returns the holder; the runtime makes the documents.
func NewDocs() *Docs { return &Docs{subs: map[string][]func(){}} }

// Track makes the documents on h.
func (d *Docs) Track(h *shared.Hub) {
	users := shared.NewCollection[UserBody](h, UserKind, UsersWatch, 1)
	users.ValidateItem = d.validateUser
	dir := shared.NewDoc[DirectoryBody](h, DirectoryID, DirectoryID, 1)
	users.OnChange(func() { d.fire(changeUsers) })
	dir.OnChange(func(_, _ *DirectoryBody) { d.fire(changeDirectory) })
	// A sign-out bumps watch:sessions with the id of the session ended,
	// so each server drops it from its cache.
	h.WatchDoc(SessionsWatch, func(ctx context.Context, raw json.RawMessage, v store.Version) error {
		d.mu.Lock()
		subs := slices.Clone(d.sessions)
		d.mu.Unlock()
		for _, fn := range subs {
			fn(ctx, raw, v)
		}
		return nil
	})
	// A lockout bumps watch:locks; each server reads the locks again.
	h.Watch(LocksWatch, func(context.Context) error {
		d.fire(changeLocks)
		return nil
	})
	d.mu.Lock()
	d.hub, d.users, d.directory = h, users, dir
	d.mu.Unlock()
}

// Reset forgets every subscriber, at each start of the components.
func (d *Docs) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs = map[string][]func(){}
	d.sessions = nil
}

func (d *Docs) on(kind string, fn func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs[kind] = append(d.subs[kind], fn)
}

func (d *Docs) fire(kind string) {
	d.mu.Lock()
	subs := slices.Clone(d.subs[kind])
	d.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// OnUsers adds a function called after users changed, here or on another
// server.
func (d *Docs) OnUsers(fn func()) { d.on(changeUsers, fn) }

// OnDirectory adds a function called after the directory sign-in
// settings changed, here or on another server.
func (d *Docs) OnDirectory(fn func()) { d.on(changeDirectory, fn) }

// OnLocks adds a function called when another server reported a lockout.
// It must not block.
func (d *Docs) OnLocks(fn func()) { d.on(changeLocks, fn) }

// onSessions adds a function called with watch:sessions whenever it
// moved.
func (d *Docs) onSessions(fn func(ctx context.Context, raw json.RawMessage, v store.Version)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions = append(d.sessions, fn)
}

// Hub returns the hub the documents are on.
func (d *Docs) Hub() *shared.Hub {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hub
}

// Users returns the collection of users.
func (d *Docs) Users() *shared.Collection[UserBody] {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.users
}

// Directory returns the directory sign-in settings document.
func (d *Docs) Directory() *shared.Doc[DirectoryBody] {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.directory
}

// clusterBody returns the cluster document's body, if it was read.
func (d *Docs) clusterBody() (*shared.ClusterBody, bool) {
	if d.Cluster == nil {
		return nil, false
	}
	c := d.Cluster()
	if c == nil {
		return nil, false
	}
	return c.Get()
}

// ClusterID returns the cluster's id, or "" before the cluster document
// was read.
func (d *Docs) ClusterID() string {
	b, ok := d.clusterBody()
	if !ok {
		return ""
	}
	return b.ClusterID
}

// key returns the cluster key that signs, or nil.
func (d *Docs) key() *shared.ClusterKey {
	h := d.Hub()
	if h == nil {
		return nil
	}
	return h.Keys().Active()
}

// keys returns the cluster keys this server accepts.
func (d *Docs) keys() *shared.KeySet {
	h := d.Hub()
	if h == nil {
		return nil
	}
	return h.Keys()
}
