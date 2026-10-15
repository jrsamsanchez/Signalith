// Package clustercfg puts the content of the shared settings to use:
// the threat intel feed list and its status, the retention policies and
// the settings of the Settings page, as documents of the shared
// configuration (internal/shared) rather than each server's files. It has the adapters the intel and retention
// packages use (FeedList, StatusStore, PolicyStore), the importers that
// move the founder's files into the cluster, and the step that applies a
// changed signalith.yaml to the shared values ("applied when changed").
package clustercfg

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Document ids and kinds.
const (
	FeedsID        = "feeds"
	RetentionID    = "retention"
	FeedStatusKind = "feedstatus"
)

// Sources of a shared value, in From.
const (
	FromYAML   = "yaml"
	FromEnv    = "env"
	FromImport = "import"
	FromPage   = "page"
	// FromApply is a change made with signalith cluster apply or
	// signalith settings reset.
	FromApply = "apply"
)

// From says where a shared value came from: the page, a server's
// signalith.yaml (applied when it changed) or the founder's files.
type From struct {
	Source string `json:"source"`
	Node   string `json:"node,omitempty"`
	At     string `json:"at,omitempty"`
}

// Docs holds the shared documents of the content, made again on each hub
// the runtime builds (Track is its RuntimeOptions.Content), and passes
// their changes to whoever uses them now. Each start of the server's
// components subscribes again after Reset, so a component of a start
// that ended hears nothing more.
type Docs struct {
	mu        sync.Mutex
	hub       *shared.Hub
	feeds     *shared.Doc[FeedsBody]
	retention *shared.Doc[RetentionBody]
	settings  *shared.Doc[SettingsBody]
	subs      map[string][]func()
	// auth holds the users and directory sign-in documents, for their
	// import and the settings of signalith.yaml applied to them.
	auth *clusterauth.Docs
}

// Kinds of change subscribers hear of.
const (
	changeFeeds     = "feeds"
	changeRetention = "retention"
	changeIntel     = "intel"
	changeSettings  = "settings"
)

// NewDocs returns the holder; the runtime makes the documents.
func NewDocs() *Docs { return &Docs{subs: map[string][]func(){}} }

// Track makes the documents on h.
func (d *Docs) Track(h *shared.Hub) {
	feeds := shared.NewDoc[FeedsBody](h, FeedsID, "feeds", 1)
	ret := shared.NewDoc[RetentionBody](h, RetentionID, "retention", 1)
	settings := shared.NewDoc[SettingsBody](h, SettingsID, SettingsKind, 1)
	feeds.OnChange(func(_, _ *FeedsBody) { d.fire(changeFeeds) })
	ret.OnChange(func(_, _ *RetentionBody) { d.fire(changeRetention) })
	settings.OnChange(func(_, _ *SettingsBody) { d.fire(changeSettings) })
	// Every intel write bumps watch:intel; each server then reloads its
	// indicators.
	h.Watch("intel", func(context.Context) error {
		d.fire(changeIntel)
		return nil
	})
	d.mu.Lock()
	d.hub, d.feeds, d.retention, d.settings = h, feeds, ret, settings
	d.mu.Unlock()
}

// Reset forgets every subscriber, at each start of the components.
func (d *Docs) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs = map[string][]func(){}
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

// OnRetention adds a function called after the retention policies
// changed, here or on another server.
func (d *Docs) OnRetention(fn func()) { d.on(changeRetention, fn) }

// OnSettings adds a function called after the shared settings of the
// Settings page changed, here or on another server.
func (d *Docs) OnSettings(fn func()) { d.on(changeSettings, fn) }

// OnIntel adds a function called when another server says it changed the
// threat intel indicators. It must not block.
func (d *Docs) OnIntel(fn func()) { d.on(changeIntel, fn) }

// UseAuth sets the documents of the users and the directory sign-in
// settings, which the users and directory importers fill and to which
// auth.* in signalith.yaml is applied. Set it before Importers.
func (d *Docs) UseAuth(a *clusterauth.Docs) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.auth = a
}

// Auth returns the documents of the users and the directory sign-in
// settings, or nil.
func (d *Docs) Auth() *clusterauth.Docs {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.auth
}

// Hub returns the hub the documents are on.
func (d *Docs) Hub() *shared.Hub {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hub
}

// Feeds returns the feed list document.
func (d *Docs) Feeds() *shared.Doc[FeedsBody] {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.feeds
}

// Retention returns the retention policies document.
func (d *Docs) Retention() *shared.Doc[RetentionBody] {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.retention
}

// Settings returns the document of the shared settings of the Settings
// page.
func (d *Docs) Settings() *shared.Doc[SettingsBody] {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.settings
}

// stamp is a From of source now, on node.
func stamp(source, node string, now time.Time) *From {
	return &From{Source: source, Node: node, At: now.UTC().Format(time.RFC3339Nano)}
}
