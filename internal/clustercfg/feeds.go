package clustercfg

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// FeedsBody is the body of <prefix>_config/feeds: every feed (those
// from a server's signalith.yaml too, marked by From) and the deleted
// feeds whose indicators are kept to age out.
type FeedsBody struct {
	Feeds        []FeedEntry `json:"feeds"`
	Kept         []KeptEntry `json:"kept"`
	shared.Extra `json:"-"`
}

// FeedEntry is one feed. Its password and header values are sealed with
// the cluster key, bound to the feed, the setting and the address they
// are sent to (SecretField).
type FeedEntry struct {
	Name         string            `json:"name"`
	Kind         string            `json:"kind,omitempty"`
	URL          string            `json:"url"`
	Collection   string            `json:"collection,omitempty"`
	Format       string            `json:"format,omitempty"`
	Type         string            `json:"type,omitempty"`
	Column       string            `json:"column,omitempty"`
	Interval     string            `json:"interval,omitempty"`
	MaxAge       string            `json:"max_age,omitempty"`
	Weight       float64           `json:"weight,omitempty"`
	Description  string            `json:"description,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Username     string            `json:"username,omitempty"`
	Password     string            `json:"password,omitempty"`
	Enabled      *bool             `json:"enabled,omitempty"`
	Catalog      string            `json:"catalog,omitempty"`
	From         *From             `json:"from,omitempty"`
	shared.Extra `json:"-"`
}

// MarshalJSON writes the entry with the fields this version does not
// know.
func (e FeedEntry) MarshalJSON() ([]byte, error) {
	type plain FeedEntry
	return shared.MarshalExtra(plain(e), e.Extra)
}

// UnmarshalJSON reads the entry, keeping the fields this version does
// not know.
func (e *FeedEntry) UnmarshalJSON(data []byte) error {
	type plain FeedEntry
	var p plain
	extra, err := shared.UnmarshalExtra(data, &p)
	*e = FeedEntry(p)
	e.Extra = extra
	return err
}

// KeptEntry is a deleted feed whose indicators stay until Until.
type KeptEntry struct {
	Name  string    `json:"name"`
	Until time.Time `json:"until"`
}

// SecretField is the setting a shared feed secret is sealed for: part is
// password or headers.<name>, and the address it is sent to is part of
// it, so a value moved to another feed, setting or server cannot be
// opened: intel.feeds[otx].headers.X-OTX-API-KEY@https://otx.alienvault.com.
func SecretField(feed, part, rawURL string) string {
	return "intel.feeds[" + feed + "]." + part + "@" + origin(rawURL)
}

// origin is the scheme, host and port of an address, in lower case.
func origin(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(rawURL))
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// opener opens values sealed with any of the cluster keys this server
// has.
func opener(keys *shared.KeySet) secrets.Opener {
	var out []secrets.Opener
	if keys != nil {
		for _, id := range keys.IDs() {
			if k := keys.Get(id); k != nil {
				out = append(out, k.SecretsKey())
			}
		}
	}
	return secrets.Chain(out...)
}

// eachSecret calls fn for the password and each header value of e, and
// sets them to what it returns.
func eachSecret(e *FeedEntry, fn func(part, v string) (string, error)) error {
	if e.Password != "" {
		v, err := fn("password", e.Password)
		if err != nil {
			return err
		}
		e.Password = v
	}
	names := slices.Sorted(maps.Keys(e.Headers))
	for _, k := range names {
		if e.Headers[k] == "" {
			continue
		}
		v, err := fn("headers."+k, e.Headers[k])
		if err != nil {
			return err
		}
		e.Headers[k] = v
	}
	return nil
}

// specOf opens an entry into a feed's settings. A secret that cannot be
// opened stays sealed, and the feed shows a problem until it is entered
// again.
func specOf(e FeedEntry, open secrets.Opener) intel.FeedSpec {
	e.Headers = maps.Clone(e.Headers)
	_ = eachSecret(&e, func(part, v string) (string, error) {
		plain, err := open.Open(SecretField(e.Name, part, e.URL), v)
		if err != nil {
			return v, nil
		}
		return plain, nil
	})
	s := intel.FeedSpec{Name: e.Name, Kind: e.Kind, URL: e.URL, Collection: e.Collection, Format: e.Format, Type: e.Type,
		Column: e.Column, Interval: e.Interval, MaxAge: e.MaxAge, Weight: e.Weight, Description: e.Description,
		Tags: slices.Clone(e.Tags), Headers: e.Headers, Username: e.Username, Password: e.Password, Catalog: e.Catalog,
		From: e.From.note()}
	if e.Enabled != nil {
		on := *e.Enabled
		s.Enabled = &on
	}
	s.Defaults()
	return s
}

// entryOf seals a feed's settings into an entry, with the key k.
func entryOf(s intel.FeedSpec, k *shared.ClusterKey, from *From) (FeedEntry, error) {
	e := FeedEntry{Name: s.Name, Kind: s.Kind, URL: s.URL, Collection: s.Collection, Format: s.Format, Type: s.Type,
		Column: s.Column, Interval: s.Interval, MaxAge: s.MaxAge, Weight: s.Weight, Description: s.Description,
		Tags: slices.Clone(s.Tags), Headers: maps.Clone(s.Headers), Username: s.Username, Password: s.Password,
		Catalog: s.Catalog, From: from}
	if s.Enabled != nil {
		on := *s.Enabled
		e.Enabled = &on
	}
	if k == nil {
		return e, errors.New("this server has no cluster key")
	}
	err := eachSecret(&e, func(part, v string) (string, error) {
		return k.SecretsKey().Seal(SecretField(e.Name, part, e.URL), v)
	})
	return e, err
}

// note says where a feed came from, for the page; "" for the page.
func (f *From) note() string {
	if f == nil {
		return ""
	}
	var what string
	switch f.Source {
	case FromYAML:
		what = "applied from signalith.yaml"
	case FromImport:
		what = "imported from the files"
	default:
		return ""
	}
	if f.Node != "" {
		what += " on " + f.Node
	}
	if t, err := time.Parse(time.RFC3339Nano, f.At); err == nil {
		what += ", " + t.UTC().Format(time.DateOnly)
	}
	return what
}

// sameSpec reports whether two feeds' settings are the same, wherever
// they came from.
func sameSpec(a, b intel.FeedSpec) bool {
	a.From, b.From = "", ""
	a.Defaults()
	b.Defaults()
	if len(a.Headers) == 0 {
		a.Headers = nil
	}
	if len(b.Headers) == 0 {
		b.Headers = nil
	}
	if len(a.Tags) == 0 {
		a.Tags = nil
	}
	if len(b.Tags) == 0 {
		b.Tags = nil
	}
	return reflect.DeepEqual(a, b) && a.IsEnabled() == b.IsEnabled()
}

// decodeFeeds opens a feed list.
func decodeFeeds(b *FeedsBody, open secrets.Opener) intel.FeedSet {
	var set intel.FeedSet
	for _, e := range b.Feeds {
		set.UI = append(set.UI, specOf(e, open))
	}
	for _, k := range b.Kept {
		set.Kept = append(set.Kept, intel.KeptFeed{Name: k.Name, Until: k.Until})
	}
	return set
}

// encodeFeeds writes next into b, whose feeds opened are cur. A feed
// that did not change keeps its entry as it was (its sealed values, its
// origin and the fields this version does not know); one that changed is
// sealed again and marked with from.
func encodeFeeds(b *FeedsBody, cur, next intel.FeedSet, k *shared.ClusterKey, from func() *From, now time.Time) error {
	old := map[string]int{}
	for i, e := range b.Feeds {
		old[e.Name] = i
	}
	before := map[string]intel.FeedSpec{}
	for _, s := range cur.UI {
		before[s.Name] = s
	}
	feeds := make([]FeedEntry, 0, len(next.UI))
	for _, s := range next.UI {
		i, had := old[s.Name]
		if prev, ok := before[s.Name]; had && ok && sameSpec(prev, s) {
			feeds = append(feeds, b.Feeds[i])
			continue
		}
		e, err := entryOf(s, k, from())
		if err != nil {
			return err
		}
		if had {
			e.Extra = b.Feeds[i].Extra
		}
		feeds = append(feeds, e)
	}
	var kept []KeptEntry
	for _, kf := range next.Kept {
		if kf.Until.After(now) {
			kept = append(kept, KeptEntry{Name: kf.Name, Until: kf.Until.UTC()})
		}
	}
	b.Feeds, b.Kept = feeds, kept
	return nil
}

// FeedList is the shared feed list, for intel.Feeds.Saved.
type FeedList struct {
	Docs *Docs
	// Node is this server's name, recorded with each change.
	Node string
	Now  func() time.Time
}

func (l *FeedList) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// ETagKey implements intel.ETagKeyer: the feeds' versions are keyed with
// the cluster's MAC key, which every member has.
func (l *FeedList) ETagKey() []byte {
	if k := l.Docs.Hub().Keys().Active(); k != nil {
		return k.MACKey()
	}
	return nil
}

// Load implements intel.FeedList.
func (l *FeedList) Load() (intel.FeedSet, error) {
	body, ok := l.Docs.Feeds().Get()
	if !ok {
		return intel.FeedSet{}, intel.ErrFeedsUnavailable
	}
	return decodeFeeds(body, opener(l.Docs.Hub().Keys())), nil
}

// Mutate implements intel.FeedList.
func (l *FeedList) Mutate(ctx context.Context, by string, fn func(*intel.FeedSet) error) (intel.FeedSet, error) {
	var out intel.FeedSet
	keys := l.Docs.Hub().Keys()
	_, err := l.Docs.Feeds().Mutate(ctx, by, func(b *FeedsBody) error {
		cur := decodeFeeds(b, opener(keys))
		next := cur.Clone()
		if err := fn(&next); err != nil {
			return err
		}
		now := l.now()
		if err := encodeFeeds(b, cur, next, keys.Active(), func() *From { return stamp(FromPage, l.Node, now) }, now); err != nil {
			return err
		}
		out = next
		return nil
	})
	if err != nil {
		return intel.FeedSet{}, err
	}
	return out, nil
}

// OnChange implements intel.FeedList.
func (l *FeedList) OnChange(fn func()) { l.Docs.on(changeFeeds, fn) }

// statusDoc is <prefix>_runtime/feedstatus:<name>: a feed's status, as
// the server that runs the background jobs (at the lease epoch) wrote it.
type statusDoc struct {
	Kind  string           `json:"kind"`
	Name  string           `json:"name"`
	Node  string           `json:"node"`
	Epoch int64            `json:"epoch"`
	At    time.Time        `json:"at"`
	Body  intel.FeedStatus `json:"body"`
}

// StatusID is the id of a feed's status document.
func StatusID(name string) string { return FeedStatusKind + ":" + name }

// StatusStore keeps the feeds' status in the runtime index, where every
// server reads it: only the server that runs the background jobs writes
// it, with its lease epoch, and a status a later holder wrote is never
// written over. Writes go out in the background (Run), so a download
// never waits for them.
type StatusStore struct {
	Client *store.Client
	// Index is the runtime index, <prefix>_runtime.
	Index string
	// Node is this server's node id.
	Node string
	// Leads reports whether this server runs the background jobs now,
	// and Epoch is the job lease's epoch.
	Leads func() bool
	Epoch func() int64
	Log   *slog.Logger
	Now   func() time.Time

	mu      sync.Mutex
	cache   map[string]*intel.FeedStatus
	readAt  time.Time
	pending map[string]pendingStatus
	wake    chan struct{}
}

// pendingStatus is a status saved but not written yet, with the epoch of
// the job lease it was saved under.
type pendingStatus struct {
	st    *intel.FeedStatus
	epoch int64
}

// statusRetry is how long a status whose write failed waits before it is
// written again.
const statusRetry = 5 * time.Second

// statusCache is how long a read of every status is used again.
const statusCache = 2 * time.Second

func (s *StatusStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *StatusStore) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Live implements the intel package's liveStatus: other servers read
// it again whenever they show the feeds.
func (s *StatusStore) Live() bool { return true }

// Load implements intel.StatusStore. When the index cannot be read, the
// last copy read is used.
func (s *StatusStore) Load() map[string]*intel.FeedStatus {
	s.mu.Lock()
	fresh := s.cache != nil && s.now().Sub(s.readAt) < statusCache
	s.mu.Unlock()
	if !fresh {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		all, err := s.read(ctx)
		cancel()
		s.mu.Lock()
		if err == nil {
			for name, p := range s.pending {
				// Not written yet: this server's own is newer.
				if p.st != nil {
					c := *p.st
					all[name] = &c
				} else {
					delete(all, name)
				}
			}
			s.cache, s.readAt = all, s.now()
		} else {
			s.log().Debug("could not read the feeds' status", "err", err)
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*intel.FeedStatus, len(s.cache))
	for name, st := range s.cache {
		c := *st
		out[name] = &c
	}
	return out
}

func (s *StatusStore) read(ctx context.Context) (map[string]*intel.FeedStatus, error) {
	docs, err := s.Client.SearchDocs(ctx, s.Index, map[string]any{"term": map[string]any{"kind": FeedStatusKind}})
	if err != nil {
		return nil, err
	}
	out := map[string]*intel.FeedStatus{}
	for _, d := range docs {
		var sd statusDoc
		if json.Unmarshal(d.Source, &sd) != nil || sd.Name == "" || d.Ref.ID != StatusID(sd.Name) {
			continue
		}
		st := sd.Body
		out[sd.Name] = &st
	}
	return out, nil
}

// Save implements intel.StatusStore: only the server that runs the
// background jobs keeps the status.
func (s *StatusStore) Save(name string, st *intel.FeedStatus) {
	if s.Leads != nil && !s.Leads() {
		return
	}
	// The epoch is the one the status was made under: a write after the
	// lease was let go (the last one, at shutdown) still carries it.
	var epoch int64
	if s.Epoch != nil {
		epoch = s.Epoch()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = map[string]pendingStatus{}
	}
	if s.cache == nil {
		s.cache = map[string]*intel.FeedStatus{}
	}
	if st == nil {
		s.pending[name] = pendingStatus{epoch: epoch}
		delete(s.cache, name)
	} else {
		c, k := *st, *st
		c.Running, k.Running = false, false
		s.pending[name], s.cache[name] = pendingStatus{st: &c, epoch: epoch}, &k
	}
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *StatusStore) wakeCh() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	return s.wake
}

// Run writes the statuses saved, until ctx ends; what is left is written
// then, within a few seconds. A write that failed is tried again after
// statusRetry.
func (s *StatusStore) Run(ctx context.Context) {
	wake := s.wakeCh()
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			s.Flush(fctx)
			cancel()
			return
		case <-wake:
		case <-retry:
		}
		retry = nil
		if s.Flush(ctx) > 0 {
			retry = time.After(statusRetry)
		}
	}
}

// Flush writes the statuses saved so far. A status whose write failed is
// kept for the next flush, unless a newer one was saved meanwhile; it
// returns how many were kept.
func (s *StatusStore) Flush(ctx context.Context) int {
	s.mu.Lock()
	pending := s.pending
	s.pending = nil
	s.mu.Unlock()
	failed := 0
	for _, name := range slices.Sorted(maps.Keys(pending)) {
		p := pending[name]
		err := s.write(ctx, name, p.st, p.epoch)
		if err == nil {
			continue
		}
		s.log().Warn("could not save a threat intel feed's status; trying again", "feed", name, "err", err)
		s.mu.Lock()
		if s.pending == nil {
			s.pending = map[string]pendingStatus{}
		}
		if _, newer := s.pending[name]; !newer {
			s.pending[name] = p
			failed++
		}
		s.mu.Unlock()
	}
	return failed
}

// write writes one status made under the lease epoch, unless a later
// holder of the job lease wrote it.
func (s *StatusStore) write(ctx context.Context, name string, st *intel.FeedStatus, epoch int64) error {
	id := StatusID(name)
	for try := 0; try < 3; try++ {
		src, ver, found, err := s.Client.Get(ctx, s.Index, id)
		if err != nil {
			return err
		}
		if found {
			var cur statusDoc
			if json.Unmarshal(src, &cur) == nil && cur.Epoch > epoch {
				return nil
			}
		}
		switch {
		case st == nil && !found:
			return nil
		case st == nil:
			err = s.Client.DeleteIf(ctx, s.Index, id, ver, false)
		case found:
			_, err = s.Client.PutIf(ctx, s.Index, id, s.doc(name, epoch, st), ver, false)
		default:
			_, err = s.Client.Create(ctx, s.Index, id, s.doc(name, epoch, st), false)
		}
		if !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrExists) {
			return err
		}
	}
	return store.ErrConflict
}

func (s *StatusStore) doc(name string, epoch int64, st *intel.FeedStatus) statusDoc {
	return statusDoc{Kind: FeedStatusKind, Name: name, Node: s.Node, Epoch: epoch, At: s.now().UTC(), Body: *st}
}
