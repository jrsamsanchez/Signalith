package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Where the feeds added on the page are kept, and the feeds' status, is
// up to the server: in files of its own (FileList and StatusFile), or,
// when several servers share one OpenSearch, in shared documents every
// server reads. Feeds only sees these interfaces.

// FeedSet is the feeds a FeedList keeps, in the order added, and the
// deleted feeds whose indicators were kept to age out.
type FeedSet struct {
	UI   []FeedSpec
	Kept []KeptFeed
}

// Clone returns a deep copy.
func (s FeedSet) Clone() FeedSet {
	return FeedSet{UI: cloneSpecs(s.UI), Kept: slices.Clone(s.Kept)}
}

// FeedList keeps the feeds that can be changed on the Threat intel page.
type FeedList interface {
	// Load returns the feeds; an error means they cannot be read now, and
	// nothing may be removed or changed on the strength of them.
	Load() (FeedSet, error)
	// Mutate changes the feeds with fn, which checks what must hold and
	// may return an error to change nothing. fn gets a copy of the latest
	// feeds and may run again on a newer copy when another server changed
	// them in between. by is the user, for the record.
	Mutate(ctx context.Context, by string, fn func(*FeedSet) error) (FeedSet, error)
	// OnChange adds a function called after the feeds changed, here or on
	// another server. It must not block.
	OnChange(fn func())
}

// ErrFeedsUnavailable is a shared feed list that cannot be read now.
var ErrFeedsUnavailable = errors.New("the shared list of feeds cannot be read from OpenSearch right now, so feeds cannot be changed; try again in a moment")

// FileList keeps the feeds added on the page in a YAML file (see
// feedfile.go). An empty Path keeps them in memory only.
type FileList struct {
	Path string
	Now  func() time.Time
	Log  *slog.Logger

	mu   sync.Mutex
	read bool
	set  FeedSet
	err  error
	subs []func()
}

func (l *FileList) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *FileList) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return slog.Default()
}

// load reads the file once, and again while it cannot be read, so a
// fixed file takes effect without a restart; the caller holds l.mu.
func (l *FileList) load() {
	if l.read && l.err == nil {
		return
	}
	l.read, l.err, l.set = true, nil, FeedSet{}
	if l.Path == "" {
		return
	}
	data, err := os.ReadFile(l.Path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		l.err = &FileError{Path: l.Path, Err: err}
		return
	}
	var ff feedsFile
	if err := yaml.Unmarshal(data, &ff); err != nil {
		l.err = &FileError{Path: l.Path, Err: err}
		return
	}
	for i := range ff.Feeds {
		s := &ff.Feeds[i]
		s.eachSecret(func(part, label, v string) (string, error) {
			plain, err := secrets.Open(FeedsFileField(s.Name, part), v)
			if err != nil {
				l.log().Warn("a saved secret of a threat intel feed cannot be decrypted; edit the feed and enter it again",
					"feed", s.Name, "secret", label, "file", l.Path, "err", err)
				return v, nil
			}
			return plain, nil
		})
		s.Defaults()
	}
	l.set = FeedSet{UI: ff.Feeds, Kept: ff.Kept}
}

// Load implements FeedList.
func (l *FileList) Load() (FeedSet, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	if l.err != nil {
		return FeedSet{}, l.err
	}
	return l.set.Clone(), nil
}

// Mutate implements FeedList. A file that cannot be read is never
// written over.
func (l *FileList) Mutate(_ context.Context, _ string, fn func(*FeedSet) error) (FeedSet, error) {
	l.mu.Lock()
	l.load()
	if l.err != nil {
		l.mu.Unlock()
		return FeedSet{}, l.err
	}
	next := l.set.Clone()
	if err := fn(&next); err != nil {
		l.mu.Unlock()
		return FeedSet{}, err
	}
	if err := l.save(next); err != nil {
		l.mu.Unlock()
		return FeedSet{}, err
	}
	l.set = next
	subs := slices.Clone(l.subs)
	out := next.Clone()
	l.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
	return out, nil
}

// OnChange implements FeedList.
func (l *FileList) OnChange(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.subs = append(l.subs, fn)
}

// save writes the file; the caller holds l.mu.
func (l *FileList) save(set FeedSet) error {
	if l.Path == "" {
		return nil
	}
	now := l.now()
	var live []KeptFeed
	for _, k := range set.Kept {
		if k.Until.After(now) {
			live = append(live, k)
		}
	}
	sealed := make([]FeedSpec, len(set.UI))
	for i, s := range set.UI {
		c := s.clone()
		err := c.eachSecret(func(part, _, v string) (string, error) {
			return secrets.Seal(FeedsFileField(c.Name, part), v)
		})
		if err != nil {
			return fmt.Errorf("could not save %s: %w", l.Path, err)
		}
		sealed[i] = c
	}
	data, err := encodeFeedsFile(feedsFile{Feeds: sealed, Kept: live})
	if err != nil {
		return err
	}
	if err := securefile.WriteFile(l.Path, data); err != nil {
		return fmt.Errorf("could not save %s: %w", l.Path, err)
	}
	return nil
}

// StatusStore keeps each feed's status across restarts.
type StatusStore interface {
	// Load returns every saved status.
	Load() map[string]*FeedStatus
	// Save keeps one feed's status; nil removes it. It must not block for
	// long: Feeds calls it while it holds its lock.
	Save(name string, st *FeedStatus)
}

// liveStatus is a StatusStore other servers write too: a server that
// does not download feeds reads it again whenever it shows them.
type liveStatus interface{ Live() bool }

// StatusFile keeps the feeds' status in a JSON file; an empty Path keeps
// it in memory only.
type StatusFile struct {
	Path string
	Log  *slog.Logger

	mu   sync.Mutex
	all  map[string]*FeedStatus
	read bool
}

func (s *StatusFile) load() {
	if s.read {
		return
	}
	s.read, s.all = true, map[string]*FeedStatus{}
	if s.Path == "" {
		return
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	var saved map[string]*FeedStatus
	if json.Unmarshal(data, &saved) == nil {
		for name, st := range saved {
			if st != nil {
				s.all[name] = st
			}
		}
	}
}

// Load implements StatusStore.
func (s *StatusFile) Load() map[string]*FeedStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	out := make(map[string]*FeedStatus, len(s.all))
	for name, st := range s.all {
		c := *st
		out[name] = &c
	}
	return out
}

// Save implements StatusStore; the file is written again whole.
func (s *StatusFile) Save(name string, st *FeedStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	if st == nil {
		delete(s.all, name)
	} else {
		c := *st
		s.all[name] = &c
	}
	if s.Path == "" {
		return
	}
	data, err := json.MarshalIndent(s.all, "", "  ")
	if err != nil {
		return
	}
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
		log.Warn("could not save threat intel feed status", "file", s.Path, "err", err)
		return
	}
	if err := replaceFile(s.Path, data); err != nil {
		log.Warn("could not save threat intel feed status", "file", s.Path, "err", err)
	}
}
