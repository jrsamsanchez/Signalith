package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Record is a user as a Backend keeps it: the user, their password hash
// (local users only), their session epoch, which a password change, a
// disable or a directory refusal moves on so their sessions end on every
// server, and the version read (ETag), for a change that must not undo
// another made since.
type Record struct {
	User
	Hash  string
	Epoch int64
	ETag  string
}

// Backend is where a Store keeps its users: the users file (Open), memory
// (NewMemory), or the shared configuration in OpenSearch for the servers
// of a cluster. The Store keeps its own copy for reads, made again from
// Load whenever the backend says something changed.
type Backend interface {
	// Load returns every user, by username.
	Load() (map[string]Record, error)
	// Create adds a user: ErrExists when the name is taken.
	Create(ctx context.Context, by string, r Record) (Record, error)
	// Change changes the user name with fn, on a copy of the user as it
	// is now (or as read at etag, when etag is set: ErrStale or another
	// error naming who changed it when it changed since). fn may return
	// an error to change nothing, or ErrNoChange to write nothing and get
	// the user as it is. A missing user is ErrNotFound.
	Change(ctx context.Context, by, name, etag string, fn func(*Record) error) (Record, error)
	// Delete removes the user name, read at etag when it is set, once
	// check, which gets the user as it is now, allows it.
	Delete(ctx context.Context, by, name, etag string, check func(Record) error) error
	// OnChange adds a function called after anything changed, whether
	// this server or another changed it. It must not call Change.
	OnChange(fn func())
}

var (
	// ErrNoChange, returned by a Backend.Change function, writes nothing.
	ErrNoChange = errors.New("nothing to change")
	// ErrStale refuses a change based on a version of the user that was
	// changed since.
	ErrStale = errors.New("this user was changed since you opened it; reload and try again")
)

// actorKey holds who makes a change, for the backends that record it.
type actorKey struct{}

// WithActor returns ctx naming the user who makes the changes made with
// it, which a shared backend records.
func WithActor(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, actorKey{}, user)
}

// Actor returns the user WithActor named, or "".
func Actor(ctx context.Context) string {
	s, _ := ctx.Value(actorKey{}).(string)
	return s
}

// storedUser is a user as written to the file, with the password hash and
// the session epoch.
type storedUser struct {
	User
	PasswordHash string `json:"password_hash,omitempty"`
	SessionEpoch int64  `json:"session_epoch,omitempty"`
}

type storeFile struct {
	Version           int          `json:"version"`
	Users             []storedUser `json:"users"`
	BuiltinLastSignIn *time.Time   `json:"builtin_last_sign_in,omitempty"`
}

// fileBackend keeps users in a JSON file, or in memory only when it has
// no path. Writes go to a temporary file that is renamed over the old
// one, so a crash never leaves half a file.
//
// Servers that share a lookups folder share the file, so another server
// may change it at any time. Every change is therefore made to the file
// as it is now, while holding a lock file next to it (see lockFile): the
// backend reads it again first when it changed since it last read or
// wrote it, and changes only what the change is about. A user disabled
// or deleted on one server stays so when another records a sign-in or
// edits someone else. The Store's reads look for changes at most once a
// second (refresh), so a disabled user is also refused on the other
// servers within a second or so.
type fileBackend struct {
	path string

	// wmu lets one change of this server's run at a time.
	wmu sync.Mutex

	mu          sync.RWMutex
	recs        map[string]Record
	builtinLast *time.Time
	// sum is the SHA-256 of the file as last read or written. The content
	// is compared, not the modification time, which some file systems
	// keep only to the second or two.
	sum [sha256.Size]byte
	// gen counts the times the file was read or written under mu, so a
	// read made without mu (refresh) is not applied over a newer one.
	gen uint64

	subsMu sync.Mutex
	subs   []func()
}

// ReadFile reads the users file at path, as a cluster's import does: every
// user with their password hash and session epoch, by username, and when
// the built-in admin last signed in. A file that is not there holds no
// users.
func ReadFile(path string) (map[string]Record, *time.Time, error) {
	f := newFileBackend(path)
	if _, err := f.reloadLocked(); err != nil {
		return nil, nil, err
	}
	return f.recs, f.builtinLast, nil
}

func newFileBackend(path string) *fileBackend {
	return &fileBackend{path: path, recs: map[string]Record{}}
}

// readUsersFile reads the users file; tests replace it.
var readUsersFile = os.ReadFile

func (f *fileBackend) OnChange(fn func()) {
	f.subsMu.Lock()
	defer f.subsMu.Unlock()
	f.subs = append(f.subs, fn)
}

func (f *fileBackend) notify() {
	f.subsMu.Lock()
	subs := append([]func(){}, f.subs...)
	f.subsMu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// etagOf is the version of a user: a digest of what an admin can see and
// change, so a sign-in recorded meanwhile does not make an edit stale.
func etagOf(r Record) string {
	u := r.User
	u.LastSignIn = nil
	data, _ := json.Marshal(storedUser{User: u, PasswordHash: r.Hash, SessionEpoch: r.Epoch})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

func (f *fileBackend) Load() (map[string]Record, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]Record, len(f.recs))
	for n, r := range f.recs {
		r.ETag = etagOf(r)
		out[n] = r
	}
	return out, nil
}

// reloadLocked reads the users file again when it changed since it was
// last read or written: another server that shares it wrote it. The
// caller holds mu. A file that is not there (yet) leaves the users as
// they are, and the next change writes it. A file that cannot be read or
// understood is an error, and the users stay as they were. It reports
// whether the users changed.
func (f *fileBackend) reloadLocked() (bool, error) {
	if f.path == "" {
		return false, nil
	}
	f.gen++
	data, err := readUsersFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return f.applyLocked(data)
}

// applyLocked takes the users from the file's content when it differs
// from what was last read or written. The caller holds mu.
func (f *fileBackend) applyLocked(data []byte) (bool, error) {
	sum := sha256.Sum256(data)
	if sum == f.sum {
		return false, nil
	}
	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return false, fmt.Errorf("users file %s is damaged (%v); fix it, or move it away and restart Signalith to start with only the built-in admin", f.path, err)
	}
	recs := map[string]Record{}
	for _, su := range sf.Users {
		u := su.User
		u.Username = NormalizeUsername(u.Username)
		if _, dup := recs[u.Username]; u.Username == "" || dup {
			return false, fmt.Errorf("users file %s lists an empty or repeated username %q", f.path, su.Username)
		}
		if u.Source != SourceDirectory {
			u.Source = SourceLocal
		}
		if !u.Role.Valid() {
			// An unknown role grants nothing.
			u.Role = Viewer
		}
		r := Record{User: u, Epoch: su.SessionEpoch}
		if u.Source == SourceLocal {
			r.Hash = su.PasswordHash
		}
		recs[u.Username] = r
	}
	f.recs, f.builtinLast, f.sum = recs, sf.BuiltinLastSignIn, sum
	return true, nil
}

// refresh brings the users up to date with changes another server made
// to the file. A file that cannot be read just then leaves the users as
// they were. The file is read without holding mu, so a shared folder
// that stops answering holds up only the caller.
func (f *fileBackend) refresh() {
	if f.path == "" {
		return
	}
	f.mu.RLock()
	gen := f.gen
	f.mu.RUnlock()
	data, err := readUsersFile(f.path)
	if err != nil {
		return
	}
	f.mu.Lock()
	if f.gen != gen {
		f.mu.Unlock()
		return // a change read or wrote the file meanwhile; that is newer
	}
	changed, _ := f.applyLocked(data)
	f.mu.Unlock()
	if changed {
		f.notify()
	}
}

// The lock file next to the users file lets one server at a time change
// it: each change reads the file, changes it and writes it back while it
// holds the lock, so no server writes over a change another made
// meanwhile. A change holds it for milliseconds. One left behind by a
// server that stopped mid-change is taken over once it has stayed the
// same for lockStale.
const lockPoll = 20 * time.Millisecond

// lockStale and lockWait are variables so tests can shorten them.
var (
	lockStale = 5 * time.Second
	lockWait  = 15 * time.Second
)

// ErrBusy says another server kept the users file locked too long.
var ErrBusy = errors.New("another Signalith server that shares the users file is still changing it; try again in a minute")

// lockFile takes the lock file and returns what releases it. A memory
// backend needs none.
func (f *fileBackend) lockFile() (func(), error) {
	if f.path == "" {
		return func() {}, nil
	}
	name := f.path + ".lock"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	token := fmt.Sprintf("%x", b)
	start := time.Now()
	seen, seenAt, made := "", time.Time{}, false
	for {
		fh, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, werr := fh.WriteString(token)
			if cerr := fh.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				_ = os.Remove(name)
				return nil, werr
			}
			return func() {
				if held, err := os.ReadFile(name); err == nil && string(held) == token {
					_ = os.Remove(name)
				}
			}, nil
		}
		if errors.Is(err, os.ErrNotExist) && !made {
			// The folder is made the way the users file's write makes it.
			made = true
			if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
				return nil, err
			}
			continue
		}
		// Windows refuses to create a file that is being removed with
		// access denied, so that is waited out too.
		if !errors.Is(err, os.ErrExist) && !errors.Is(err, os.ErrPermission) {
			return nil, err
		}
		now := time.Now()
		if held, rerr := os.ReadFile(name); rerr == nil {
			if seenAt.IsZero() || string(held) != seen {
				seen, seenAt = string(held), now
			} else if now.Sub(seenAt) >= lockStale {
				// The same holder all along: it stopped mid-change.
				_ = os.Remove(name)
				seen, seenAt = "", time.Time{}
				continue
			}
		}
		if now.Sub(start) >= lockWait {
			if errors.Is(err, os.ErrPermission) {
				return nil, fmt.Errorf("cannot create %s: %w", name, err)
			}
			return nil, ErrBusy
		}
		time.Sleep(lockPoll)
	}
}

// begin starts a change: it takes the lock file and reads the file as it
// is now, telling the subscribers when that changed the users, so checks
// over every user see them. The caller holds wmu, and calls the returned
// function once the change is written or given up.
func (f *fileBackend) begin() (func(), error) {
	release, err := f.lockFile()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	changed, err := f.reloadLocked()
	f.mu.Unlock()
	if err != nil {
		release()
		return nil, err
	}
	if changed {
		f.notify()
	}
	return release, nil
}

// saveLocked writes the file; the caller holds mu.
func (f *fileBackend) saveLocked() error {
	if f.path == "" {
		return nil
	}
	names := make([]string, 0, len(f.recs))
	for n := range f.recs {
		names = append(names, n)
	}
	sort.Strings(names)
	sf := storeFile{Version: 1, Users: make([]storedUser, 0, len(f.recs)), BuiltinLastSignIn: f.builtinLast}
	for _, n := range names {
		r := f.recs[n]
		sf.Users = append(sf.Users, storedUser{User: r.User, PasswordHash: r.Hash, SessionEpoch: r.Epoch})
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	// On Windows a file another program has open just then (another
	// server reading it from a shared folder, or a virus scanner) cannot
	// be replaced, so a failed write is tried again shortly.
	wait := 50 * time.Millisecond
	for try := 1; ; try++ {
		err = WriteFileAtomic(f.path, data)
		if err == nil || try == saveTries {
			break
		}
		time.Sleep(wait)
		wait *= 2
	}
	if err == nil {
		f.sum = sha256.Sum256(data)
		f.gen++
	}
	return err
}

// saveTries is how often a write of the users file is tried.
const saveTries = 3

// WriteFileAtomic replaces name with data whole, readable only by
// Signalith's own account; a file that is replaced keeps its permissions.
// See package securefile.
func WriteFileAtomic(name string, data []byte) error {
	return securefile.WriteFile(name, data)
}

// put writes r as user name (or removes the user when r is nil) and tells
// the subscribers; the file is left as it was when the write fails.
func (f *fileBackend) put(name string, r *Record) error {
	f.mu.Lock()
	old, had := f.recs[name]
	if r == nil {
		delete(f.recs, name)
	} else {
		f.recs[name] = *r
	}
	if err := f.saveLocked(); err != nil {
		if had {
			f.recs[name] = old
		} else {
			delete(f.recs, name)
		}
		f.mu.Unlock()
		return err
	}
	f.mu.Unlock()
	f.notify()
	return nil
}

func (f *fileBackend) current(name string) (Record, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	r, ok := f.recs[name]
	return r, ok
}

func (f *fileBackend) Create(_ context.Context, _ string, r Record) (Record, error) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	release, err := f.begin()
	if err != nil {
		return Record{}, err
	}
	defer release()
	name := r.Username
	if _, ok := f.current(name); ok {
		return Record{}, ErrExists
	}
	r.ETag = ""
	if err := f.put(name, &r); err != nil {
		return Record{}, err
	}
	r.ETag = etagOf(r)
	return r, nil
}

func (f *fileBackend) Change(_ context.Context, _, name, etag string, fn func(*Record) error) (Record, error) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	release, err := f.begin()
	if err != nil {
		return Record{}, err
	}
	defer release()
	cur, ok := f.current(name)
	if !ok {
		return Record{}, ErrNotFound
	}
	cur.ETag = etagOf(cur)
	if etag != "" && etag != cur.ETag {
		return Record{}, ErrStale
	}
	r := cur
	if err := fn(&r); errors.Is(err, ErrNoChange) {
		return cur, nil
	} else if err != nil {
		return Record{}, err
	}
	r.Username, r.ETag = name, ""
	if err := f.put(name, &r); err != nil {
		return Record{}, err
	}
	r.ETag = etagOf(r)
	return r, nil
}

func (f *fileBackend) Delete(_ context.Context, _, name, etag string, check func(Record) error) error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	release, err := f.begin()
	if err != nil {
		return err
	}
	defer release()
	cur, ok := f.current(name)
	if !ok {
		return ErrNotFound
	}
	cur.ETag = etagOf(cur)
	if etag != "" && etag != cur.ETag {
		return ErrStale
	}
	if check != nil {
		if err := check(cur); err != nil {
			return err
		}
	}
	return f.put(name, nil)
}

// recordBuiltin notes when the built-in admin signed in, at most once
// every signInWrites.
func (f *fileBackend) recordBuiltin(now time.Time) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	release, err := f.begin()
	if err != nil {
		return // the file cannot be read or is busy: leave it alone
	}
	defer release()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.builtinLast != nil && now.Sub(*f.builtinLast) < signInWrites {
		return
	}
	prev := f.builtinLast
	f.builtinLast = &now
	if err := f.saveLocked(); err != nil {
		f.builtinLast = prev
	}
}

func (f *fileBackend) builtinLastSignIn() *time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.builtinLast
}
