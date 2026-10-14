package users

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// Where a user's password is checked.
const (
	// SourceLocal users have a password stored by Signalith.
	SourceLocal = "local"
	// SourceDirectory users sign in with their LDAP or Active Directory
	// password; Signalith keeps a record of them from their first sign-in.
	SourceDirectory = "directory"
	// SourceBuiltin is the admin account from signalith.yaml. It is never
	// stored here; the API lists it so people can see it exists.
	SourceBuiltin = "builtin"
)

// User is one person who can sign in. It never holds a password hash.
type User struct {
	// Username is lower case and unique; sign-in ignores case.
	Username string `json:"username"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Role     Role   `json:"role"`
	Source   string `json:"source"`
	// Disabled users cannot sign in, and their sessions end.
	Disabled bool `json:"disabled,omitempty"`
	// MustChangePassword sends the user to choose a new password right
	// after signing in, and refuses everything else until they do.
	MustChangePassword bool `json:"must_change_password,omitempty"`
	// DN is a directory user's entry, as found at their last sign-in.
	DN string `json:"dn,omitempty"`
	// Refused says why a directory user has no access since the directory
	// was last asked about them: not found there (deleted, or disabled in
	// Active Directory), disabled or expired there, or in no mapped group.
	// It clears when they next sign in successfully.
	Refused    string     `json:"refused,omitempty"`
	Created    time.Time  `json:"created"`
	Updated    time.Time  `json:"updated"`
	LastSignIn *time.Time `json:"last_sign_in,omitempty"`
	// SessionEpoch moves on whenever the user's sessions must end on
	// every server: a new password, disabled, refused by the directory.
	// Sessions record the epoch they were made in.
	SessionEpoch int64 `json:"-"`
}

// NewUser is what an admin enters to add a local user.
type NewUser struct {
	Username           string
	Name               string
	Email              string
	Role               Role
	Password           string
	MustChangePassword bool
}

// Change edits a user; nil fields stay as they are.
type Change struct {
	Name     *string
	Email    *string
	Role     *Role
	Disabled *bool
}

var (
	ErrNotFound = errors.New("there is no user with that name")
	ErrExists   = errors.New("that username is taken; choose another")
	// ErrLastAdmin stops a change that would leave nobody able to manage
	// Signalith.
	ErrLastAdmin = errors.New("Signalith needs at least one enabled admin; make someone else an admin first")
	// ErrManaged refuses edits to what the directory decides.
	ErrManaged = errors.New("the name, email, role and password of directory users come from the directory; here you can only disable or delete them")
	// ErrReserved refuses the built-in admin's name.
	ErrReserved = errors.New("that name belongs to the built-in admin from signalith.yaml; choose another")
)

// FieldError is a value that cannot be used, with the field it belongs
// to (username, name, email, role or password), so a form can mark it.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

func fieldError(field string, err error) error {
	if err == nil {
		return nil
	}
	return &FieldError{Field: field, Err: err}
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,63}$`)

// NormalizeUsername returns the stored form of a username: trimmed and
// lower case.
func NormalizeUsername(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// ValidUsername checks a new local username.
func ValidUsername(name string) error {
	if !usernamePattern.MatchString(name) {
		return errors.New("usernames are 1-64 letters, digits, dots, dashes, underscores or @, starting with a letter or digit")
	}
	return nil
}

func validName(name string) error {
	if len([]rune(name)) > 100 {
		return errors.New("keep the name under 100 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("the name cannot contain control characters")
		}
	}
	return nil
}

func validEmail(email string) error {
	if email == "" {
		return nil
	}
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || len(email) > 254 {
		return fmt.Errorf("%q is not an email address like name@example.com", email)
	}
	return nil
}

// MinPasswordLength is the shortest password Signalith accepts.
const MinPasswordLength = 8

// HashPassword returns a bcrypt hash of a new password, after checking its
// length. bcrypt reads at most 72 bytes, so longer passwords are refused
// rather than silently cut.
func HashPassword(pw string) (string, error) {
	if len([]rune(pw)) < MinPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(pw) > 72 {
		return "", errors.New("password must be at most 72 bytes (bcrypt reads no more)")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// dummyHash is compared against when a user does not exist, so a wrong
// username takes as long to refuse as a wrong password.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	return h
})

// WasteTime does the work of checking a password without a user, so
// sign-in failures take the same time whatever the reason.
func WasteTime(pw string) { _ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(pw)) }

// GeneratePassword returns a random temporary password such as
// "kq7m-3xhp-9tvd-w2fa": 16 characters (about 79 bits) from letters and
// digits that are hard to confuse, in groups of four to read out easily.
func GeneratePassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		// 256 is not a multiple of 31; rejection sampling would remove the
		// slight bias, but it costs well under a bit of the 79.
		sb.WriteByte(alphabet[int(v)%len(alphabet)])
	}
	return sb.String()
}

// Store keeps the users in a Backend, with a copy in memory for reads:
// the users file (Open), memory only (NewMemory), or the shared
// configuration of a cluster. The rules (unique names, the reserved
// name, at least one enabled admin, what the directory decides) are
// checked here, on the user as the backend has it at the moment of the
// change.
type Store struct {
	// BuiltinAdmin is the built-in admin's name from signalith.yaml. The
	// name is reserved, and that account always counts as an enabled admin.
	BuiltinAdmin string
	// Builtin, when set, names the built-in admin and its password hash
	// instead of BuiltinAdmin: the servers of a cluster keep it in the
	// shared settings. ok is false while it is not known.
	Builtin func() (name, hash string, ok bool)
	// SignIns, when set, records sign-ins instead of the backend: the
	// servers of a cluster keep them apart from the users, so a sign-in
	// does not change the user. builtin is true for the built-in admin.
	SignIns func(ctx context.Context, name string, builtin bool)
	Now     func() time.Time

	b    Backend
	path string

	// loadMu lets one copy be made from the backend at a time, so an
	// older one is never put in use after a newer one.
	loadMu sync.Mutex
	mu     sync.RWMutex
	users  map[string]*User
	hashes map[string]string // username -> bcrypt hash, local users only
	etags  map[string]string

	// recheck is how often reads look for changes to the file, checked
	// when they last did, and reading whether one such read is under way.
	recheck   time.Duration
	checkMu   sync.Mutex
	checked   time.Time
	checkedOK bool
	reading   bool
}

// recheckEvery is how often reads look for changes another server made.
const recheckEvery = time.Second

// New returns a store over a backend, with the users it holds now.
func New(b Backend) (*Store, error) {
	s := &Store{Now: time.Now, b: b, users: map[string]*User{}, hashes: map[string]string{}, etags: map[string]string{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	b.OnChange(func() { _ = s.load() })
	return s, nil
}

// NewMemory returns a store that keeps users only in memory.
func NewMemory() *Store {
	s, _ := New(newFileBackend(""))
	return s
}

// Open loads the users file, or starts empty if it does not exist yet.
// A file that cannot be read is an error rather than an empty list, so a
// damaged file is never overwritten.
func Open(path string) (*Store, error) {
	f := newFileBackend(path)
	if _, err := f.reloadLocked(); err != nil {
		return nil, err
	}
	s, err := New(f)
	if err != nil {
		return nil, err
	}
	s.path = path
	s.recheck = recheckEvery
	s.checked, s.checkedOK = time.Now(), true
	return s, nil
}

// load makes the copy for reads again from the backend.
func (s *Store) load() error {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	recs, err := s.b.Load()
	if err != nil {
		return err
	}
	people, hashes, etags := make(map[string]*User, len(recs)), map[string]string{}, make(map[string]string, len(recs))
	for name, r := range recs {
		u := r.User
		u.SessionEpoch = r.Epoch
		people[name] = &u
		etags[name] = r.ETag
		if r.Hash != "" && u.Source == SourceLocal {
			hashes[name] = r.Hash
		}
	}
	s.mu.Lock()
	s.users, s.hashes, s.etags = people, hashes, etags
	s.mu.Unlock()
	return nil
}

// fresh brings the users up to date with changes another server made to
// the file, looking at most once every recheck. A file that cannot be
// read just then leaves the users as they were.
//
// The file is read by one caller at a time, so a shared folder that stops
// answering holds up that one read, never every sign-in and page: the
// others go on with the users as last read.
func (s *Store) fresh() {
	r, ok := s.b.(interface{ refresh() })
	if !ok || s.path == "" {
		return
	}
	s.checkMu.Lock()
	due := !s.reading && (!s.checkedOK || time.Since(s.checked) >= s.recheck)
	if due {
		s.checked, s.checkedOK, s.reading = time.Now(), true, true
	}
	s.checkMu.Unlock()
	if !due {
		return
	}
	defer func() {
		s.checkMu.Lock()
		s.reading = false
		s.checkMu.Unlock()
	}()
	r.refresh()
}

// Path returns the users file, or "" for a store that keeps users
// elsewhere.
func (s *Store) Path() string { return s.path }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Store) sortedNamesLocked() []string {
	names := make([]string, 0, len(s.users))
	for n := range s.users {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Get returns a user by name, ignoring case.
func (s *Store) Get(name string) (User, bool) {
	s.fresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[NormalizeUsername(name)]
	if !ok {
		return User{}, false
	}
	return *u, true
}

// ETag returns the version of the user name as last read, for a change
// that must not undo another made since (UpdateIf and the like); "" when
// there is no such user.
func (s *Store) ETag(name string) string {
	s.fresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.etags[NormalizeUsername(name)]
}

// List returns every user, sorted by username.
func (s *Store) List() []User {
	s.fresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, n := range s.sortedNamesLocked() {
		out = append(out, *s.users[n])
	}
	return out
}

// builtinName returns the built-in admin's name, or "" when there is
// none.
func (s *Store) builtinName() string {
	if s.Builtin != nil {
		name, _, ok := s.Builtin()
		if !ok {
			return ""
		}
		return name
	}
	return s.BuiltinAdmin
}

func (s *Store) reserved(name string) bool {
	b := s.builtinName()
	return b != "" && strings.EqualFold(name, b)
}

// Create adds a local user.
func (s *Store) Create(ctx context.Context, in NewUser) (User, error) {
	name := NormalizeUsername(in.Username)
	if err := ValidUsername(name); err != nil {
		return User{}, fieldError("username", err)
	}
	if s.reserved(name) {
		return User{}, fieldError("username", ErrReserved)
	}
	if _, taken := s.Get(name); taken {
		return User{}, fieldError("username", ErrExists)
	}
	in.Name, in.Email = strings.TrimSpace(in.Name), strings.TrimSpace(in.Email)
	if err := validName(in.Name); err != nil {
		return User{}, fieldError("name", err)
	}
	if err := validEmail(in.Email); err != nil {
		return User{}, fieldError("email", err)
	}
	if !in.Role.Valid() {
		return User{}, fieldError("role", fmt.Errorf("role %q must be viewer, analyst or admin", in.Role))
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		return User{}, fieldError("password", err)
	}
	now := s.now()
	r, err := s.b.Create(ctx, Actor(ctx), Record{User: User{Username: name, Name: in.Name, Email: in.Email, Role: in.Role, Source: SourceLocal,
		MustChangePassword: in.MustChangePassword, Created: now, Updated: now}, Hash: hash, Epoch: 1})
	if errors.Is(err, ErrExists) {
		return User{}, fieldError("username", ErrExists)
	}
	if err != nil {
		return User{}, err
	}
	return recordUser(r), nil
}

// recordUser returns the user of a record, with its session epoch.
func recordUser(r Record) User {
	u := r.User
	u.SessionEpoch = r.Epoch
	return u
}

// adminsLeft counts the enabled admins if the named user had role and
// disabled instead. The built-in admin always counts.
func (s *Store) adminsLeft(name string, role Role, disabled bool) int {
	builtin := s.builtinName()
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	if builtin != "" {
		n++
	}
	if _, ok := s.users[name]; !ok && role == Admin && !disabled {
		// A user this copy does not hold yet.
		n++
	}
	for _, u := range s.users {
		r, off := u.Role, u.Disabled
		if u.Username == name {
			r, off = role, disabled
		}
		// Directory users' roles depend on groups that may have changed
		// since they last signed in, so only local admins count.
		if u.Source == SourceLocal && r == Admin && !off {
			n++
		}
	}
	return n
}

// Update changes a user's details, role or disabled state. Directory
// users can only be disabled or enabled.
func (s *Store) Update(ctx context.Context, name string, ch Change) (User, error) {
	return s.UpdateIf(ctx, name, "", ch)
}

// UpdateIf is Update for a user read at etag (ETag): ErrStale, or an
// error naming who changed it, when it changed since. An empty etag
// changes the user as it is now.
func (s *Store) UpdateIf(ctx context.Context, name, etag string, ch Change) (User, error) {
	name = NormalizeUsername(name)
	r, err := s.b.Change(ctx, Actor(ctx), name, etag, func(r *Record) error {
		cur := r.User
		u := cur
		if ch.Name != nil {
			u.Name = strings.TrimSpace(*ch.Name)
		}
		if ch.Email != nil {
			u.Email = strings.TrimSpace(*ch.Email)
		}
		if ch.Role != nil {
			u.Role = *ch.Role
		}
		if ch.Disabled != nil {
			u.Disabled = *ch.Disabled
		}
		if cur.Source == SourceDirectory && (u.Name != cur.Name || u.Email != cur.Email || u.Role != cur.Role) {
			return ErrManaged
		}
		if err := validName(u.Name); err != nil {
			return fieldError("name", err)
		}
		if err := validEmail(u.Email); err != nil {
			return fieldError("email", err)
		}
		if !u.Role.Valid() {
			return fieldError("role", fmt.Errorf("role %q must be viewer, analyst or admin", u.Role))
		}
		wasAdmin := cur.Source == SourceLocal && cur.Role == Admin && !cur.Disabled
		if wasAdmin && (u.Role != Admin || u.Disabled) && s.adminsLeft(name, u.Role, u.Disabled) == 0 {
			return ErrLastAdmin
		}
		if u == cur {
			return ErrNoChange
		}
		if u.Disabled && !cur.Disabled {
			// Their sessions end everywhere.
			r.Epoch++
		}
		u.Updated = s.now()
		r.User = u
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return recordUser(r), nil
}

// Delete removes a user and returns what was removed.
func (s *Store) Delete(ctx context.Context, name string) (User, error) {
	return s.DeleteIf(ctx, name, "")
}

// DeleteIf is Delete for a user read at etag (see UpdateIf).
func (s *Store) DeleteIf(ctx context.Context, name, etag string) (User, error) {
	name = NormalizeUsername(name)
	var gone User
	err := s.b.Delete(ctx, Actor(ctx), name, etag, func(r Record) error {
		cur := r.User
		if cur.Source == SourceLocal && cur.Role == Admin && !cur.Disabled && s.adminsLeft(name, Viewer, true) == 0 {
			return ErrLastAdmin
		}
		gone = recordUser(r)
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return gone, nil
}

// SetPassword gives a local user a new password. mustChange makes it a
// temporary one the user replaces at their next sign-in. Their sessions
// end everywhere.
func (s *Store) SetPassword(ctx context.Context, name, password string, mustChange bool) (User, error) {
	return s.SetPasswordIf(ctx, name, "", password, mustChange)
}

// SetPasswordIf is SetPassword for a user read at etag (see UpdateIf).
func (s *Store) SetPasswordIf(ctx context.Context, name, etag, password string, mustChange bool) (User, error) {
	name = NormalizeUsername(name)
	if u, ok := s.Get(name); !ok {
		return User{}, ErrNotFound
	} else if u.Source != SourceLocal {
		return User{}, ErrManaged
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, fieldError("password", err)
	}
	r, err := s.b.Change(ctx, Actor(ctx), name, etag, func(r *Record) error {
		if r.Source != SourceLocal {
			return ErrManaged
		}
		r.MustChangePassword = mustChange
		r.Updated = s.now()
		r.Hash = hash
		r.Epoch++
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return recordUser(r), nil
}

// CheckPassword reports whether password is the local user's password. It
// takes as long for a user that does not exist.
func (s *Store) CheckPassword(name, password string) bool {
	s.fresh()
	s.mu.RLock()
	hash, ok := s.hashes[NormalizeUsername(name)]
	s.mu.RUnlock()
	if !ok {
		WasteTime(password)
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// PasswordVersion changes whenever the user's password does, so a cache
// of checked passwords can include it in its keys.
func (s *Store) PasswordVersion(name string) string {
	s.fresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hashes[NormalizeUsername(name)]
}

// signInWrites limits how often a sign-in time is written, so a script
// signing in on every request does not rewrite the file each time.
const signInWrites = time.Minute

// RecordSignIn notes when a user signed in. It changes only that, in the
// user as it is now: a user another server disabled or deleted meanwhile
// stays disabled or deleted.
func (s *Store) RecordSignIn(ctx context.Context, name string) {
	name = NormalizeUsername(name)
	if s.SignIns != nil {
		s.SignIns(ctx, name, false)
		return
	}
	now := s.now()
	_, _ = s.b.Change(ctx, Actor(ctx), name, "", func(r *Record) error {
		if r.LastSignIn != nil && now.Sub(*r.LastSignIn) < signInWrites {
			return ErrNoChange
		}
		r.LastSignIn = &now
		return nil
	})
}

// RecordBuiltinSignIn notes when the built-in admin signed in.
func (s *Store) RecordBuiltinSignIn(ctx context.Context) {
	if s.SignIns != nil {
		s.SignIns(ctx, s.builtinName(), true)
		return
	}
	if f, ok := s.b.(*fileBackend); ok {
		f.recordBuiltin(s.now())
	}
}

// BuiltinLastSignIn returns when the built-in admin last signed in.
func (s *Store) BuiltinLastSignIn() *time.Time {
	s.fresh()
	if f, ok := s.b.(*fileBackend); ok {
		return f.builtinLastSignIn()
	}
	return nil
}

// SeeDirectoryUser records a directory user who just signed in: added on
// their first sign-in, then kept up to date with the name, email and role
// the directory gives. A disabled user is returned unchanged, and a name
// taken by a local user is refused.
func (s *Store) SeeDirectoryUser(ctx context.Context, d DirectoryUser) (User, error) {
	name := NormalizeUsername(d.Username)
	if name == "" || s.reserved(name) {
		return User{}, ErrReserved
	}
	for try := 1; ; try++ {
		now := s.now()
		r, err := s.b.Change(ctx, Actor(ctx), name, "", func(r *Record) error {
			if r.Source != SourceDirectory {
				return ErrExists
			}
			if r.Disabled {
				return ErrNoChange
			}
			u := r.User
			changed := u.Name != d.Name || u.Email != d.Email || u.Role != d.Role || u.DN != d.DN || u.Refused != ""
			u.Name, u.Email, u.Role, u.DN, u.Refused = d.Name, d.Email, d.Role, d.DN, ""
			if changed {
				u.Updated = now
			}
			if s.SignIns != nil {
				// The sign-in is recorded apart.
				if !changed {
					return ErrNoChange
				}
			} else {
				if !changed && u.LastSignIn != nil && now.Sub(*u.LastSignIn) < signInWrites {
					return ErrNoChange
				}
				u.LastSignIn = &now
			}
			r.User = u
			return nil
		})
		if !errors.Is(err, ErrNotFound) {
			if err != nil {
				return User{}, err
			}
			s.signedIn(ctx, r)
			return recordUser(r), nil
		}
		// Their first sign-in.
		r, err = s.b.Create(ctx, Actor(ctx), Record{User: User{Username: name, Source: SourceDirectory, Name: d.Name, Email: d.Email,
			Role: d.Role, DN: d.DN, Created: now, Updated: now, LastSignIn: &now}, Epoch: 1})
		if errors.Is(err, ErrExists) && try < 3 {
			// Someone else added them just now: change that one.
			continue
		}
		if err != nil {
			return User{}, err
		}
		s.signedIn(ctx, r)
		return recordUser(r), nil
	}
}

// signedIn records a directory user's sign-in through SignIns, when set.
func (s *Store) signedIn(ctx context.Context, r Record) {
	if s.SignIns != nil && !r.Disabled {
		s.SignIns(ctx, r.Username, false)
	}
}

// RefreshDirectoryUser updates a directory user from a new look at the
// directory (without their password): name, email, DN and role, and it
// clears Refused. It reports whether anything changed.
func (s *Store) RefreshDirectoryUser(ctx context.Context, name string, d DirectoryUser) (User, bool, error) {
	name = NormalizeUsername(name)
	changed := false
	r, err := s.b.Change(ctx, Actor(ctx), name, "", func(r *Record) error {
		if r.Source != SourceDirectory {
			return ErrNotFound
		}
		u := r.User
		u.Name, u.Email, u.Role, u.DN, u.Refused = d.Name, d.Email, d.Role, d.DN, ""
		if u == r.User {
			return ErrNoChange
		}
		u.Updated = s.now()
		r.User, changed = u, true
		return nil
	})
	if err != nil {
		return User{}, false, err
	}
	return recordUser(r), changed, nil
}

// RefuseDirectoryUser records that the directory no longer lets a
// directory user in, and why; their sessions end everywhere. It reports
// whether that is news.
func (s *Store) RefuseDirectoryUser(ctx context.Context, name, reason string) (User, bool, error) {
	name = NormalizeUsername(name)
	if reason == "" {
		reason = "refused by the directory"
	}
	changed := false
	r, err := s.b.Change(ctx, Actor(ctx), name, "", func(r *Record) error {
		if r.Source != SourceDirectory {
			return ErrNotFound
		}
		if r.Refused == reason {
			return ErrNoChange
		}
		r.Refused = reason
		r.Updated = s.now()
		r.Epoch++
		changed = true
		return nil
	})
	if err != nil {
		return User{}, false, err
	}
	return recordUser(r), changed, nil
}

// Count returns how many users come from each source.
func (s *Store) Count() map[string]int {
	s.fresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]int{SourceLocal: 0, SourceDirectory: 0}
	for _, u := range s.users {
		out[u.Source]++
	}
	return out
}
