package users

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/securefile"
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

// Store keeps users in a JSON file. Writes go to a temporary file that is
// renamed over the old one, so a crash never leaves half a file.
//
// Servers that share a lookups folder share the file, so another server
// may change it at any time. Every change is therefore made to the file
// as it is now, while holding a lock file next to it (see lockFile): the
// store reads it again first when it changed since this store last read
// or wrote it, and changes only what the change is about.
// A user disabled or deleted on one server stays so when another records
// a sign-in or edits someone else. Reads look for changes at most once a
// second (recheck), so a disabled user is also refused on the other
// servers within a second or so.
type Store struct {
	// BuiltinAdmin is the built-in admin's name from signalith.yaml. The
	// name is reserved, and that account always counts as an enabled admin.
	BuiltinAdmin string
	Now          func() time.Time

	path        string
	mu          sync.RWMutex
	users       map[string]*User
	hashes      map[string]string // username -> bcrypt hash, local users only
	builtinLast *time.Time
	// sum is the SHA-256 of the file as this store last read or wrote it.
	// The content is compared, not the modification time, which some
	// file systems keep only to the second or two.
	sum [sha256.Size]byte

	// gen counts the times this store read or wrote the file under mu,
	// so a read made without mu (fresh) is not applied over a newer one.
	gen uint64

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

// storedUser is a user as written to the file, with the password hash.
type storedUser struct {
	User
	PasswordHash string `json:"password_hash,omitempty"`
}

type storeFile struct {
	Version           int          `json:"version"`
	Users             []storedUser `json:"users"`
	BuiltinLastSignIn *time.Time   `json:"builtin_last_sign_in,omitempty"`
}

// NewMemory returns a store that keeps users only in memory.
func NewMemory() *Store {
	return &Store{Now: time.Now, users: map[string]*User{}, hashes: map[string]string{}}
}

// Open loads the users file, or starts empty if it does not exist yet.
// A file that cannot be read is an error rather than an empty list, so a
// damaged file is never overwritten.
func Open(path string) (*Store, error) {
	s := NewMemory()
	s.path = path
	s.recheck = recheckEvery
	if err := s.reloadLocked(); err != nil {
		return nil, err
	}
	s.checked, s.checkedOK = time.Now(), true
	return s, nil
}

// readUsersFile reads the users file; tests replace it.
var readUsersFile = os.ReadFile

// reloadLocked reads the users file again when it changed since this store
// last read or wrote it: another server that shares it wrote it. The
// caller holds the write lock. A file that is not there (yet) leaves the
// users as they are, and the next change writes it. A file that cannot be
// read or understood is an error, and the users stay as they were.
func (s *Store) reloadLocked() error {
	if s.path == "" {
		return nil
	}
	s.gen++
	data, err := readUsersFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.applyLocked(data)
}

// applyLocked takes the users from the file's content when it differs
// from what this store last read or wrote. The caller holds the write
// lock.
func (s *Store) applyLocked(data []byte) error {
	sum := sha256.Sum256(data)
	if sum == s.sum {
		return nil
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("users file %s is damaged (%v); fix it, or move it away and restart Signalith to start with only the built-in admin", s.path, err)
	}
	people, hashes := map[string]*User{}, map[string]string{}
	for _, su := range f.Users {
		u := su.User
		u.Username = NormalizeUsername(u.Username)
		if u.Username == "" || people[u.Username] != nil {
			return fmt.Errorf("users file %s lists an empty or repeated username %q", s.path, su.Username)
		}
		if u.Source != SourceDirectory {
			u.Source = SourceLocal
		}
		if !u.Role.Valid() {
			// An unknown role grants nothing.
			u.Role = Viewer
		}
		people[u.Username] = &u
		if su.PasswordHash != "" && u.Source == SourceLocal {
			hashes[u.Username] = su.PasswordHash
		}
	}
	s.users, s.hashes, s.builtinLast, s.sum = people, hashes, f.BuiltinLastSignIn, sum
	return nil
}

// fresh brings the users up to date with changes another server made to
// the file, looking at most once every recheck. A file that cannot be
// read just then leaves the users as they were.
//
// The file is read without holding mu, and by one caller at a time, so a
// shared folder that stops answering holds up that one read, never every
// sign-in and page: the others go on with the users as last read.
func (s *Store) fresh() {
	if s.path == "" {
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
	s.mu.RLock()
	gen := s.gen
	s.mu.RUnlock()
	data, err := readUsersFile(s.path)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return // a change read or wrote the file meanwhile; that is newer
	}
	_ = s.applyLocked(data)
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
// store needs none.
func (s *Store) lockFile() (func(), error) {
	if s.path == "" {
		return func() {}, nil
	}
	name := s.path + ".lock"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	token := fmt.Sprintf("%x", b)
	start := time.Now()
	seen, seenAt, made := "", time.Time{}, false
	for {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, werr := f.WriteString(token)
			if cerr := f.Close(); werr == nil {
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

// beginLocked starts a change: it takes the lock file and reads the file
// as it is now. The caller holds the write lock, and calls the returned
// function once the change is written or given up.
func (s *Store) beginLocked() (func(), error) {
	release, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	if err := s.reloadLocked(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

// Path returns the users file, or "" for a memory-only store.
func (s *Store) Path() string { return s.path }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// saveLocked writes the file; the caller holds the write lock.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	f := storeFile{Version: 1, Users: make([]storedUser, 0, len(s.users)), BuiltinLastSignIn: s.builtinLast}
	for _, name := range s.sortedNamesLocked() {
		f.Users = append(f.Users, storedUser{User: *s.users[name], PasswordHash: s.hashes[name]})
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	// On Windows a file another program has open just then (another
	// server reading it from a shared folder, or a virus scanner) cannot
	// be replaced, so a failed write is tried again shortly.
	wait := 50 * time.Millisecond
	for try := 1; ; try++ {
		err = WriteFileAtomic(s.path, data)
		if err == nil || try == saveTries {
			break
		}
		time.Sleep(wait)
		wait *= 2
	}
	if err == nil {
		s.sum = sha256.Sum256(data)
		s.gen++
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

func (s *Store) reserved(name string) bool {
	return s.BuiltinAdmin != "" && strings.EqualFold(name, s.BuiltinAdmin)
}

// Create adds a local user.
func (s *Store) Create(in NewUser) (User, error) {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return User{}, err
	}
	defer release()
	if _, ok := s.users[name]; ok {
		return User{}, fieldError("username", ErrExists)
	}
	now := s.now()
	u := &User{Username: name, Name: in.Name, Email: in.Email, Role: in.Role, Source: SourceLocal,
		MustChangePassword: in.MustChangePassword, Created: now, Updated: now}
	s.users[name], s.hashes[name] = u, hash
	if err := s.saveLocked(); err != nil {
		delete(s.users, name)
		delete(s.hashes, name)
		return User{}, err
	}
	return *u, nil
}

// adminsLeftLocked counts the enabled admins if the named user had role
// and disabled instead. The built-in admin always counts.
func (s *Store) adminsLeftLocked(name string, role Role, disabled bool) int {
	n := 0
	if s.BuiltinAdmin != "" {
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
func (s *Store) Update(name string, ch Change) (User, error) {
	name = NormalizeUsername(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return User{}, err
	}
	defer release()
	cur, ok := s.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	u := *cur
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
		return User{}, ErrManaged
	}
	if err := validName(u.Name); err != nil {
		return User{}, fieldError("name", err)
	}
	if err := validEmail(u.Email); err != nil {
		return User{}, fieldError("email", err)
	}
	if !u.Role.Valid() {
		return User{}, fieldError("role", fmt.Errorf("role %q must be viewer, analyst or admin", u.Role))
	}
	wasAdmin := cur.Source == SourceLocal && cur.Role == Admin && !cur.Disabled
	if wasAdmin && (u.Role != Admin || u.Disabled) && s.adminsLeftLocked(name, u.Role, u.Disabled) == 0 {
		return User{}, ErrLastAdmin
	}
	if u == *cur {
		return u, nil
	}
	u.Updated = s.now()
	s.users[name] = &u
	if err := s.saveLocked(); err != nil {
		s.users[name] = cur
		return User{}, err
	}
	return u, nil
}

// Delete removes a user and returns what was removed.
func (s *Store) Delete(name string) (User, error) {
	name = NormalizeUsername(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return User{}, err
	}
	defer release()
	cur, ok := s.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	if cur.Source == SourceLocal && cur.Role == Admin && !cur.Disabled && s.adminsLeftLocked(name, Viewer, true) == 0 {
		return User{}, ErrLastAdmin
	}
	hash := s.hashes[name]
	delete(s.users, name)
	delete(s.hashes, name)
	if err := s.saveLocked(); err != nil {
		s.users[name] = cur
		if hash != "" {
			s.hashes[name] = hash
		}
		return User{}, err
	}
	return *cur, nil
}

// SetPassword gives a local user a new password. mustChange makes it a
// temporary one the user replaces at their next sign-in.
func (s *Store) SetPassword(name, password string, mustChange bool) (User, error) {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return User{}, err
	}
	defer release()
	cur, ok := s.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	if cur.Source != SourceLocal {
		return User{}, ErrManaged
	}
	u, oldHash := *cur, s.hashes[name]
	u.MustChangePassword = mustChange
	u.Updated = s.now()
	s.users[name], s.hashes[name] = &u, hash
	if err := s.saveLocked(); err != nil {
		s.users[name], s.hashes[name] = cur, oldHash
		return User{}, err
	}
	return u, nil
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
// file as it is now: a user another server disabled or deleted meanwhile
// stays disabled or deleted.
func (s *Store) RecordSignIn(name string) {
	name = NormalizeUsername(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return // the file cannot be read or is busy: leave it alone
	}
	defer release()
	cur, ok := s.users[name]
	if !ok {
		return
	}
	now := s.now()
	if cur.LastSignIn != nil && now.Sub(*cur.LastSignIn) < signInWrites {
		return
	}
	u := *cur
	u.LastSignIn = &now
	s.users[name] = &u
	if err := s.saveLocked(); err != nil {
		s.users[name] = cur
	}
}

// RecordBuiltinSignIn notes when the built-in admin signed in.
func (s *Store) RecordBuiltinSignIn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return // the file cannot be read or is busy: leave it alone
	}
	defer release()
	now := s.now()
	if s.builtinLast != nil && now.Sub(*s.builtinLast) < signInWrites {
		return
	}
	prev := s.builtinLast
	s.builtinLast = &now
	if err := s.saveLocked(); err != nil {
		s.builtinLast = prev
	}
}

// BuiltinLastSignIn returns when the built-in admin last signed in.
func (s *Store) BuiltinLastSignIn() *time.Time {
	s.fresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.builtinLast
}

// SeeDirectoryUser records a directory user who just signed in: added on
// their first sign-in, then kept up to date with the name, email and role
// the directory gives. A disabled user is returned unchanged, and a name
// taken by a local user is refused.
func (s *Store) SeeDirectoryUser(d DirectoryUser) (User, error) {
	name := NormalizeUsername(d.Username)
	if name == "" || s.reserved(name) {
		return User{}, ErrReserved
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return User{}, err
	}
	defer release()
	now := s.now()
	cur, ok := s.users[name]
	if ok && cur.Source != SourceDirectory {
		return User{}, ErrExists
	}
	if ok && cur.Disabled {
		return *cur, nil
	}
	u := User{Username: name, Source: SourceDirectory, Created: now}
	if ok {
		u = *cur
	}
	changed := !ok || u.Name != d.Name || u.Email != d.Email || u.Role != d.Role || u.DN != d.DN || u.Refused != ""
	u.Name, u.Email, u.Role, u.DN, u.Refused = d.Name, d.Email, d.Role, d.DN, ""
	if changed {
		u.Updated = now
	}
	if !changed && u.LastSignIn != nil && now.Sub(*u.LastSignIn) < signInWrites {
		return u, nil
	}
	u.LastSignIn = &now
	s.users[name] = &u
	if err := s.saveLocked(); err != nil {
		if ok {
			s.users[name] = cur
		} else {
			delete(s.users, name)
		}
		return User{}, err
	}
	return u, nil
}

// RefreshDirectoryUser updates a directory user from a new look at the
// directory (without their password): name, email, DN and role, and it
// clears Refused. It reports whether anything changed.
func (s *Store) RefreshDirectoryUser(name string, d DirectoryUser) (User, bool, error) {
	name = NormalizeUsername(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return User{}, false, err
	}
	defer release()
	cur, ok := s.users[name]
	if !ok || cur.Source != SourceDirectory {
		return User{}, false, ErrNotFound
	}
	u := *cur
	u.Name, u.Email, u.Role, u.DN, u.Refused = d.Name, d.Email, d.Role, d.DN, ""
	if u == *cur {
		return u, false, nil
	}
	u.Updated = s.now()
	s.users[name] = &u
	if err := s.saveLocked(); err != nil {
		s.users[name] = cur
		return User{}, false, err
	}
	return u, true, nil
}

// RefuseDirectoryUser records that the directory no longer lets a
// directory user in, and why. It reports whether that is news.
func (s *Store) RefuseDirectoryUser(name, reason string) (User, bool, error) {
	name = NormalizeUsername(name)
	if reason == "" {
		reason = "refused by the directory"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.beginLocked()
	if err != nil {
		return User{}, false, err
	}
	defer release()
	cur, ok := s.users[name]
	if !ok || cur.Source != SourceDirectory {
		return User{}, false, ErrNotFound
	}
	if cur.Refused == reason {
		return *cur, false, nil
	}
	u := *cur
	u.Refused = reason
	u.Updated = s.now()
	s.users[name] = &u
	if err := s.saveLocked(); err != nil {
		s.users[name] = cur
		return User{}, false, err
	}
	return u, true, nil
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
