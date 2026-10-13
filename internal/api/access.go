package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// route is one API route and the least role that may use it.
type route struct {
	Pattern string
	Role    users.Role
	// Unclassified routes were registered without a role. They are
	// admin-only, and TestEveryRouteHasARole fails until they get one.
	Unclassified bool
	// Anytime routes stay open to a user who must choose a new password
	// before doing anything else.
	Anytime bool
}

// router registers API routes with the role each needs. It is the one
// place access is decided: every route it registers goes through allow.
type router struct {
	s      *Server
	mux    *http.ServeMux
	routes []route
}

// viewer registers a route every signed-in user may use.
func (rt *router) viewer(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Viewer}, h)
}

// analyst registers a route for day-to-day SOC work.
func (rt *router) analyst(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Analyst}, h)
}

// admin registers a route that changes how Signalith works.
func (rt *router) admin(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Admin}, h)
}

// self registers a route about the signed-in user, open to every role
// even before a required password change.
func (rt *router) self(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Viewer, Anytime: true}, h)
}

// HandleFunc registers a route without a role, so it is admin-only. Use
// viewer, analyst or admin instead: TestEveryRouteHasARole fails on
// routes registered this way.
func (rt *router) HandleFunc(pattern string, h http.HandlerFunc) { rt.Handle(pattern, h) }

// Handle is HandleFunc for an http.Handler.
func (rt *router) Handle(pattern string, h http.Handler) {
	rt.add(route{Pattern: pattern, Role: users.Admin, Unclassified: true}, h)
}

func (rt *router) add(r route, h http.Handler) {
	rt.routes = append(rt.routes, r)
	rt.mux.Handle(r.Pattern, rt.s.allow(r, h))
}

// principal is the signed-in user of a request. Its role is looked up
// for every request, so a change applies at once.
type principal struct {
	Username           string
	Name               string
	Email              string
	Role               users.Role
	Source             string // builtin, local or directory
	MustChangePassword bool
	// Method is how the request signed in: session or basic.
	Method string
	token  string // the session's token, to keep it when others end
}

type userKey struct{}

// principalOf returns the signed-in user, or nil.
func principalOf(r *http.Request) *principal {
	p, _ := r.Context().Value(userKey{}).(*principal)
	return p
}

// userOf returns the signed-in user's name.
func userOf(r *http.Request) string {
	if p := principalOf(r); p != nil {
		return p.Username
	}
	return "unknown"
}

// allow refuses a request whose user's role is below the route's, or who
// must change their password first.
func (s *Server) allow(rt route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r)
		if p == nil {
			s.unauthorized(w, r)
			return
		}
		if p.MustChangePassword && !rt.Anytime {
			if !strings.HasPrefix(r.URL.Path, "/api/") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				// The sign-in page asks for the new password.
				http.Redirect(w, r, "/login?change=1", http.StatusSeeOther)
				return
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "Choose a new password before you continue.", "code": "password_change_required"})
			return
		}
		if !p.Role.AtLeast(rt.Role) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":    fmt.Sprintf("This needs the %s role, and your role is %s. Ask an admin if you need access.", rt.Role.Label(), p.Role.Label()),
				"code":     "forbidden",
				"role":     p.Role,
				"required": rt.Role,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireUser admits requests with a valid sign-in session or HTTP Basic
// credentials and puts the user in the request context. Signed-out
// browsers are sent to the sign-in page; API clients get 401.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			writeSignInError(w, err)
			return
		}
		if p == nil {
			s.unauthorized(w, r)
			return
		}
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
			return
		}
		s.noteName(r)
		// Searches the request runs count against the user's share of
		// the search slots.
		ctx := search.ForUser(context.WithValue(r.Context(), userKey{}, p), p.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// backgroundHeader marks a request the web UI made on its own, with no one
// using the page just before (a refresh on a timer). It does not count as
// activity, so an unattended tab still signs out after the idle timeout.
const backgroundHeader = "X-Signalith-Background"

func background(r *http.Request) bool { return r.Header.Get(backgroundHeader) == "1" }

// authenticate checks the session cookie, then Basic credentials. It
// returns nil without an error when the request is not signed in.
func (s *Server) authenticate(r *http.Request) (*principal, error) {
	if c, err := r.Cookie(s.cookieName(r)); err == nil {
		lookup := s.sessions().Lookup
		if background(r) {
			lookup = s.sessions().Peek
		}
		if ss, ok := lookup(c.Value); ok {
			// A password changed since signing in (perhaps on another
			// server sharing the users file) ends the session too.
			if p := s.principalFor(ss.User); p != nil && (ss.Version == "" || ss.Version == s.passwordStamp(ss.User)) {
				p.Method, p.token = "session", c.Value
				return p, nil
			}
			// Deleted, disabled or given a new password since signing in.
			s.sessions().Delete(c.Value)
		}
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, nil
	}
	p, err := s.checkBasic(r, user, pass)
	if errors.Is(err, errWrongCredentials) {
		return nil, nil
	}
	if p != nil {
		p.Method = "basic"
	}
	return p, err
}

// principalFor looks up a signed-in user's current role and state, or
// returns nil if they may no longer sign in. Directory users are checked
// with the directory again every few minutes (see recheckDirectoryUser).
func (s *Server) principalFor(name string) *principal {
	if strings.EqualFold(name, s.conf().Auth.AdminUser) {
		return s.builtinPrincipal()
	}
	u, ok := s.userStore().Get(name)
	if !ok || u.Disabled {
		return nil
	}
	if u.Source == users.SourceDirectory {
		if !s.dir().Enabled() || u.Refused != "" {
			return nil
		}
		s.recheckDirectoryUser(u.Username)
	}
	return principalFromUser(u)
}

// passwordStamp identifies a local user's current password without
// holding its hash, or is "" for users without one here (the built-in
// admin and directory users).
func (s *Server) passwordStamp(name string) string {
	v := s.userStore().PasswordVersion(name)
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:16])
}

func (s *Server) builtinPrincipal() *principal {
	return &principal{Username: s.conf().Auth.AdminUser, Role: users.Admin, Source: users.SourceBuiltin}
}

func principalFromUser(u users.User) *principal {
	return &principal{Username: u.Username, Name: u.Name, Email: u.Email, Role: u.Role, Source: u.Source,
		MustChangePassword: u.MustChangePassword}
}

// signInError is a refused sign-in, with the status and words to send.
type signInError struct {
	status     int
	code       string
	msg        string
	retryAfter time.Duration
}

func (e *signInError) Error() string { return e.msg }

var (
	errWrongCredentials = &signInError{status: http.StatusUnauthorized, code: "wrong_credentials",
		msg: "Username and password don't match."}
	errDisabled = &signInError{status: http.StatusForbidden, code: "disabled",
		msg: "This account is disabled. Ask an admin to enable it."}
	errPasswordExpired = &signInError{status: http.StatusForbidden, code: "password_expired",
		msg: "Your directory password has expired or must be changed. Change it (for example by signing in to Windows), then sign in here again."}
	errNoRole = &signInError{status: http.StatusForbidden, code: "not_in_group",
		msg: "Your directory account is not in a group that can use Signalith. Ask an admin to add you to one."}
	errDirectoryDown = &signInError{status: http.StatusServiceUnavailable, code: "directory_unavailable",
		msg: "Signalith could not reach the directory server to check your password. Try again in a minute, or ask an admin."}
	errDirectoryBusy = &signInError{status: http.StatusServiceUnavailable, code: "directory_unavailable", retryAfter: 30 * time.Second,
		msg: "Signalith is checking many directory sign-ins right now. Try again in a minute."}
)

func writeSignInError(w http.ResponseWriter, err error) {
	var se *signInError
	if !errors.As(err, &se) {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if se.retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(math.Ceil(se.retryAfter.Seconds()))))
	}
	writeJSON(w, se.status, map[string]any{"error": se.msg, "code": se.code})
}

func lockedOut(wait time.Duration) error {
	msg := "Too many sign-in attempts at the same time. Wait a few seconds, then try again."
	if wait > auth.Busy {
		n := int(math.Ceil(wait.Minutes()))
		msg = fmt.Sprintf("Too many failed sign-ins. Try again in %d minutes.", n)
		if n == 1 {
			msg = "Too many failed sign-ins. Try again in a minute."
		}
	}
	return &signInError{status: http.StatusTooManyRequests, code: "locked_out", retryAfter: wait, msg: msg}
}

// limitKey is the client a sign-in attempt counts against: its IPv4
// address, or its IPv6 /64 network, since an IPv6 host can usually pick
// any address in its /64 and would otherwise get a fresh allowance of
// guesses with each one.
func limitKey(r *http.Request) string {
	if a := clientaddr.Parse(r.RemoteAddr); a.IsValid() {
		return clientaddr.Key(a).String()
	}
	return clientIP(r)
}

// beginAttempt starts a password check that counts toward the sign-in
// limits (see auth.Limiter), or returns the locked-out error.
func (s *Server) beginAttempt(r *http.Request, account string) (*auth.Attempt, error) {
	a, ok, wait := s.limiter().Begin(limitKey(r), users.LoginName(account))
	if !ok {
		return nil, lockedOut(wait)
	}
	return a, nil
}

// signIn checks a username and password for the sign-in page or Basic
// auth: the built-in admin first, then local users, then the directory.
// A local username is never looked up in the directory. Wrong passwords
// count toward the limits per address and account, and every attempt is
// logged without the password.
func (s *Server) signIn(r *http.Request, name, password, method string) (*principal, error) {
	client := clientIP(r)
	name = strings.TrimSpace(name)
	attempt, err := s.beginAttempt(r, name)
	if err != nil {
		return nil, err
	}
	p, reason, err := s.checkCredentials(r.Context(), name, password)
	if err != nil {
		locked := false
		if errors.Is(err, errWrongCredentials) {
			locked = attempt.Fail()
		} else {
			// Unreachable directory, or a right password for an account
			// that may not sign in: no guess was refused.
			attempt.Done()
		}
		s.Log.Warn("sign-in failed", "audit", true, "user", name, "client", client, "method", method, "reason", reason, "locked_out", locked)
		return nil, err
	}
	attempt.Succeed()
	s.notePlainSignIn(r)
	s.noteName(r)
	s.Log.Info("signed in", "audit", true, "user", p.Username, "role", p.Role, "source", p.Source, "client", client, "method", method)
	return p, nil
}

// checkCredentials does the checking for signIn and returns why it
// refused, for the log.
func (s *Server) checkCredentials(ctx context.Context, name, password string) (*principal, string, error) {
	if name == "" || password == "" {
		return nil, "empty username or password", errWrongCredentials
	}
	store := s.userStore()
	if strings.EqualFold(name, s.conf().Auth.AdminUser) {
		if !s.conf().CheckPassword(name, password) {
			return nil, "wrong password", errWrongCredentials
		}
		store.RecordBuiltinSignIn()
		return s.builtinPrincipal(), "", nil
	}
	if u, ok := store.Get(name); ok && u.Source == users.SourceLocal {
		if !store.CheckPassword(u.Username, password) {
			return nil, "wrong password", errWrongCredentials
		}
		if u.Disabled {
			return nil, "account disabled", errDisabled
		}
		store.RecordSignIn(u.Username)
		return principalFromUser(u), "", nil
	}
	d := s.dir()
	if !d.Enabled() {
		users.WasteTime(password)
		return nil, "no such user", errWrongCredentials
	}
	// DOMAIN\name is looked up as name, so a local or built-in name with a
	// domain in front is refused without asking the directory.
	login := users.LoginName(name)
	if !strings.EqualFold(login, name) {
		if u, ok := store.Get(login); strings.EqualFold(login, s.conf().Auth.AdminUser) || (ok && u.Source == users.SourceLocal) {
			users.WasteTime(password)
			return nil, "a domain in front of a local user's or the built-in admin's name", errWrongCredentials
		}
	}
	// A local name costs a password hash check. Do the same work for every
	// other name, alongside the directory lookup, so the time a refusal
	// takes does not tell which names are local users.
	hashed := make(chan struct{})
	go func() {
		defer close(hashed)
		users.WasteTime(password)
	}()
	defer func() { <-hashed }()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	release, err := s.directorySlot(ctx)
	if err != nil {
		return nil, "too many directory sign-ins at once", errDirectoryBusy
	}
	du, err := d.Authenticate(ctx, name, password)
	release()
	var sie *users.SignInError
	var de *users.DirectoryError
	if errors.As(err, &sie) && sie.Revoke != "" {
		// The directory has taken this person's access away: end it here
		// too, sessions included.
		who := login
		if du != nil && du.Username != "" {
			who = du.Username
		}
		s.revokeDirectoryUser(who, sie.Revoke)
	}
	switch {
	case errors.As(err, &sie) && errors.Is(err, users.ErrNoRole):
		return nil, "directory: " + sie.Reason, errNoRole
	case errors.As(err, &sie) && errors.Is(err, users.ErrPasswordExpired):
		return nil, "directory: " + sie.Reason, errPasswordExpired
	case errors.As(err, &sie):
		return nil, "directory: " + sie.Reason, errWrongCredentials
	case errors.As(err, &de):
		return nil, fmt.Sprintf("directory unavailable (%s at %s): %s", de.Code, de.Server, de.Detail()), errDirectoryDown
	case err != nil:
		return nil, "directory: " + err.Error(), errDirectoryDown
	}
	u, err := store.SeeDirectoryUser(*du)
	if errors.Is(err, users.ErrExists) || errors.Is(err, users.ErrReserved) {
		return nil, fmt.Sprintf("directory user %s has the name of a local user or the built-in admin", du.Username), errWrongCredentials
	}
	if err != nil {
		return nil, "could not save the directory user: " + err.Error(),
			&signInError{status: http.StatusInternalServerError, code: "store_failed", msg: "Signalith could not save your sign-in. Ask an admin to check the server log."}
	}
	if u.Disabled {
		return nil, "account disabled in Signalith", errDisabled
	}
	s.directoryChecked(u.Username, d.Revision())
	return principalFromUser(u), "", nil
}

// ---- checking directory users again ----

// directoryRecheck is how often a signed-in directory user is looked up
// again with the service account. Someone removed from their groups, or
// disabled or deleted in the directory, loses access within about this
// long; a change to the directory settings is checked at their next
// request.
const directoryRecheck = 5 * time.Minute

// maxDirectoryChecks bounds how many directory sign-ins and checks run at
// once, so a burst of sign-ins cannot tie up every connection.
const maxDirectoryChecks = 32

type dirCheck struct {
	at      time.Time
	rev     uint64
	running bool
}

// directorySlot waits for a free directory connection, for at most 10
// seconds, and returns a function that frees it.
func (s *Server) directorySlot(ctx context.Context) (func(), error) {
	s.dirSlotsOnce.Do(func() { s.dirSlots = make(chan struct{}, maxDirectoryChecks) })
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	select {
	case s.dirSlots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.dirSlots }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		return nil, errors.New("too many directory connections")
	}
}

// directoryChecked notes that the directory was just asked about a user,
// with the settings of revision rev, so the next check waits.
func (s *Server) directoryChecked(name string, rev uint64) {
	s.checksMu.Lock()
	defer s.checksMu.Unlock()
	if s.dirChecks == nil {
		s.dirChecks = map[string]dirCheck{}
	}
	s.dirChecks[name] = dirCheck{at: time.Now(), rev: rev}
}

// recheckDirectoryUser starts a look at the directory for a signed-in
// directory user, in the background, when the last one is older than
// directoryRecheck or the directory settings have changed since. The
// result applies from their next request: a new role, or their sessions
// end when the directory no longer lets them in.
func (s *Server) recheckDirectoryUser(name string) {
	every := s.DirectoryRecheck
	if every <= 0 {
		every = directoryRecheck
	}
	rev := s.dir().Revision()
	s.checksMu.Lock()
	if s.dirChecks == nil {
		s.dirChecks = map[string]dirCheck{}
	}
	c, seen := s.dirChecks[name]
	if c.running || (seen && c.rev == rev && time.Since(c.at) < every) {
		s.checksMu.Unlock()
		return
	}
	settingsChanged := seen && c.rev != rev
	c.running = true
	s.dirChecks[name] = c
	s.checksMu.Unlock()
	s.background.Add(1)
	go func() {
		defer s.background.Done()
		s.runDirectoryRecheck(name, rev, settingsChanged)
	}()
}

func (s *Server) runDirectoryRecheck(name string, rev uint64, settingsChanged bool) {
	defer s.directoryChecked(name, rev)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	release, err := s.directorySlot(ctx)
	var du *users.DirectoryUser
	if err == nil {
		du, err = s.dir().Lookup(ctx, name)
		release()
	}
	var sie *users.SignInError
	switch {
	case err == nil && users.NormalizeUsername(du.Username) != name:
		s.revokeDirectoryUser(name, "renamed in the directory to "+du.Username)
	case err == nil:
		before, _ := s.userStore().Get(name)
		u, changed, err := s.userStore().RefreshDirectoryUser(name, *du)
		if err == nil && changed && u.Role != before.Role {
			s.Log.Info("directory user's role changed", "audit", true, "user", name, "from", before.Role, "to", u.Role, "by", "directory")
		}
	case errors.As(err, &sie) && sie.Revoke != "":
		s.revokeDirectoryUser(name, sie.Revoke)
	case errors.Is(err, users.ErrDirectoryOff):
		// Directory users cannot use Signalith while it is off.
	default:
		// The directory could not be asked. Access stays as it was and is
		// checked again after the usual wait; but a role given under
		// settings that have changed since is not trusted, so those
		// sessions end.
		ended := 0
		if settingsChanged {
			ended = s.sessions().EndUser(name, "")
		}
		s.Log.Warn("could not check a directory user with the directory", "user", name, "err", err, "sessions_ended", ended)
	}
}

// revokeDirectoryUser takes away a directory user's access after the
// directory refused them, and ends their sessions. Names that are not
// directory users are ignored.
func (s *Server) revokeDirectoryUser(name, reason string) {
	u, changed, err := s.userStore().RefuseDirectoryUser(name, reason)
	if err != nil {
		return
	}
	ended := s.sessions().EndUser(u.Username, "")
	if changed || ended > 0 {
		s.Log.Warn("directory user lost access", "audit", true, "user", u.Username, "reason", reason, "sessions_ended", ended, "by", "directory")
	}
}

// How long checked Basic credentials are remembered. Keys include the
// password hash (or the directory settings' revision), so a changed
// password or setting is never served from the cache; the shorter time
// for directory users bounds how long a password changed in the directory
// keeps working here.
const (
	basicCacheLocal     = 10 * time.Minute
	basicCacheDirectory = 2 * time.Minute
)

// credCache remembers recently checked Basic credentials by a hash, so
// API clients do not pay for bcrypt or a directory round trip on every
// request. Only successes are kept.
type credCache struct {
	mu sync.Mutex
	m  map[[32]byte]credEntry
}

type credEntry struct {
	user  string
	until time.Time
}

func (c *credCache) get(key [32]byte) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return "", false
	}
	if time.Now().After(e.until) {
		delete(c.m, key)
		return "", false
	}
	return e.user, true
}

func (c *credCache) put(key [32]byte, user string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[[32]byte]credEntry{}
	}
	if len(c.m) >= 10000 {
		now := time.Now()
		for k, e := range c.m {
			if now.After(e.until) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= 10000 {
			clear(c.m)
		}
	}
	c.m[key] = credEntry{user: user, until: time.Now().Add(ttl)}
}

// credentialKey identifies a username and password together with what
// they were checked against.
func (s *Server) credentialKey(user, pass string) ([32]byte, time.Duration) {
	version, ttl := "", basicCacheLocal
	switch {
	case strings.EqualFold(strings.TrimSpace(user), s.conf().Auth.AdminUser):
		version = "builtin:" + s.conf().Auth.AdminPasswordHash
	case s.userStore().PasswordVersion(user) != "":
		version = "local:" + s.userStore().PasswordVersion(user)
	default:
		version, ttl = fmt.Sprintf("directory:%d", s.dir().Revision()), basicCacheDirectory
	}
	return sha256.Sum256([]byte(user + "\x00" + pass + "\x00" + version)), ttl
}

// checkBasic checks HTTP Basic credentials, from the cache when it can.
func (s *Server) checkBasic(r *http.Request, user, pass string) (*principal, error) {
	key, ttl := s.credentialKey(user, pass)
	if name, ok := s.creds.get(key); ok {
		if p := s.principalFor(name); p != nil {
			return p, nil
		}
	}
	p, err := s.signIn(r, user, pass, "basic")
	if err != nil {
		return nil, err
	}
	s.creds.put(key, p.Username, ttl)
	return p, nil
}
