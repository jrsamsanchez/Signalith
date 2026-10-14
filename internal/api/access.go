package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
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
	// remember is whether that session was kept through idle periods.
	remember bool
	// epoch is the user's session epoch, which a session made for them
	// starts in (shared users only).
	epoch int64
	// shared is set when the users are kept in the shared settings.
	shared bool
	// breakGlass is set when the built-in admin signed in with the
	// password signalith passwd -local wrote on this server.
	breakGlass bool
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
		if ss, ok := s.sessions().Lookup(r.Context(), c.Value, !background(r)); ok {
			// A password changed since signing in (perhaps on another
			// server sharing the users file) ends the session too.
			if p := s.principalFor(ss.User); p != nil && (ss.Version == "" || ss.Version == s.passwordStamp(ss.User)) {
				p.Method, p.token, p.remember = "session", c.Value, ss.Remember
				return p, nil
			}
			// Deleted, disabled or given a new password since signing in.
			// Shared sessions are not deleted for that: this server may
			// not have read the user yet, and the user's session epoch or
			// housekeeping ends them.
			if s.SharedUsers == nil {
				s.sessions().Delete(r.Context(), c.Value)
			}
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
// with the directory again every few minutes (see recheckDirectoryUser);
// with shared users, the server that runs the background jobs does that
// for every server.
func (s *Server) principalFor(name string) *principal {
	if s.isBuiltin(name) {
		if !s.builtinReadable() {
			return nil
		}
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
		if s.SharedUsers == nil {
			s.recheckDirectoryUser(u.Username)
		}
	}
	p := principalFromUser(u)
	p.shared = s.SharedUsers != nil
	return p
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
	return &principal{Username: s.builtinName(), Role: users.Admin, Source: users.SourceBuiltin,
		epoch: s.builtinEpoch(), shared: s.SharedUsers != nil}
}

func principalFromUser(u users.User) *principal {
	return &principal{Username: u.Username, Name: u.Name, Email: u.Email, Role: u.Role, Source: u.Source,
		MustChangePassword: u.MustChangePassword, epoch: u.SessionEpoch}
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
	errDegraded = &signInError{status: http.StatusServiceUnavailable, code: "degraded", retryAfter: time.Minute,
		msg: "OpenSearch cannot be used right now, so only admins can sign in. Try again later."}
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

// lockedOut is the answer to a sign-in the limits refused (see
// auth.Limiter).
func lockedOut(rf *auth.Refusal) error {
	var msg string
	switch rf.Reason {
	case auth.ReasonBusy:
		msg = "Too many sign-in attempts at the same time. Wait a few seconds, then try again."
	case auth.ReasonSlowed:
		msg = "Many wrong passwords were tried for this account, so sign-ins to it from new browsers are slowed down. " +
			"Try again in " + waitText(rf.Wait) + ", or use a browser you have signed in to this account with before."
	default:
		msg = "Too many failed sign-ins. Try again in " + waitText(rf.Wait) + "."
	}
	return &signInError{status: http.StatusTooManyRequests, code: "locked_out", retryAfter: rf.Wait, msg: msg}
}

// waitText says how long a wait is in whole seconds or minutes, rounded
// up: "a minute", "15 minutes", "8 seconds".
func waitText(d time.Duration) string {
	secs := max(int(math.Ceil(d.Seconds())), 1)
	switch {
	case secs == 1:
		return "a second"
	case secs < 60:
		return fmt.Sprintf("%d seconds", secs)
	case secs <= 60:
		return "a minute"
	}
	return fmt.Sprintf("%d minutes", (secs+59)/60)
}

// knownCookiePrefix starts the name of the cookie that marks a browser as
// one that signed in to an account before; the rest of the name stands
// for the account (auth.BrowserKey.CookieSuffix). It is HTTPS-only, for
// this exact host and every path (the __Host- prefix), like the session
// cookie.
const knownCookiePrefix = "__Host-signalith_known_"

// browserKey signs the known-browser cookies; one kept in memory when
// none was given.
func (s *Server) browserKey() *auth.BrowserKey {
	s.sessions()
	return s.KnownBrowsers
}

// passwordVersion changes whenever account's password does, for the
// passwords Signalith keeps itself: the built-in admin's and local users'.
// A known-browser cookie is only good for the version it was made with, so
// changing or resetting the password makes every browser a stranger to
// the account again. Directory passwords are not seen here.
func (s *Server) passwordVersion(account string) string {
	login := users.LoginName(account)
	if s.isBuiltin(login) {
		if s.SharedUsers != nil {
			// The same on every server.
			return "builtin:" + s.builtinHash()
		}
		return "builtin:" + s.conf().AdminPasswordVersion()
	}
	if v := s.userStore().PasswordVersion(login); v != "" {
		return "local:" + v
	}
	return "directory"
}

// knownBrowser returns the id from a valid known-browser cookie for
// account, if the request has one.
func (s *Server) knownBrowser(r *http.Request, account string) (string, bool) {
	key := s.browserKey()
	name := knownCookiePrefix + key.CookieSuffix(account)
	version, now := "", time.Now()
	for _, c := range r.Cookies() {
		if c.Name != name {
			continue
		}
		if version == "" {
			version = s.passwordVersion(account)
		}
		if id, ok := key.Check(account, version, c.Value, now); ok {
			return id, true
		}
	}
	return "", false
}

// rememberBrowser marks the browser as one that has signed in to each of
// the accounts named (the name typed and the account's own name), so the
// account's slow-down for strangers does not apply to it. The cookie is
// HTTPS-only, so over plain HTTP nothing is remembered.
func (s *Server) rememberBrowser(w http.ResponseWriter, r *http.Request, names ...string) {
	if !s.secureCookie(r) {
		return
	}
	key, now := s.browserKey(), time.Now()
	seen := map[string]bool{}
	for _, n := range names {
		account := strings.ToLower(users.LoginName(n))
		if account == "" || seen[account] {
			continue
		}
		seen[account] = true
		http.SetCookie(w, &http.Cookie{Name: knownCookiePrefix + key.CookieSuffix(account),
			Value: key.Issue(account, s.passwordVersion(account), now), Path: "/",
			MaxAge: int(auth.KnownBrowserAge.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	}
}

// beginAttempt starts a password check that counts toward the sign-in
// limits (see auth.Limiter), or returns the locked-out error. browser
// names a signed-in session making the check, if any; otherwise a
// known-browser cookie for the account counts.
func (s *Server) beginAttempt(r *http.Request, from clientInfo, account, browser string) (*auth.Attempt, error) {
	account = users.LoginName(account)
	c := auth.Client{Address: from.key(), Shared: from.Shared, Browser: browser, Version: s.passwordVersion(account)}
	if c.Browser == "" {
		if id, ok := s.knownBrowser(r, account); ok {
			c.Browser = "cookie:" + id
		}
	}
	a, err := s.limiter().Begin(c, account)
	var rf *auth.Refusal
	if errors.As(err, &rf) {
		return nil, lockedOut(rf)
	}
	return a, err
}

// noteFailure logs what a wrong password led to beyond the failure
// itself: an address locked for every account may be many people behind
// one proxy or NAT, which can be listed so that it never is.
func (s *Server) noteFailure(from clientInfo, f auth.Failure) {
	if f.AddressLocked {
		s.Log.Warn("sign-ins from this address are paused after too many wrong passwords. If many people reach Signalith through it, "+
			"list it on the Settings page. If it is a reverse proxy that sets X-Forwarded-For itself, list it under Trusted reverse proxies (server.trusted_proxies) "+
			"and choose X-Forwarded-For under Client address header (server.client_header). Otherwise list it under Proxies and gateways (server.shared_addresses)",
			append(from.logAttrs(), "minutes", int(s.limiter().Lockout.Minutes()))...)
	}
}

// signIn checks a username and password for the sign-in page or Basic
// auth: the built-in admin first, then local users, then the directory.
// A local username is never looked up in the directory. Wrong passwords
// count toward the limits (see auth.Limiter), and every attempt is logged
// without the password.
func (s *Server) signIn(r *http.Request, name, password, method string) (*principal, error) {
	from := s.client(r)
	name = strings.TrimSpace(name)
	attempt, err := s.beginAttempt(r, from, name, "")
	if err != nil {
		return nil, err
	}
	// The Users page shows how each user last signed in.
	ctx := clusterauth.WithMethod(r.Context(), method)
	p, reason, err := s.checkCredentials(ctx, name, password)
	if err != nil {
		var f auth.Failure
		if errors.Is(err, errWrongCredentials) {
			f = attempt.Fail()
		} else {
			// Unreachable directory, or a right password for an account
			// that may not sign in: no guess was refused.
			attempt.Done()
		}
		s.Log.Warn("sign-in failed", slices.Concat([]any{"audit", true, "user", name}, from.logAttrs(),
			[]any{"method", method, "reason", reason, "locked_out", f.LockedOut()})...)
		s.noteFailure(from, f)
		return nil, err
	}
	attempt.Succeed()
	s.notePlainSignIn(r)
	s.noteName(r)
	s.Log.Info("signed in", slices.Concat([]any{"audit", true, "user", p.Username, "role", p.Role, "source", p.Source}, from.logAttrs(),
		[]any{"method", method})...)
	return p, nil
}

// checkCredentials does the checking for signIn and returns why it
// refused, for the log.
func (s *Server) checkCredentials(ctx context.Context, name, password string) (*principal, string, error) {
	if name == "" || password == "" {
		return nil, "empty username or password", errWrongCredentials
	}
	store := s.userStore()
	if s.isBuiltin(name) {
		ok, local := s.checkBuiltinPassword(password, true)
		if !ok {
			return nil, "wrong password", errWrongCredentials
		}
		store.RecordBuiltinSignIn(ctx)
		p := s.builtinPrincipal()
		p.breakGlass = local
		return p, "", nil
	}
	if u, ok := store.Get(name); ok && u.Source == users.SourceLocal {
		if !store.CheckPassword(u.Username, password) {
			return nil, "wrong password", errWrongCredentials
		}
		if u.Disabled {
			return nil, "account disabled", errDisabled
		}
		p := principalFromUser(u)
		if err := s.degradedRefusal(p); err != nil {
			return nil, "OpenSearch cannot be used, and only admins may sign in then", err
		}
		store.RecordSignIn(ctx, u.Username)
		return p, "", nil
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
		if u, ok := store.Get(login); s.isBuiltin(login) || (ok && u.Source == users.SourceLocal) {
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
		s.revokeDirectoryUser(ctx, who, sie.Revoke)
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
	if err := s.degradedRefusal(&principal{Username: du.Username, Source: users.SourceDirectory}); err != nil {
		return nil, "OpenSearch cannot be used, and only admins may sign in then", err
	}
	u, err := store.SeeDirectoryUser(ctx, *du)
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
		s.revokeDirectoryUser(ctx, name, "renamed in the directory to "+du.Username)
	case err == nil:
		before, _ := s.userStore().Get(name)
		u, changed, err := s.userStore().RefreshDirectoryUser(ctx, name, *du)
		if err == nil && changed && u.Role != before.Role {
			s.Log.Info("directory user's role changed", "audit", true, "user", name, "from", before.Role, "to", u.Role, "by", "directory")
		}
	case errors.As(err, &sie) && sie.Revoke != "":
		s.revokeDirectoryUser(ctx, name, sie.Revoke)
	case errors.Is(err, users.ErrDirectoryOff):
		// Directory users cannot use Signalith while it is off.
	default:
		// The directory could not be asked. Access stays as it was and is
		// checked again after the usual wait; but a role given under
		// settings that have changed since is not trusted, so those
		// sessions end.
		ended := 0
		if settingsChanged {
			ended = s.sessions().EndUser(ctx, name, "")
		}
		s.Log.Warn("could not check a directory user with the directory", "user", name, "err", err, "sessions_ended", ended)
	}
}

// revokeDirectoryUser takes away a directory user's access after the
// directory refused them, and ends their sessions. Names that are not
// directory users are ignored.
func (s *Server) revokeDirectoryUser(ctx context.Context, name, reason string) {
	u, changed, err := s.userStore().RefuseDirectoryUser(ctx, name, reason)
	if err != nil {
		return
	}
	ended := s.sessions().EndUser(ctx, u.Username, "")
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
	case s.isBuiltin(user):
		version = "builtin:" + s.builtinHash()
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
			if err := s.degradedRefusal(p); err != nil {
				return nil, err
			}
			return p, nil
		}
	}
	p, err := s.signIn(r, user, pass, "basic")
	if err != nil {
		return nil, err
	}
	// The break-glass password works only while the shared settings
	// cannot be used: it is checked again each time.
	if !p.breakGlass {
		s.creds.put(key, p.Username, ttl)
	}
	return p, nil
}
