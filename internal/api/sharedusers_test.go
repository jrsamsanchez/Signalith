package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The servers of a cluster whose users are shared, each an API server
// over the shared users, directory settings and sessions of one fake
// OpenSearch. A watch cycle (cycle) stands for one poll.

const memberPrefix = "signalith"

// memberClock is the clock of the sign-in limits; tests move it.
type memberClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *memberClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *memberClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// memberShared is the shared configuration as the API sees it; paused
// stands for writes being refused.
type memberShared struct{ paused atomic.Bool }

func (m *memberShared) Content() bool { return true }
func (m *memberShared) Writable() error {
	if m.paused.Load() {
		return &shared.PausedError{Why: "OpenSearch cannot be reached"}
	}
	return nil
}
func (m *memberShared) Submit(context.Context, string, any, string) (*shared.Request, error) {
	return nil, errors.New("no requests here")
}
func (m *memberShared) Request(context.Context, string) (*shared.Request, bool, error) {
	return nil, false, errors.New("no requests here")
}

// member is one server of the cluster.
type member struct {
	t        *testing.T
	name     string
	rt       *shared.Runtime
	docs     *clusterauth.Docs
	srv      *Server
	url      string
	client   *http.Client
	sessions *clusterauth.Sessions
	shared   *memberShared
	degraded atomic.Bool
	// writesRefused is whether OpenSearch refuses this server's writes.
	writesRefused atomic.Bool
	// copyAge makes the copy of the shared settings look older.
	copyAge atomic.Int64
	logs    *syncBuffer
	// localHash is what signalith passwd -local wrote here.
	localHash atomic.Pointer[string]
}

// cluster is a fake OpenSearch with two members, A (the founder) and B.
type memberCluster struct {
	fake *ostest.Server
	cl   *store.Client
	clk  *memberClock
	a, b *member
}

func (c *memberCluster) client() (*store.Client, string) { return c.cl, memberPrefix }

// newMemberCluster founds a cluster on A, with the built-in admin
// "admin" (password s3cret-pass), and joins B. change, when set, changes
// each API server before it starts.
func newMemberCluster(t *testing.T, change func(*Server)) *memberCluster {
	t.Helper()
	fake := ostest.New(t)
	c := &memberCluster{fake: fake, cl: store.New(store.Config{URL: fake.URL}), clk: &memberClock{t: time.Now()}}
	c.a = c.newMember(t, "siem-a", nil, change)
	c.b = c.newMember(t, "siem-b", c.a.rt.Hub().Keys().Active(), change)
	c.b.cycle()
	return c
}

func (c *memberCluster) newMember(t *testing.T, name string, key *shared.ClusterKey, change func(*Server)) *member {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	master := secrets.NewKeyring(dir)
	if key != nil {
		if err := (shared.KeyStore{Dir: dir, Master: master}).SaveClusterKey(key); err != nil {
			t.Fatal(err)
		}
	}
	m := &member{t: t, name: name, docs: clusterauth.NewDocs(), shared: &memberShared{}, logs: &syncBuffer{}}
	log := slog.New(slog.NewTextHandler(m.logs, nil))
	m.rt = shared.NewRuntime(shared.RuntimeOptions{StateDir: dir, Self: shared.Self{NodeID: "n_" + name, Name: name},
		Content: m.docs.Track, Log: log})
	m.docs.Cluster = m.rt.Cluster
	m.rt.Use(c.cl, memberPrefix, master)
	if key == nil {
		if err := m.rt.Found(ctx, "test"); err != nil {
			t.Fatal(err)
		}
		h, err := users.HashPassword("s3cret-pass")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.docs.CreateBuiltin(ctx, "test", "admin", h, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if mode, why := m.rt.Mode(); mode != shared.ModeMember {
		t.Fatalf("%s: %s (%s)", name, mode, why)
	}
	ub := &clusterauth.UsersBackend{Docs: m.docs}
	st, err := users.New(ub)
	if err != nil {
		t.Fatal(err)
	}
	seen := &clusterauth.LastSeen{Client: c.client, Node: name, Writable: func() bool { return m.shared.Writable() == nil }}
	st.Builtin, st.SignIns = m.docs.Builtin, seen.Hook(log)
	directory := users.NewDirectory(&clusterauth.DirectoryBackend{Docs: m.docs, Node: name})
	m.sessions = &clusterauth.Sessions{Docs: m.docs, Client: c.client, Node: "n_" + name, Cache: clusterauth.NewSessionCache(),
		DirectoryOn: directory.Enabled, Degraded: m.degraded.Load, Confirmed: func() time.Time {
			return m.rt.Hub().Confirmed().Add(-time.Duration(m.copyAge.Load()))
		}, Log: log}
	m.sessions.SetIdle(12 * time.Hour)
	m.sessions.Listen()
	limiter := auth.NewLimiter()
	limiter.Now, limiter.Divisor = c.clk.Now, func() int { return 2 }
	locks := &clusterauth.Locks{Docs: m.docs, Client: c.client, Node: "n_" + name, Limiter: limiter,
		Writable: func() bool { return m.shared.Writable() == nil }, Log: log}
	locks.Listen()
	ts, srv := newUsersServer(t, func(s *Server) {
		s.Log = log
		s.Users, s.Directory, s.SessionStore, s.Limiter = st, directory, m.sessions, limiter
		s.KnownBrowsers = auth.NewBrowserKeyFrom(m.rt.Hub().Keys().Active().KnownBrowserKey())
		s.Shared = m.shared
		s.SharedUsers = &SharedUsers{Docs: m.docs, Seen: seen, LocalHash: func() string {
			if p := m.localHash.Load(); p != nil {
				return *p
			}
			return ""
		}, WritesRefused: m.writesRefused.Load, MayDegrade: m.sessions.MayDegrade}
		if change != nil {
			change(s)
		}
	})
	m.srv = srv
	m.url, m.client = ts.URL, &http.Client{CheckRedirect: noRedirect.CheckRedirect}
	return m
}

// cycle reads the shared settings once, as the watcher does every 2
// seconds: one poll.
func (m *member) cycle() {
	m.t.Helper()
	if err := m.rt.Hub().Cycle(context.Background()); err != nil {
		m.t.Fatal(err)
	}
}

// signIn signs in on the sign-in page and returns the session cookie, or
// nil with the status.
func (m *member) signIn(user, pass string) (*http.Cookie, int) {
	m.t.Helper()
	r := signInWith(m.t, m.client, m.url, attempt{user: user, pass: pass})
	for _, c := range r.cookies {
		if c.Name == sessionCookie && c.Value != "" {
			return c, r.code
		}
	}
	return nil, r.code
}

// call sends a request with the session cookie c (or Basic credentials
// user:pass when c is nil and basic is set) and extra headers.
func (m *member) call(method, path, body string, c *http.Cookie, hdr map[string]string) (int, map[string]any, *http.Response) {
	m.t.Helper()
	req, _ := http.NewRequest(method, m.url+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if c != nil {
		req.AddCookie(c)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		m.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, resp
}

// me reports the status of GET /api/me with the cookie c.
func (m *member) me(c *http.Cookie) int {
	m.t.Helper()
	code, _, _ := m.call("GET", "/api/me", "", c, nil)
	return code
}

// basic reports the status of GET /api/me with Basic credentials.
func (m *member) basic(user, pass string) int {
	m.t.Helper()
	req, _ := http.NewRequest("GET", m.url+"/api/me", nil)
	req.SetBasicAuth(user, pass)
	resp, err := m.client.Do(req)
	if err != nil {
		m.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// addUser adds a local user on m as the built-in admin, who need not
// change the password.
func (m *member) addUser(admin *http.Cookie, name, pass string, role users.Role) {
	m.t.Helper()
	code, out, _ := m.call("POST", "/api/users", fmt.Sprintf(`{"username":%q,"password":%q,"role":%q,"must_change_password":false}`, name, pass, role), admin, nil)
	if code != http.StatusCreated {
		m.t.Fatalf("add %s on %s: %d %v", name, m.name, code, out)
	}
}

// waitFor waits up to 10 seconds for ok.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// V7, V8: a session made on A works on B at once, with nothing refreshed;
// a sign-out on B is refused on A within one poll.
func TestSharedSessionOnEveryServer(t *testing.T) {
	c := newMemberCluster(t, nil)
	cookie, code := c.a.signIn("admin", "s3cret-pass")
	if cookie == nil || code != http.StatusOK {
		t.Fatalf("sign in on A: %d", code)
	}
	if !strings.HasPrefix(cookie.Value, "s1.") {
		t.Fatalf("not a cluster cookie: %s", cookie.Value)
	}
	if got := c.b.me(cookie); got != http.StatusOK {
		t.Fatalf("the cookie made on A on B: %d", got)
	}
	if got := c.a.me(cookie); got != http.StatusOK {
		t.Fatalf("on A: %d", got)
	}
	if code, _, _ := c.b.call("POST", "/api/logout", "", cookie, nil); code != http.StatusOK {
		t.Fatalf("sign out on B: %d", code)
	}
	if got := c.b.me(cookie); got != http.StatusUnauthorized {
		t.Fatalf("on B after signing out there: %d", got)
	}
	c.a.cycle()
	if got := c.a.me(cookie); got != http.StatusUnauthorized {
		t.Fatalf("on A one poll after the sign-out on B: %d", got)
	}
}

// V9, V24: a user disabled on A is refused on B within one poll, with a
// session and with Basic credentials B had remembered; a password
// changed on A makes the old Basic credentials fail on B.
func TestUserChangesApplyOnEveryServer(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	c.a.addUser(admin, "jlee", "first-password-1", users.Analyst)
	c.a.addUser(admin, "kim", "kim-password-1", users.Analyst)
	c.b.cycle()
	jlee, code := c.b.signIn("jlee", "first-password-1")
	if jlee == nil {
		t.Fatalf("jlee on B: %d", code)
	}
	if got := c.b.basic("jlee", "first-password-1"); got != http.StatusOK {
		t.Fatalf("Basic on B: %d", got)
	}
	if got := c.b.basic("kim", "kim-password-1"); got != http.StatusOK {
		t.Fatalf("Basic for kim on B: %d", got)
	}
	if code, out, _ := c.a.call("PUT", "/api/users/jlee", `{"disabled":true}`, admin, nil); code != http.StatusOK {
		t.Fatalf("disable on A: %d %v", code, out)
	}
	c.b.cycle()
	if got := c.b.me(jlee); got != http.StatusUnauthorized {
		t.Errorf("jlee's session on B after the disable on A: %d", got)
	}
	if got := c.b.basic("jlee", "first-password-1"); got != http.StatusForbidden && got != http.StatusUnauthorized {
		t.Errorf("jlee's remembered Basic credentials on B: %d", got)
	}
	// V24: a password reset on A.
	if code, out, _ := c.a.call("POST", "/api/users/kim/password", `{"password":"kim-password-2"}`, admin, nil); code != http.StatusOK {
		t.Fatalf("reset on A: %d %v", code, out)
	}
	c.b.cycle()
	if got := c.b.basic("kim", "kim-password-1"); got != http.StatusUnauthorized {
		t.Errorf("kim's old Basic credentials on B: %d", got)
	}
}

// V10: a session made on B just before a password reset on A ends, by
// the user's session epoch, on both servers.
func TestResetEndsSessionsMadeJustBefore(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	c.a.addUser(admin, "jlee", "first-password-1", users.Analyst)
	c.b.cycle()
	jlee, _ := c.b.signIn("jlee", "first-password-1")
	if jlee == nil || c.b.me(jlee) != http.StatusOK {
		t.Fatal("jlee cannot sign in on B")
	}
	time.Sleep(500 * time.Millisecond)
	if code, out, _ := c.a.call("POST", "/api/users/jlee/password", "", admin, nil); code != http.StatusOK {
		t.Fatalf("reset on A: %d %v", code, out)
	}
	if got := c.a.me(jlee); got != http.StatusUnauthorized {
		t.Errorf("on A after the reset there: %d", got)
	}
	c.b.cycle()
	if got := c.b.me(jlee); got != http.StatusUnauthorized {
		t.Errorf("on B one poll after the reset on A: %d", got)
	}
}

// V11: changing one's own password keeps the browser signed in with a
// new session, ends the user's other sessions on both servers, and clears
// must_change_password. The built-in admin may do the same (C7), and
// every server takes the new password within one poll.
func TestOwnPasswordChangeAcrossServers(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	code, out, _ := c.a.call("POST", "/api/users", `{"username":"jlee","password":"first-password-1","role":"analyst"}`, admin, nil)
	if code != http.StatusCreated {
		t.Fatalf("add jlee: %d %v", code, out)
	}
	c.b.cycle()
	onA, _ := c.a.signIn("jlee", "first-password-1")
	onB, _ := c.b.signIn("jlee", "first-password-1")
	if onA == nil || onB == nil {
		t.Fatal("jlee cannot sign in")
	}
	code, out, resp := c.a.call("POST", "/api/me/password", `{"current_password":"first-password-1","new_password":"second-password-2"}`, onA, nil)
	if code != http.StatusOK || out["must_change_password"] != false {
		t.Fatalf("change on A: %d %v", code, out)
	}
	var fresh *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			fresh = ck
		}
	}
	if fresh == nil || fresh.Value == onA.Value {
		t.Fatal("no new session cookie")
	}
	if got := c.a.me(fresh); got != http.StatusOK {
		t.Errorf("the new cookie on A: %d", got)
	}
	c.b.cycle()
	if got := c.b.me(fresh); got != http.StatusOK {
		t.Errorf("the new cookie on B: %d", got)
	}
	for name, ck := range map[string]*http.Cookie{"A's old": onA, "B's": onB} {
		if got := c.a.me(ck); got != http.StatusUnauthorized {
			t.Errorf("%s session on A: %d", name, got)
		}
		if got := c.b.me(ck); got != http.StatusUnauthorized {
			t.Errorf("%s session on B: %d", name, got)
		}
	}

	// The built-in admin, from the user menu.
	code, out, _ = c.a.call("GET", "/api/me", "", admin, nil)
	if code != http.StatusOK || out["can_change_password"] != true {
		t.Fatalf("me: %d %v", code, out)
	}
	code, out, resp = c.a.call("POST", "/api/me/password", `{"current_password":"s3cret-pass","new_password":"another-admin-pass"}`, admin, nil)
	if code != http.StatusOK {
		t.Fatalf("the built-in admin's change: %d %v", code, out)
	}
	fresh = nil
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			fresh = ck
		}
	}
	if fresh == nil || c.a.me(fresh) != http.StatusOK || c.a.me(admin) != http.StatusUnauthorized {
		t.Fatal("the built-in admin's session was not replaced")
	}
	c.b.cycle()
	if _, code := c.b.signIn("admin", "s3cret-pass"); code != http.StatusUnauthorized {
		t.Errorf("the old password on B: %d", code)
	}
	if ck, code := c.b.signIn("admin", "another-admin-pass"); ck == nil {
		t.Errorf("the new password on B: %d", code)
	}
	// Other changes to the built-in admin stay refused.
	if code, _, _ := c.b.call("POST", "/api/users/admin/password", "", fresh, nil); code != http.StatusConflict {
		t.Errorf("a reset of the built-in admin: %d", code)
	}
}

// V26: a change with a stale If-Match is refused with 412 naming who
// changed the user and where; without If-Match, a change made meanwhile
// on another server is kept.
func TestUserETags(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	c.a.addUser(admin, "jlee", "first-password-1", users.Analyst)
	c.b.cycle()
	code, out, _ := c.b.call("GET", "/api/users", "", admin, nil)
	if code != http.StatusOK || out["shared"] != true {
		t.Fatalf("list on B: %d %v", code, out)
	}
	etag := ""
	for _, u := range out["users"].([]any) {
		if v := u.(map[string]any); v["username"] == "jlee" {
			etag, _ = v["etag"].(string)
		}
	}
	if etag == "" {
		t.Fatalf("no etag: %v", out["users"])
	}
	if code, _, _ := c.a.call("PUT", "/api/users/jlee", `{"name":"J. Lee"}`, admin, nil); code != http.StatusOK {
		t.Fatalf("change on A: %d", code)
	}
	code, out, _ = c.b.call("PUT", "/api/users/jlee", `{"email":"j@example.com"}`, admin, map[string]string{"If-Match": etag})
	if code != http.StatusPreconditionFailed || !strings.Contains(fmt.Sprint(out["error"]), "siem-a") || !strings.Contains(fmt.Sprint(out["error"]), "admin") {
		t.Fatalf("stale change on B: %d %v", code, out)
	}
	// The page says who changed it and where in its own words.
	if out["code"] != "stale" || out["changed_on"] != "siem-a" || out["changed_by"] != "admin" || out["changed_at"] == nil {
		t.Errorf("stale answer: %v", out)
	}
	// Without If-Match, B's change goes on top of A's, though B has not
	// read it yet.
	if code, out, _ := c.b.call("PUT", "/api/users/jlee", `{"email":"j@example.com"}`, admin, nil); code != http.StatusOK {
		t.Fatalf("change on B: %d %v", code, out)
	}
	c.a.cycle()
	u, _ := c.a.srv.Users.Get("jlee")
	if u.Name != "J. Lee" || u.Email != "j@example.com" {
		t.Errorf("a change was lost: %+v", u)
	}
	// The directory settings carry their version too.
	code, out, _ = c.a.call("GET", "/api/auth/directory", "", admin, nil)
	if code != http.StatusOK || out["from_config"] != false || out["shared"] != true {
		t.Fatalf("directory: %d %v", code, out)
	}
	code, _, _ = c.a.call("PUT", "/api/auth/directory", `{"type":"ad","url":"ldaps://dc.example.com","enabled":false}`, admin,
		map[string]string{"If-Match": "stale"})
	if code != http.StatusPreconditionFailed {
		t.Errorf("stale directory save: %d", code)
	}
	// While writes are refused, changes are refused with 503.
	c.a.shared.paused.Store(true)
	if code, _, _ := c.a.call("PUT", "/api/users/jlee", `{"name":"X"}`, admin, nil); code != http.StatusServiceUnavailable {
		t.Errorf("change while paused: %d", code)
	}
}

// V29: the Users page shows each user's newest sign-in and the server it
// was on.
func TestLastSignInAcrossServers(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	c.a.addUser(admin, "jlee", "first-password-1", users.Analyst)
	c.b.cycle()
	if ck, _ := c.b.signIn("jlee", "first-password-1"); ck == nil {
		t.Fatal("jlee cannot sign in on B")
	}
	waitFor(t, "jlee's sign-in on B is listed on A", func() bool {
		_, out, _ := c.a.call("GET", "/api/users", "", admin, nil)
		for _, u := range out["users"].([]any) {
			v := u.(map[string]any)
			if v["username"] == "jlee" && v["last_sign_in_server"] == "siem-b" && v["last_sign_in"] != nil {
				return true
			}
		}
		return false
	})
	_, out, _ := c.b.call("GET", "/api/users", "", admin, nil)
	if b := out["users"].([]any)[0].(map[string]any); b["username"] != "admin" || b["last_sign_in_server"] != "siem-a" {
		t.Errorf("the built-in admin's row: %v", b)
	}
}

// V13: a lockout of an address and account on A refuses them on B; an
// address locked on A is refused on B; both end on time. With 2 servers,
// each allows half the tries.
func TestLockoutsAcrossServers(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	c.a.addUser(admin, "jlee", "first-password-1", users.Analyst)
	c.a.addUser(admin, "kim", "kim-password-1", users.Analyst)
	c.b.cycle()
	for i := 1; i <= 5; i++ {
		if _, code := c.a.signIn("jlee", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("guess %d on A: %d", i, code)
		}
	}
	if _, code := c.a.signIn("jlee", "first-password-1"); code != http.StatusTooManyRequests {
		t.Fatalf("jlee on A after 5 guesses (10 halved): %d", code)
	}
	waitFor(t, "the lock is written", func() bool {
		docs, _ := c.cl.SearchDocs(context.Background(), memberPrefix+"_runtime", map[string]any{"term": map[string]any{"kind": "lock"}})
		return len(docs) == 1
	})
	c.b.cycle()
	waitFor(t, "B refuses jlee from the address", func() bool {
		_, code := c.b.signIn("jlee", "first-password-1")
		return code == http.StatusTooManyRequests
	})
	if ck, code := c.b.signIn("kim", "kim-password-1"); ck == nil {
		t.Fatalf("kim on B: %d", code)
	}
	// The address: 15 guesses at made-up accounts (30 halved).
	for i := 0; i < 15; i++ {
		c.a.signIn(fmt.Sprint("nobody", i), "guess")
	}
	if _, code := c.a.signIn("kim", "kim-password-1"); code != http.StatusTooManyRequests {
		t.Fatalf("kim on A after the address was locked: %d", code)
	}
	c.b.cycle()
	waitFor(t, "B refuses the address", func() bool {
		_, code := c.b.signIn("kim", "kim-password-1")
		return code == http.StatusTooManyRequests
	})
	c.clk.Advance(16 * time.Minute)
	for _, m := range []*member{c.a, c.b} {
		if ck, code := m.signIn("jlee", "first-password-1"); ck == nil {
			t.Errorf("jlee on %s after the lockout ended: %d", m.name, code)
		}
	}
}

// V14: 50 wrong passwords for different accounts through one trusted
// proxy that sends no client address lock no one out: no lock is
// written, and another account signs in on both servers.
func TestSharedAddressWritesNoLock(t *testing.T) {
	c := newMemberCluster(t, func(s *Server) { s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"} })
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	c.a.addUser(admin, "jlee", "first-password-1", users.Analyst)
	c.b.cycle()
	for i := 0; i < 50; i++ {
		m := c.a
		if i%2 == 1 {
			m = c.b
		}
		if _, code := m.signIn(fmt.Sprint("nobody", i), "guess"); code != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d", i, code)
		}
	}
	for _, m := range []*member{c.a, c.b} {
		if ck, code := m.signIn("jlee", "first-password-1"); ck == nil {
			t.Errorf("jlee on %s: %d", m.name, code)
		}
	}
	time.Sleep(100 * time.Millisecond)
	docs, err := c.cl.SearchDocs(context.Background(), memberPrefix+"_runtime", map[string]any{"term": map[string]any{"kind": "lock"}})
	if err != nil || len(docs) != 0 {
		t.Errorf("locks written for a shared address: %d %v", len(docs), err)
	}
}

// V16: X-Forwarded-For from a peer that is not a trusted proxy is not
// believed: the lock written is the peer's, not the address it named.
func TestUntrustedForwardedForInLocks(t *testing.T) {
	c := newMemberCluster(t, nil)
	for i := 0; i < 5; i++ {
		signInWith(t, c.a.client, c.a.url, attempt{user: "jlee", pass: "wrong", xff: fmt.Sprintf("203.0.113.%d", i)})
	}
	cid, secret := c.a.docs.ClusterID(), c.a.docs.Hub().Keys().Active().LockKey()
	peer := clusterauth.LockID(cid, auth.ScopeAddressAccount, auth.LockKey(secret, "p\x00127.0.0.1\x00jlee"))
	waitFor(t, "the lock of the peer's address", func() bool {
		return c.fake.Source(memberPrefix+"_runtime", peer) != nil
	})
	for i := 0; i < 5; i++ {
		named := clusterauth.LockID(cid, auth.ScopeAddressAccount, auth.LockKey(secret, fmt.Sprintf("p\x00203.0.113.%d\x00jlee", i)))
		if c.fake.Source(memberPrefix+"_runtime", named) != nil {
			t.Errorf("a lock for the forwarded address 203.0.113.%d", i)
		}
	}
}

// V25: a browser known to an account on A is known on B: the
// known-browser key comes from the cluster key.
func TestKnownBrowserOnEveryServer(t *testing.T) {
	c := newMemberCluster(t, nil)
	req := httptest.NewRequest("POST", "https://siem-a/api/login", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	c.a.srv.rememberBrowser(rec, req, "jlee")
	known := knownCookies(rec.Result().Cookies())
	if len(known) != 1 {
		t.Fatalf("known-browser cookies %v", rec.Result().Cookies())
	}
	onB := httptest.NewRequest("POST", "https://siem-b/api/login", nil)
	onB.AddCookie(known[0])
	if _, ok := c.b.srv.knownBrowser(onB, "jlee"); !ok {
		t.Error("B does not know the browser A remembered")
	}
	// A server with its own key would not.
	other := &Server{Config: c.b.srv.Config, Users: c.b.srv.Users, KnownBrowsers: auth.NewBrowserKey(), SharedUsers: c.b.srv.SharedUsers}
	if _, ok := other.knownBrowser(onB, "jlee"); ok {
		t.Error("a key of its own knows the browser")
	}
}

// V17 at the API: while OpenSearch cannot be used, the built-in admin
// signs in with the password signalith passwd -local wrote, for a session
// this server keeps in memory; that password does not work otherwise.
func TestDegradedBuiltinSignIn(t *testing.T) {
	c := newMemberCluster(t, nil)
	h, err := config.HashPassword("local-break-glass")
	if err != nil {
		t.Fatal(err)
	}
	c.a.localHash.Store(&h)
	if _, code := c.a.signIn("admin", "local-break-glass"); code != http.StatusUnauthorized {
		t.Fatalf("the -local password while the shared settings work: %d", code)
	}
	c.a.shared.paused.Store(true)
	c.a.degraded.Store(true)
	ck, code := c.a.signIn("admin", "local-break-glass")
	if ck == nil {
		t.Fatalf("the -local password while degraded: %d", code)
	}
	if got := c.a.me(ck); got != http.StatusOK {
		t.Fatalf("the degraded session: %d", got)
	}
	if got := c.b.me(ck); got != http.StatusUnauthorized {
		t.Errorf("the degraded session on B: %d", got)
	}
	if !strings.Contains(c.a.logs.String(), "signed in while OpenSearch cannot be written") {
		t.Errorf("the degraded sign-in was not logged:\n%s", c.a.logs.String())
	}
}

// While OpenSearch refuses writes (a full disk), the server stays a
// member, and the -local password still works there, for a session kept
// in memory; on a server whose writes are taken it does not.
func TestBreakGlassWhileWritesRefused(t *testing.T) {
	c := newMemberCluster(t, nil)
	h, err := config.HashPassword("local-break-glass")
	if err != nil {
		t.Fatal(err)
	}
	c.a.localHash.Store(&h)
	c.b.localHash.Store(&h)
	c.fake.Block(true)
	c.a.writesRefused.Store(true)
	ck, code := c.a.signIn("admin", "local-break-glass")
	if ck == nil {
		t.Fatalf("the -local password while writes are refused: %d", code)
	}
	if got := c.a.me(ck); got != http.StatusOK {
		t.Fatalf("the session: %d", got)
	}
	if ck, code := c.b.signIn("admin", "local-break-glass"); ck != nil || code != http.StatusUnauthorized {
		t.Errorf("the -local password on a server that sees no refused writes: %d", code)
	}
	// Basic with it works only while writes are refused: it is not
	// remembered.
	if got := c.a.basic("admin", "local-break-glass"); got != http.StatusOK {
		t.Fatalf("Basic with the -local password: %d", got)
	}
	c.fake.Block(false)
	c.a.writesRefused.Store(false)
	if got := c.a.basic("admin", "local-break-glass"); got != http.StatusUnauthorized {
		t.Errorf("Basic with the -local password once writes are taken again: %d", got)
	}
}

// While this server cannot use the shared settings, Basic credentials
// follow the same rule as sign-ins: only the built-in admin and local
// admins whose copy is recent.
func TestBasicWhileDegraded(t *testing.T) {
	c := newMemberCluster(t, nil)
	ctx := context.Background()
	for _, u := range []users.NewUser{
		{Username: "vic", Role: users.Viewer, Password: "viewer-password-1"},
		{Username: "ada", Role: users.Admin, Password: "admin-password-1"},
	} {
		if _, err := c.a.srv.Users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	c.a.cycle()
	if got := c.a.basic("vic", "viewer-password-1"); got != http.StatusOK {
		t.Fatalf("Basic as a viewer: %d", got)
	}
	c.a.shared.paused.Store(true)
	c.a.degraded.Store(true)
	if got := c.a.basic("vic", "viewer-password-1"); got != http.StatusServiceUnavailable {
		t.Errorf("Basic as a viewer while degraded (remembered): %d", got)
	}
	if got := c.a.basic("ada", "admin-password-1"); got != http.StatusOK {
		t.Errorf("Basic as a local admin while degraded: %d", got)
	}
	if got := c.a.basic("admin", adminPass); got != http.StatusOK {
		t.Errorf("Basic as the built-in admin while degraded: %d", got)
	}
	// A copy older than a day: local admins are refused too.
	c.a.copyAge.Store(int64(25 * time.Hour))
	if got := c.a.basic("ada", "admin-password-1"); got != http.StatusServiceUnavailable {
		t.Errorf("Basic as a local admin with an old copy: %d", got)
	}
	// Refused for that reason is no wrong password: it locks nobody out.
	for range 20 {
		c.a.basic("vic", "viewer-password-1")
	}
	c.a.shared.paused.Store(false)
	c.a.degraded.Store(false)
	if got := c.a.basic("vic", "viewer-password-1"); got != http.StatusOK {
		t.Errorf("Basic as a viewer once OpenSearch is back: %d", got)
	}
}

// With shared users the built-in admin's password is the cluster's only:
// when this server cannot read its document, this server's own configured
// password does not take its place.
func TestBuiltinFailsClosed(t *testing.T) {
	c := newMemberCluster(t, func(s *Server) {
		h, _ := config.HashPassword("file-pass")
		s.Config.Auth.AdminPasswordHash = h
	})
	if got := c.a.basic("admin", adminPass); got != http.StatusOK {
		t.Fatalf("the cluster's password: %d", got)
	}
	if got := c.a.basic("admin", "file-pass"); got != http.StatusUnauthorized {
		t.Fatalf("this server's own password: %d", got)
	}
	ck, _ := c.a.signIn("admin", adminPass)
	if ck == nil {
		t.Fatal("no session")
	}
	ctx := context.Background()
	_, etag, _ := c.a.docs.Users().Get("admin")
	if _, err := c.a.docs.Users().Delete(ctx, "test", "admin", etag); err != nil {
		t.Fatal(err)
	}
	c.a.cycle()
	for _, pass := range []string{adminPass, "file-pass"} {
		if got := c.a.basic("admin", pass); got != http.StatusUnauthorized {
			t.Errorf("Basic with %s and no built-in admin document: %d", pass, got)
		}
	}
	if got := c.a.me(ck); got != http.StatusUnauthorized {
		t.Errorf("a session with no built-in admin document: %d", got)
	}
}

// On a member of a cluster whose users are not shared yet, the Users page
// and the Servers page name the servers whose version keeps them apart;
// a server not in a cluster says nothing of it.
func TestUsersPendingNamesOldServers(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = &fakeCluster{holder: "siem-a"}
		s.Shared = &memberShared{}
		s.Version = "1.6.0"
	})
	code, out := do(t, ts, "GET", "/api/users", "", true)
	if code != http.StatusOK || out["shared"] != false {
		t.Fatalf("list: %d %v", code, out)
	}
	p, _ := out["shared_pending"].(map[string]any)
	sv, _ := p["servers"].([]any)
	if p["version"] != "1.6.0" || len(sv) != 1 || sv[0].(map[string]any)["name"] != "siem-a" || sv[0].(map[string]any)["version"] != "1.5.0" {
		t.Errorf("pending: %v", out["shared_pending"])
	}
	_, out = do(t, ts, "GET", "/api/cluster", "", true)
	found := false
	for _, w := range out["warnings"].([]any) {
		if text := w.(map[string]any)["text"].(string); strings.Contains(text, "runs 1.6.0 or later") && strings.Contains(text, "siem-a (1.5.0)") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning naming siem-a: %v", out["warnings"])
	}

	ts, _ = newTestServerWith(t, func(s *Server) { s.Cluster = &fakeCluster{holder: "siem-a"} })
	if _, out := do(t, ts, "GET", "/api/users", "", true); out["shared_pending"] != nil {
		t.Errorf("a server not in a cluster: %v", out["shared_pending"])
	}
}
