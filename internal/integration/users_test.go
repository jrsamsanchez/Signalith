//go:build integration && linux

package integration

// Users and sign-in shared by the servers of a cluster (multi-server
// design, PR 5), with real `signalith serve` processes: a browser signs in
// through a round-robin proxy with no sticky sessions and its session
// works on both servers, a sign-out ends it on both, and it carries on on
// one server when the other is killed; while OpenSearch refuses writes
// (the flood-stage block) the built-in admin still signs in, with a
// session kept on that server, which is stored for every server once
// writes work again; and the users are not shared while a server of an
// earlier version is live, and become shared once it is upgraded, with the
// founder's users brought in.
//
// The unit tests in internal/api, internal/clusterauth and cmd/signalith
// cover the rest against the in-memory fake (see the PR 5 plan's list).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
)

// sessionCookie is the session cookie's name over HTTPS.
const sessionCookie = "__Host-signalith_session"

// usersView is GET /api/users as the tests need it.
type usersView struct {
	Users []struct {
		Username         string `json:"username"`
		LastSignInServer string `json:"last_sign_in_server"`
	} `json:"users"`
	Shared  bool `json:"shared"`
	Pending *struct {
		Version string `json:"version"`
		Servers []struct {
			Name string `json:"name"`
		} `json:"servers"`
	} `json:"shared_pending"`
}

// users reads the server's GET /api/users as the built-in admin; ok is
// false when it did not answer.
func (s *testServer) users() (v usersView, ok bool) {
	return v, s.call(http.MethodGet, "/api/users", nil, &v) == http.StatusOK
}

// usersShared reports whether the server keeps its users in the shared
// settings.
func (s *testServer) usersShared() bool {
	v, ok := s.users()
	return ok && v.Shared
}

// addUser adds a local user who signs in with password at once.
func (s *testServer) addUser(name, role, password string) {
	s.h.t.Helper()
	code, _, body := s.request(http.MethodPost, "/api/users",
		map[string]any{"username": name, "role": role, "password": password, "must_change_password": false}, nil)
	if code != http.StatusCreated {
		s.h.t.Fatalf("adding %s on %s: %d %s", name, s.name, code, body)
	}
}

// hasUser reports whether the server's Users page lists name.
func (s *testServer) hasUser(name string) bool {
	v, _ := s.users()
	for _, u := range v.Users {
		if u.Username == name {
			return true
		}
	}
	return false
}

// signIn signs in on the server itself as the sign-in page does and
// returns the session cookie, nil when the sign-in was refused, with the
// status.
func (s *testServer) signIn(user, password string) (*http.Cookie, int) {
	b, _ := json.Marshal(map[string]any{"username": user, "password": password})
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/api/login", s.port), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.api.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" && resp.StatusCode == http.StatusOK {
			return c, resp.StatusCode
		}
	}
	return nil, resp.StatusCode
}

// me asks the server's GET /api/me with the session cookie c, and returns
// the status (0 when there was no answer).
func (s *testServer) me(c *http.Cookie) int {
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/me", s.port), nil)
	req.AddCookie(c)
	resp, err := s.api.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// roundRobin is a load balancer with no sticky sessions: an HTTPS proxy
// that sends each request to the next server of its list.
type roundRobin struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	// backends are the servers it sends to; served names the server that
	// answered each request, in order.
	backends []*testServer
	next     int
	served   []string
	byHost   map[string]*testServer
}

func newRoundRobin(t *testing.T, servers ...*testServer) *roundRobin {
	t.Helper()
	p := &roundRobin{t: t, backends: servers, byHost: map[string]*testServer{}}
	for _, s := range servers {
		p.byHost[fmt.Sprintf("127.0.0.1:%d", s.port)] = s
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			p.mu.Lock()
			s := p.backends[p.next%len(p.backends)]
			p.next++
			p.mu.Unlock()
			u, _ := url.Parse(fmt.Sprintf("https://127.0.0.1:%d", s.port))
			pr.SetURL(u)
		},
		// Each server has its own certificate authority.
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			s := p.byHost[r.URL.Host]
			resp, err := s.api.Transport.RoundTrip(r)
			if err == nil {
				p.mu.Lock()
				p.served = append(p.served, s.name)
				p.mu.Unlock()
			}
			return resp, err
		}),
	}
	p.srv = httptest.NewTLSServer(rp)
	t.Cleanup(p.srv.Close)
	return p
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// only sends every later request to s.
func (p *roundRobin) only(s *testServer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.backends = []*testServer{s}
}

// servedBy returns the servers that answered so far, and forgets them.
func (p *roundRobin) servedBy() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.served
	p.served = nil
	return out
}

// browser is a client of the proxy that keeps cookies, as a browser does.
func (p *roundRobin) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := p.srv.Client()
	c.Jar, c.Timeout = jar, 10*time.Second
	return c
}

// do makes a request through the proxy and returns its status.
func (p *roundRobin) do(c *http.Client, method, path string, body any) int {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, p.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// cookie is the browser's session cookie for the proxy.
func (p *roundRobin) cookie(c *http.Client) *http.Cookie {
	u, _ := url.Parse(p.srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			return ck
		}
	}
	return nil
}

// waitShared waits until every server keeps its users in the shared
// settings, which a new cluster does from the start.
func waitShared(t *testing.T, servers ...*testServer) {
	t.Helper()
	waitUntil(t, 120*time.Second, "the servers share their users", func() bool {
		for _, s := range servers {
			if !s.usersShared() {
				return false
			}
		}
		return true
	})
}

// A browser signs in through a load balancer that sends each request to
// the next server: the session works on both, the Users page of the other
// server shows where the sign-in was, a sign-out ends the session on both,
// and when the server a browser used is killed, it carries on on the
// other without signing in again.
func TestClusterSharedUsersRoundRobin(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitShared(t, a, b)
	a.addUser("jlee", "analyst", "jlee-password-1")
	waitUntil(t, 10*time.Second, "siem-b reads jlee", func() bool { return b.hasUser("jlee") })

	lb := newRoundRobin(t, a, b)
	br := lb.browser()
	if code := lb.do(br, http.MethodPost, "/api/login", map[string]any{"username": "jlee", "password": "jlee-password-1"}); code != http.StatusOK {
		t.Fatalf("sign-in through the load balancer: %d", code)
	}
	lb.servedBy()
	for i := range 6 {
		if code := lb.do(br, http.MethodGet, "/api/me", nil); code != http.StatusOK {
			t.Fatalf("request %d with the session: %d (served by %v)", i, code, lb.servedBy())
		}
	}
	if got := strings.Join(lb.servedBy(), ","); !strings.Contains(got, "siem-a") || !strings.Contains(got, "siem-b") {
		t.Errorf("the requests were not shared out: %s", got)
	}
	waitUntil(t, 30*time.Second, "siem-b's Users page shows where jlee signed in", func() bool {
		v, _ := b.users()
		for _, u := range v.Users {
			if u.Username == "jlee" && u.LastSignInServer != "" {
				return true
			}
		}
		return false
	})

	// Signing out on one server ends the session on both.
	old := lb.cookie(br)
	if old == nil {
		t.Fatal("the browser has no session cookie")
	}
	if code := lb.do(br, http.MethodPost, "/api/logout", map[string]any{}); code != http.StatusOK {
		t.Fatalf("sign-out: %d", code)
	}
	waitUntil(t, 20*time.Second, "the signed-out session is refused on both servers", func() bool {
		return a.me(old) == http.StatusUnauthorized && b.me(old) == http.StatusUnauthorized
	})

	// Killed: the browser carries on on the other server.
	if code := lb.do(br, http.MethodPost, "/api/login", map[string]any{"username": "jlee", "password": "jlee-password-1"}); code != http.StatusOK {
		t.Fatalf("sign-in again: %d", code)
	}
	a.kill9()
	lb.only(b)
	for i := range 3 {
		if code := lb.do(br, http.MethodGet, "/api/me", nil); code != http.StatusOK {
			t.Fatalf("request %d after siem-a was killed: %d", i, code)
		}
	}
}

// blockWrites makes OpenSearch refuse every write to the test's indices
// as when its disk passes the flood-stage watermark, or lifts that.
func (h *clusterHarness) blockWrites(on bool) {
	h.t.Helper()
	if h.fake != nil {
		h.fake.Block(on)
		return
	}
	var v any
	if on {
		v = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.os.Do(ctx, http.MethodPut, "/"+url.PathEscape(h.prefix+"*")+"/_settings",
		map[string]any{"index.blocks.read_only_allow_delete": v}, nil); err != nil {
		h.t.Fatalf("block writes %v: %v", on, err)
	}
}

// While OpenSearch refuses writes, the built-in admin still signs in, with
// a session kept on that server only, and a viewer cannot; once writes
// work again, the admin's session is stored for every server.
func TestClusterSharedUsersWhileWritesRefused(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitShared(t, a, b)
	a.addUser("vera", "viewer", "vera-password-1")
	waitUntil(t, 10*time.Second, "siem-b reads vera", func() bool { return b.hasUser("vera") })

	h.blockWrites(true)
	t.Cleanup(func() {
		if t.Failed() {
			h.blockWrites(false)
		}
	})
	var admin *http.Cookie
	waitUntil(t, 30*time.Second, "the built-in admin signs in on siem-a while writes are refused", func() bool {
		admin, _ = a.signIn("admin", clusterPassword)
		return admin != nil
	})
	if code := a.me(admin); code != http.StatusOK {
		t.Fatalf("the admin's session on siem-a: %d", code)
	}
	if c, code := a.signIn("vera", "vera-password-1"); c != nil {
		t.Errorf("a viewer signed in while writes are refused (%d)", code)
	}

	h.blockWrites(false)
	// The next session stored writes the admin's through.
	waitUntil(t, 60*time.Second, "vera signs in once writes work again", func() bool {
		c, _ := a.signIn("vera", "vera-password-1")
		return c != nil
	})
	waitUntil(t, 30*time.Second, "the admin's session works on siem-b", func() bool { return b.me(admin) == http.StatusOK })
}

// oldServer writes the heartbeat of a server of an earlier version that
// reads only level 1 of the shared settings, every 3 seconds until the
// test ends; upgrade makes it say it reads level 2, as after an upgrade.
type oldServer struct {
	level atomic.Int32
}

func (h *clusterHarness) startOldServer(name string) *oldServer {
	t := h.t
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if err := cluster.EnsureRuntime(ctx, h.os, h.prefix); err != nil {
		cancel()
		t.Fatal(err)
	}
	o := &oldServer{}
	o.level.Store(1)
	started := time.Now().UTC()
	write := func() error {
		lv := int(o.level.Load())
		hb := cluster.Heartbeat{Kind: "node", NodeID: "n_0123456789abcdef0123", Name: name, BootID: "old-boot", State: cluster.StateReady,
			Version: "0.0.1-old", OS: "linux", Arch: "amd64", StartedAt: started, HeartbeatAt: time.Now().UTC(), Problems: []string{},
			Mode: "member", LevelMin: 1, LevelMax: lv}
		wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
		defer wcancel()
		return h.os.Do(wctx, http.MethodPut, "/"+url.PathEscape(cluster.RuntimeIndex(h.prefix))+"/_doc/node:"+hb.NodeID+"?refresh=true", hb, nil)
	}
	if err := write(); err != nil {
		cancel()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				_ = write()
			}
		}
	})
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return o
}

// While a server of an earlier version is live, the servers keep their
// own users, and the Users and Servers pages name it. Once it is upgraded,
// the users become shared, with the founder's brought in.
func TestClusterSharedUsersWaitForOldServer(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	old := h.startOldServer("siem-old")
	a := h.startLeader("siem-a", serverOptions{})
	waitUntil(t, 60*time.Second, "siem-a is a member", func() bool { return a.mode() == "member" })
	a.addUser("jlee", "analyst", "jlee-password-1")
	var v usersView
	waitUntil(t, 30*time.Second, "the Users page names siem-old", func() bool {
		var ok bool
		v, ok = a.users()
		return ok && v.Pending != nil && len(v.Pending.Servers) == 1 && v.Pending.Servers[0].Name == "siem-old"
	})
	if v.Shared {
		t.Fatal("the users are shared while siem-old reads only level 1")
	}
	cv, _ := a.view()
	named := false
	for _, w := range cv.Warnings {
		named = named || strings.Contains(w.Text, "siem-old")
	}
	if !named {
		t.Errorf("the Servers page does not name siem-old: %+v", cv.Warnings)
	}
	// Long enough for a level raise, which must not happen.
	time.Sleep(15 * time.Second)
	if a.usersShared() {
		t.Fatal("the users became shared while siem-old reads only level 1")
	}

	old.level.Store(2)
	waitUntil(t, 180*time.Second, "the users become shared once siem-old is upgraded", func() bool { return a.usersShared() })
	if c, code := a.signIn("jlee", "jlee-password-1"); c == nil {
		t.Errorf("jlee, brought in from siem-a's users, cannot sign in: %d", code)
	}
	if v, _ := a.users(); v.Pending != nil {
		t.Errorf("still pending: %+v", v.Pending)
	}
}
