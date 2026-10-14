package clusterauth

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

const testPrefix = "signalith"

// testClock is the time the sessions, users and locks see; tests move it.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock { return &testClock{t: time.Now().UTC().Round(time.Millisecond)} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// logBuffer is a log that tests can read.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// testOS is one fake OpenSearch.
type testOS struct {
	fake *ostest.Server
	cl   *store.Client
}

func newOS(t *testing.T) *testOS {
	fake := ostest.New(t)
	return &testOS{fake: fake, cl: store.New(store.Config{URL: fake.URL})}
}

func (o *testOS) client() (*store.Client, string) { return o.cl, testPrefix }

// server is one member of the cluster: its runtime, the users' documents,
// a users store over them and its sessions.
type server struct {
	t        *testing.T
	name     string
	rt       *shared.Runtime
	docs     *Docs
	ub       *UsersBackend
	store    *users.Store
	sessions *Sessions
	logs     *logBuffer
	log      *slog.Logger
	// degraded and confirmed are what the sessions are told.
	degraded  atomic.Bool
	confirmed atomic.Pointer[time.Time]
	dirOn     atomic.Bool
}

// builtinPassword is the built-in admin's password in every test.
const builtinPassword = "s3cret-pass"

var builtinHash = sync.OnceValue(func() string {
	h, err := users.HashPassword(builtinPassword)
	if err != nil {
		panic(err)
	}
	return h
})

// newServer starts a server named name. With key it has the cluster key
// and joins; without, it founds the cluster and makes the built-in admin
// "admin".
func newServer(t *testing.T, o *testOS, name string, key *shared.ClusterKey, clk *testClock) *server {
	t.Helper()
	dir := t.TempDir()
	master := secrets.NewKeyring(dir)
	if key != nil {
		if err := (shared.KeyStore{Dir: dir, Master: master}).SaveClusterKey(key); err != nil {
			t.Fatal(err)
		}
	}
	s := &server{t: t, name: name, docs: NewDocs(), logs: &logBuffer{}}
	s.log = slog.New(slog.NewJSONHandler(s.logs, nil))
	s.rt = shared.NewRuntime(shared.RuntimeOptions{StateDir: dir, Self: shared.Self{NodeID: "n_" + name, Name: name},
		Content: s.docs.Track, Log: s.log})
	s.docs.Cluster = s.rt.Cluster
	s.rt.Use(o.cl, testPrefix, master)
	ctx := context.Background()
	if key == nil {
		if err := s.rt.Found(ctx, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.docs.CreateBuiltin(ctx, "test", "admin", builtinHash(), clk.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if mode, why := s.rt.Mode(); mode != shared.ModeMember {
		t.Fatalf("%s: mode %s (%s)", name, mode, why)
	}
	s.ub = &UsersBackend{Docs: s.docs}
	st, err := users.New(s.ub)
	if err != nil {
		t.Fatal(err)
	}
	st.Builtin, st.Now = s.docs.Builtin, clk.Now
	s.store = st
	s.dirOn.Store(true)
	s.sessions = &Sessions{Docs: s.docs, Client: o.client, Node: "n_" + name, Cache: NewSessionCache(),
		DirectoryOn: s.dirOn.Load, Degraded: s.degraded.Load, Log: s.log, Now: clk.Now,
		Confirmed: func() time.Time {
			if p := s.confirmed.Load(); p != nil {
				return *p
			}
			return s.rt.Hub().Confirmed()
		}}
	s.sessions.SetIdle(12 * time.Hour)
	s.sessions.Listen()
	return s
}

// pair founds a cluster on A and joins B.
func pair(t *testing.T) (*testOS, *server, *server, *testClock) {
	t.Helper()
	o := newOS(t)
	clk := newClock()
	a := newServer(t, o, "siem-a", nil, clk)
	b := newServer(t, o, "siem-b", a.key(), clk)
	b.cycle()
	return o, a, b, clk
}

func (s *server) key() *shared.ClusterKey { return s.rt.Hub().Keys().Active() }

// cycle reads the shared settings once, as the watcher does every 2
// seconds.
func (s *server) cycle() {
	s.t.Helper()
	if err := s.rt.Hub().Cycle(context.Background()); err != nil {
		s.t.Fatal(err)
	}
}

// addUser adds a local user.
func (s *server) addUser(name string, role users.Role) users.User {
	s.t.Helper()
	u, err := s.store.Create(context.Background(), users.NewUser{Username: name, Role: role, Password: "a-good-password"})
	if err != nil {
		s.t.Fatal(err)
	}
	return u
}

// signIn starts a session for a user as they are on this server.
func (s *server) signIn(name string, remember bool) string {
	s.t.Helper()
	u, ok := s.store.Get(name)
	method := u.Source
	if !ok {
		v, _, found := s.docs.BuiltinUser()
		if !found || v.Username != name {
			s.t.Fatalf("no user %s", name)
		}
		u = users.User{Username: v.Username, SessionEpoch: v.SessionEpoch}
		method = users.SourceBuiltin
	}
	token, err := s.sessions.Create(context.Background(), auth.NewSession{User: u.Username, Remember: remember, Epoch: u.SessionEpoch, Method: method, Client: "10.0.0.9"})
	if err != nil {
		s.t.Fatal(err)
	}
	return token
}

// valid reports whether a cookie is signed in here.
func (s *server) valid(cookie string) bool {
	_, ok := s.sessions.Lookup(context.Background(), cookie, true)
	return ok
}

// sessionDocs counts the session documents of user.
func (o *testOS) sessionDocs(t *testing.T, user string) int {
	t.Helper()
	docs, err := o.cl.SearchDocs(context.Background(), shared.SessionsIndex(testPrefix), map[string]any{"term": map[string]any{"user": user}})
	if err != nil {
		t.Fatal(err)
	}
	return len(docs)
}

// requestsTo returns the requests made to the fake that contain part.
func requestsTo(reqs []string, part string) []string {
	var out []string
	for _, r := range reqs {
		if strings.Contains(r, part) {
			out = append(out, r)
		}
	}
	return out
}
