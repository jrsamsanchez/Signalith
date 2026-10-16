package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const (
	testPrefix = "s"
	testIndex  = "s_config"
)

// testEnv is one fake OpenSearch with a cluster key, on a fake clock.
type testEnv struct {
	t     *testing.T
	os    *ostest.Server
	c     *store.Client
	clock *ostest.Clock
	key   *ClusterKey
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	fake := ostest.New(t)
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, os: fake, c: store.New(store.Config{URL: fake.URL}), key: k,
		clock: ostest.NewClock(time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))}
	if err := EnsureConfig(context.Background(), e.c, testPrefix); err != nil {
		t.Fatal(err)
	}
	return e
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

// hub returns a server's hub, with the cluster key, pointed at the fake.
func (e *testEnv) hub(name string) (*Hub, *logBuffer) {
	logs := &logBuffer{}
	h := NewHub(Options{NodeName: name, Clock: e.clock, Log: slog.New(slog.NewJSONHandler(logs, nil))})
	h.SetKeys(NewKeySet(e.key))
	h.Use(e.c, testPrefix)
	return h, logs
}

// cycle runs one watch cycle.
func cycle(t *testing.T, h *Hub) {
	t.Helper()
	if err := h.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// putSigned writes a document signed with k straight into the fake, as a
// server of another version would.
func (e *testEnv) putSigned(k *ClusterKey, id, kind string, format int, rev int64, body string, extra map[string]any) {
	e.t.Helper()
	env := &Envelope{Kind: kind, ID: id, Format: format, Rev: rev, UpdatedAt: "2026-10-12T09:00:00Z",
		UpdatedBy: By{User: "sam", Node: "siem-z"}, Body: body}
	if err := Sign(k, id, env); err != nil {
		e.t.Fatal(err)
	}
	e.os.Put(testIndex, id, sourceOf(e.t, env, extra))
}

func sourceOf(t *testing.T, env *Envelope, extra map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// testBody is a body type.
type testBody struct {
	Name  string     `json:"name"`
	Items []string   `json:"items,omitempty"`
	Feeds []testFeed `json:"feeds,omitempty"`
	Extra `json:"-"`
}

// testFeed is an item inside a body that keeps its own unknown fields.
type testFeed struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Extra `json:"-"`
}

func (f testFeed) MarshalJSON() ([]byte, error) {
	type plain testFeed
	return MarshalExtra(plain(f), f.Extra)
}

func (f *testFeed) UnmarshalJSON(data []byte) error {
	type plain testFeed
	var p plain
	extra, err := UnmarshalExtra(data, &p)
	*f = testFeed(p)
	f.Extra = extra
	return err
}

func mustContain(t *testing.T, what, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("%s does not contain %q:\n%s", what, sub, s)
	}
}
