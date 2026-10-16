package ticketing

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// TestMain gives the tests a master key of their own, in a temporary
// folder, for the ticketing file's encrypted secrets.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "signalith-test-keys-")
	if err != nil {
		panic(err)
	}
	secrets.SetDefault(secrets.NewKeyring(dir))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// clock is a test clock that moves only when told.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// env is a Service with in-memory stores, a test clock and a recorded
// sleep.
type env struct {
	t     *testing.T
	svc   *Service
	cases *cases.Memory
	links *Memory
	clk   *clock
	mu    sync.Mutex
	slept []time.Duration
}

func newEnv(t *testing.T, conns ...Connection) *env {
	t.Helper()
	e := &env{t: t, cases: cases.NewMemory(), links: NewMemory(), clk: newClock()}
	m := &Manager{File: filepath.Join(t.TempDir(), "tickets.yaml"), Now: e.clk.Now}
	m.mu.Lock()
	err := m.save(Settings{Connections: conns})
	m.read = false // read the file back, decrypting its secrets
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	e.svc = &Service{Settings: m, Cases: e.cases, Links: e.links, Server: "node-1", Now: e.clk.Now,
		PublicURL: func() string { return "https://siem.example.com/" },
		sleep: func(_ context.Context, d time.Duration) error {
			e.mu.Lock()
			e.slept = append(e.slept, d)
			e.mu.Unlock()
			return nil
		}}
	return e
}

// newCase writes a case opened now.
func (e *env) newCase(id, title, severity string) *cases.Case {
	e.t.Helper()
	now := e.clk.Now()
	c := &cases.Case{ID: id, Title: title, Description: "Suspicious logons on host-7.\nCheck it.", Severity: severity, Status: "new", CreatedBy: "ann", Created: now, Updated: now}
	if err := e.cases.Create(context.Background(), c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

// change changes a case as an analyst would, now.
func (e *env) change(id string, u cases.Update) {
	e.t.Helper()
	_, err := e.cases.Modify(context.Background(), id, func(c *cases.Case) (bool, error) {
		return c.Apply(u, "ann", e.clk.Now()), nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// note adds an analyst's note to a case, now.
func (e *env) note(id, text string) {
	e.change(id, cases.Update{Comment: text})
}

func (e *env) getCase(id string) *cases.Case {
	e.t.Helper()
	c, err := e.cases.Get(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) link(connID, caseID string) Stored {
	e.t.Helper()
	st, err := e.links.Get(context.Background(), LinkID(connID, caseID))
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

// pass moves the clock a minute and runs a pass.
func (e *env) pass() {
	e.clk.add(time.Minute)
	e.svc.Pass(context.Background())
}

// notes returns a case's notes as "author: text".
func notesOf(c *cases.Case) []string {
	var out []string
	for _, en := range c.Entries {
		if en.Kind == cases.KindNote {
			out = append(out, en.Author+": "+en.Text)
		}
	}
	return out
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func ptr[T any](v T) *T { return &v }
