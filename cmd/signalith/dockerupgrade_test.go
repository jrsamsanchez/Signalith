package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// catIndices answers _cat/indices with rows, or err; down makes the
// first that many questions fail as an OpenSearch that is not up yet.
type catIndices struct {
	mu    sync.Mutex
	rows  []map[string]string
	err   error
	down  int
	asked int
	path  string
}

func (f *catIndices) Do(_ context.Context, method, path string, _, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	f.path = method + " " + path
	if f.asked <= f.down {
		return errors.New("opensearch unreachable")
	}
	if f.err != nil {
		return f.err
	}
	rows := out.(*[]struct {
		Index   string `json:"index"`
		Created string `json:"creation.date"`
	})
	for _, r := range f.rows {
		*rows = append(*rows, struct {
			Index   string `json:"index"`
			Created string `json:"creation.date"`
		}{r["index"], r["creation.date"]})
	}
	return nil
}

func row(index string, made time.Time) map[string]string {
	return map[string]string{"index": index, "creation.date": strconv.FormatInt(made.UnixMilli(), 10)}
}

// Only an event index OpenSearch made before the setup step first ran
// counts, whatever day its name says; the oldest is kept as the evidence.
func TestDecideDockerUpgrade(t *testing.T) {
	setup := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	now := setup.Add(time.Hour)
	for _, tc := range []struct {
		name  string
		rows  []map[string]string
		err   error
		want  bool
		index string
	}{
		{name: "no events"},
		{name: "no index", err: &store.Error{Status: http.StatusNotFound, Body: `{"error":{"type":"index_not_found_exception"}}`}},
		{name: "events after setup, sample data dated back", rows: []map[string]string{
			row("signalith-authentication-2026.10.07", setup.Add(2*time.Minute)), row("signalith-windows-2026.10.13", setup.Add(time.Second))}},
		{name: "events from before setup", rows: []map[string]string{
			row("signalith-windows-2026.10.13", setup.Add(time.Minute)), row("signalith-windows-2026.10.01", setup.AddDate(0, 0, -12)),
			row("signalith-windows-2026.09.30", setup.AddDate(0, 0, -13))}, want: true, index: "signalith-windows-2026.09.30"},
		{name: "made a moment before setup", rows: []map[string]string{row("signalith-linux-2026.10.13", setup.Add(-time.Millisecond))},
			want: true, index: "signalith-linux-2026.10.13"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cat := &catIndices{rows: tc.rows, err: tc.err}
			u, err := decideDockerUpgrade(context.Background(), cat, "signalith", setup, now)
			if err != nil {
				t.Fatal(err)
			}
			if cat.path != "GET /_cat/indices/signalith-%2A?format=json&h=index,creation.date&expand_wildcards=open,closed" {
				t.Errorf("asked %s", cat.path)
			}
			if u.Upgraded != tc.want || u.Index != tc.index || !u.Setup.Equal(setup) || !u.Decided.Equal(now) {
				t.Errorf("%+v", u)
			}
		})
	}
	// No answer, or an answer without dates: nothing is decided.
	for _, cat := range []*catIndices{{err: errors.New("connection refused")}, {err: &store.Error{Status: 403}},
		{rows: []map[string]string{{"index": "signalith-windows-2026.10.13"}}}} {
		if u, err := decideDockerUpgrade(context.Background(), cat, "signalith", setup, now); err == nil {
			t.Errorf("decided %+v", u)
		}
	}
}

// dockerQuickStartConfig is a Docker quick start's config, as loaded
// before anything was decided about the example token.
func dockerQuickStartConfig(t *testing.T) *config.Config {
	t.Helper()
	return dockerQuickStartConfigAt(t, "https://opensearch:9200")
}

// dockerQuickStartConfigAt is dockerQuickStartConfig using the OpenSearch
// at osURL.
func dockerQuickStartConfigAt(t *testing.T, osURL string) *config.Config {
	t.Helper()
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a long enough password")
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	body := "server:\n  listen: 0.0.0.0:8080\n  tls:\n    mode: auto\ningest:\n  tokens: [tok-0123456789abcdef]\n" +
		"opensearch:\n  url: " + osURL + "\n" +
		"lookups:\n  dir: " + filepath.ToSlash(filepath.Join(state, "lookups")) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c.WithDockerUpgrade(nil)
}

func withSetup(t *testing.T, setup time.Time, err error) {
	t.Helper()
	old := dockerSetup
	dockerSetup = func() (time.Time, error) { return setup, err }
	t.Cleanup(func() { dockerSetup = old })
}

func fastDockerUpgrade(t *testing.T) {
	t.Helper()
	w, r, l := dockerUpgradeWait, dockerUpgradeRetry, dockerUpgradeLater
	dockerUpgradeWait, dockerUpgradeRetry, dockerUpgradeLater = 200*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { dockerUpgradeWait, dockerUpgradeRetry, dockerUpgradeLater = w, r, l })
}

// The first start waits a little for OpenSearch to answer, and keeps the
// decision in the state folder; without an answer it starts undecided.
func TestDecideDockerUpgradeAtStart(t *testing.T) {
	fastDockerUpgrade(t)
	setup := time.Now().Add(-time.Minute)
	withSetup(t, setup, nil)
	log := slog.New(slog.DiscardHandler)

	c := dockerQuickStartConfig(t)
	cat := &catIndices{down: 3, rows: []map[string]string{row("signalith-windows-2026.09.30", setup.AddDate(0, 0, -13))}}
	if !decideDockerUpgradeAtStart(context.Background(), c, cat, log) || cat.asked != 4 {
		t.Fatalf("not decided after %d questions", cat.asked)
	}
	if u, err := config.ReadDockerUpgrade(c.StateDir()); err != nil || u == nil || !u.Upgraded {
		t.Errorf("kept %+v %v", u, err)
	}

	c = dockerQuickStartConfig(t)
	if decideDockerUpgradeAtStart(context.Background(), c, &catIndices{down: 1 << 30}, log) {
		t.Error("decided without OpenSearch")
	}
	if u, _ := config.ReadDockerUpgrade(c.StateDir()); u != nil {
		t.Errorf("kept %+v", u)
	}
	// Another server's events in an OpenSearch other than the quick
	// start's own prove nothing about this install's agents: it is new,
	// without asking.
	for _, osURL := range []string{"https://192.168.1.30:9200", "https://opensearch.example.com:9200", "http://opensearch-shared:9200"} {
		c = dockerQuickStartConfigAt(t, osURL)
		cat = &catIndices{rows: []map[string]string{row("signalith-windows-2026.09.01", setup.AddDate(0, -1, 0))}}
		if !decideDockerUpgradeAtStart(context.Background(), c, cat, log) || cat.asked != 0 {
			t.Fatalf("%s: not decided, or asked %d", osURL, cat.asked)
		}
		u, err := config.ReadDockerUpgrade(c.StateDir())
		if err != nil || u == nil || u.Upgraded || !u.Setup.Equal(setup) {
			t.Fatalf("%s: kept %+v %v", osURL, u, err)
		}
		if got := c.WithDockerUpgrade(u); got.OldToken() != config.OldTokenRefused || got.Server.PlaintextIngest() {
			t.Errorf("%s: old token %v", osURL, got.OldToken())
		}
	}
	// Without the setup step's time, asking OpenSearch does not help.
	withSetup(t, time.Time{}, errors.New("no secrets"))
	cat = &catIndices{}
	if decideDockerUpgradeAtStart(context.Background(), dockerQuickStartConfig(t), cat, log) || cat.asked != 0 {
		t.Errorf("decided without the setup time, asked %d", cat.asked)
	}
}

// A server that started undecided decides as soon as OpenSearch answers,
// and an upgraded quick start then accepts its older agents at once.
func TestSettleDockerUpgrade(t *testing.T) {
	fastDockerUpgrade(t)
	setup := time.Now().Add(-time.Minute)
	withSetup(t, setup, nil)
	c := dockerQuickStartConfig(t)
	srv := &api.Server{Config: c, Pipeline: &ingest.Pipeline{Store: nopBulk{}}, Log: slog.New(slog.DiscardHandler),
		Runtime: &api.Runtime{OS: "linux", Container: true, Addresses: []string{}}}
	if srv.Running().OldToken() != config.OldTokenUndecided || srv.Running().Server.PlaintextIngest() {
		t.Fatalf("started %v", srv.Running().OldToken())
	}
	cat := &catIndices{down: 2, rows: []map[string]string{row("signalith-windows-2026.09.30", setup.AddDate(0, 0, -13))}}
	settleDockerUpgrade(context.Background(), c, cat, srv, slog.New(slog.DiscardHandler))
	if got := srv.Running(); got.OldToken() != config.OldTokenAccepted || !got.Server.PlaintextIngest() || !got.OldTokenAccepted() {
		t.Errorf("after deciding: %v", got.OldToken())
	}
	if u, _ := config.ReadDockerUpgrade(c.StateDir()); u == nil || !u.Upgraded || !strings.HasPrefix(u.Index, "signalith-windows-") {
		t.Errorf("kept %+v", u)
	}
	// Stopping ends the wait, undecided.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c = dockerQuickStartConfig(t)
	srv = &api.Server{Config: c, Pipeline: &ingest.Pipeline{Store: nopBulk{}}, Log: slog.New(slog.DiscardHandler)}
	settleDockerUpgrade(ctx, c, &catIndices{down: 1 << 30}, srv, slog.New(slog.DiscardHandler))
	if srv.Running().OldToken() != config.OldTokenUndecided {
		t.Errorf("after stopping: %v", srv.Running().OldToken())
	}
}
