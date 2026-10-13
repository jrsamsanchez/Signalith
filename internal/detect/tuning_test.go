package detect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/search"
)

func TestExceptionMatches(t *testing.T) {
	at := func(s string) *time.Time { v, _ := time.Parse(time.RFC3339, s); return &v }
	e := Exception{ID: "ex-1", Match: map[string]string{"host": "WEB*", "user": `corp\svc-?`}}
	for _, tc := range []struct {
		row  map[string]any
		want bool
	}{
		{map[string]any{"host": "web1", "user": `CORP\svc-a`}, true},
		{map[string]any{"host": "web1", "user": `CORP\svc-ab`}, false},
		{map[string]any{"host": "db1", "user": `CORP\svc-a`}, false},
		{map[string]any{"host": "web1"}, false},
		{map[string]any{"host": []any{"db1", "web2"}, "user": `corp\svc-b`}, true},
	} {
		if got := e.Matches(tc.row); got != tc.want {
			t.Errorf("Matches(%v) = %v", tc.row, got)
		}
	}
	w := Exception{ID: "ex-2", From: at("2026-10-11T02:00:00Z"), Until: at("2026-10-11T04:00:00Z")}
	for s, want := range map[string]bool{"2026-10-11T01:59:59Z": false, "2026-10-11T02:00:00Z": true, "2026-10-11T03:59:59Z": true, "2026-10-11T04:00:00Z": false} {
		if got := w.Active(*at(s)); got != want {
			t.Errorf("Active(%s) = %v", s, got)
		}
	}
	if p := (&Exception{ID: "ex-3"}).problems(); len(p) != 1 || !strings.Contains(p[0], "needs an end time") {
		t.Errorf("problems = %v", p)
	}
	if p := (&Exception{ID: "ex-4", Match: map[string]string{"bad field": "x", "host": " "}}).problems(); len(p) != 2 {
		t.Errorf("problems = %v", p)
	}
}

func TestExceptionsSuppressResults(t *testing.T) {
	lib, _, _ := NewLibrary("")
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	run := &fakeRunner{rows: []search.Row{
		{"src": "203.0.113.9", "dest": "web1", "count": int64(40), "users": int64(3)},
		{"src": "198.51.100.1", "dest": "web1", "count": int64(12), "users": int64(1)},
	}}
	s := &Scheduler{Library: lib, Engine: run, Findings: findings.NewMemory(), Now: func() time.Time { return now }}
	until := now.Add(time.Hour)
	d, err := lib.UpdateExceptions("auth-brute-force", func(es []Exception) ([]Exception, error) {
		return append(es, Exception{ID: "ex-scanner", Match: map[string]string{"src": "203.0.113.9"}, Until: &until, Added: now}), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Run(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Suppressed != 1 || res.Findings[0].Entities["src"] != "198.51.100.1" {
		t.Fatalf("run = %+v", res)
	}
	if st := s.Status()["auth-brute-force"]; st.LastSuppressed != 1 {
		t.Errorf("state = %+v", st)
	}
	// Once the exception ends, the source raises a finding again.
	now = until
	res, _ = s.Run(context.Background(), d)
	if res.Suppressed != 0 || len(res.Findings) != 1 || res.Findings[0].Entities["src"] != "203.0.113.9" {
		t.Fatalf("after the exception = %+v", res)
	}
}

func TestExceptionsAreSavedWithoutCopyingTheRule(t *testing.T) {
	dir := t.TempDir()
	lib, _, err := NewLibrary(dir)
	if err != nil {
		t.Fatal(err)
	}
	add := func(id string) *Detection {
		d, err := lib.UpdateExceptions(id, func(es []Exception) ([]Exception, error) {
			return append(es, Exception{ID: "ex-a", Match: map[string]string{"host": "web1"}}), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	// A built-in detection keeps its rule in the binary: the exception is
	// state, not an override.
	d := add("auth-brute-force")
	if d.Source != "builtin" || len(d.Exceptions) != 1 {
		t.Fatalf("detection = %+v", d)
	}
	if _, err := os.Stat(filepath.Join(dir, "auth-brute-force.yaml")); !os.IsNotExist(err) {
		t.Errorf("an override was written: %v", err)
	}
	state, err := os.ReadFile(filepath.Join(dir, StateDir, "auth-brute-force.yaml"))
	if err != nil || !strings.Contains(string(state), "ex-a") {
		t.Fatalf("state = %s, %v", state, err)
	}
	// It survives a restart, and turning the rule on keeps it.
	lib, problems, _ := NewLibrary(dir)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if err := lib.SetEnabled([]string{"auth-brute-force"}, false); err != nil {
		t.Fatal(err)
	}
	if d, _ := lib.Get("auth-brute-force"); len(d.Exceptions) != 1 || d.Enabled {
		t.Errorf("after restart = %+v", d)
	}
	// Saving the detection as shown (exceptions and all) still is not an
	// override.
	d, _ = lib.Get("auth-brute-force")
	if err := lib.Put(d); err != nil {
		t.Fatal(err)
	}
	if d, _ := lib.Get("auth-brute-force"); d.Source != "builtin" || len(d.Exceptions) != 1 {
		t.Errorf("after put = %+v", d)
	}
	// Removing the last exception, with the rule back to its default,
	// removes the state file.
	if err := lib.SetEnabled([]string{"auth-brute-force"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.UpdateExceptions("auth-brute-force", func([]Exception) ([]Exception, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, StateDir, "auth-brute-force.yaml")); !os.IsNotExist(err) {
		t.Errorf("state file left: %v", err)
	}

	// A custom detection keeps its exceptions in its own file.
	c, _ := lib.Get("auth-brute-force")
	c.ID, c.Title, c.Exceptions = "my-brute-force", "Mine", nil
	if err := lib.Put(c); err != nil {
		t.Fatal(err)
	}
	add("my-brute-force")
	data, _ := os.ReadFile(filepath.Join(dir, "my-brute-force.yaml"))
	if !strings.Contains(string(data), "ex-a") {
		t.Errorf("custom file = %s", data)
	}
	// Bad exceptions are refused with the problem named.
	_, err = lib.UpdateExceptions("my-brute-force", func(es []Exception) ([]Exception, error) {
		return append(es, Exception{ID: "ex-a", Match: map[string]string{"host": "x"}}), nil
	})
	if err == nil || !strings.Contains(err.Error(), "used twice") {
		t.Errorf("err = %v", err)
	}
	if _, err := lib.UpdateExceptions("nope", nil); err != ErrNotFound {
		t.Errorf("err = %v", err)
	}
}
