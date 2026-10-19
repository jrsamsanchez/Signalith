package shared

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// Each mode that is not a plain member says what an admin should know,
// with a banner for the red ones.
func TestWarningsByMode(t *testing.T) {
	e := newEnv(t)
	s := e.server("siem-a", nil)
	for _, c := range []struct {
		mode   Mode
		why    string
		setup  func(rt *Runtime)
		level  string
		text   string
		banner bool
	}{
		{mode: ModeLegacyA, level: "amber", text: "could not be reached when this server started"},
		{mode: ModeLegacyC, level: "amber", text: "Waiting for siem-b, which runs the background jobs",
			setup: func(rt *Runtime) { rt.holder, rt.noHolderSince = "siem-b", nil }},
		{mode: ModeLegacyC, level: "red", text: "No server that may run the background jobs has been up for 10 minutes", banner: true,
			setup: func(rt *Runtime) {
				since := rt.clock.Mono() - NoHolderWait - time.Second
				rt.holder, rt.noHolderSince = "", &since
			}},
		{mode: ModeImporting, level: "amber", text: "moving its settings into OpenSearch"},
		{mode: ModeDegraded, why: "connection refused", level: "red", text: "changes are paused. connection refused.", banner: true},
		{mode: ModeKeyMissing, level: "red", text: "signed with a cluster key this server does not have", banner: true},
		{mode: ModeGone, level: "red", text: "This server keeps no copy of them", banner: true},
	} {
		if c.setup != nil {
			s.rt.mu.Lock()
			c.setup(s.rt)
			s.rt.mu.Unlock()
		}
		s.rt.setMode(c.mode, c.why)
		w := s.rt.Warnings()
		if len(w) == 0 {
			t.Errorf("%s: no warning", c.mode)
			continue
		}
		if w[0].Level != c.level || !strings.Contains(w[0].Text, c.text) || (w[0].Banner != "") != c.banner {
			t.Errorf("%s: %+v", c.mode, w[0])
		}
	}
	s.rt.setMode(ModeLegacyC, "")
	s.rt.mu.Lock()
	s.rt.holder, s.rt.noHolderSince = "", nil
	s.rt.mu.Unlock()
	if w := s.rt.Warnings(); len(w) != 0 {
		t.Errorf("legacy (c) with nothing to wait for: %+v", w)
	}
}

// FlushCacheBody returns a document's body as the copy on disk holds it.
func TestFlushCacheBody(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	if _, err := a.rt.FlushCacheBody(ClusterDocID); !errors.Is(err, ErrNoCache) {
		t.Errorf("before the copy is kept: %v", err)
	}
	a.holds.Store(true)
	a.step()
	ctx, cancel := context.WithCancel(context.Background())
	a.rt.Start(ctx)
	defer func() {
		cancel()
		a.rt.Wait()
	}()
	waitFor(t, func() bool { return a.rt.FlushCache() == nil && fileExists(CachePath(a.dir)) })
	body, err := a.rt.FlushCacheBody(ClusterDocID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, a.rt.Status().ClusterID) {
		t.Errorf("cluster body %s", body)
	}
	if _, err := a.rt.FlushCacheBody("no-such-doc"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a document the copy does not hold: %v", err)
	}
}

func TestCheckLevel(t *testing.T) {
	if err := CheckLevel(LevelMax); err != nil {
		t.Errorf("CheckLevel(%d) = %v", LevelMax, err)
	}
	var le *LevelError
	if err := CheckLevel(LevelMax + 1); !errors.As(err, &le) || le.Level != LevelMax+1 || !strings.Contains(err.Error(), "newer version") {
		t.Errorf("CheckLevel above = %v", err)
	}
	if err := CheckLevel(LevelMin - 1); !errors.As(err, &le) || !strings.Contains(err.Error(), "no longer reads") {
		t.Errorf("CheckLevel below = %v", err)
	}
}

// Item returns an item with who changed it last; a deleted one is gone.
func TestCollectionItem(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	c := NewCollection[testBody](a, "rule", "rules", 1)
	if _, err := c.Create(ctx, "sam", "r1", &testBody{Name: "one"}); err != nil {
		t.Fatal(err)
	}
	it, ok := c.Item("r1")
	_, etag, _ := c.Get("r1")
	if !ok || it.Name != "r1" || it.Value.Name != "one" || it.ETag != etag || it.UpdatedBy.User != "sam" || it.UpdatedBy.Node != "siem-a" || it.UpdatedAt == "" {
		t.Errorf("item %+v %v", it, ok)
	}
	if _, err := c.Delete(ctx, "sam", "r1", etag); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Item("r1"); ok {
		t.Error("a deleted item is returned")
	}
	if _, ok := c.Item("never"); ok {
		t.Error("an item never made is returned")
	}
}
