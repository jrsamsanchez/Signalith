// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// warningsText is every warning of a runtime, one per line.
func warningsText(rt *Runtime) string {
	var b strings.Builder
	for _, w := range rt.Warnings() {
		b.WriteString(w.Level + ": " + w.Text + "\n")
	}
	return b.String()
}

func TestLevelVersionsAndWarning(t *testing.T) {
	self := Peer{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax, Version: "1.6.0"}
	old := Peer{NodeID: "n_siem-c", Name: "siem-c", Live: true, Version: "1.5.0"} // reads level 1
	e := newEnv(t)
	var peers peerList
	peers.set(self, old)
	a := e.server("siem-a", func(o *RuntimeOptions) {
		o.Peers = peers.get
		o.Version = "1.6.0"
	})
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	wantLevel(t, e, 1)

	t.Run("names the live server that holds the raise back", func(t *testing.T) {
		got := warningsText(a.rt)
		mustContain(t, "warnings", got, "amber: The servers run 1.5.0 and 1.6.0. What 1.6.0 adds waits until every server runs it: upgrade siem-c (1.5.0). A server stopped for 24 hours stops counting.")
	})
	t.Run("names an offline server with its cut-off time", func(t *testing.T) {
		gone := old
		since := e.clock.Now().Add(-time.Hour)
		gone.Live, gone.SeenAgo, gone.OfflineSince = false, time.Hour, &since
		peers.set(self, gone)
		got := warningsText(a.rt)
		mustContain(t, "warnings", got, "upgrade siem-c (1.5.0), offline since 08:00 UTC, stops counting at 08:00 UTC tomorrow, or remove it.")
		if strings.Contains(got, "A server stopped for 24 hours") {
			t.Errorf("the general note with an offline server:\n%s", got)
		}
		// Without the time it went offline, it is worked out from how
		// long ago it was seen.
		gone.OfflineSince = nil
		peers.set(self, gone)
		mustContain(t, "warnings", warningsText(a.rt), "offline since 08:00 UTC, stops counting at 08:00 UTC tomorrow")
	})
	t.Run("none on a single server", func(t *testing.T) {
		peers.set(self)
		if w := a.rt.levelWarning(); w != nil {
			t.Errorf("warning %+v", w)
		}
		gone := old
		gone.Live, gone.SeenAgo = false, LevelSeen
		peers.set(self, gone)
		if w := a.rt.levelWarning(); w != nil {
			t.Errorf("a server gone for 24 hours still counts: %+v", w)
		}
	})
	t.Run("the raise records the version", func(t *testing.T) {
		upgraded := old
		upgraded.LevelMax, upgraded.Version = LevelMax, "1.6.0"
		peers.set(self, upgraded)
		a.step()
		body := wantLevel(t, e, 2)
		if body.LevelVersions["2"] != "1.6.0" {
			t.Errorf("level_versions %v", body.LevelVersions)
		}
		// Every server reads the next level too: nothing waits.
		if w := a.rt.levelWarning(); w != nil {
			t.Errorf("warning once every server reads the next level: %+v", w)
		}
	})
	t.Run("an older version names the version to install", func(t *testing.T) {
		for l := 3; l <= LevelMax; l++ {
			if !a.rt.RaiseLevel(context.Background()) {
				t.Fatal("did not raise the level")
			}
		}
		body := wantLevel(t, e, LevelMax)
		if body.LevelVersions[strconv.Itoa(LevelMax)] != "1.6.0" {
			t.Fatalf("level_versions %v", body.LevelVersions)
		}
		older := e.server("siem-c", func(o *RuntimeOptions) {
			o.KeyFile = writeKeyFile(t, a.key())
			o.levelMax = LevelMax - 1
			o.Version = "1.5.0"
		})
		select {
		case err := <-older.rt.Fatal():
			var le *LevelError
			want := "This server runs 1.5.0; the cluster uses a newer format since 1.6.0 was installed. Install 1.6.0 or newer."
			if !errors.As(err, &le) || err.Error() != want {
				t.Errorf("fatal = %v, want %q", err, want)
			}
		default:
			t.Fatal("an older version started")
		}
	})
}

func TestLevelErrorText(t *testing.T) {
	for _, tc := range []struct {
		err  LevelError
		want string
	}{
		{LevelError{Level: LevelMax + 1, Since: "1.7.0", Version: "1.6.0"},
			"This server runs 1.6.0; the cluster uses a newer format since 1.7.0 was installed. Install 1.7.0 or newer."},
		{LevelError{Level: LevelMax + 1, Since: "1.7.0"},
			"This server runs an older version; the cluster uses a newer format since 1.7.0 was installed. Install 1.7.0 or newer."},
		{LevelError{Level: LevelMax + 1, Version: "1.6.0"},
			"which a newer version of Signalith wrote; this version reads up to level " + strconv.Itoa(LevelMax)},
		{LevelError{Level: 0, Since: "1.7.0"}, "which this version of Signalith no longer reads"},
	} {
		if got := tc.err.Error(); !strings.Contains(got, tc.want) {
			t.Errorf("%+v: %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestClockTime(t *testing.T) {
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	for at, want := range map[time.Time]string{
		now.Add(-time.Hour):      "08:00 UTC",
		now.Add(23 * time.Hour):  "08:00 UTC tomorrow",
		now.Add(-25 * time.Hour): "2026-10-11 08:00 UTC",
		now.Add(50 * time.Hour):  "2026-10-14 11:00 UTC",
	} {
		if got := clockTime(now, at); got != want {
			t.Errorf("clockTime(%v) = %q, want %q", at, got, want)
		}
	}
	if got := andList([]string{"1.4.0", "1.5.0", "1.6.0"}); got != "1.4.0, 1.5.0 and 1.6.0" {
		t.Errorf("andList %q", got)
	}
}
