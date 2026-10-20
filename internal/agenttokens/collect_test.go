// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agenttokens

import (
	"testing"
	"time"
)

// TestCollectSilentAlert: an install line's silent-agent alert is an
// hour unless set to 4h, 24h or off; anything else is refused (ASI-14).
func TestCollectSilentAlert(t *testing.T) {
	for _, c := range []struct {
		in, stored string
		after      time.Duration
		ok         bool
	}{
		{"", "", time.Hour, true},
		{"1h", "", time.Hour, true},
		{" 4H ", "4h", 4 * time.Hour, true},
		{"24h", "24h", 24 * time.Hour, true},
		{"off", "off", 0, true},
		{"2h", "", 0, false},
		{"0", "", 0, false},
	} {
		got, field, ok := CleanCollect(Collect{SilentAlert: c.in})
		if ok != c.ok {
			t.Errorf("%q: ok %v, want %v (field %q)", c.in, ok, c.ok, field)
			continue
		}
		if !ok {
			if field != "silent_alert" {
				t.Errorf("%q: field %q", c.in, field)
			}
			continue
		}
		if got.SilentAlert != c.stored || got.SilentAfter() != c.after {
			t.Errorf("%q: stored %q after %v, want %q %v", c.in, got.SilentAlert, got.SilentAfter(), c.stored, c.after)
		}
	}
	if e := errCollectInvalid("silent_alert"); e.Msg != "Use 1h, 4h, 24h or off." {
		t.Errorf("message: %q", e.Msg)
	}
}
