// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

func TestRecheckCookie(t *testing.T) {
	k, other := NewBrowserKey(), NewBrowserKey()
	now := time.Unix(1_800_000_000, 0)
	v := k.IssueRecheck("Ann", "tok-1", now)
	if !k.CheckRecheck("ann", "tok-1", v, now.Add(RecheckAge-time.Second)) {
		t.Error("fresh value refused")
	}
	for name, ok := range map[string]bool{
		"expired":       k.CheckRecheck("ann", "tok-1", v, now.Add(RecheckAge)),
		"other session": k.CheckRecheck("ann", "tok-2", v, now),
		"other account": k.CheckRecheck("bob", "tok-1", v, now),
		"other key":     other.CheckRecheck("ann", "tok-1", v, now),
		"no session":    k.CheckRecheck("ann", "", k.IssueRecheck("ann", "", now), now),
		"tampered":      k.CheckRecheck("ann", "tok-1", flip(v, 3), now),
		"known browser": k.CheckRecheck("ann", "tok-1", k.Issue("ann", "", now), now),
	} {
		if ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// A response action asks for a recheck made within ActionRecheckAge, and
// no route can ask for a longer one than RecheckAge.
func TestRecheckWithin(t *testing.T) {
	k := NewBrowserKey()
	now := time.Unix(1_800_000_000, 0)
	v := k.IssueRecheck("ann", "tok-1", now)
	if !k.CheckRecheckWithin("ann", "tok-1", v, now.Add(ActionRecheckAge-time.Second), ActionRecheckAge) {
		t.Error("a recheck inside the window was refused")
	}
	if k.CheckRecheckWithin("ann", "tok-1", v, now.Add(ActionRecheckAge), ActionRecheckAge) {
		t.Error("a recheck older than ActionRecheckAge was accepted")
	}
	if !k.CheckRecheck("ann", "tok-1", v, now.Add(ActionRecheckAge)) {
		t.Error("the same recheck was refused for other sensitive changes")
	}
	if k.CheckRecheckWithin("ann", "tok-1", v, now.Add(RecheckAge), time.Hour) {
		t.Error("a window longer than RecheckAge was honoured")
	}
}
