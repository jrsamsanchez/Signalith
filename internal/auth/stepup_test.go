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
