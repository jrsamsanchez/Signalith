package config

import (
	"strings"
	"testing"
	"time"
)

// Sessions last 1 hour idle and 24 hours in all unless set otherwise: the
// NIST SP 800-63B limits for AAL2. auth.session_max_age is from 1h to 30d.
func TestSessionLifetimes(t *testing.T) {
	c := Default()
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	c.Auth.AdminPasswordHash = h
	if c.SessionIdle() != time.Hour || c.SessionMaxAge() != 24*time.Hour {
		t.Errorf("defaults %v %v", c.SessionIdle(), c.SessionMaxAge())
	}
	c.Auth.SessionTimeout, c.Auth.SessionMaxAge = "12h", "7d"
	if c.SessionIdle() != 12*time.Hour || c.SessionMaxAge() != 7*24*time.Hour {
		t.Errorf("set %v %v", c.SessionIdle(), c.SessionMaxAge())
	}
	for v, ok := range map[string]bool{"1h": true, "24h": true, "30d": true, "59m": false, "31d": false, "soon": false, "0": false} {
		c.Auth.SessionMaxAge = v
		err := c.Validate()
		if ok && err != nil {
			t.Errorf("%s: %v", v, err)
		}
		if !ok && (err == nil || !strings.Contains(err.Error(), "auth.session_max_age")) {
			t.Errorf("%s: %v", v, err)
		}
	}
}

func TestSessionMaxAgeOnTheSettingsPage(t *testing.T) {
	path := writeConfig(t, "")
	res, err := CheckEdit(path, Edit{By: "alice", Values: map[string]any{"auth.session_max_age": "40d"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Fields["auth.session_max_age"], "from 1h to 30d") {
		t.Errorf("fields %v", res.Fields)
	}
	res, err = CheckEdit(path, Edit{By: "alice", Values: map[string]any{"auth.session_max_age": "8h"}})
	if err != nil || !res.OK() || res.Config.SessionMaxAge() != 8*time.Hour {
		t.Fatalf("%v %v %v", err, res.Fields, res.Problems)
	}
}

// The built-in admin's new password follows the users' rules.
func TestCheckNewAdminPassword(t *testing.T) {
	if CheckNewPassword("admin", "Password1") == nil || CheckNewPassword("admin", "admin-pass-1") == nil {
		t.Error("weak admin password accepted")
	}
	if err := CheckNewPassword("admin", RandomToken(9)); err != nil {
		t.Error(err)
	}
}
