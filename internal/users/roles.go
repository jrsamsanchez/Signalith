// Package users keeps the people who can sign in to Signalith: local
// users with passwords stored here, and users of an LDAP or Active
// Directory server whose role comes from their groups. Every user has one
// of three roles: viewer, analyst or admin.
package users

import "fmt"

// Role decides what a user may do. Each role can do everything the roles
// below it can.
type Role string

const (
	// Viewer can look at everything and change nothing.
	Viewer Role = "viewer"
	// Analyst can also triage findings, work investigations, build
	// dashboards, use Ask and add threat intel indicators by hand.
	Analyst Role = "analyst"
	// Admin can also change detections, feeds, lists, data collection,
	// users and directory sign-in.
	Admin Role = "admin"
)

// Roles lists every role, lowest first.
var Roles = []Role{Viewer, Analyst, Admin}

// RoleInfo describes a role for the Users page.
type RoleInfo struct {
	ID          Role   `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// RoleInfos describes every role, lowest first.
var RoleInfos = []RoleInfo{
	{Viewer, "Viewer", "Searches and looks at everything, but changes nothing."},
	{Analyst, "Analyst", "Also triages findings, works investigations and builds dashboards."},
	{Admin, "Admin", "Also manages detections, threat intel, data collection and users."},
}

// rank orders roles; unknown roles rank below viewer, so they can do
// nothing.
func (r Role) rank() int {
	switch r {
	case Viewer:
		return 1
	case Analyst:
		return 2
	case Admin:
		return 3
	}
	return 0
}

// Valid reports whether r is one of the three roles.
func (r Role) Valid() bool { return r.rank() > 0 }

// AtLeast reports whether r can do what min allows.
func (r Role) AtLeast(min Role) bool { return r.Valid() && r.rank() >= min.rank() }

// Label is the role's name for people: Viewer, Analyst or Admin.
func (r Role) Label() string {
	for _, i := range RoleInfos {
		if i.ID == r {
			return i.Label
		}
	}
	return string(r)
}

// ParseRole reads a role name.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("role %q must be viewer, analyst or admin", s)
	}
	return r, nil
}

// Highest returns the highest of the given roles, or "" if there are none.
func Highest(roles ...Role) Role {
	var best Role
	for _, r := range roles {
		if r.rank() > best.rank() {
			best = r
		}
	}
	return best
}
