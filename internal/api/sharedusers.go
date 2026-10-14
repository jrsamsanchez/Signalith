package api

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// SharedUsers is set on a member of a cluster whose users, directory
// sign-in settings and sessions are kept in the shared settings: Users,
// Directory and SessionStore then work over them, and the built-in admin
// is the cluster's (one password for every server, which its user may
// change on the page). nil on a server that keeps them in its own files,
// where everything works as it always did.
type SharedUsers struct {
	Docs *clusterauth.Docs
	// Seen keeps the last sign-ins, which the Users page lists.
	Seen *clusterauth.LastSeen
	// LocalHash returns the built-in admin's password hash that
	// signalith passwd -local wrote on this server, or "": it works only
	// while the shared settings cannot be used (sharedDegraded).
	LocalHash func() string
	// WritesRefused reports whether OpenSearch refuses writes now (a
	// full disk), which keeps the mode a member's while no session can be
	// stored.
	WritesRefused func() bool
	// MayDegrade says whether a user signing in by method may sign in
	// while the shared settings cannot be used (clusterauth.Sessions).
	MayDegrade func(user, method string) error
}

var _ SessionStore = (*clusterauth.Sessions)(nil)

// builtinName is the built-in admin's name: the cluster's when users are
// shared (a server whose auth.admin_user differs uses the shared one),
// else auth.admin_user.
func (s *Server) builtinName() string {
	if s.SharedUsers != nil {
		if n := s.SharedUsers.Docs.BuiltinName(); n != "" {
			return n
		}
	}
	return s.conf().Auth.AdminUser
}

// isBuiltin reports whether name is the built-in admin's.
func (s *Server) isBuiltin(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), s.builtinName())
}

// builtinHash is the built-in admin's password hash in use. With shared
// users it is the cluster's, and "" (no password matches) when this
// server cannot read the built-in admin's document: never this server's
// own configured password.
func (s *Server) builtinHash() string {
	if s.SharedUsers != nil {
		if _, h, ok := s.SharedUsers.Docs.Builtin(); ok {
			return h
		}
		return ""
	}
	return s.conf().Auth.AdminPasswordHash
}

// builtinEpoch is the built-in admin's session epoch: 0 on a server that
// keeps sessions in memory.
func (s *Server) builtinEpoch() int64 {
	if s.SharedUsers == nil {
		return 0
	}
	if v, _, ok := s.SharedUsers.Docs.BuiltinUser(); ok {
		return v.SessionEpoch
	}
	return 0
}

// checkBuiltinPassword reports whether pw is the built-in admin's
// password. With shared users, the one signalith passwd -local wrote on
// this server works too while the shared settings cannot be used (local
// then reports it was that one), so an admin can always sign in to fix
// that.
func (s *Server) checkBuiltinPassword(pw string, allowLocal bool) (ok, local bool) {
	if s.SharedUsers == nil {
		return s.conf().CheckPassword(s.conf().Auth.AdminUser, pw), false
	}
	if h := s.builtinHash(); h != "" && bcrypt.CompareHashAndPassword([]byte(h), []byte(pw)) == nil {
		return true, false
	}
	if allowLocal && s.SharedUsers.LocalHash != nil && s.sharedDegraded() {
		if h := s.SharedUsers.LocalHash(); h != "" && bcrypt.CompareHashAndPassword([]byte(h), []byte(pw)) == nil {
			return true, true
		}
	}
	return false, false
}

// sharedPaused reports whether the shared settings cannot be written on
// this server now.
func (s *Server) sharedPaused() bool {
	return s.Shared != nil && s.Shared.Writable() != nil
}

// sharedDegraded reports whether the shared users cannot be used as
// usual now: the shared settings are paused, or OpenSearch refuses
// writes, so no session can be stored.
func (s *Server) sharedDegraded() bool {
	if s.sharedPaused() {
		return true
	}
	return s.SharedUsers != nil && s.SharedUsers.WritesRefused != nil && s.SharedUsers.WritesRefused()
}

// degradedRefusal refuses p while this server cannot use the shared
// settings, unless p may sign in then (the built-in admin, and local
// admins whose copy is recent): the copy of the users this server has
// may be too old to trust for anyone else. It is no counted failure.
func (s *Server) degradedRefusal(p *principal) error {
	if s.SharedUsers == nil || s.SharedUsers.MayDegrade == nil || !s.sharedPaused() {
		return nil
	}
	if s.SharedUsers.MayDegrade(p.Username, p.Source) != nil {
		return errDegraded
	}
	return nil
}

// builtinReadable reports whether the built-in admin may be signed in as
// on this server: with shared users, only while its document can be
// read, or while this server cannot use the shared settings (the
// break-glass password then works).
func (s *Server) builtinReadable() bool {
	if s.SharedUsers == nil {
		return true
	}
	if _, _, ok := s.SharedUsers.Docs.Builtin(); ok {
		return true
	}
	return s.sharedDegraded()
}

// usersWritable refuses a change of users or directory settings kept in
// the shared settings while they cannot be written (503). On a server
// that keeps them in its own files it always allows.
func (s *Server) usersWritable(w http.ResponseWriter) bool {
	if s.SharedUsers == nil || s.Shared == nil {
		return true
	}
	return s.sharedWritable(w)
}

// changeContext names the signed-in user as who makes the changes made
// with it, which the shared settings record.
func changeContext(r *http.Request) context.Context {
	return users.WithActor(r.Context(), userOf(r))
}

// setSessionCookie gives the browser a session's cookie; a remembered
// session's lasts as long as the session.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, remember bool) {
	c := &http.Cookie{Name: s.cookieName(r), Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: s.secureCookie(r)}
	if remember {
		c.MaxAge = int(s.sessions().MaxAge().Seconds())
	}
	http.SetCookie(w, c)
}

// sharedPending is why a member of a cluster does not share the users
// yet: Servers names the servers seen in the last day whose version
// cannot read them (the cluster's level stays below
// shared.LevelSharedUsers until every one can), each with its version.
// With none, the users wait to be brought in by the server that founded
// the cluster.
type sharedPending struct {
	// Version is this server's version, which every server needs.
	Version string          `json:"version"`
	Servers []pendingServer `json:"servers"`
}

type pendingServer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// usersPending returns why the users are not shared yet on a member of a
// cluster, or nil on a server that shares them, or that is no member and
// keeps them in its files for good.
func (s *Server) usersPending() *sharedPending {
	if s.SharedUsers != nil || !s.sharedContent() {
		return nil
	}
	out := &sharedPending{Version: s.Version, Servers: []pendingServer{}}
	if s.Cluster == nil {
		return out
	}
	for _, sv := range s.Cluster.Status().Servers {
		if sv.Self || sv.SeenAgo != nil && *sv.SeenAgo >= shared.LevelSeen {
			continue
		}
		// A heartbeat without levels is from a version before them, which
		// reads level 1 only.
		if sv.Detail == nil || max(sv.Detail.LevelMax, 1) < shared.LevelSharedUsers {
			out.Servers = append(out.Servers, pendingServer{Name: sv.Name, Version: sv.Version})
		}
	}
	return out
}

// pendingWarning says on the Servers page which servers keep the users
// from being shared, or "" when none does.
func (p *sharedPending) warning() string {
	if p == nil || len(p.Servers) == 0 {
		return ""
	}
	names := make([]string, len(p.Servers))
	for i, sv := range p.Servers {
		names[i] = sv.Name
		if sv.Version != "" {
			names[i] += " (" + sv.Version + ")"
		}
	}
	return fmt.Sprintf("Users and sign-in become shared by every server once every server runs %s or later. "+
		"Until then each server keeps its own users and sessions. Upgrade %s.", cmp.Or(p.Version, "this version"), strings.Join(names, ", "))
}
