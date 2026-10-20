// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Demo mode (demo.enabled; see docs/demo.md) makes the server a public,
// read-only demo. It is decided here, in a few central places:
//
//   - Visitors sign in with one click (demoRoute) as a built-in viewer
//     that has no password and no account: its sessions are kept in this
//     server's memory only, apart from the users' sessions, and are short.
//     demoMayUse allows such a session only the routes a viewer may use
//     that only read.
//   - Password sign-in (the sign-in page, HTTP Basic and API tokens) works
//     only from demo.admin_networks (demoAdminClient).
//   - Of the routes that work without signing in, only signing in and out
//     and the CA certificate stay (demoPublicRoutes): event intake from
//     agents, HEC and OTLP, osquery, sensors, joining servers, install
//     downloads, single sign-on, SCIM, passkeys and chat buttons are off.
//   - demoOff refuses everyone, admins too, the features that send to or
//     fetch from other systems.
//
// The rest is decided where those features start: the agent port and
// syslog are not opened, the background jobs that reach out do not run,
// and config.Config turns the AI assistant, single sign-on, SCIM,
// Microsoft 365 and Okta off.

// demoRoute signs a visitor in to the demo.
const demoRoute = "POST /api/demo"

// demoUser and sourceDemo name the demo's visitor (demoPrincipal). The
// source is what tells it apart: no user of the users file has it, so a
// local user who happens to be called demo is never taken for it.
const (
	demoUser   = "demo"
	sourceDemo = "demo"
)

// Visitor sessions end after demoIdle without use, and demoMaxAge after
// they started, whatever auth.session_timeout says. At most demoLimit are
// kept; the least recently used go first.
const (
	demoIdle   = 30 * time.Minute
	demoMaxAge = 2 * time.Hour
	demoLimit  = 10000
)

// demoPublicRoutes are the routes of publicRoutes that work in demo mode.
var demoPublicRoutes = []string{"POST /api/login", "POST /api/logout", "GET /api/tls/ca.pem", demoRoute}

// demoReads are the routes for viewers that only read although they are
// not GET: running a search, a dashboard or a notebook (a viewer's run is
// not saved).
var demoReads = []string{
	"POST /api/search", "POST /api/explain", "POST /api/build", "POST /api/parse",
	"POST /api/dashboards/{id}/run", "POST /api/panels/run", "POST /api/notebooks/{id}/run",
}

// demoOffRoute is a route path (after /api/) demo mode refuses to
// everyone, with the paths under it; writes only refuses only the
// methods other than GET.
type demoOffRoute struct {
	path   string
	writes bool
}

// demoOffRoutes are the features demo mode turns off: they send to or
// fetch from other systems (AI models, webhooks and mail servers, Jira
// and ServiceNow, Slack and Teams, scripts and directory servers,
// threat intel feeds, scanned networks, identity providers), or add
// tenants, whose servers would take events in.
var demoOffRoutes = []demoOffRoute{
	{path: "investigate"}, {path: "findings/{id}/investigate"},
	{path: "notify"}, {path: "respond"}, {path: "playbooks"}, {path: "chat"},
	{path: "ticketing"}, {path: "cases/{id}/tickets"}, {path: "vulns"},
	{path: "intel/feeds", writes: true}, {path: "intel/catalog", writes: true}, {path: "intel/taxii"},
	{path: "auth/oidc"}, {path: "auth/saml"}, {path: "auth/scim"}, {path: "auth/directory", writes: true},
	{path: "settings/test"}, {path: "tenants", writes: true},
}

var errDemoOff = errors.New("This is turned off in the public demo.")

// demo reports whether the server is a public demo.
func (s *Server) demo() bool { return s.conf().DemoOn() }

// demoSessions keeps the visitors' sessions, in this server's memory.
func (s *Server) demoSessions() *auth.Sessions {
	s.demoOnce.Do(func() {
		s.demoSess = auth.NewSessions(demoIdle)
		s.demoSess.MaxAge = demoMaxAge
		s.demoSess.Limit = demoLimit
		s.demoLimits = tokenRate{Each: 10, Per: time.Minute, All: 3000, AllPer: time.Hour}
	})
	return s.demoSess
}

// demoPrincipal is the demo's visitor: a viewer.
func demoPrincipal() *principal {
	return &principal{Username: demoUser, Name: "Demo visitor", Role: users.Viewer, Source: sourceDemo}
}

// demoVisitor returns the visitor whose session cookie r carries, or nil.
func (s *Server) demoVisitor(r *http.Request) *principal {
	c, err := r.Cookie(s.cookieName(r))
	if err != nil {
		return nil
	}
	look := s.demoSessions().Lookup
	if background(r) {
		look = s.demoSessions().Peek
	}
	ss, ok := look(c.Value)
	if !ok || ss.Method != sourceDemo {
		return nil
	}
	p := demoPrincipal()
	p.Method, p.token, p.signedIn = "session", c.Value, ss.Created
	p.Active, _ = s.activeTenant(p, "")
	return p
}

// searchUser is whose share of the search slots p's searches count
// against: the user's, or for the demo's visitors, who are all the same
// user, the session's, so one visitor's slow searches never hold back
// the others.
func searchUser(p *principal) string {
	if p.Source != sourceDemo {
		return p.Username
	}
	sum := sha256.Sum256([]byte(p.token))
	return demoUser + ":" + hex.EncodeToString(sum[:6])
}

// demoAdminClient reports whether r comes from demo.admin_networks, where
// password sign-in still works in demo mode.
func (s *Server) demoAdminClient(r *http.Request) bool {
	a := s.client(r).Addr
	return a.IsValid() && inPrefixes(a, s.conf().DemoAdminNetworks())
}

// demoMayUse reports whether the demo's visitor may use route rt: one for
// viewers that only reads, and asks for no password again.
func demoMayUse(rt route, r *http.Request) bool {
	if rt.Role != users.Viewer || rt.Recheck {
		return false
	}
	return r.Method == http.MethodGet || r.Method == http.MethodHead || slices.Contains(demoReads, rt.Pattern)
}

// demoOff reports whether demo mode refuses route rt to everyone. The
// routes for viewers that only read are never refused: the pages every
// visitor opens use them, and the features behind them are off anyway.
func demoOff(rt route, method string) bool {
	read := method == http.MethodGet || method == http.MethodHead
	if rt.Role == users.Viewer && read {
		return false
	}
	_, path, _ := strings.Cut(rt.Pattern, " ")
	rest, ok := strings.CutPrefix(path, "/api/")
	if !ok {
		return false
	}
	for _, o := range demoOffRoutes {
		if (rest == o.path || strings.HasPrefix(rest, o.path+"/")) && !(o.writes && read) {
			return true
		}
	}
	return false
}

// demoPublicOff reports whether demo mode refuses a route of publicRoutes,
// one that works without signing in.
func demoPublicOff(pattern string) bool {
	return slices.Contains(publicRoutes, pattern) && !slices.Contains(demoPublicRoutes, pattern)
}

func writeDemoOff(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]any{"error": errDemoOff.Error(), "code": "demo_off"})
}

func writeDemoReadOnly(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error": "The public demo is read-only. Install Signalith to try this: https://signalith.io", "code": "demo_read_only"})
}

// demoRate limits how often visitors start a session: 10 a minute from
// one address (an IPv6 /64), 3000 an hour in all.
func (s *Server) demoRate() *tokenRate {
	s.demoSessions()
	return &s.demoLimits
}

// handleDemoLogin signs a visitor in to the demo, with no password: a
// session for the built-in viewer, kept apart from the users' sessions.
func (s *Server) handleDemoLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.demo() {
		writeError(w, http.StatusNotFound, errors.New("this server is not a public demo"))
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
		return
	}
	c := s.client(r)
	key := ""
	if c.Addr.IsValid() && !c.Shared {
		key = clientaddr.Key(c.Addr).String()
	}
	if wait := s.demoRate().take(key, time.Now()); wait > 0 {
		rf := &auth.Refusal{Wait: wait}
		writeSignInError(w, lockedOut(rf))
		return
	}
	n := auth.NewSession{User: demoUser, Method: sourceDemo}
	if c.Addr.IsValid() {
		n.Client = c.Addr.String()
	}
	token := s.demoSessions().Start(n)
	s.setSessionCookie(w, r, token, false)
	s.Log.Info("demo visitor signed in", c.logAttrs()...)
	p := demoPrincipal()
	p.Method = "session"
	writeJSON(w, http.StatusOK, meView(p))
}

// demoSignInRefused answers a password sign-in from outside
// demo.admin_networks.
func demoSignInRefused(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error": "Signing in with a password is turned off on this public demo. Use Explore the demo instead.", "code": "demo_password_off"})
}
