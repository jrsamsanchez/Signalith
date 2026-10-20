// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/oidc"
	"github.com/jrsamsanchez/signalith/internal/saml"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Single sign-on with an OpenID Connect identity provider (see package
// oidc and docs/sso.md). The sign-in page's button opens ssoStartRoute,
// which sends the browser to the provider with a fresh state, nonce and
// PKCE challenge, kept in a short-lived cookie; the provider sends it
// back to ssoCallbackRoute, which checks all of them, trades the code for
// tokens, checks the ID token and starts an ordinary session. Nothing is
// kept on the server between the two, so the callback may reach any
// server of a cluster.

const (
	ssoStartRoute    = "GET /api/auth/oidc/start"
	ssoCallbackRoute = "GET /api/auth/oidc/callback"
)

// The routes' paths, for addresses.
var (
	ssoStartPath    = strings.TrimPrefix(ssoStartRoute, "GET ")
	ssoCallbackPath = strings.TrimPrefix(ssoCallbackRoute, "GET ")
)

var ssoPublicRoutes = []string{ssoStartRoute, ssoCallbackRoute}

// The cookie that carries a sign-in under way. It is Lax, not Strict like
// the session cookie, because the provider's redirect back is a
// navigation from another site.
const (
	ssoCookie       = "signalith_sso"
	secureSSOCookie = "__Host-signalith_sso"
	// ssoWait is how long a sign-in at the provider may take.
	ssoWait = 10 * time.Minute
)

// ssoKeys are the single sign-on settings, in page order.
func ssoKeys() []string {
	var out []string
	for _, set := range config.Registry {
		if set.Section == "sso" {
			out = append(out, set.Key)
		}
	}
	return out
}

func (s *Server) routeSSO(api *router) {
	api.admin("GET /api/auth/oidc", s.handleGetSSO)
	api.admin("POST /api/auth/oidc/test", s.handleTestSSO)
}

func (s *Server) oidcClient() *oidc.Client {
	s.ssoOnce.Do(func() {
		if s.OIDC == nil {
			s.OIDC = oidc.NewClient()
		}
	})
	return s.OIDC
}

// ssoRedirectURL is the address the provider sends browsers back to:
// the callback at the public address. It must be registered with the
// provider exactly.
func ssoRedirectURL(c *config.Config) string {
	return strings.TrimRight(c.Server.PublicURL, "/") + ssoCallbackPath
}

func (s *Server) ssoCookieName(r *http.Request) string {
	if s.secureCookie(r) {
		return secureSSOCookie
	}
	return ssoCookie
}

// ssoState is what the cookie holds while a sign-in is at the provider.
type ssoState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x,omitempty"`
	Issuer   string `json:"i"`
	Expires  int64  `json:"e"`
}

// localPath returns next when it is a path on this server (with its query
// and fragment), or "/". Anything that could leave the site (another
// scheme or host, //host, a backslash) or land on the API is refused, so
// the sign-in can never be used to send someone elsewhere.
func localPath(next string) string {
	if next == "" || len(next) > 2048 || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.ContainsAny(next, "\\\r\n\t\x00") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") ||
		strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, "/api/") || u.Path == "/login" {
		return "/"
	}
	out := u.EscapedPath()
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.EscapedFragment()
	}
	return out
}

// ssoFail sends the browser back to the sign-in page, which says what
// went wrong by code; detail goes to the server log only.
func (s *Server) ssoFail(w http.ResponseWriter, r *http.Request, code, user, detail string) {
	s.Log.Warn("single sign-on failed", slices.Concat([]any{"audit", true, "user", user}, s.client(r).logAttrs(),
		[]any{"method", "sso", "code", code, "reason", detail})...)
	http.Redirect(w, r, "/login?sso_error="+url.QueryEscape(code), http.StatusSeeOther)
}

// handleSSOStart sends the browser to the identity provider.
func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	c := s.conf()
	if !c.OIDCOn() {
		s.ssoFail(w, r, "off", "", "single sign-on is off")
		return
	}
	next := localPath(r.URL.Query().Get("next"))
	// The cookie must be set on the host the provider sends the browser
	// back to: a browser that came in another way is sent to the public
	// address first, once.
	if pu, err := url.Parse(c.Server.PublicURL); err == nil && pu.Host != "" && !strings.EqualFold(pu.Host, r.Host) && r.URL.Query().Get("hop") == "" {
		q := url.Values{"next": {next}, "hop": {"1"}}
		http.Redirect(w, r, strings.TrimRight(c.Server.PublicURL, "/")+ssoStartPath+"?"+q.Encode(), http.StatusSeeOther)
		return
	}
	set := c.OIDCSettings()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	md, err := s.oidcClient().Discover(ctx, set.Issuer)
	if err != nil {
		s.ssoFail(w, r, "provider", "", err.Error())
		return
	}
	req := oidc.NewRequest()
	st := ssoState{State: req.State, Nonce: req.Nonce, Verifier: req.Verifier, Next: next, Issuer: set.Issuer,
		Expires: time.Now().Add(ssoWait).Unix()}
	data, _ := json.Marshal(st)
	http.SetCookie(w, &http.Cookie{Name: s.ssoCookieName(r), Value: base64.RawURLEncoding.EncodeToString(data), Path: "/",
		MaxAge: int(ssoWait.Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secureCookie(r)})
	target := oidc.AuthURL(md, oidc.Settings{Issuer: set.Issuer, ClientID: set.ClientID, RedirectURL: ssoRedirectURL(c), Scopes: set.Scopes}, req)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// readSSOState reads and removes the sign-in cookie.
func (s *Server) readSSOState(w http.ResponseWriter, r *http.Request) (ssoState, bool) {
	var st ssoState
	name := s.ssoCookieName(r)
	ck, err := r.Cookie(name)
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: s.secureCookie(r)})
	if err != nil {
		return st, false
	}
	data, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || json.Unmarshal(data, &st) != nil || st.State == "" || st.Nonce == "" || st.Verifier == "" {
		return st, false
	}
	return st, time.Now().Unix() <= st.Expires
}

// handleSSOCallback finishes a sign-in: the provider sent the browser
// back with a code (or an error) and the state.
func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	st, ok := s.readSSOState(w, r)
	if e := q.Get("error"); e != "" {
		s.ssoFail(w, r, "denied", "", "the identity provider answered "+oidcText(e)+": "+oidcText(q.Get("error_description")))
		return
	}
	if !ok {
		s.ssoFail(w, r, "expired", "", "no sign-in under way in this browser, or it took longer than 10 minutes")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		s.ssoFail(w, r, "expired", "", "the state does not match the sign-in under way in this browser")
		return
	}
	c := s.conf()
	set := c.OIDCSettings()
	if !c.OIDCOn() || set.Issuer != st.Issuer {
		s.ssoFail(w, r, "off", "", "single sign-on was turned off or moved to another provider during the sign-in")
		return
	}
	code := q.Get("code")
	if code == "" {
		s.ssoFail(w, r, "failed", "", "the identity provider sent no code")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	cl := s.oidcClient()
	md, err := cl.Discover(ctx, set.Issuer)
	if err != nil {
		s.ssoFail(w, r, "provider", "", err.Error())
		return
	}
	conn := oidc.Settings{Issuer: set.Issuer, ClientID: set.ClientID, ClientSecret: set.ClientSecret, RedirectURL: ssoRedirectURL(c), Scopes: set.Scopes}
	tok, err := cl.Exchange(ctx, md, conn, code, st.Verifier)
	if err != nil {
		s.ssoFail(w, r, "failed", "", err.Error())
		return
	}
	claims, err := cl.Verify(ctx, md, set.ClientID, st.Nonce, tok.IDToken)
	if err != nil {
		s.ssoFail(w, r, "failed", "", err.Error())
		return
	}
	note := ""
	if set.GroupsClaim != "" && !claims.Has(set.GroupsClaim) && md.UserinfoEndpoint != "" {
		// Some providers (Okta's org server among them) send groups only
		// from userinfo.
		if more, err := cl.UserInfo(ctx, md, tok.AccessToken, claims.String("sub")); err != nil {
			note = err.Error()
		} else {
			for k, v := range more {
				if _, have := claims[k]; !have {
					claims[k] = v
				}
			}
		}
	}
	s.finishSSO(w, r, set, claims, st.Next, note)
}

// oidcText is text from the provider, made safe for the log.
func oidcText(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, v)
	if len(v) > 200 {
		v = v[:200] + "…"
	}
	return v
}

// ssoIdentity is who the claims say someone is, and what they may do.
type ssoIdentity struct {
	user    users.SSOUser
	groups  []string
	matched []string
	// verified is the email address when the provider vouches for it.
	verified string
}

// ssoIdentityOf works out who claims describe with set, or the code and
// reason of a refusal.
func ssoIdentityOf(set config.OIDCSettings, claims oidc.Claims) (ssoIdentity, string, string) {
	var id ssoIdentity
	email := strings.TrimSpace(claims.String("email"))
	verified, said := claims.EmailVerified()
	if set.Provider == oidc.Entra && !said {
		// Entra ID sends no email_verified. Its xms_edov optional claim
		// says whether the email domain is one the tenant has verified;
		// without it, a user could set any address on their account.
		verified = claims.String("xms_edov") == "true" || claims["xms_edov"] == true
		said = true
	}
	switch {
	case email == "":
	case verified:
		id.verified = strings.ToLower(email)
	case said:
		// Not verified: not used to decide anything, and not kept.
		email = ""
	}
	if strings.EqualFold(set.UsernameClaim, "email") && id.verified == "" {
		return id, "username", "the username claim is email, and the provider did not say the email address is verified"
	}
	name := users.NormalizeUsername(claims.String(set.UsernameClaim))
	if name == "" {
		return id, "username", "the ID token has no " + set.UsernameClaim + " claim; change the username claim, or have the provider send it"
	}
	if users.ValidUsername(name) != nil {
		return id, "username", "the " + set.UsernameClaim + " claim " + oidcText(name) + " is not a usable username"
	}
	if !set.DomainAllowed(id.verified) {
		return id, "domain", "the verified email address " + oidcText(id.verified) + " is not in an allowed domain"
	}
	id.groups = claims.Strings(set.GroupsClaim)
	role, matched := set.OIDCRole(id.groups, id.verified)
	id.matched = matched
	if role == "" {
		reason := "in no group mapped to a role (groups: " + oidcText(strings.Join(id.groups, ", ")) + ")"
		if names, ok := claims["_claim_names"].(map[string]any); ok && names[set.GroupsClaim] != nil {
			reason += "; Entra ID left the groups out because there are too many, so map app roles (the roles claim) instead"
		}
		return id, "role", reason
	}
	full := claims.String("name")
	if full == "" {
		full = strings.TrimSpace(claims.String("given_name") + " " + claims.String("family_name"))
	}
	id.user = users.SSOUser{Username: name, Name: oidcText(full), Email: email, Role: users.Role(role),
		Subject: users.SSOSubject(set.Issuer, claims.String("sub")), VerifiedEmail: id.verified}
	for _, c := range []string{"sub", "oid"} {
		if v := claims.String(c); v != "" {
			id.user.IDs = append(id.user.IDs, v)
		}
	}
	return id, "", ""
}

// finishSSO signs in the person the checked claims describe, and sends the
// browser on to next.
func (s *Server) finishSSO(w http.ResponseWriter, r *http.Request, set config.OIDCSettings, claims oidc.Claims, next, note string) {
	id, code, reason := ssoIdentityOf(set, claims)
	if code != "" {
		if note != "" {
			reason += "; " + note
		}
		s.ssoFail(w, r, code, claims.String(set.UsernameClaim), reason)
		return
	}
	s.signInSSO(w, r, id.user, set.NewUsers(), next, []any{"issuer", set.Issuer, "groups_matched", strings.Join(id.matched, ",")})
}

// signInSSO signs in u, whom an identity provider vouched for, adding
// them when create allows, and sends the browser on to next. logAttrs go
// to the sign-in's audit line.
func (s *Server) signInSSO(w http.ResponseWriter, r *http.Request, u users.SSOUser, create bool, next string, logAttrs []any) {
	// The cookie's path was checked when the sign-in started; check it
	// again, as a cookie can be set by others on plain HTTP.
	next = localPath(next)
	if err := s.degradedRefusal(&principal{Username: u.Username, Source: users.SourceSSO}); err != nil {
		s.ssoFail(w, r, "busy", u.Username, "OpenSearch cannot be used, and only admins may sign in then")
		return
	}
	ctx := clusterauth.WithMethod(r.Context(), "sso")
	rec, err := s.userStore().SeeSSOUser(ctx, u, create)
	switch {
	case errors.Is(err, users.ErrSSONew):
		s.ssoFail(w, r, "new", u.Username, "not a Signalith user yet, and new users are not added")
		return
	case errors.Is(err, users.ErrSSOUnconfirmed):
		s.ssoFail(w, r, "unconfirmed", u.Username, "provisioned (SCIM), and neither the provider's ids for the user ("+oidcText(strings.Join(u.IDs, ", "))+
			") match its externalId nor the verified email address its email")
		return
	case errors.Is(err, users.ErrSSOOther):
		s.ssoFail(w, r, "taken", u.Username, "the name belongs to another user (local, directory, the built-in admin, or another identity at the provider)")
		return
	case err != nil:
		s.ssoFail(w, r, "store", u.Username, "could not save the user: "+err.Error())
		return
	case rec.Disabled:
		s.ssoFail(w, r, "disabled", u.Username, "account disabled in Signalith")
		return
	}
	p := principalFromUser(rec)
	p.shared = s.SharedUsers != nil
	token, err := s.startSession(r, p, false)
	if err != nil {
		s.ssoFail(w, r, "store", u.Username, "could not start a session: "+err.Error())
		return
	}
	s.setSessionCookie(w, r, token, false)
	s.Log.Info("signed in", slices.Concat([]any{"audit", true, "user", p.Username, "role", p.Role, "source", p.Source}, s.client(r).logAttrs(),
		[]any{"method", "sso"}, logAttrs)...)
	// The session cookie is SameSite=Strict, and this answer ends a
	// navigation that came from the provider's site, so a redirect would
	// arrive without it. A page that moves on by itself starts a new,
	// same-site navigation, which carries it.
	target := html.EscapeString(next)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<meta http-equiv="refresh" content="0;url=` + target + `"><title>Signing in · Signalith</title></head>` +
		`<body style="font-family:system-ui,sans-serif;padding:2rem"><p>Signed in. <a href="` + target + `">Continue to Signalith</a></p></body></html>`))
}

// ---- the Single sign-on tab ----

// handleGetSSO returns the single sign-on settings as saved, what the
// provider needs to know about Signalith, and the provider presets.
func (s *Server) handleGetSSO(w http.ResponseWriter, r *http.Request) {
	var saved *config.Saved
	var sh *config.Shared
	var err error
	if s.settingsShared() {
		// With the revision of each, so a save refuses to overwrite a
		// change someone made since.
		saved, sh, _, err = s.savedShared(r.Context())
	} else {
		saved, err = s.savedSettings()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	problems, _ := config.FieldProblems(saved.Config, saved.Problems)
	fields := []settingField{}
	for _, key := range ssoKeys() {
		set, _ := config.Lookup(key)
		f := settingField{Key: set.Key, Label: set.Label, Help: set.Help, Type: set.Type, Choices: set.Choices,
			Placeholder: set.Placeholder, EmptyMeans: set.EmptyMeans, Source: saved.Source(set.Key), Env: set.Env, Apply: "live",
			Problem: problems[set.Key]}
		f.Value, f.Set = fieldValue(saved.Config, set)
		if f.Set != nil && *f.Set {
			f.SentTo = set.SentTo(saved.Config)
		}
		if msg := saved.PageSecretProblem(set.Key); msg != "" {
			f.Warning = msg
		}
		if f.Source.Kind == config.FromEnv {
			f.Locked, f.LockedReason = true, config.LockedReason(f.Source.Env)
		}
		if sh != nil {
			v := sh.Rev(set.Key)
			f.Scope, f.Version = string(set.Scope), &v
		}
		fields = append(fields, f)
	}
	running := s.conf()
	redirect := ssoRedirectURL(saved.Config)
	warning := ""
	if u, err := url.Parse(redirect); err == nil && u.Scheme == "http" && !isLoopback(u.Hostname()) {
		warning = "Most identity providers accept only https:// addresses here, except for localhost. Turn HTTPS on, or set the web address on the Server tab."
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"fields":           fields,
		"on":               running.OIDCOn(),
		"redirect_uri":     redirect,
		"redirect_warning": warning,
		"presets":          oidc.Presets,
		"editable":         s.Config.Path() != "",
		"shared":           s.settingsShared(),
		"sso_users":        s.userStore().Count()[users.SourceSSO],
		"scim_url":         scimURL(saved.Config.Server.PublicURL),
		"scim_on":          running.SCIMOn(),
		"scim_warning":     scimWarning(scimURL(saved.Config.Server.PublicURL)),
		"saml_on":          running.SAMLOn(),
		"saml_entity_id":   samlSP(saved.Config).EntityID,
		"saml_acs_url":     samlSP(saved.Config).ACSURL,
		"saml_warning":     samlWarning(saved.Config),
		"saml_presets":     saml.Presets,
	})
}

// scimWarning says why the provider could not use the SCIM address.
func scimWarning(addr string) string {
	if u, err := url.Parse(addr); err == nil && u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return "Provisioning works only over HTTPS, so the token is never sent in the clear. Turn HTTPS on, or set the web address on the Server tab."
	}
	return ""
}

// ssoStep is one check of the single sign-on test.
type ssoStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// handleTestSSO checks the settings in the form, saved or not, against
// the provider: its discovery document, its keys, and what Signalith
// needs from it. A full sign-in needs a person, so it is not tried.
func (s *Server) handleTestSSO(w http.ResponseWriter, r *http.Request) {
	c, fields, err := s.testValues(r, ssoKeys()...)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	set := c.OIDCSettings()
	if len(fields) == 0 {
		switch {
		case c.Auth.OIDC.Provider == "":
			fields["auth.oidc.provider"] = "Choose the identity provider."
		case set.Issuer == "":
			fields["auth.oidc.issuer"] = "Enter the issuer address, like " + set.Preset.IssuerExample + "."
		case oidc.CheckIssuer(set.Issuer) != "":
			fields["auth.oidc.issuer"] = sentence(oidc.CheckIssuer(set.Issuer))
		case set.ClientID == "":
			fields["auth.oidc.client_id"] = "Enter the client ID."
		}
	}
	if len(fields) > 0 {
		writeFieldProblems(w, fields)
		return
	}
	done, ok := s.oneTest(w)
	if !ok {
		return
	}
	defer done()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	// A fresh client, so the test reads the provider as it is now.
	cl := &oidc.Client{HTTP: s.oidcClient().HTTP}
	rep := struct {
		OK          bool      `json:"ok"`
		Message     string    `json:"message"`
		Steps       []ssoStep `json:"steps"`
		RedirectURI string    `json:"redirect_uri"`
	}{RedirectURI: ssoRedirectURL(c), Steps: []ssoStep{}}
	start := time.Now()
	md, err := cl.Discover(ctx, set.Issuer)
	if err != nil {
		rep.Steps = append(rep.Steps, ssoStep{Name: "Discovery document", Detail: sentence(err.Error())})
		rep.Message = "Signalith could not use the issuer's discovery document."
	} else {
		rep.Steps = append(rep.Steps, ssoStep{Name: "Discovery document", OK: true, Detail: "Read from " + strings.TrimRight(set.Issuer, "/") + "/.well-known/openid-configuration."})
		n, kerr := cl.Keys(ctx, md)
		if kerr != nil {
			rep.Steps = append(rep.Steps, ssoStep{Name: "Signing keys", Detail: sentence(kerr.Error())})
			rep.Message = "Signalith could not read the provider's signing keys."
		} else {
			rep.Steps = append(rep.Steps, ssoStep{Name: "Signing keys", OK: true, Detail: fmt.Sprintf("%d signing %s Signalith can check ID tokens with.", n, plural(n, "key", "keys"))})
			pkce := "The provider does not list its PKCE methods; Signalith sends S256, which every provider listed here supports."
			if len(md.CodeChallengeMethods) > 0 {
				pkce = "The provider supports PKCE with S256."
			}
			rep.Steps = append(rep.Steps, ssoStep{Name: "PKCE", OK: true, Detail: pkce})
			auth := "None: a public client, which PKCE alone protects."
			if set.ClientSecret != "" {
				auth = "The client secret goes to " + md.TokenEndpoint + " as HTTP Basic."
				if len(md.TokenAuthMethods) > 0 && !slices.Contains(md.TokenAuthMethods, "client_secret_basic") {
					auth = "The client secret goes to " + md.TokenEndpoint + " in the form, as the provider asks."
				}
			}
			rep.Steps = append(rep.Steps, ssoStep{Name: "Client secret", OK: true, Detail: auth})
			rep.OK = true
			rep.Message = "The provider is ready. Register the redirect URI above with it, save, then try a sign-in in a private window."
		}
	}
	s.audit(r, "settings tested", "what", "sso", "issuer", set.Issuer, "client_id", set.ClientID, "ok", rep.OK, "took_ms", time.Since(start).Milliseconds())
	writeJSON(w, http.StatusOK, rep)
}
