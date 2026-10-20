// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/saml"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Single sign-on with a SAML 2.0 identity provider (see package saml and
// docs/sso.md), beside OpenID Connect. The sign-in page's button opens
// samlStartRoute, which sends the browser to the provider with an
// AuthnRequest whose ID and RelayState are kept in a short-lived cookie;
// the provider posts its signed response to samlACSRoute, which checks
// it against them and starts an ordinary session. Responses nobody asked
// for (IdP-initiated) are refused, and each assertion is used once.

const (
	samlStartRoute    = "GET /api/auth/saml/start"
	samlACSRoute      = "POST /api/auth/saml/acs"
	samlMetadataRoute = "GET /api/auth/saml/metadata"
	samlTestRoute     = "POST /api/auth/saml/test"
)

var (
	samlStartPath    = strings.TrimPrefix(samlStartRoute, "GET ")
	samlACSPath      = strings.TrimPrefix(samlACSRoute, "POST ")
	samlMetadataPath = strings.TrimPrefix(samlMetadataRoute, "GET ")
)

var samlPublicRoutes = []string{samlStartRoute, samlACSRoute, samlMetadataRoute}

// The cookie that carries a SAML sign-in under way. The provider posts
// the response back from its own site, which only a SameSite=None
// cookie survives; None needs Secure, so SAML needs HTTPS (or
// localhost, which browsers treat as secure).
const (
	samlCookie       = "signalith_saml"
	secureSAMLCookie = "__Host-signalith_saml"
)

func (s *Server) routeSAML(api *router) {
	api.admin(samlTestRoute, s.handleTestSAML)
	// Read the provider's metadata now, so its users' sessions work from
	// the first request (samlIssuerOK refuses them until then).
	if c := s.conf(); c != nil && c.SAMLOn() {
		s.samlIssuerOK(c, "")
	}
}

// samlSP is Signalith as the provider knows it: the entity ID is the
// address of Signalith's metadata, and the assertion consumer service
// the address responses are posted to, both at the public address.
func samlSP(c *config.Config) saml.SP {
	base := strings.TrimRight(c.Server.PublicURL, "/")
	return saml.SP{EntityID: base + samlMetadataPath, ACSURL: base + samlACSPath}
}

func (s *Server) samlMetadata() *saml.Metadata {
	s.samlOnce.Do(func() {
		if s.SAMLMeta == nil {
			s.SAMLMeta = saml.NewMetadata()
		}
	})
	return s.SAMLMeta
}

// samlIdP returns the identity provider set up in c, from its metadata
// (fresh skips the cache). A sign-in then calls noteSAMLEntity; a test,
// whose settings may not be saved, does not.
func (s *Server) samlIdP(ctx context.Context, c *config.Config, fresh bool) (*saml.IdP, error) {
	set := c.SAMLSettings()
	var idp *saml.IdP
	var err error
	switch {
	case set.MetadataXML != "":
		idp, err = saml.ParseMetadataCached([]byte(set.MetadataXML))
	case set.MetadataURL != "":
		idp, err = s.samlMetadata().Get(ctx, set.MetadataURL, fresh)
	default:
		err = errors.New("no metadata is set")
	}
	if err != nil {
		return nil, err
	}
	return idp, nil
}

// samlKnown is the entity ID of the SAML provider, read from the
// metadata the settings named (source).
type samlKnown struct{ source, entity string }

// samlSource names where the SAML settings in c take the metadata from,
// so a change of provider is noticed.
func samlSource(c *config.Config) string {
	set := c.SAMLSettings()
	if set.MetadataXML != "" {
		sum := sha256.Sum256([]byte(set.MetadataXML))
		return "xml:" + hex.EncodeToString(sum[:])
	}
	return "url:" + set.MetadataURL
}

// noteSAMLEntity remembers the entity ID of the SAML provider c uses.
func (s *Server) noteSAMLEntity(c *config.Config, idp *saml.IdP) {
	s.samlEntity.Store(samlKnown{source: samlSource(c), entity: idp.EntityID})
}

// samlIssuerOK reports whether a single sign-on user's issuer (from
// their Subject) is the SAML provider in use, by its entity ID from the
// metadata the settings name now. Until this server has read that
// metadata (after a start, or a change of provider), SAML users are
// refused, and the metadata is read in the background.
func (s *Server) samlIssuerOK(c *config.Config, issuer string) bool {
	if !c.SAMLOn() {
		return false
	}
	src := samlSource(c)
	if k, _ := s.samlEntity.Load().(samlKnown); k.source == src && k.entity != "" {
		return issuer == config.SAMLEntityPrefix+k.entity
	}
	set := c.SAMLSettings()
	switch {
	case set.MetadataXML != "":
		idp, err := saml.ParseMetadataCached([]byte(set.MetadataXML))
		if err != nil {
			return false
		}
		s.noteSAMLEntity(c, idp)
		return issuer == config.SAMLEntityPrefix+idp.EntityID
	case set.MetadataURL != "" && s.samlLoading.CompareAndSwap(false, true):
		go func() {
			defer s.samlLoading.Store(false)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if idp, err := s.samlIdP(ctx, c, false); err == nil {
				s.noteSAMLEntity(c, idp)
			}
		}()
	}
	return false
}

func (s *Server) samlCookieName(r *http.Request) string {
	if s.overHTTPS(r) {
		return secureSAMLCookie
	}
	return samlCookie
}

// samlStatePurpose keys the MAC of the sign-in cookie.
const samlStatePurpose = "saml sign-in"

// sealSAMLState returns the cookie value of st: its JSON, and a MAC under
// the servers' shared key (the one of the known-browser cookies), so a
// cookie Signalith did not make, or changed, is refused. Without it, an
// attacker holding someone's SAMLResponse could write a cookie with its
// InResponseTo and sign in as them.
func (s *Server) sealSAMLState(st samlState) string {
	data, _ := json.Marshal(st)
	body := base64.RawURLEncoding.EncodeToString(data)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.browserKey().MAC(samlStatePurpose, []byte(body)))
}

// openSAMLState checks and reads a cookie value sealSAMLState made.
func (s *Server) openSAMLState(v string) (samlState, bool) {
	var st samlState
	body, mac, ok := strings.Cut(v, ".")
	if !ok {
		return st, false
	}
	got, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil || !hmac.Equal(got, s.browserKey().MAC(samlStatePurpose, []byte(body))) {
		return st, false
	}
	data, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(data, &st) != nil {
		return st, false
	}
	return st, true
}

// samlState is what the cookie holds while a sign-in is at the provider.
type samlState struct {
	ID         string `json:"i"`
	RelayState string `json:"r"`
	Next       string `json:"x,omitempty"`
	Entity     string `json:"p"`
	Expires    int64  `json:"e"`
}

// handleSAMLStart sends the browser to the identity provider.
func (s *Server) handleSAMLStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	c := s.conf()
	if !c.SAMLOn() {
		s.ssoFail(w, r, "off", "", "SAML single sign-on is off")
		return
	}
	next := localPath(r.URL.Query().Get("next"))
	// The cookie must be set on the host the provider posts back to.
	if pu, err := url.Parse(c.Server.PublicURL); err == nil && pu.Host != "" && !strings.EqualFold(pu.Host, r.Host) && r.URL.Query().Get("hop") == "" {
		q := url.Values{"next": {next}, "hop": {"1"}}
		http.Redirect(w, r, strings.TrimRight(c.Server.PublicURL, "/")+samlStartPath+"?"+q.Encode(), http.StatusSeeOther)
		return
	}
	if !s.overHTTPS(r) && !isLoopback(hostOnly(r.Host)) {
		s.ssoFail(w, r, "https", "", "SAML sign-in needs HTTPS: the sign-in cookie must be SameSite=None, which browsers keep only when Secure")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	idp, err := s.samlIdP(ctx, c, false)
	if err != nil {
		s.ssoFail(w, r, "provider", "", "SAML metadata: "+err.Error())
		return
	}
	s.noteSAMLEntity(c, idp)
	req := saml.NewRequest(time.Now())
	target, err := saml.RedirectURL(idp, samlSP(c), req)
	if err != nil {
		s.ssoFail(w, r, "provider", "", err.Error())
		return
	}
	st := samlState{ID: req.ID, RelayState: req.RelayState, Next: next, Entity: idp.EntityID, Expires: time.Now().Add(ssoWait).Unix()}
	http.SetCookie(w, &http.Cookie{Name: s.samlCookieName(r), Value: s.sealSAMLState(st), Path: "/",
		MaxAge: int(ssoWait.Seconds()), HttpOnly: true, SameSite: http.SameSiteNoneMode, Secure: true})
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// hostOnly is the host of a Host header, without the port.
func hostOnly(hostport string) string {
	if u, err := url.Parse("//" + hostport); err == nil {
		return u.Hostname()
	}
	return hostport
}

// readSAMLState reads and removes the sign-in cookie.
func (s *Server) readSAMLState(w http.ResponseWriter, r *http.Request) (samlState, bool) {
	var st samlState
	name := s.samlCookieName(r)
	ck, err := r.Cookie(name)
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteNoneMode, Secure: true})
	if err != nil {
		return st, false
	}
	st, ok := s.openSAMLState(ck.Value)
	if !ok || st.ID == "" || st.RelayState == "" || st.Entity == "" {
		return st, false
	}
	return st, time.Now().Unix() <= st.Expires
}

// handleSAMLACS finishes a sign-in: the provider posted its response.
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, saml.MaxResponse+8<<10)
	if err := r.ParseForm(); err != nil {
		s.ssoFail(w, r, "failed", "", "the SAML response could not be read: "+err.Error())
		return
	}
	st, ok := s.readSAMLState(w, r)
	if !ok {
		s.ssoFail(w, r, "expired", "", "no SAML sign-in under way in this browser, or it took longer than 10 minutes (an IdP-initiated sign-in is refused)")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("RelayState")), []byte(st.RelayState)) != 1 {
		s.ssoFail(w, r, "expired", "", "the RelayState does not match the sign-in under way in this browser")
		return
	}
	c := s.conf()
	if !c.SAMLOn() {
		s.ssoFail(w, r, "off", "", "SAML single sign-on was turned off during the sign-in")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	idp, err := s.samlIdP(ctx, c, false)
	if err != nil {
		s.ssoFail(w, r, "provider", "", "SAML metadata: "+err.Error())
		return
	}
	s.noteSAMLEntity(c, idp)
	if idp.EntityID != st.Entity {
		s.ssoFail(w, r, "off", "", "SAML single sign-on moved to another identity provider during the sign-in")
		return
	}
	now := time.Now()
	a, err := saml.ParseResponse(r.PostForm.Get("SAMLResponse"), idp, samlSP(c), st.ID, now)
	if errors.Is(err, saml.ErrDenied) {
		s.ssoFail(w, r, "denied", "", err.Error())
		return
	}
	if err != nil {
		s.ssoFail(w, r, "failed", "", "SAML response refused: "+err.Error())
		return
	}
	if !s.samlReplays.Use(idp.EntityID+" "+a.ID, a.Expires, now) {
		s.ssoFail(w, r, "replay", a.NameID, "the SAML assertion "+oidcText(a.ID)+" was used before")
		return
	}
	// With several servers, the assertion is spent on all of them; when
	// that cannot be recorded, another server may have taken it already.
	if su := s.SharedUsers; su != nil && su.Spent != nil {
		err := su.Spent.Use(ctx, "saml", idp.EntityID+" "+a.ID, a.Expires)
		if errors.Is(err, clusterauth.ErrSpent) {
			s.ssoFail(w, r, "replay", a.NameID, "the SAML assertion "+oidcText(a.ID)+" was used before, on another server")
			return
		}
		if err != nil {
			s.ssoFail(w, r, "store", a.NameID, "the SAML assertion could not be recorded as used for the other servers: "+err.Error())
			return
		}
	}
	set := c.SAMLSettings()
	u, matched, code, reason := samlIdentityOf(set, idp.EntityID, a)
	if code != "" {
		s.ssoFail(w, r, code, oidcText(a.NameID), reason)
		return
	}
	s.signInSSO(w, r, u, set.NewUsers(), st.Next, []any{"protocol", "saml", "issuer", idp.EntityID, "groups_matched", strings.Join(matched, ",")})
}

// samlIdentityOf works out who a checked assertion describes with set,
// or the code and reason of a refusal.
func samlIdentityOf(set config.SAMLSettings, entity string, a *saml.Assertion) (users.SSOUser, []string, string, string) {
	var u users.SSOUser
	transient := a.NameIDFormat == saml.NameIDTransient
	var name string
	if strings.EqualFold(set.UsernameAttribute, saml.NameIDAttribute) {
		if transient {
			return u, nil, "username", "the NameID is transient (new at every sign-in); have the provider send a persistent NameID, such as the user principal name, or choose a username attribute"
		}
		name = a.NameID
	} else {
		name = a.Value(set.UsernameAttribute)
		if name == "" {
			return u, nil, "username", "the assertion has no " + set.UsernameAttribute + " attribute; change the username attribute, or have the provider send it"
		}
	}
	name = users.NormalizeUsername(name)
	if users.ValidUsername(name) != nil {
		return u, nil, "username", "the username " + oidcText(name) + " is not a usable username"
	}
	// The provider is the organization's own, set up by its admins, so the
	// address it sends is taken as one it vouches for: it maps roles and
	// matches provisioned users. Send it only from a directory field
	// people cannot edit themselves (docs/sso.md).
	email := ""
	for _, at := range saml.EmailAttributes {
		if v := strings.TrimSpace(a.Value(at)); v != "" {
			email = v
			break
		}
	}
	if email == "" && strings.HasSuffix(a.NameIDFormat, ":emailAddress") {
		email = a.NameID
	}
	email = strings.ToLower(email)
	groups := a.Values(set.GroupsAttribute)
	role, matched := set.SAMLRole(groups, email)
	if role == "" {
		reason := "in no group mapped to a role (groups: " + oidcText(strings.Join(groups, ", ")) + ")"
		if a.Value(saml.ClaimGroupsLink) != "" {
			reason += "; Entra ID left the groups out because there are too many, so send only the groups assigned to the application, or map app roles"
		}
		return u, nil, "role", reason
	}
	full := ""
	for _, at := range saml.NameAttributes {
		if v := a.Value(at); v != "" && v != name {
			full = v
			break
		}
	}
	if full == "" {
		for _, fl := range saml.FirstLast {
			if v := strings.TrimSpace(a.Value(fl[0]) + " " + a.Value(fl[1])); v != "" {
				full = v
				break
			}
		}
	}
	// The subject: Entra ID's object ID never changes, while its NameID
	// (the user principal name) can be renamed.
	sub := ""
	if set.Provider == saml.Entra {
		sub = a.Value(saml.ClaimObjectID)
	}
	if sub == "" {
		if transient {
			return u, nil, "username", "the NameID is transient (new at every sign-in), so Signalith cannot tell it is the same person next time; have the provider send a persistent NameID"
		}
		sub = a.NameID
	}
	u = users.SSOUser{Username: name, Name: oidcText(full), Email: email, Role: users.Role(role),
		Subject: users.SSOSubject(config.SAMLEntityPrefix+entity, sub), VerifiedEmail: email}
	if !transient {
		u.IDs = append(u.IDs, a.NameID)
	}
	if v := a.Value(saml.ClaimObjectID); v != "" && set.Provider == saml.Entra {
		u.IDs = append(u.IDs, v)
	}
	return u, matched, "", ""
}

// handleSAMLMetadata serves Signalith's own SAML metadata, which most
// providers can read to set Signalith up. It holds nothing secret.
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(saml.SPMetadata(samlSP(s.conf())))
}

// samlWarning says why the provider could not use Signalith's addresses.
func samlWarning(c *config.Config) string {
	if u, err := url.Parse(samlSP(c).ACSURL); err == nil && u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return "SAML sign-in works only over HTTPS. Turn HTTPS on, or set the web address on the Server tab."
	}
	return ""
}

// handleTestSAML checks the SAML settings in the form, saved or not: it
// reads the metadata and says what Signalith found in it. A full sign-in
// needs a person, so it is not tried.
func (s *Server) handleTestSAML(w http.ResponseWriter, r *http.Request) {
	c, fields, err := s.testValues(r, ssoKeys()...)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	set := c.SAMLSettings()
	for k := range fields {
		if !strings.HasPrefix(k, "auth.saml.") {
			delete(fields, k)
		}
	}
	if len(fields) == 0 {
		switch {
		case c.Auth.SAML.Provider == "":
			fields["auth.saml.provider"] = "Choose the identity provider."
		case set.MetadataURL == "" && set.MetadataXML == "":
			fields["auth.saml.metadata_url"] = "Enter the metadata address, like " + set.Preset.MetadataExample + ", or paste the metadata."
		case set.MetadataURL != "" && set.MetadataXML != "":
			fields["auth.saml.metadata_xml"] = "Set the metadata address or paste the metadata, not both."
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
	sp := samlSP(c)
	rep := struct {
		OK       bool      `json:"ok"`
		Message  string    `json:"message"`
		Steps    []ssoStep `json:"steps"`
		EntityID string    `json:"entity_id"`
		ACSURL   string    `json:"acs_url"`
	}{EntityID: sp.EntityID, ACSURL: sp.ACSURL, Steps: []ssoStep{}}
	start := time.Now()
	from := "Pasted into the settings."
	if set.MetadataXML == "" {
		from = "Read from " + set.MetadataURL + "."
	}
	idp, err := s.samlIdP(ctx, c, true)
	if err != nil {
		rep.Steps = append(rep.Steps, ssoStep{Name: "Metadata", Detail: sentence(err.Error())})
		rep.Message = "Signalith could not use the identity provider's metadata."
	} else {
		rep.Steps = append(rep.Steps, ssoStep{Name: "Metadata", OK: true, Detail: from})
		rep.Steps = append(rep.Steps, ssoStep{Name: "Identity provider", OK: true, Detail: "Entity ID " + idp.EntityID + "; sign-in address " + idp.SSOURL + "."})
		now := time.Now()
		valid, soonest := 0, time.Time{}
		var expired []string
		for _, cert := range idp.Certs {
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				expired = append(expired, cert.NotAfter.UTC().Format("2006-01-02"))
				continue
			}
			valid++
			if soonest.IsZero() || cert.NotAfter.Before(soonest) {
				soonest = cert.NotAfter
			}
		}
		switch {
		case valid == 0:
			rep.Steps = append(rep.Steps, ssoStep{Name: "Signing certificates", Detail: "Every signing certificate in the metadata has expired or is not valid yet (" + strings.Join(expired, ", ") + "). Renew it at the identity provider."})
			rep.Message = "The identity provider's signing certificate cannot be used."
		default:
			detail := fmt.Sprintf("%d signing %s Signalith checks responses with; the first expires on %s.", valid, plural(valid, "certificate", "certificates"), soonest.UTC().Format("2 January 2006"))
			if soonest.Sub(now) < 30*24*time.Hour {
				detail += " That is within 30 days: make sure the provider publishes the new one in its metadata."
			}
			rep.Steps = append(rep.Steps, ssoStep{Name: "Signing certificates", OK: true, Detail: detail})
			rep.OK = true
			rep.Message = "Give it the entity ID and the ACS URL above, save, then try a sign-in in a private window."
		}
	}
	s.audit(r, "settings tested", "what", "saml", "metadata", set.MetadataURL, "ok", rep.OK, "took_ms", time.Since(start).Milliseconds())
	writeJSON(w, http.StatusOK, rep)
}
