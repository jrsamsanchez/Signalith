package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/scim"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Provisioning with SCIM 2.0 (see package scim and docs/sso.md): the
// identity provider of single sign-on adds, changes, disables and removes
// single sign-on users ahead of their sign-ins, with a bearer token whose
// SHA-256 is a setting (auth.scim.token_sha256). It sees and changes only
// single sign-on users. A user's SCIM id is their Signalith username.
// Groups are not provisioned: roles come from the groups claim at each
// sign-in, so /Groups is always empty.

const (
	scimConfigRoute    = "GET /api/scim/v2/ServiceProviderConfig"
	scimTypesRoute     = "GET /api/scim/v2/ResourceTypes"
	scimSchemasRoute   = "GET /api/scim/v2/Schemas"
	scimListRoute      = "GET /api/scim/v2/Users"
	scimCreateRoute    = "POST /api/scim/v2/Users"
	scimGetRoute       = "GET /api/scim/v2/Users/{id}"
	scimPutRoute       = "PUT /api/scim/v2/Users/{id}"
	scimPatchRoute     = "PATCH /api/scim/v2/Users/{id}"
	scimDeleteRoute    = "DELETE /api/scim/v2/Users/{id}"
	scimGroupsRoute    = "GET /api/scim/v2/Groups"
	scimTokenRoute     = "POST /api/auth/scim/token"
	scimActor          = "scim"
	scimMaxResults     = 200
	scimDefaultResults = 100
)

// scimBase is where the provider is pointed.
var scimBase = strings.TrimSuffix(strings.TrimPrefix(scimListRoute, "GET "), "/Users")

// scimPublicRoutes check the provisioning token instead of a sign-in.
var scimPublicRoutes = []string{scimConfigRoute, scimTypesRoute, scimSchemasRoute, scimListRoute, scimCreateRoute,
	scimGetRoute, scimPutRoute, scimPatchRoute, scimDeleteRoute, scimGroupsRoute}

func (s *Server) routeSCIM(mux *http.ServeMux, api *router) {
	for route, h := range map[string]http.HandlerFunc{
		scimConfigRoute:  s.handleSCIMConfig,
		scimTypesRoute:   s.handleSCIMTypes,
		scimSchemasRoute: s.handleSCIMSchemas,
		scimListRoute:    s.handleSCIMList,
		scimCreateRoute:  s.handleSCIMCreate,
		scimGetRoute:     s.handleSCIMGet,
		scimPutRoute:     s.handleSCIMPut,
		scimPatchRoute:   s.handleSCIMPatch,
		scimDeleteRoute:  s.handleSCIMDelete,
		scimGroupsRoute:  s.handleSCIMGroups,
	} {
		mux.Handle(route, s.scimAuth(h))
	}
	api.admin(scimTokenRoute, s.handleSCIMToken)
}

// scimURL is the address to give the identity provider.
func scimURL(publicURL string) string { return strings.TrimRight(publicURL, "/") + scimBase }

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func scimFail(w http.ResponseWriter, status int, scimType, detail string) {
	writeSCIM(w, status, &scim.Error{Status: status, ScimType: scimType, Detail: detail})
}

// scimAuth lets a request in with the provisioning token, over HTTPS
// (or from this computer), while provisioning is on.
func (s *Server) scimAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := s.conf()
		if !c.SCIMOn() {
			scimFail(w, http.StatusForbidden, "", "provisioning (SCIM) is off in Signalith; an admin turns it on under Settings > Single sign-on")
			return
		}
		if !s.overHTTPS(r) && !s.client(r).Addr.IsLoopback() {
			scimFail(w, http.StatusForbidden, "", "provisioning (SCIM) works only over HTTPS, so the token is never sent in the clear")
			return
		}
		scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || !c.SCIMToken(strings.TrimSpace(token)) {
			if n := s.scimRefused.note(s.client(r).Addr.String(), time.Now()); n > 0 {
				s.Log.Warn("SCIM token refused", slices.Concat([]any{"audit", true, "method", r.Method, "path", r.URL.Path, "refusals", n},
					s.client(r).logAttrs())...)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="Signalith SCIM"`)
			scimFail(w, http.StatusUnauthorized, "", "the SCIM token is missing or wrong")
			return
		}
		next(w, r.WithContext(users.WithActor(r.Context(), scimActor)))
	})
}

// scimRefusals limits the log of refused SCIM tokens to one line a
// minute for each address, with how many were refused since, so a client
// cannot flood the log.
type scimRefusals struct {
	mu   sync.Mutex
	seen map[string]scimRefusal
}

type scimRefusal struct {
	logged time.Time
	count  int
}

// note counts a refusal from addr, and returns how many to log now (0 to
// log nothing).
func (f *scimRefusals) note(addr string, now time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = map[string]scimRefusal{}
	}
	e := f.seen[addr]
	e.count++
	if !e.logged.IsZero() && now.Sub(e.logged) < time.Minute {
		f.seen[addr] = e
		return 0
	}
	n := e.count
	f.seen[addr] = scimRefusal{logged: now}
	if len(f.seen) > 10000 {
		// Forget what is over a minute old, or everything, rather than
		// grow without end.
		for k, v := range f.seen {
			if now.Sub(v.logged) >= time.Minute {
				delete(f.seen, k)
			}
		}
		if len(f.seen) > 10000 {
			f.seen = map[string]scimRefusal{}
		}
	}
	return n
}

// scimAudit logs a change provisioning made.
func (s *Server) scimAudit(r *http.Request, msg string, args ...any) {
	s.Log.Info(msg, slices.Concat([]any{"audit", true, "by", scimActor}, s.client(r).logAttrs(), args)...)
}

// scimUser is a single sign-on user as SCIM has it.
func (s *Server) scimUser(u users.User) scim.User {
	created, updated := u.Created, u.Updated
	out := scim.User{Schemas: []string{scim.UserSchema}, ID: u.Username, ExternalID: u.ExternalID, UserName: u.Username,
		DisplayName: u.Name, Active: !u.Disabled,
		Meta: &scim.Meta{ResourceType: "User", Created: &created, LastModified: &updated,
			Location: scimURL(s.conf().Server.PublicURL) + "/Users/" + url.PathEscape(u.Username)}}
	if u.Name != "" {
		out.Name = &scim.Name{Formatted: u.Name}
	}
	out.SetEmail(u.Email)
	return out
}

// provisionedOf is what a SCIM User says of a Signalith user.
func provisionedOf(u scim.User) users.Provisioned {
	return users.Provisioned{Username: u.UserName, Name: u.FullName(), Email: u.PrimaryEmail(), ExternalID: u.ExternalID, Active: u.Active}
}

// scimUserError answers a store error.
func scimUserError(w http.ResponseWriter, err error) {
	var fe *users.FieldError
	var se *scim.Error
	switch {
	case errors.As(err, &se):
		writeSCIM(w, se.Status, se)
	case errors.Is(err, users.ErrNotFound):
		scimFail(w, http.StatusNotFound, "", "there is no single sign-on user with that id")
	case errors.Is(err, users.ErrExists):
		scimFail(w, http.StatusConflict, "uniqueness", "a single sign-on user with that userName exists already")
	case errors.Is(err, users.ErrNotSSO):
		scimFail(w, http.StatusConflict, "uniqueness", users.ErrNotSSO.Error())
	case errors.Is(err, users.ErrRename):
		scimFail(w, http.StatusBadRequest, "mutability", users.ErrRename.Error())
	case errors.As(err, &fe):
		scimFail(w, http.StatusBadRequest, "invalidValue", fe.Field+": "+fe.Err.Error())
	default:
		scimFail(w, http.StatusInternalServerError, "", "could not save the user: "+err.Error())
	}
}

// scimBody reads a request body, at most scim.MaxBody.
func scimBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, scim.MaxBody))
	if err != nil {
		scimFail(w, http.StatusRequestEntityTooLarge, "", "the request body is too large or could not be read")
		return nil, false
	}
	return b, true
}

// scimWritable answers 503 when the servers of a cluster cannot change
// the shared users just now.
func (s *Server) scimWritable(w http.ResponseWriter) bool {
	if s.SharedUsers != nil && s.Shared != nil {
		if err := s.Shared.Writable(); err != nil {
			scimFail(w, http.StatusServiceUnavailable, "", err.Error())
			return false
		}
	}
	return true
}

// scimTarget returns the single sign-on user the path names.
func (s *Server) scimTarget(w http.ResponseWriter, r *http.Request) (users.User, bool) {
	u, ok := s.userStore().Get(r.PathValue("id"))
	if !ok || u.Source != users.SourceSSO {
		scimFail(w, http.StatusNotFound, "", "there is no single sign-on user with that id")
		return users.User{}, false
	}
	return u, true
}

// ---- discovery ----

func (s *Server) handleSCIMConfig(w http.ResponseWriter, r *http.Request) {
	no := map[string]bool{"supported": false}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://github.com/jrsamsanchez/signalith/blob/main/docs/sso.md#provisioning-with-scim",
		"patch":            map[string]bool{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": scimMaxResults},
		"changePassword":   no,
		"sort":             no,
		"etag":             no,
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token", "primary": true,
			"description": "The SCIM token from Settings > Single sign-on in Signalith."}},
		"meta": map[string]string{"resourceType": "ServiceProviderConfig", "location": scimURL(s.conf().Server.PublicURL) + "/ServiceProviderConfig"},
	})
}

func (s *Server) handleSCIMTypes(w http.ResponseWriter, r *http.Request) {
	user := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User",
		"endpoint": "/Users", "schema": scim.UserSchema, "meta": map[string]string{"resourceType": "ResourceType",
			"location": scimURL(s.conf().Server.PublicURL) + "/ResourceTypes/User"}}
	writeSCIM(w, http.StatusOK, map[string]any{"schemas": []string{scim.ListSchema}, "totalResults": 1, "startIndex": 1,
		"itemsPerPage": 1, "Resources": []any{user}})
}

func (s *Server) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	attr := func(name, typ string, required bool, uniqueness string, sub ...map[string]any) map[string]any {
		a := map[string]any{"name": name, "type": typ, "multiValued": false, "required": required, "caseExact": false,
			"mutability": "readWrite", "returned": "default", "uniqueness": uniqueness}
		if len(sub) > 0 {
			a["subAttributes"] = sub
		}
		return a
	}
	emails := attr("emails", "complex", false, "none", attr("value", "string", false, "none"), attr("type", "string", false, "none"),
		attr("primary", "boolean", false, "none"))
	emails["multiValued"] = true
	user := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": scim.UserSchema, "name": "User",
		"description": "A Signalith user who signs in with single sign-on",
		"attributes": []any{attr("userName", "string", true, "server"), attr("displayName", "string", false, "none"),
			attr("name", "complex", false, "none", attr("formatted", "string", false, "none"), attr("givenName", "string", false, "none"),
				attr("familyName", "string", false, "none")),
			emails, attr("active", "boolean", false, "none")},
		"meta": map[string]string{"resourceType": "Schema", "location": scimURL(s.conf().Server.PublicURL) + "/Schemas/" + scim.UserSchema}}
	writeSCIM(w, http.StatusOK, map[string]any{"schemas": []string{scim.ListSchema}, "totalResults": 1, "startIndex": 1,
		"itemsPerPage": 1, "Resources": []any{user}})
}

// handleSCIMGroups lists no groups: Signalith takes roles from the groups
// claim at sign-in instead.
func (s *Server) handleSCIMGroups(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{"schemas": []string{scim.ListSchema}, "totalResults": 0, "startIndex": 1,
		"itemsPerPage": 0, "Resources": []any{}})
}

// ---- users ----

// handleSCIMList lists the single sign-on users, filtered (userName eq
// "...", as providers look a user up before they add them) and paged
// with startIndex (from 1) and count.
func (s *Server) handleSCIMList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f, err := scim.ParseFilter(q.Get("filter"))
	if err != nil {
		scimFail(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	start, count := 1, scimDefaultResults
	if v := q.Get("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 1 {
			start = n
		}
	}
	if v := q.Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			count = min(n, scimMaxResults)
		}
	}
	var all []scim.User
	for _, u := range s.userStore().SSOUsers() {
		su := s.scimUser(u)
		if f.Match(&su) {
			all = append(all, su)
		}
	}
	page := []scim.User{}
	if start-1 < len(all) {
		page = all[start-1 : min(len(all), start-1+count)]
	}
	writeSCIM(w, http.StatusOK, map[string]any{"schemas": []string{scim.ListSchema}, "totalResults": len(all), "startIndex": start,
		"itemsPerPage": len(page), "Resources": page})
}

func (s *Server) handleSCIMGet(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.scimTarget(w, r); ok {
		writeSCIM(w, http.StatusOK, s.scimUser(u))
	}
}

func (s *Server) handleSCIMCreate(w http.ResponseWriter, r *http.Request) {
	body, ok := scimBody(w, r)
	if !ok || !s.scimWritable(w) {
		return
	}
	in, err := scim.DecodeUser(body)
	if err != nil {
		scimUserError(w, err)
		return
	}
	if strings.TrimSpace(in.UserName) == "" {
		scimFail(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	u, err := s.userStore().Provision(r.Context(), provisionedOf(in))
	if err != nil {
		scimUserError(w, err)
		return
	}
	s.scimAudit(r, "user provisioned", "user", u.Username, "external_id", u.ExternalID, "active", !u.Disabled)
	w.Header().Set("Location", s.scimUser(u).Meta.Location)
	writeSCIM(w, http.StatusCreated, s.scimUser(u))
}

// handleSCIMPut replaces what provisioning knows of a user with the body.
func (s *Server) handleSCIMPut(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.scimTarget(w, r)
	if !ok {
		return
	}
	body, ok := scimBody(w, r)
	if !ok || !s.scimWritable(w) {
		return
	}
	in, err := scim.DecodeUser(body)
	if err != nil {
		scimUserError(w, err)
		return
	}
	if strings.TrimSpace(in.UserName) == "" {
		in.UserName = cur.Username
	}
	s.scimChange(w, r, cur, func(p *users.Provisioned) error {
		*p = provisionedOf(in)
		return nil
	})
}

// handleSCIMPatch applies the operations to the user as they are now.
func (s *Server) handleSCIMPatch(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.scimTarget(w, r)
	if !ok {
		return
	}
	body, ok := scimBody(w, r)
	if !ok || !s.scimWritable(w) {
		return
	}
	ops, err := scim.DecodePatch(body)
	if err != nil {
		scimUserError(w, err)
		return
	}
	s.scimChange(w, r, cur, func(p *users.Provisioned) error {
		u := scim.User{UserName: p.Username, DisplayName: p.Name, ExternalID: p.ExternalID, Active: p.Active}
		u.SetEmail(p.Email)
		if err := scim.Apply(&u, ops); err != nil {
			return err
		}
		*p = provisionedOf(u)
		return nil
	})
}

// scimChange changes the user cur with fn and answers with the result.
// Made inactive, their sessions end now.
func (s *Server) scimChange(w http.ResponseWriter, r *http.Request, cur users.User, fn func(*users.Provisioned) error) {
	u, err := s.userStore().ChangeProvisioned(r.Context(), cur.Username, "", fn)
	if err != nil {
		scimUserError(w, err)
		return
	}
	var changed []string
	if u.Name != cur.Name {
		changed = append(changed, "name")
	}
	if u.Email != cur.Email {
		changed = append(changed, "email")
	}
	if u.ExternalID != cur.ExternalID {
		changed = append(changed, "external_id")
	}
	if len(changed) > 0 {
		s.scimAudit(r, "user changed", "user", u.Username, "fields", strings.Join(changed, ","))
	}
	if u.Disabled != cur.Disabled {
		if u.Disabled {
			ended := s.sessions().EndUser(r.Context(), u.Username, "")
			s.scimAudit(r, "user disabled", "user", u.Username, "sessions_ended", ended)
		} else {
			s.scimAudit(r, "user enabled", "user", u.Username)
		}
	}
	writeSCIM(w, http.StatusOK, s.scimUser(u))
}

func (s *Server) handleSCIMDelete(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.scimTarget(w, r)
	if !ok || !s.scimWritable(w) {
		return
	}
	u, err := s.userStore().DeleteProvisioned(r.Context(), cur.Username, "")
	if err != nil {
		scimUserError(w, err)
		return
	}
	ended := s.sessions().EndUser(r.Context(), u.Username, "")
	s.scimAudit(r, "user deleted", "user", u.Username, "source", u.Source, "sessions_ended", ended)
	s.releaseNotebooks(r.Context(), u.Username, scimActor)
	w.WriteHeader(http.StatusNoContent)
}

// ---- the Single sign-on tab ----

// handleSCIMToken makes a new provisioning token: the token, shown once,
// and its SHA-256, which the page saves as auth.scim.token_sha256. Nothing
// changes until it is saved, so the token in use keeps working until then.
func (s *Server) handleSCIMToken(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	token := "sgl_scim_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	s.audit(r, "SCIM token created", "saved", false)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "sha256": hex.EncodeToString(sum[:]), "created": time.Now().UTC()})
}
