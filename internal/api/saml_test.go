package api

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/beevik/etree"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/saml"
	"github.com/jrsamsanchez/signalith/internal/saml/samltest"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// samlLoginPage is the part of login.html the server changes for SAML.
const samlLoginPage = `<div class="auth__sso" id="sso" hidden>` +
	`<a href="api/auth/oidc/start" hidden><span id="sso-label">Sign in with single sign-on</span></a>` +
	`<a href="api/auth/saml/start" hidden><span id="saml-label">Sign in with SAML single sign-on</span></a></div>`

// newSAMLServer starts a server whose SAML single sign-on uses the test
// provider it returns, which publishes its metadata at a URL.
func newSAMLServer(t *testing.T, change func(c *config.SAML)) (*httptest.Server, *Server, *samltest.IdP) {
	t.Helper()
	idp := samltest.New(t, "https://idp.example.com/adfs/services/trust", "https://idp.example.com/adfs/ls/")
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(idp.Metadata()) }))
	t.Cleanup(md.Close)
	yes := true
	ts, s := newUsersServer(t, func(s *Server) {
		s.UI = fstest.MapFS{"index.html": {Data: []byte("<h1>app</h1>")}, "login.html": {Data: []byte(samlLoginPage)}}
		s.Config.Auth.SAML = config.SAML{Enabled: true, Provider: saml.Okta, MetadataURL: md.URL + "/metadata",
			AdminGroups: []string{"soc-admins"}, AnalystGroups: []string{"soc"}, CreateUsers: &yes}
		if change != nil {
			change(&s.Config.Auth.SAML)
		}
	})
	s.Config.Server.PublicURL = ts.URL
	return ts, s, idp
}

// samlStart presses the SAML button: it returns the request's ID and
// RelayState, and the sign-in cookie.
func samlStart(t *testing.T, ts *httptest.Server, next string) (string, string, *http.Cookie) {
	t.Helper()
	resp := send(t, "GET", ts.URL+"/api/auth/saml/start?next="+url.QueryEscape(next), "", nil)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || loc == nil || loc.Host != "idp.example.com" {
		t.Fatalf("start = %d to %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	raw, err := base64.StdEncoding.DecodeString(loc.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	xml, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xml); err != nil {
		t.Fatal(err)
	}
	var ck *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == samlCookie {
			ck = c
		}
	}
	if ck == nil || ck.SameSite != http.SameSiteNoneMode || !ck.Secure || !ck.HttpOnly {
		t.Fatalf("sign-in cookie = %+v", ck)
	}
	return doc.Root().SelectAttrValue("ID", ""), loc.Query().Get("RelayState"), ck
}

// samlPost posts a response to the assertion consumer service as the
// browser would, and returns the answer and the session cookie it set.
func samlPost(t *testing.T, ts *httptest.Server, samlResponse, relay string, ck *http.Cookie) (*http.Response, string, *http.Cookie) {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relay}}
	hdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://idp.example.com", "Sec-Fetch-Site": "cross-site"}
	var cookies []*http.Cookie
	if ck != nil {
		cookies = append(cookies, ck)
	}
	resp, raw := sendRead(t, "POST", ts.URL+"/api/auth/saml/acs", form.Encode(), hdr, cookies...)
	var sess *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			sess = c
		}
	}
	return resp, raw, sess
}

// sendRead is send, keeping the body.
func sendRead(t *testing.T, method, u, body string, hdr map[string]string, cookies ...*http.Cookie) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

// samlError is the sso_error code a refused sign-in was sent back with.
func samlError(resp *http.Response) string {
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc == nil || loc.Path != "/login" {
		return ""
	}
	return loc.Query().Get("sso_error")
}

func TestSAMLSignIn(t *testing.T) {
	ts, s, idp := newSAMLServer(t, nil)

	// The sign-in page shows the SAML button, with its label, and not the
	// OpenID Connect one.
	page := pageText(t, ts.URL+"/login")
	if strings.Contains(page, `id="sso" hidden`) || !strings.Contains(page, `href="api/auth/saml/start">`) ||
		!strings.Contains(page, ">Sign in with Okta<") || !strings.Contains(page, `href="api/auth/oidc/start" hidden`) {
		t.Fatalf("login page = %s", page)
	}

	id, relay, ck := samlStart(t, ts, "/#cases?id=7")
	sp := samlSP(s.conf())
	r := idp.Honest(sp.EntityID, sp.ACSURL, id, time.Now())
	r.NameID = "Alice@corp.example.com"
	r.Attributes = map[string][]string{"email": {"alice@corp.example.com"}, "groups": {"soc", "everyone"}, "firstName": {"Alice"}, "lastName": {"Example"}}
	resp64 := idp.Respond(t, r)
	resp, body, sess := samlPost(t, ts, resp64, relay, ck)
	if resp.StatusCode != 200 || sess == nil || !strings.Contains(body, `content="0;url=/#cases?id=7"`) {
		t.Fatalf("ACS = %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	code, who, _ := callWith(t, ts.URL, "GET", "/api/me", "", sess)
	if code != 200 || who["username"] != "alice@corp.example.com" || who["role"] != "analyst" {
		t.Fatalf("me = %d %v", code, who)
	}
	u, ok := s.userStore().Get("alice@corp.example.com")
	if !ok || u.Source != users.SourceSSO || u.Email != "alice@corp.example.com" || u.Name != "Alice Example" ||
		u.Subject != users.SSOSubject("saml:"+idp.EntityID, "Alice@corp.example.com") {
		t.Fatalf("user = %+v", u)
	}

	// The same response again, cookie and all, is a replay.
	if resp, _, sess := samlPost(t, ts, resp64, relay, ck); sess != nil || samlError(resp) != "replay" {
		t.Errorf("replay = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Turning SAML off ends their sessions, and hides the button.
	off := *s.Config
	off.Auth.SAML.Enabled = false
	s.live.Store(&off)
	if code, _, _ := callWith(t, ts.URL, "GET", "/api/me", "", sess); code != 401 {
		t.Errorf("me with SAML off = %d", code)
	}
	if page := pageText(t, ts.URL+"/login"); !strings.Contains(page, `id="sso" hidden`) {
		t.Errorf("login page shows the buttons while off")
	}
	if resp := send(t, "GET", ts.URL+"/api/auth/saml/start", "", nil); samlError(resp) != "off" {
		t.Errorf("start with SAML off = %s", resp.Header.Get("Location"))
	}
	s.live.Store(nil)

	// Another provider's users are refused once its entity ID is known.
	s.samlEntity.Store("https://other.example.com")
	if code, _, _ := callWith(t, ts.URL, "GET", "/api/me", "", sess); code != 401 {
		t.Errorf("me after moving to another provider = %d", code)
	}
}

func TestSAMLRefusals(t *testing.T) {
	ts, s, idp := newSAMLServer(t, nil)
	sp := samlSP(s.conf())
	cases := []struct {
		name   string
		change func(r *samltest.Response)
		post   func(id, relay string, ck *http.Cookie, resp string) (string, string, *http.Cookie)
		want   string
	}{
		{name: "no cookie (IdP-initiated)", post: func(id, relay string, ck *http.Cookie, resp string) (string, string, *http.Cookie) {
			return resp, relay, nil
		}, want: "expired"},
		{name: "wrong RelayState", post: func(id, relay string, ck *http.Cookie, resp string) (string, string, *http.Cookie) {
			return resp, "other", ck
		}, want: "expired"},
		{name: "answers another request", change: func(r *samltest.Response) { r.InResponseTo, r.SubjectInResponseTo = "_x", "_x" }, want: "failed"},
		{name: "unsigned", change: func(r *samltest.Response) { r.SignAssertion = false }, want: "failed"},
		{name: "wrong audience", change: func(r *samltest.Response) { r.Audience = "https://other.example.com" }, want: "failed"},
		{name: "denied", change: func(r *samltest.Response) { r.Status = "urn:oasis:names:tc:SAML:2.0:status:Requester" }, want: "denied"},
		{name: "no mapped group", change: func(r *samltest.Response) { r.Attributes["groups"] = []string{"everyone"} }, want: "role"},
		{name: "transient NameID", change: func(r *samltest.Response) { r.NameIDFormat = saml.NameIDTransient }, want: "username"},
		{name: "bad username", change: func(r *samltest.Response) { r.NameID = "a b/c" }, want: "username"},
	}
	for _, c := range cases {
		id, relay, ck := samlStart(t, ts, "")
		r := idp.Honest(sp.EntityID, sp.ACSURL, id, time.Now())
		if c.change != nil {
			c.change(&r)
		}
		resp64 := idp.Respond(t, r)
		if c.post != nil {
			resp64, relay, ck = c.post(id, relay, ck, resp64)
		}
		resp, _, sess := samlPost(t, ts, resp64, relay, ck)
		if sess != nil || samlError(resp) != c.want {
			t.Errorf("%s: got %d %s, want %s", c.name, resp.StatusCode, resp.Header.Get("Location"), c.want)
		}
	}
	if _, ok := s.userStore().Get("alice@example.com"); ok {
		t.Error("a refused sign-in added the user")
	}
}

// Entra ID's object ID is the subject, so a renamed user stays the same
// person; AD FS's username comes from the upn claim.
func TestSAMLProviders(t *testing.T) {
	ts, s, idp := newSAMLServer(t, func(c *config.SAML) {
		c.Provider = saml.Entra
		c.AdminGroups = []string{"6f1c4a3e-0000-0000-0000-000000000001"}
	})
	sp := samlSP(s.conf())
	id, relay, ck := samlStart(t, ts, "")
	r := idp.Honest(sp.EntityID, sp.ACSURL, id, time.Now())
	r.Attributes = map[string][]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         {"bob@corp.example.com"},
		"http://schemas.microsoft.com/identity/claims/objectidentifier":      {"0b1d0000-0000-0000-0000-00000000000b"},
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups":     {"6f1c4a3e-0000-0000-0000-000000000001"},
		"http://schemas.microsoft.com/identity/claims/displayname":           {"Bob Example"},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"Bob@Corp.example.com"},
	}
	if resp, _, sess := samlPost(t, ts, idp.Respond(t, r), relay, ck); sess == nil {
		t.Fatalf("Entra sign-in = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	u, _ := s.userStore().Get("bob@corp.example.com")
	if u.Role != users.Admin || u.Name != "Bob Example" || u.Email != "bob@corp.example.com" ||
		u.Subject != users.SSOSubject("saml:"+idp.EntityID, "0b1d0000-0000-0000-0000-00000000000b") {
		t.Fatalf("Entra user = %+v", u)
	}

	// Too many groups: Entra sends a link instead, and the refusal says so.
	ts2, s2, idp2 := newSAMLServer(t, func(c *config.SAML) { c.Provider = saml.ADFS })
	sp2 := samlSP(s2.conf())
	id, relay, ck = samlStart(t, ts2, "")
	r = idp2.Honest(sp2.EntityID, sp2.ACSURL, id, time.Now())
	r.Attributes = map[string][]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": {"carol@corp.example.com"},
		"http://schemas.xmlsoap.org/claims/Group":                   {"soc-admins"},
	}
	if resp, _, sess := samlPost(t, ts2, idp2.Respond(t, r), relay, ck); sess == nil {
		t.Fatalf("AD FS sign-in = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if u, ok := s2.userStore().Get("carol@corp.example.com"); !ok || u.Role != users.Admin {
		t.Fatalf("AD FS user = %+v", u)
	}
}

// Over plain HTTP from anywhere but this computer, SAML is refused: its
// cookie must be Secure to survive the provider's cross-site post.
func TestSAMLNeedsHTTPS(t *testing.T) {
	ts, s, _ := newSAMLServer(t, nil)
	s.Config.Server.PublicURL = "http://siem.example.com"
	req, _ := http.NewRequest("GET", ts.URL+"/api/auth/saml/start", nil)
	req.Host = "siem.example.com"
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if samlError(resp) != "https" {
		t.Errorf("start over http = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSAMLMetadataAndTab(t *testing.T) {
	ts, s, idp := newSAMLServer(t, nil)
	resp, raw := sendRead(t, "GET", ts.URL+"/api/auth/saml/metadata", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(raw, `entityID="`+ts.URL+`/api/auth/saml/metadata"`) ||
		!strings.Contains(raw, `Location="`+ts.URL+`/api/auth/saml/acs"`) {
		t.Fatalf("SP metadata = %d %s", resp.StatusCode, raw)
	}

	admin := func(method, path, body string) (int, map[string]any, string) {
		return call(t, ts, method, path, body, "admin", adminPass, nil)
	}
	code, body, raw2 := admin("GET", "/api/auth/oidc", "")
	if code != 200 || body["saml_on"] != true || body["saml_acs_url"] != ts.URL+"/api/auth/saml/acs" || body["saml_entity_id"] != ts.URL+"/api/auth/saml/metadata" {
		t.Fatalf("GET = %d %s", code, raw2)
	}
	code, body, raw2 = admin("POST", "/api/auth/saml/test", `{"values":{}}`)
	if code != 200 || body["ok"] != true || !strings.Contains(raw2, idp.EntityID) {
		t.Fatalf("test = %d %s", code, raw2)
	}
	// Pasted metadata works too, and bad metadata says why.
	code, body, raw2 = admin("POST", "/api/auth/saml/test", `{"values":{"auth.saml.metadata_url":"","auth.saml.metadata_xml":`+mustJSON(string(idp.Metadata()))+`}}`)
	if code != 200 || body["ok"] != true {
		t.Errorf("test with pasted metadata = %d %s", code, raw2)
	}
	if code, body, _ := admin("POST", "/api/auth/saml/test", `{"values":{"auth.saml.metadata_url":"","auth.saml.metadata_xml":"<x/>"}}`); code != 400 || body["fields"] == nil {
		t.Errorf("test with bad metadata = %d %v", code, body)
	}
	if code, body, _ := admin("POST", "/api/auth/saml/test", `{"values":{"auth.saml.metadata_url":"http://idp.example.com/md"}}`); code != 400 || body["fields"] == nil {
		t.Errorf("test with http metadata = %d %v", code, body)
	}

	if _, err := s.userStore().Create(t.Context(), users.NewUser{Username: "ana", Role: users.Analyst, Password: "a-long-password-1"}); err != nil {
		t.Fatal(err)
	}
	if code, _ := doAs(t, ts, "ana", "a-long-password-1", "POST", "/api/auth/saml/test", "{}"); code != 403 {
		t.Errorf("analyst test = %d", code)
	}
}
