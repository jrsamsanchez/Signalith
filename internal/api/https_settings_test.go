package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"gopkg.in/yaml.v3"
)

// section finds a section in GET /api/settings.
func section(t *testing.T, view map[string]any, id string) map[string]any {
	t.Helper()
	for _, sec := range view["sections"].([]any) {
		if s := sec.(map[string]any); s["id"] == id {
			return s
		}
	}
	t.Fatalf("no section %s", id)
	return nil
}

// The HTTPS settings have their own section, with the rules Validate has
// for them and what the running certificate covers.
func TestHTTPSSection(t *testing.T) {
	// A file from before HTTPS was the default, with an http:// address.
	ts, _, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:18748\n  public_url: http://siem.lan:18748\n", func(s *Server) { s.TLS = newCertManager(t) })
	_, view := do(t, ts, "GET", "/api/settings", "", true)
	var keys []string
	apply := map[string]string{}
	for _, f := range section(t, view, "https")["fields"].([]any) {
		fm := f.(map[string]any)
		keys = append(keys, fm["key"].(string))
		apply[fm["key"].(string)] = fm["apply"].(string)
	}
	if want := []string{"server.tls.mode", "server.tls.names", "server.tls.ca_scope", "server.tls_cert", "server.tls_key", "server.tls.plaintext_ingest", "server.trusted_proxies", "server.client_header"}; !slices.Equal(keys, want) {
		t.Errorf("fields %v", keys)
	}
	for k, want := range map[string]string{"server.tls.mode": "restart", "server.tls.names": "restart", "server.tls.ca_scope": "live", "server.tls_cert": "restart",
		"server.tls_key": "restart", "server.tls.plaintext_ingest": "live", "server.trusted_proxies": "live", "server.client_header": "live"} {
		if apply[k] != want {
			t.Errorf("%s applies %s", k, apply[k])
		}
	}
	if f := field(t, view, "server.tls.mode"); f["value"] != "auto" || len(f["choices"].([]any)) != 3 {
		t.Errorf("mode %v", f)
	}
	if f := field(t, view, "server.tls.plaintext_ingest"); f["value"] != "allow" {
		t.Errorf("plaintext %v", f)
	}
	// The http:// address is used as https://, and the page offers that.
	if f := field(t, view, "server.public_url"); f["value"] != "http://siem.lan:18748" ||
		!strings.Contains(f["warning"].(string), "Signalith serves HTTPS on this port") || f["suggest"] != "https://siem.lan:18748" {
		t.Errorf("public url %v", f)
	}
	if tlsView := view["tls"].(map[string]any); tlsView["mode"] != "auto" || tlsView["ca_sha256"] == nil || tlsView["own_ca"] != true {
		t.Errorf("tls %v", tlsView)
	}

	// Cross-field problems by field, before anything is saved.
	code, out := do(t, ts, "PUT", "/api/settings", `{"check_only":true,"values":{"server.tls.mode":"files"}}`, true)
	if fields, _ := out["fields"].(map[string]any); code != 400 || !strings.Contains(fields["server.tls.mode"].(string), "Enter your certificate and key files") {
		t.Errorf("files without files %d %v", code, out)
	}
}

// Turning HTTPS off, or trading Signalith's own certificate for your own
// files, asks first: browsers and agents that trusted one do not trust
// the other.
func TestHTTPSConfirmations(t *testing.T) {
	cert, key := selfSigned(t)
	ts, _, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:18749\n  tls:\n    mode: auto\n", nil)
	ask := func(values map[string]string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"check_only": true, "values": values})
		code, out := do(t, ts, "PUT", "/api/settings", string(body), true)
		if code != 200 {
			t.Fatalf("%v: %d %v", values, code, out)
		}
		for _, c := range out["confirm"].([]any) {
			if cm := c.(map[string]any); cm["key"] == "server.tls.mode" {
				return cm
			}
		}
		return nil
	}
	if c := ask(map[string]string{"server.tls.mode": "off", "server.trusted_proxies": "127.0.0.1"}); c == nil || c["title"] != "Turn HTTPS off?" ||
		!strings.Contains(c["text"].(string), "plain http:// only") {
		t.Errorf("off: %v", c)
	}
	if c := ask(map[string]string{"server.tls.mode": "files", "server.tls_cert": cert, "server.tls_key": key}); c == nil ||
		c["title"] != "Use your own certificate files?" || c["old"] != "auto" || c["new"] != "files" {
		t.Errorf("files: %v", c)
	}
	if c := ask(map[string]string{"server.tls.names": "siem.lan"}); c != nil {
		t.Errorf("names asked %v", c)
	}
}

// Agents on plain HTTP and the trusted proxies apply at once.
func TestHTTPSLiveSettings(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:18748\n", nil)
	plain := httptest.NewServer(srv.PlainHandler(srv.Handler()))
	defer plain.Close()
	batch := `[{"date":1760000000,"log":"Accepted password for bob from 192.0.2.4 port 22 ssh2"}]`
	bearer := map[string]string{"Authorization": "Bearer tok-0123456789abcdef"}
	ingestCode := func() int {
		t.Helper()
		resp, _ := plainSend(t, "POST", plain.URL+"/api/ingest", batch, bearer)
		return resp.StatusCode
	}
	if code := ingestCode(); code != http.StatusOK {
		t.Fatalf("an old config takes plain-text agents: %d", code)
	}
	code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"server.tls.plaintext_ingest":"deny"}}`, true)
	if code != 200 || !slices.Contains(out["applied"].([]any), any("server.tls.plaintext_ingest")) {
		t.Fatalf("deny %d %v", code, out)
	}
	if code := ingestCode(); code != http.StatusServiceUnavailable {
		t.Errorf("after deny: %d", code)
	}
	do(t, ts, "PUT", "/api/settings", `{"values":{"server.tls.plaintext_ingest":"allow"}}`, true)
	if code := ingestCode(); code != http.StatusOK {
		t.Errorf("after allow: %d", code)
	}

	// A proxy that says the browser used HTTPS is believed from the
	// addresses listed, and only those once some are.
	viaProxy := func() int {
		t.Helper()
		hdr := map[string]string{"X-Forwarded-Proto": "https", "Authorization": "Basic YWRtaW46czNjcmV0LXBhc3M="}
		resp, _ := plainSend(t, "GET", plain.URL+"/api/health", "", hdr)
		return resp.StatusCode
	}
	do(t, ts, "PUT", "/api/settings", `{"values":{"server.trusted_proxies":["192.0.2.1"]}}`, true)
	if code := viaProxy(); code != http.StatusForbidden {
		t.Errorf("proxy not listed: %d", code)
	}
	do(t, ts, "PUT", "/api/settings", `{"values":{"server.trusted_proxies":["127.0.0.1"]}}`, true)
	if code := viaProxy(); code != http.StatusOK {
		t.Errorf("proxy listed: %d", code)
	}
}

// A public address saved on the page goes into Signalith's own
// certificate at once, as one entered on Add data does; one its
// certificate authority may not sign is shown as a warning.
func TestPublicURLJoinsTheCertificate(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:18748\n  tls:\n    mode: auto\n", func(s *Server) { s.TLS = newCertManager(t) })
	code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"server.public_url":"https://siem2.lan:18748"}}`, true)
	if code != 200 || !slices.Contains(out["applied"].([]any), any("server.public_url")) {
		t.Fatalf("save %d %v", code, out)
	}
	if !srv.TLS.Covers("siem2.lan") {
		t.Errorf("certificate covers %v", srv.TLS.Names())
	}
	if f := field(t, out, "server.public_url"); f["warning"] != nil {
		t.Errorf("warning %v", f["warning"])
	}
	_, out = do(t, ts, "PUT", "/api/settings", `{"values":{"server.public_url":"https://www.example.com:18748","server.tls.names":["alias.lan","8.8.8.8"]}}`, true)
	if f := field(t, out, "server.public_url"); !strings.Contains(f["warning"].(string), "can't include www.example.com") {
		t.Errorf("public url %v", f)
	}
	if f := field(t, out, "server.tls.names"); !strings.Contains(f["warning"].(string), "can't include 8.8.8.8") {
		t.Errorf("names %v", f)
	}
	if srv.TLS.Covers("www.example.com") {
		t.Error("the certificate covers a name its authority may not sign")
	}
}

// The export writes server.tls as its own part, as signalith.yaml has it.
func TestExportHTTPSSettings(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:18748\n  tls:\n    mode: auto\n    names: [siem.lan]\n    plaintext_ingest: deny\n  trusted_proxies: [10.0.0.5]\n", nil)
	_, out := do(t, ts, "GET", "/api/settings/export", "", true)
	text := out["yaml"].(string)
	if !strings.Contains(text, "  tls:\n    mode: auto  # this server only\n    names: [siem.lan]  # this server's own names\n") || !strings.Contains(text, "    plaintext_ingest: deny\n") ||
		!strings.Contains(text, "  trusted_proxies: [10.0.0.5]\n") {
		t.Errorf("export:\n%s", text)
	}
	var c config.Config
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil || c.Server.TLS == nil || c.Server.TLS.Mode != "auto" || c.Server.TLS.PlaintextIngest != "deny" {
		t.Errorf("does not load: %v %+v", err, c.Server.TLS)
	}
}
