package api

import (
	"slices"
	"strings"
	"testing"
)

// Add data > Syslog turns on plain syslog with one click: it saves
// syslog.udp and syslog.tcp through the Settings page's own route (PUT
// /api/settings, admins only), and the change waits for Restart now. The
// page reads GET /api/settings to show that, or that the environment
// sets them.
func TestAddDataTurnsOnPlainSyslog(t *testing.T) {
	t.Setenv("SIGNALITH_SYSLOG_UDP", "")
	t.Setenv("SIGNALITH_SYSLOG_TCP", "")
	ts, srv, logs := newSettingsServer(t, "syslog:\n  udp: \"\"\n  tcp: \"\"\n  tls: 127.0.0.1:16514\n", nil)
	body := `{"values":{"syslog.udp":"0.0.0.0:514","syslog.tcp":"0.0.0.0:514"}}`

	// Only admins may.
	if code, out := doAs(t, ts, "andy", "role-password", "PUT", "/api/settings", body); code != 403 || out["code"] != "forbidden" {
		t.Fatalf("analyst: %d %v", code, out)
	}
	_, view, _ := call(t, ts, "GET", "/api/settings", "", "admin", "s3cret-pass", nil)
	for _, k := range []string{"syslog.udp", "syslog.tcp"} {
		if f := field(t, view, k); f["value"] != "" || f["locked"] != false || f["pending"] != false || !strings.Contains(f["help"].(string), "unencrypted") {
			t.Errorf("%s before: %v", k, f)
		}
	}

	code, out, raw := call(t, ts, "PUT", "/api/settings", body, "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("save %d %s", code, raw)
	}
	after := []string{}
	for _, k := range out["after_restart"].([]any) {
		after = append(after, k.(string))
	}
	slices.Sort(after)
	if !slices.Equal(after, []string{"syslog.tcp", "syslog.udp"}) || out["restart"].(map[string]any)["needed"] != true {
		t.Errorf("after restart %v, restart %v", after, out["restart"])
	}
	for _, k := range []string{"syslog.udp", "syslog.tcp"} {
		if f := field(t, out, k); f["value"] != "0.0.0.0:514" || f["pending"] != true || f["source"].(map[string]any)["kind"] != "page" {
			t.Errorf("%s after: %v", k, f)
		}
	}
	// Nothing listens until the restart.
	if c := srv.conf(); c.Syslog.UDP != "" || c.Syslog.TCP != "" {
		t.Errorf("plain syslog applied before the restart: %+v", c.Syslog)
	}
	if l := logs.String(); !strings.Contains(l, `msg="settings saved"`) || !strings.Contains(l, "syslog.udp") {
		t.Errorf("audit log:\n%s", l)
	}
}

// Where the environment sets plain syslog (the Helm chart does), the
// settings show it locked, with the variable, so Add data says where to
// change it instead of offering the button.
func TestAddDataPlainSyslogLockedByEnvironment(t *testing.T) {
	t.Setenv("SIGNALITH_SYSLOG_UDP", "off")
	t.Setenv("SIGNALITH_SYSLOG_TCP", "off")
	ts, _, _ := newSettingsServer(t, "syslog:\n  tls: 127.0.0.1:16514\n", nil)
	_, view, _ := call(t, ts, "GET", "/api/settings", "", "admin", "s3cret-pass", nil)
	for _, k := range []string{"syslog.udp", "syslog.tcp"} {
		f := field(t, view, k)
		reason, _ := f["locked_reason"].(string)
		if f["locked"] != true || !strings.Contains(reason, "SIGNALITH_SYSLOG_") {
			t.Errorf("%s: %v", k, f)
		}
	}
}
