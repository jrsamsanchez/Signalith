package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/security"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// RunSecurityChecks checks after its delay and keeps the report, until
// its context ends.
func TestRunSecurityChecks(t *testing.T) {
	got := make(chan *security.Report, 4)
	_, srv, _ := newSecurityServer(t, func(s *Server) {
		s.Security = NewSecurityChecker(s.Log)
		s.Security.OnReport = func(r *security.Report) { got <- r }
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.RunSecurityChecks(ctx, time.Millisecond)
		close(done)
	}()
	select {
	case r := <-got:
		if r == nil || srv.security().Report() == nil {
			t.Errorf("report %v", r)
		}
	case <-time.After(security.RunLimit + 30*time.Second):
		t.Fatal("no check ran")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(security.RunLimit + 30*time.Second):
		t.Fatal("RunSecurityChecks did not return when its context ended")
	}
	// A context ended before the first check returns at once.
	ended, stop := context.WithCancel(context.Background())
	stop()
	srv.RunSecurityChecks(ended, time.Hour)
}

func TestSecuritySummaryOf(t *testing.T) {
	at := time.Now().Add(-time.Minute)
	r := &security.Report{CheckedAt: at, Summary: security.Summary{Risk: 2, Attention: 3, Unknown: 1}}
	s := SecuritySummaryOf(r)
	if s.CheckedAt == nil || !s.CheckedAt.Equal(at) || s.Risk != 2 || s.Attention != 3 || s.Unknown != 1 || s.CAScope != "" {
		t.Errorf("without a CA: %+v", s)
	}
	r.CA = &security.CAReport{Current: &tlsauto.CAInfo{Scope: "strict"}}
	if s := SecuritySummaryOf(r); s.CAScope != "strict" {
		t.Errorf("with a CA: %+v", s)
	}
}

// archiving is true when the default policy or any category's archives.
func TestSecurityArchiving(t *testing.T) {
	s := &Server{}
	if s.archiving() {
		t.Error("no retention")
	}
	s.Retention = &retention.Manager{Config: retention.Config{Default: &retention.Policy{KeepDays: 30, Archive: true}}}
	if !s.archiving() {
		t.Error("the default archives")
	}
	s.Retention = &retention.Manager{Config: retention.Config{Policies: map[string]retention.Policy{"endpoint": {KeepDays: 30, Archive: true}}}}
	if !s.archiving() {
		t.Error("a category archives")
	}
	s.Retention = &retention.Manager{Config: retention.Config{Default: &retention.Policy{KeepDays: 30}}}
	if s.archiving() {
		t.Error("nothing archives")
	}
	bad := filepath.Join(t.TempDir(), "retention.yaml")
	if err := os.WriteFile(bad, []byte("default: [not, a, policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Retention = &retention.Manager{Config: retention.Config{Default: &retention.Policy{Archive: true}}, Store: retention.NewStore(bad)}
	if s.archiving() {
		t.Error("a settings file that cannot be read")
	}
}

// The other servers' checks come from their heartbeats, sorted by name;
// one that has not checked says so.
func TestSecurityOtherServers(t *testing.T) {
	at := time.Now().Add(-time.Hour)
	crl := &cluster.CRLStatus{Problem: "the revocation list expired"}
	s := &Server{Config: config.Default(), Cluster: statusCluster{st: cluster.Status{Servers: []cluster.ServerStatus{
		{NodeID: "n_b", Name: "siem-b", Self: true, Detail: &cluster.Heartbeat{OSIdentity: &cluster.OSIdentityStatus{CRL: crl}}},
		{NodeID: "n_z", Name: "siem-z", Detail: &cluster.Heartbeat{NodeURL: "https://10.0.0.9:8443",
			Security: &cluster.SecuritySummary{Risk: 1, Attention: 2, CheckedAt: &at, CAScope: "standard"}}},
		{NodeID: "n_a", Name: "siem-a"},
	}}}}
	others := s.otherServers()
	if len(others) != 2 || others[0].Name != "siem-a" || !others[0].NotChecked {
		t.Fatalf("others %+v", others)
	}
	z := others[1]
	if z.NotChecked || z.Risk != 1 || z.Attention != 2 || z.URL != "https://10.0.0.9:8443" || z.CAScope != "standard" || z.CheckedAt == nil {
		t.Errorf("siem-z %+v", z)
	}
	if n := s.serverName(); n != "siem-b" {
		t.Errorf("server name %q", n)
	}
	s.Pipeline = &ingest.Pipeline{}
	rt := s.runtimeFacts(time.Now(), false)
	if rt.ClusterServer != "siem-b" || rt.CRLProblem != "the revocation list expired" {
		t.Errorf("runtime facts %+v", rt)
	}

	// Alone, the server is named by the cluster.node_name setting, else by
	// the computer.
	s.Cluster = nil
	if s.otherServers() != nil {
		t.Error("others without a cluster")
	}
	c := config.Default()
	c.Cluster.NodeName = "siem-solo"
	s.Config = c
	if n := s.serverName(); n != "siem-solo" {
		t.Errorf("node name %q", n)
	}
	s.Config = config.Default()
	if host, _ := os.Hostname(); s.serverName() != host {
		t.Errorf("host name %q, want %q", s.serverName(), host)
	}
}

func TestNotAutoError(t *testing.T) {
	c := config.Default()
	c.Server.TLS = &config.ServerTLS{Mode: config.TLSOff}
	if err := notAutoError(c); !strings.Contains(err.Error(), "doesn't serve HTTPS itself") {
		t.Errorf("off: %v", err)
	}
	c.Syslog.TLS = "0.0.0.0:6514"
	if err := notAutoError(c); !strings.Contains(err.Error(), "uses your own certificate files") {
		t.Errorf("syslog over TLS: %v", err)
	}
	if fingerprintOf(nil) != "" || fingerprintOf(&tlsauto.CAInfo{Fingerprint: "ab:cd"}) != "ab:cd" {
		t.Error("fingerprintOf")
	}
}

// heldSettings is a store whose settings are not shared yet, but whose
// own settings moved into the shared settings already: a save goes there.
type heldSettings struct{ *nodeSettings }

func (h heldSettings) Shared() bool { return false }

// saveSetting saves one setting as the Settings page does: to
// settings.yaml, or to the shared settings when they are shared or the
// server's own settings moved there.
func TestSaveSetting(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/security/ca", nil)
	// Without a settings file, nothing can be saved.
	if code, err := (&Server{Config: config.Default()}).saveSetting(req, "search.max_events", 5); code != http.StatusConflict || err != errNoConfigFile {
		t.Errorf("no file: %d %v", code, err)
	}

	_, srv, logs := newSettingsServer(t, "", nil)
	if code, err := srv.saveSetting(req, "search.max_events", "lots"); code != http.StatusBadRequest || !strings.HasPrefix(err.Error(), "Nothing was saved: ") {
		t.Errorf("a bad value: %d %v", code, err)
	}
	if code, err := srv.saveSetting(req, "search.max_events", float64(1234)); code != http.StatusOK || err != nil {
		t.Fatalf("save: %d %v", code, err)
	}
	if srv.conf().Search.MaxEvents != 1234 || !strings.Contains(logs.String(), "settings saved") {
		t.Errorf("max events %d\n%s", srv.conf().Search.MaxEvents, logs.String())
	}
	page, err := config.ReadPageSettings(srv.Config.SettingsFile())
	if err != nil || page.Settings["search.max_events"] == nil {
		t.Errorf("settings.yaml %v %v", page, err)
	}
	if code, err := srv.saveSetting(req, "search.max_events", float64(1234)); code != http.StatusOK || err != nil {
		t.Errorf("the same value again: %d %v", code, err)
	}

	// Moved: the save goes to the shared settings.
	ns := newNodeSettings()
	_, srv, _ = newSettingsServer(t, "", func(s *Server) { s.Settings = heldSettings{ns} })
	if code, err := srv.saveSetting(req, "search.max_events", float64(4321)); code != http.StatusOK || err != nil {
		t.Fatalf("moved: %d %v", code, err)
	}
	if v := ns.sh.Cluster["search.max_events"]; string(v.Value) != "4321" {
		t.Errorf("shared value %s", v.Value)
	}
}

// saveSettingShared checks the value, refuses while the shared settings
// are paused, writes a connection setting to settings.yaml and the others
// to the shared settings.
func TestSaveSettingShared(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/security/ca", nil)
	ns := newNodeSettings()
	_, srv, logs := newSettingsServer(t, "", func(s *Server) { s.Settings, s.Cluster = ns, threeServers() })
	if code, err := srv.saveSetting(req, "search.max_events", "lots"); code != http.StatusBadRequest || !strings.HasPrefix(err.Error(), "Nothing was saved: ") {
		t.Errorf("a bad value: %d %v", code, err)
	}
	if code, err := srv.saveSetting(req, "server.tls.ca_scope", "strict"); code != http.StatusOK || err != nil {
		t.Fatalf("own setting: %d %v", code, err)
	}
	if e := ns.sh.Server["server.tls.ca_scope"]; e == nil || e.Value.Value != "strict" {
		t.Errorf("own setting saved as %+v", e)
	}
	if !strings.Contains(logs.String(), "scope=server") || !strings.Contains(logs.String(), "server=siem-b") {
		t.Errorf("audit:\n%s", logs.String())
	}
	if code, err := srv.saveSetting(req, "server.tls.ca_scope", "strict"); code != http.StatusOK || err != nil {
		t.Errorf("unchanged: %d %v", code, err)
	}
	if code, err := srv.saveSetting(req, "opensearch.username", "siem"); code != http.StatusOK || err != nil {
		t.Fatalf("a connection setting: %d %v", code, err)
	}
	if page, err := config.ReadPageSettings(srv.Config.SettingsFile()); err != nil || page.Settings["opensearch.username"] == nil {
		t.Errorf("settings.yaml %v %v", page, err)
	}
	ns.mu.Lock()
	ns.memSettings.writable = &shared.PausedError{Why: "OpenSearch refuses writes"}
	ns.mu.Unlock()
	if code, err := srv.saveSetting(req, "search.max_events", float64(50)); code != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "OpenSearch refuses writes") {
		t.Errorf("paused: %d %v", code, err)
	}
}
