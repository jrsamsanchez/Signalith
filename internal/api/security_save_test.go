package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// One setting saved from another page (the CA scope from the Security
// page) is checked and written as the Settings page would; each failure
// is answered by what failed.
func TestSaveSettingFile(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/security/ca", nil)
	if code, err := (&Server{Config: config.Default()}).saveSetting(r, "search.max_events", float64(10)); code != http.StatusConflict || !errors.Is(err, errNoConfigFile) {
		t.Errorf("no config file: %d %v", code, err)
	}

	_, srv, _ := newSettingsServer(t, "", nil)
	file := config.PageFile{Config: srv.Config.Path()}
	srv.Pages = failPages{PageFile: file, checkErr: errDown}
	if code, err := srv.saveSetting(r, "search.max_events", float64(1234)); code != http.StatusInternalServerError || !errors.Is(err, errDown) {
		t.Errorf("check fails: %d %v", code, err)
	}
	srv.Pages = failPages{PageFile: file, writeErr: errDown}
	if code, err := srv.saveSetting(r, "search.max_events", float64(1234)); code != http.StatusInternalServerError || !errors.Is(err, errDown) {
		t.Errorf("write fails: %d %v", code, err)
	}
	srv.Pages = nil
	if code, err := srv.saveSetting(r, "search.max_events", "many"); code != http.StatusBadRequest || err == nil {
		t.Errorf("bad value: %d %v", code, err)
	}
	if code, err := srv.saveSetting(r, "search.max_events", float64(1234)); code != http.StatusOK || err != nil {
		t.Fatalf("save: %d %v", code, err)
	}
	if code, err := srv.saveSetting(r, "search.max_events", float64(1234)); code != http.StatusOK || err != nil {
		t.Errorf("no change: %d %v", code, err)
	}

	sf := srv.conf().SettingsFile()
	if err := os.MkdirAll(filepath.Dir(sf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sf, []byte("values: [this is: not: settings\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, err := srv.saveSetting(r, "search.max_events", float64(99)); code != http.StatusConflict || err == nil {
		t.Errorf("unreadable file: %d %v", code, err)
	}
}

// Saved while this server's settings move, or once they are shared, the
// setting goes to the shared settings; a store that cannot be read or
// changed refuses it.
func TestSaveSettingSharedFailures(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/security/ca", nil)
	ms := &movingSettings{memSettings: newMemSettings(), moved: true}
	_, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings = ms })
	if code, err := srv.saveSetting(r, "search.max_events", float64(4321)); code != http.StatusOK || err != nil || ms.released.Load() != 1 {
		t.Fatalf("moved: %d %v released %d", code, err, ms.released.Load())
	}
	ms.memSettings.mu.Lock()
	_, saved := ms.memSettings.sh.Cluster["search.max_events"]
	ms.memSettings.mu.Unlock()
	if !saved {
		t.Error("not in the shared settings")
	}

	fs := &failSettings{nodeSettings: newNodeSettings()}
	_, srv, _ = newSettingsServer(t, "", func(s *Server) { s.Settings = fs })
	if code, err := srv.saveSetting(r, "search.max_events", "many"); code != http.StatusBadRequest || err == nil {
		t.Errorf("bad value: %d %v", code, err)
	}
	if code, err := srv.saveSetting(r, "opensearch.username", "siem"); code != http.StatusOK || err != nil {
		t.Errorf("connection setting: %d %v", code, err)
	}
	if p, err := (config.PageFile{Config: srv.Config.Path()}).Read(); err != nil || !slices.Contains(p.Keys(), "opensearch.username") {
		t.Errorf("connection setting not in the file: %v %v", p, err)
	}
	fs.fail(errDown, nil, "")
	if code, err := srv.saveSetting(r, "search.max_events", float64(10)); code != http.StatusInternalServerError || !errors.Is(err, errDown) {
		t.Errorf("layer fails: %d %v", code, err)
	}
	fs.fail(nil, errDown, "")
	if code, err := srv.saveSetting(r, "search.max_events", float64(10)); code != http.StatusInternalServerError || !errors.Is(err, errDown) {
		t.Errorf("save fails: %d %v", code, err)
	}
	fs.fail(nil, nil, "")
	fs.memSettings.mu.Lock()
	fs.memSettings.writable = errors.New("paused")
	fs.memSettings.mu.Unlock()
	if code, err := srv.saveSetting(r, "search.max_events", float64(10)); code != http.StatusServiceUnavailable || err == nil {
		t.Errorf("not writable: %d %v", code, err)
	}
	fs.memSettings.mu.Lock()
	fs.memSettings.writable = nil
	fs.memSettings.mu.Unlock()

	sf := srv.conf().SettingsFile()
	if err := os.MkdirAll(filepath.Dir(sf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sf, []byte("values: [this is: not: settings\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, err := srv.saveSetting(r, "opensearch.username", "other"); code != http.StatusConflict || err == nil {
		t.Errorf("unreadable file: %d %v", code, err)
	}
}

// The Security page counts the syslog senders of the last day by
// protocol, and lists plain senders that name no host by their address.
func TestRuntimeFactsSyslog(t *testing.T) {
	_, srv, _ := newSecurityServer(t, nil)
	rcv := syslog.New(syslog.Config{UDP: "127.0.0.1:0"}, srv.Pipeline, srv.Log)
	ctx, cancel := context.WithCancel(context.Background())
	if err := rcv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); rcv.Wait() })
	srv.Syslog = rcv
	c, err := net.Dial("udp", rcv.Stats().Listeners[0].Address)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "<13>Oct 12 13:00:00 fw1 app: hello")
	c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for len(rcv.Stats().Senders) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	srv.Pipeline.NotePlaintext(netip.MustParseAddr("10.0.0.5"), nil)

	for _, inContainer := range []bool{false, true} {
		rt := srv.runtimeFacts(time.Now(), inContainer)
		if rt.SyslogSenders["udp"] != 1 || !slices.Contains(rt.PlainSenders, "10.0.0.5") {
			t.Errorf("in container %v: %+v", inContainer, rt)
		}
	}
	// A day later the sender is not counted.
	if rt := srv.runtimeFacts(time.Now().Add(48*time.Hour), false); len(rt.SyslogSenders) != 0 || rt.SyslogNATed {
		t.Errorf("a day later: %+v", rt)
	}
}
