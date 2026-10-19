package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The Docker quick start's signalith.yaml takes syslog over TLS only. An
// install that was there before (its data volume holds Signalith's own
// files) keeps the plain syslog its older file had, decided once; a new
// one (an empty volume, apart from the image's own folders) stays on TLS
// only, and a value saved on the Settings page or set in the environment
// still wins.
func TestDockerQuickStartKeepsPlainSyslogOnUpgrade(t *testing.T) {
	const quickStartSyslog = "syslog:\n  udp: \"\"\n  tcp: \"\"\n  tls: 127.0.0.1:16514\n  public_port: 514\n"
	quick := func(t *testing.T, on bool) {
		t.Helper()
		old := dockerQuickStartHere
		dockerQuickStartHere = func() bool { return on }
		t.Cleanup(func() { dockerQuickStartHere = old })
	}
	t.Setenv("SIGNALITH_SYSLOG_UDP", "")
	t.Setenv("SIGNALITH_SYSLOG_TCP", "")
	now := time.Now()

	t.Run("new install", func(t *testing.T) {
		quick(t, true)
		state := t.TempDir()
		t.Setenv("SIGNALITH_STATE_DIR", state)
		// The image's own folders are in a new volume.
		for _, d := range []string{"detections", "lookups", "dashboards", "archive"} {
			if err := os.MkdirAll(filepath.Join(state, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		path := writeConfig(t, quickStartSyslog)
		c, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		p, made, err := DecidePlainSyslog(c, now)
		if err != nil || !made || p.Kept {
			t.Fatalf("decision %+v made %v: %v", p, made, err)
		}
		// Signalith's own files appear later; the decision stands.
		if err := os.MkdirAll(filepath.Join(state, "tls"), 0o700); err != nil {
			t.Fatal(err)
		}
		if p, made, _ := DecidePlainSyslog(c, now); made || p.Kept {
			t.Errorf("decided again: %+v %v", p, made)
		}
		c, _ = Load(path)
		if c.Syslog.UDP != "" || c.Syslog.TCP != "" || c.PlainSyslogKept() {
			t.Errorf("new install has plain syslog: %+v", c.Syslog)
		}
	})

	t.Run("upgraded install", func(t *testing.T) {
		quick(t, true)
		state := t.TempDir()
		t.Setenv("SIGNALITH_STATE_DIR", state)
		if err := os.MkdirAll(filepath.Join(state, "tls"), 0o700); err != nil {
			t.Fatal(err)
		}
		path := writeConfig(t, quickStartSyslog)
		c, _ := Load(path)
		if c.Syslog.UDP != "" {
			t.Fatalf("plain syslog before the decision: %+v", c.Syslog)
		}
		p, made, err := DecidePlainSyslog(c, now)
		if err != nil || !made || !p.Kept {
			t.Fatalf("decision %+v made %v: %v", p, made, err)
		}
		if p, made, _ := DecidePlainSyslog(c, now); made || !p.Kept {
			t.Errorf("decided again: %+v %v", p, made)
		}
		c, err = Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if c.Syslog.UDP != QuickStartPlainAddr || c.Syslog.TCP != QuickStartPlainAddr || c.Syslog.PublicPort != 514 || !c.PlainSyslogKept() {
			t.Errorf("upgraded install: %+v kept %v", c.Syslog, c.PlainSyslogKept())
		}

		// Turned off on the Settings page, it stays off.
		res, err := PageFile{Config: path}.CheckEdit(Edit{Values: map[string]any{"syslog.udp": "", "syslog.tcp": ""}})
		if err != nil || !res.OK() {
			t.Fatalf("edit: %v %+v", err, res)
		}
		if err := (PageFile{Config: path}).Write(res.Page); err != nil {
			t.Fatal(err)
		}
		if c, _ := Load(path); c.Syslog.UDP != "" || c.Syslog.TCP != "" {
			t.Errorf("the page's off lost: %+v", c.Syslog)
		}
		if err := os.Remove(c.SettingsFile()); err != nil {
			t.Fatal(err)
		}

		// The environment wins too.
		t.Setenv("SIGNALITH_SYSLOG_UDP", "off")
		t.Setenv("SIGNALITH_SYSLOG_TCP", "off")
		if c, _ := Load(path); c.Syslog.UDP != "" || c.Syslog.TCP != "" {
			t.Errorf("the environment's off lost: %+v", c.Syslog)
		}
	})

	t.Run("not the quick start", func(t *testing.T) {
		quick(t, false)
		state := t.TempDir()
		t.Setenv("SIGNALITH_STATE_DIR", state)
		if err := os.MkdirAll(filepath.Join(state, "tls"), 0o700); err != nil {
			t.Fatal(err)
		}
		c, _ := Load(writeConfig(t, quickStartSyslog))
		if p, made, err := DecidePlainSyslog(c, now); p != nil || made || err != nil {
			t.Errorf("decided outside the quick start: %+v %v %v", p, made, err)
		}
		if _, err := os.Stat(PlainSyslogFileIn(state)); !os.IsNotExist(err) {
			t.Errorf("wrote %s outside the quick start", PlainSyslogFileIn(state))
		}
	})
}
