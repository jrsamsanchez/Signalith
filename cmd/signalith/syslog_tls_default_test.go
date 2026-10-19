package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"gopkg.in/yaml.v3"
)

// A new install takes syslog over TLS only: plain syslog over UDP and TCP
// is unencrypted and anyone who can reach the port can send fake events,
// so init leaves it off unless an installer asks for it.
func TestInitSyslogTLSOnlyByDefault(t *testing.T) {
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	t.Setenv("SIGNALITH_SYSLOG_UDP", "")
	t.Setenv("SIGNALITH_SYSLOG_TCP", "")
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	out := captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-admin-password", "first-password"}); err != nil {
			t.Fatal(err)
		}
	})
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Syslog.UDP != "" || c.Syslog.TCP != "" || c.Syslog.TLS != "0.0.0.0:6514" {
		t.Errorf("syslog %+v, want TLS on 0.0.0.0:6514 only", c.Syslog)
	}
	if !strings.Contains(out, "Syslog:      TLS 0.0.0.0:6514\n") || !strings.Contains(out, "Plain syslog (UDP and TCP 514) is off") || !strings.Contains(out, "Add data > Syslog") {
		t.Errorf("init output does not say plain syslog is off:\n%s", out)
	}
	// The installers open the firewall only for what is on.
	if got := captureStdout(t, func() { printSyslogPorts(c) }); got != "tls 6514 any\n" {
		t.Errorf("syslog ports %q, want TLS only", got)
	}

	// Installers that want plain syslog still ask for it.
	path2 := filepath.Join(t.TempDir(), "signalith.yaml")
	out = captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path2, "-admin-password", "first-password", "-syslog-udp", "0.0.0.0:514", "-syslog-tcp=0.0.0.0:514"}); err != nil {
			t.Fatal(err)
		}
	})
	c2, err := config.Load(path2)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Syslog.UDP != "0.0.0.0:514" || c2.Syslog.TCP != "0.0.0.0:514" || c2.Syslog.TLS != "0.0.0.0:6514" {
		t.Errorf("with -syslog-udp and -syslog-tcp: %+v", c2.Syslog)
	}
	if strings.Contains(out, "Plain syslog (UDP and TCP 514) is off") {
		t.Errorf("init says plain syslog is off when it was asked for:\n%s", out)
	}

	// An existing config is never rewritten: init refuses it, and plain
	// syslog stays as it is.
	if err := cmdInit([]string{"-c", path2, "-admin-password", "first-password"}); err == nil {
		t.Error("init overwrote an existing config")
	}
	if c3, err := config.Load(path2); err != nil || c3.Syslog.UDP != "0.0.0.0:514" || c3.Syslog.TCP != "0.0.0.0:514" {
		t.Errorf("existing config changed: %v %+v", err, c3.Syslog)
	}
}

// The Docker quick start and the load balancer lab take syslog over TLS
// only, until plain syslog is turned on; then devices send it to 514.
func TestDockerConfigsSyslogTLSOnly(t *testing.T) {
	for _, name := range []string{"signalith.yaml", "signalith-cluster.yaml"} {
		raw, err := os.ReadFile(filepath.Join(dockerDir, name))
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Syslog *config.Syslog `yaml:"syslog"`
		}
		if err := yaml.Unmarshal(raw, &f); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		s := f.Syslog
		if s == nil || s.UDP != "" || s.TCP != "" || s.TLS != "0.0.0.0:6514" || s.PublicPort != 514 {
			t.Errorf("%s: syslog %+v, want TLS on 0.0.0.0:6514 only and public_port 514", name, s)
		}
		text := strings.ReplaceAll(string(raw), "\r\n", "\n")
		if !strings.Contains(text, "0.0.0.0:5514") || !strings.Contains(text, "Turn on plain syslog") {
			t.Errorf("%s does not say how to turn on plain syslog", name)
		}
	}
}
