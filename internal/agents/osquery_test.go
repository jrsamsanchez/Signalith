package agents

import (
	"errors"
	"strings"
	"testing"
)

func TestOsqueryLinux(t *testing.T) {
	a, err := Generate(Options{OS: "osquery", ServerURL: "https://siem.corp.example:8080", Token: "tok123", CA: testCA})
	if err != nil {
		t.Fatal(err)
	}
	if a.ConfigPath != "signalith-osquery-setup.sh" || a.ConfigStep == 0 || a.CAPath != "/etc/osquery/signalith-ca.pem" {
		t.Errorf("agent = %q %d %q", a.ConfigPath, a.ConfigStep, a.CAPath)
	}
	for _, want := range []string{
		"--tls_hostname=siem.corp.example:8080",
		"--tls_server_certs=/etc/osquery/signalith-ca.pem",
		"--enroll_secret_path=/etc/osquery/signalith-enroll-secret",
		"--enroll_tls_endpoint=/api/osquery/enroll",
		"--logger_tls_endpoint=/api/osquery/log",
		"--distributed_tls_read_endpoint=/api/osquery/distributed/read",
		"--enable_file_events=true",
		"--host_identifier=uuid",
		"tok123\nSIGNALITH_EOF",
		"chmod 0600 /etc/osquery/signalith-enroll-secret",
		"-----END CERTIFICATE-----\nSIGNALITH_EOF",
		"systemctl restart osqueryd",
	} {
		if !strings.Contains(a.Config, want) {
			t.Errorf("script lacks %q:\n%s", want, a.Config)
		}
	}
	// The secret is written with umask 077 before any file holds it.
	if strings.Index(a.Config, "umask 077") > strings.Index(a.Config, "tok123") {
		t.Error("secret written before umask")
	}
}

func TestOsqueryWindowsAndMac(t *testing.T) {
	a, err := Generate(Options{OS: "osquery", Platform: "windows", ServerURL: "https://siem.corp.example", Token: "tok123", CA: testCA})
	if err != nil {
		t.Fatal(err)
	}
	if a.ConfigPath != "signalith-osquery-setup.ps1" {
		t.Errorf("path = %q", a.ConfigPath)
	}
	for _, want := range []string{
		"--tls_hostname=siem.corp.example:443",
		`--tls_server_certs=C:\Program Files\osquery\signalith-ca.pem`,
		"--enable_ntfs_event_publisher=true",
		"'*S-1-5-18:F' '*S-1-5-32-544:F'",
		"Restart-Service osqueryd",
	} {
		if !strings.Contains(a.Config, want) {
			t.Errorf("script lacks %q:\n%s", want, a.Config)
		}
	}

	m, err := Generate(Options{OS: "osquery", Platform: "darwin", ServerURL: "https://siem.corp.example", Token: "tok123"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(m.Config, "tls_server_certs") || !strings.Contains(m.Config, "launchctl load") ||
		!strings.Contains(strings.Join(m.Steps, "\n"), "Full Disk Access") {
		t.Errorf("mac script:\n%s\n%v", m.Config, m.Steps)
	}
}

func TestOsqueryRefuses(t *testing.T) {
	for name, o := range map[string]Options{
		"plain http":     {ServerURL: "http://siem.corp.example:8080", Token: "t"},
		"no token":       {ServerURL: "https://siem.corp.example"},
		"quote in token": {ServerURL: "https://siem.corp.example", Token: "a'b"},
		"newline":        {ServerURL: "https://siem.corp.example", Token: "a\nb"},
		"platform":       {ServerURL: "https://siem.corp.example", Token: "t", Platform: "solaris"},
		"ip, other CA":   {ServerURL: "https://192.0.2.10:8080", Token: "t", CA: testCA},
	} {
		o.OS = "osquery"
		if _, err := Generate(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := Generate(Options{OS: "osquery", ServerURL: "https://192.0.2.10:8080", Token: "t", CA: testCA})
	if !errors.Is(err, ErrNoNameToCheck) {
		t.Errorf("ip error = %v", err)
	}
	if _, err := Generate(Options{OS: "osquery", ServerURL: "https://192.0.2.10:8080", Token: "t", CA: testCA, OwnCA: true}); err != nil {
		t.Errorf("ip with Signalith's CA: %v", err)
	}
}
