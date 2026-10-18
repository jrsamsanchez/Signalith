package agents

import (
	"strings"
	"testing"
)

// The Signalith Agent's configurations keep Fluent Bit's files in the
// agent's folders, read the token from the agent, and need no steps: the
// agent writes the files itself.
func TestGenerateManaged(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	lin, err := Generate(Options{OS: "linux", LinuxSource: "file", ServerURL: "https://siem.example.com:7779", Token: EnvToken, CA: ca, Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		line("Header", "Authorization Bearer ${SIGNALITH_TOKEN}"),
		line("tls.ca_file", "/etc/signalith-agent/ca.pem"),
		line("storage.path", "/var/lib/signalith-agent/fluent-bit/buffer"),
		line("DB", "/var/lib/signalith-agent/fluent-bit/signalith-auth.db"),
	} {
		if !strings.Contains(lin.Config, want) {
			t.Errorf("linux config missing %q:\n%s", want, lin.Config)
		}
	}
	if lin.ConfigPath != "/etc/signalith-agent/fluent-bit.conf" || lin.CAPath != "/etc/signalith-agent/ca.pem" || len(lin.Steps) != 0 {
		t.Errorf("linux: %s %s %v", lin.ConfigPath, lin.CAPath, lin.Steps)
	}
	if strings.Contains(lin.Config, "/var/lib/fluent-bit") || strings.Contains(lin.Config, "/etc/fluent-bit") {
		t.Errorf("linux config uses Fluent Bit's own folders:\n%s", lin.Config)
	}

	win, err := Generate(Options{OS: "windows", ServerURL: "https://siem.example.com:7779", Token: EnvToken, CA: ca, Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		line("tls.ca_file", `C:\ProgramData\Signalith\Agent\ca.pem`),
		line("storage.path", `C:\ProgramData\Signalith\Agent\fluent-bit\signalith-buffer`),
	} {
		if !strings.Contains(win.Config, want) {
			t.Errorf("windows config missing %q:\n%s", want, win.Config)
		}
	}
	if win.ConfigPath != `C:\ProgramData\Signalith\Agent\fluent-bit.conf` || len(win.Steps) != 0 {
		t.Errorf("windows: %s %v", win.ConfigPath, win.Steps)
	}
}
