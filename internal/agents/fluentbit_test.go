package agents

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseServerURLAccepts(t *testing.T) {
	for _, in := range []string{
		"http://192.168.1.20:8080",
		"http://siem.corp.local:8080/",
		"https://siem.example.com",
		"HTTP://Desktop-7Q2K:8080",
		"http://my_pc:1",
		"http://x:65535",
		"http://[::1]:8080",
		"https://[2001:db8::20]:8443",
		"http://localhost:8080",
		"http://a-b_c.example:8080",
		"http://10.0.0.1",
	} {
		if _, err := ParseServerURL(in); err != nil {
			t.Errorf("ParseServerURL(%q) = %v, want ok", in, err)
		}
	}
}

func TestParseServerURLRejects(t *testing.T) {
	for _, in := range []string{
		"",
		" http://a:8080",
		"http://a:8080 ",
		"http://a b:8080",
		"http://a:8080\n[OUTPUT]\n    Name stdout",
		"http://a:8080\r\n    Header X-Evil 1",
		"http://a\n:8080",
		"\nhttp://a:8080",
		"http://a:8080\t",
		"http://a:8080\x00",
		"http://a:8080\u2028",
		"http://a\u0085b:8080",
		"http://a%0Ab:8080",
		"http://a:8080/%0A",
		"http://a:8080/api/ingest",
		"http://a:8080?x=1",
		"http://a:8080/?",
		"http://a:8080#top",
		"ftp://a:21",
		"javascript:alert(1)",
		"http:a",
		"a:8080",
		"192.168.1.20:8080",
		"//a:8080",
		"http://",
		"http:///x",
		"http://user:pw@a:8080",
		"http://user@a",
		"http://a:0",
		"http://a:65536",
		"http://a:080",
		"http://a:",
		"http://a:-1",
		"http://a:http",
		"http://-a:8080",
		"http://a..b:8080",
		"http://a.:8080",
		"http://évil.example:8080",
		"http://a;b:8080",
		"http://[fe80::1%25eth0]:8080",
		"http://[127.0.0.1]:8080",
		"http://::1:8080",
		"http://127.1:8080",
		"http://256.1.1.1",
		"http://999:8080",
		"http://1.2.3.4.5",
		"http://a-:8080",
		"http://" + strings.Repeat("a.", 200) + "com",
	} {
		if u, err := ParseServerURL(in); err == nil {
			t.Errorf("ParseServerURL(%q) = %v, want an error", in, u)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for in, want := range map[string]bool{
		"http://localhost:8080":         true,
		"http://LocalHost":              true,
		"http://app.localhost:8080":     true,
		"http://127.0.0.1:8080":         true,
		"http://127.10.20.30":           true,
		"http://[::1]:8080":             true,
		"http://0.0.0.0:8080":           true,
		"http://192.168.1.20:8080":      false,
		"http://siem.corp.local:8080":   false,
		"https://localhost.example.com": false,
		"http://[2001:db8::20]:8080":    false,
		"http://128.0.0.1":              false,
	} {
		u, err := ParseServerURL(in)
		if err != nil {
			t.Fatalf("ParseServerURL(%q): %v", in, err)
		}
		if got := IsLoopback(u); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestGenerateUsesServerAddress(t *testing.T) {
	a, err := Generate(Options{OS: "linux", ServerURL: "https://192.168.1.20:8443/", Token: "tok-0123456789abcdef", OwnCA: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Host                 192.168.1.20\n", "Port                 8443\n", "tls                  On\n"} {
		if !strings.Contains(a.Config, want) {
			t.Errorf("config missing %q:\n%s", want, a.Config)
		}
	}
	if a.ServerURL != "https://192.168.1.20:8443" || a.ServerLoopback {
		t.Errorf("server_url = %q, loopback = %v", a.ServerURL, a.ServerLoopback)
	}

	a, err = Generate(Options{OS: "linux", ServerURL: "https://[2001:db8::20]:8443", Token: "tok-0123456789abcdef", OwnCA: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Config, "Host                 2001:db8::20\n") || !strings.Contains(a.Config, "tls                  On\n") {
		t.Errorf("IPv6 address:\n%s", a.Config)
	}

	a, err = Generate(Options{OS: "windows", ServerURL: "http://localhost", Token: "tok-0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Config, "Port                 80\n") || a.ServerURL != "http://localhost" || !a.ServerLoopback {
		t.Errorf("server_url = %q, loopback = %v:\n%s", a.ServerURL, a.ServerLoopback, a.Config)
	}
}

func TestGenerateRejectsInjectedAddress(t *testing.T) {
	for _, in := range []string{
		"http://a:8080\n[OUTPUT]\n    Name stdout\n    Match *",
		"http://a:8080\r\n    Header Authorization Bearer stolen",
		"http://a%0A[OUTPUT]:8080",
		"",
	} {
		a, err := Generate(Options{OS: "linux", ServerURL: in, Token: "tok-0123456789abcdef"})
		if err == nil {
			t.Errorf("Generate with server %q succeeded:\n%s", in, a.Config)
			continue
		}
		if strings.ContainsAny(err.Error(), "\r\n") {
			t.Errorf("error for %q has a raw line break: %q", in, err.Error())
		}
	}
}

const testCA = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----"

func TestGenerateTrustsTheServerCA(t *testing.T) {
	a, err := Generate(Options{OS: "linux", ServerURL: "https://siem.corp.local:8080", Token: "tok-0123456789abcdef", CA: testCA})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tls                  On\n", "tls.verify           On\n",
		"tls.ca_file          /etc/fluent-bit/signalith-ca.pem\n", "tls.vhost            siem.corp.local\n",
		"tls.verify_hostname  On\n",
	} {
		if !strings.Contains(a.Config, want) {
			t.Errorf("config missing %q:\n%s", want, a.Config)
		}
	}
	if a.CA != testCA+"\n" || a.CAPath != LinuxCAPath || a.CAStep != 2 || a.ConfigStep != 3 {
		t.Errorf("ca %q path %q steps %d %d", a.CA, a.CAPath, a.CAStep, a.ConfigStep)
	}
	if !strings.Contains(a.Steps[1], "signalith-ca.pem") || !strings.Contains(a.Steps[2], "fluent-bit.conf") {
		t.Errorf("steps: %q", a.Steps)
	}
	// The config file goes in place readable by root only.
	if want := "sudo install -m 600 -o root -g root fluent-bit.conf /etc/fluent-bit/fluent-bit.conf"; !strings.Contains(a.Steps[3], want) ||
		!strings.Contains(a.Steps[3], "sudo install -m 644 -o root -g root signalith-ca.pem /etc/fluent-bit/signalith-ca.pem") {
		t.Errorf("install step: %q", a.Steps[3])
	}

	// Windows: the CA next to the config, and the config locked down.
	a, err = Generate(Options{OS: "windows", ServerURL: "https://192.168.1.20:8080", Token: "tok-0123456789abcdef", CA: testCA, OwnCA: true, Sysmon: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(a.Config, "PowerShell") {
		t.Errorf("PowerShell channel without the option:\n%s", a.Config)
	}
	if !strings.Contains(a.Config, `tls.ca_file          C:\Program Files\fluent-bit\conf\signalith-ca.pem`) {
		t.Errorf("windows config:\n%s", a.Config)
	}
	// An IP address is no name to ask for or check, and Signalith's own
	// CA vouches for nothing else.
	if strings.Contains(a.Config, "tls.vhost") || strings.Contains(a.Config, "verify_hostname") {
		t.Errorf("vhost for an IP address:\n%s", a.Config)
	}
	// A browser saves both files to Downloads; a step copies them into
	// place.
	if a.CAStep != 3 || a.ConfigStep != 4 || !strings.Contains(a.Steps[a.CAStep-1], "as signalith-ca.pem.") || !strings.Contains(a.Steps[a.ConfigStep-1], "as fluent-bit.conf.") {
		t.Errorf("steps %d %d: %q", a.CAStep, a.ConfigStep, a.Steps)
	}
	// Then only SYSTEM and Administrators may read the config and the
	// buffer, named by SID so it works in every language.
	for _, want := range []string{
		`cd "$env:USERPROFILE\Downloads"`,
		`Copy-Item signalith-ca.pem, fluent-bit.conf 'C:\Program Files\fluent-bit\conf\' -Force`,
		`icacls 'C:\Program Files\fluent-bit\conf\fluent-bit.conf' /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'`,
		`icacls 'C:\ProgramData\fluent-bit' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'`,
	} {
		if !strings.Contains(a.Steps[4], want) {
			t.Errorf("install step lacks %s: %q", want, a.Steps[4])
		}
	}
	if !strings.Contains(a.Config, `storage.path         C:\ProgramData\fluent-bit\signalith-buffer`) {
		t.Errorf("the buffer is not in the folder the steps lock down:\n%s", a.Config)
	}
	// Without a CA file, only the config is copied.
	a, _ = Generate(Options{OS: "windows", ServerURL: "https://siem.example.com", Token: "tok-0123456789abcdef"})
	if !strings.Contains(a.Steps[a.ConfigStep], "Copy-Item fluent-bit.conf 'C:") || strings.Contains(a.Steps[a.ConfigStep], "signalith-ca.pem") {
		t.Errorf("windows without a CA: %q", a.Steps)
	}
}

func TestGenerateWithoutCA(t *testing.T) {
	// A certificate the agent's system trusts: no CA file.
	a, err := Generate(Options{OS: "linux", ServerURL: "https://siem.example.com", Token: "tok-0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(a.Config, "ca_file") || a.CAStep != 0 || a.ConfigStep != 2 || !strings.Contains(a.Config, "tls.vhost            siem.example.com\n") {
		t.Errorf("public CA: steps %d %d\n%s", a.CAStep, a.ConfigStep, a.Config)
	}
	// Any public CA vouches for many sites, so the agent must also check
	// the certificate is for this server's name, or anyone with a
	// certificate for any domain could take its token and events.
	if !strings.Contains(a.Config, "tls.verify_hostname  On\n") {
		t.Errorf("public CA without a host name check:\n%s", a.Config)
	}
	if !strings.Contains(a.Steps[2], "sudo install -m 600 -o root -g root fluent-bit.conf /etc/fluent-bit/fluent-bit.conf") {
		t.Errorf("install step: %q", a.Steps[2])
	}
	// Plain http (HTTPS is off, behind a proxy): no TLS settings at all.
	a, _ = Generate(Options{OS: "linux", ServerURL: "http://siem:8080", Token: "tok-0123456789abcdef", CA: testCA})
	if !strings.Contains(a.Config, "tls                  Off\n") || strings.Contains(a.Config, "ca_file") || strings.Contains(a.Config, "vhost") || a.CA != "" {
		t.Errorf("http:\n%s", a.Config)
	}
	// A private CA Signalith does not have: the agent still reads a CA
	// file, and the step says where to get it.
	a, _ = Generate(Options{OS: "linux", ServerURL: "https://siem.corp:8080", Token: "tok-0123456789abcdef", CAUnknown: true})
	if !strings.Contains(a.Config, "tls.ca_file") || a.CA != "" || !strings.Contains(a.Steps[a.CAStep-1], "doesn't include it") {
		t.Errorf("unknown CA: %q\n%s", a.Steps, a.Config)
	}
}

func TestAntivirusCollection(t *testing.T) {
	for _, sysmon := range []bool{false, true} {
		a, err := Generate(Options{OS: "windows", ServerURL: "http://192.168.1.20:8080", Token: "tok-0123456789abcdef", Sysmon: sysmon})
		if err != nil {
			t.Fatal(err)
		}
		channels := "Security,System,Application,Microsoft-Windows-Windows Defender/Operational,Microsoft-Windows-CodeIntegrity/Operational,Microsoft-Windows-Windows Firewall With Advanced Security/Firewall,Microsoft-Windows-Bits-Client/Operational,Microsoft-Windows-AppXDeploymentServer/Operational,Microsoft-Windows-WMI-Activity/Operational"
		if sysmon {
			channels += ",Microsoft-Windows-Sysmon/Operational"
		}
		if !strings.Contains(a.Config, line("Channels", channels)) || !strings.Contains(a.Config, line("Ignore_Missing_Channels", "On")) {
			t.Errorf("sysmon %v: config lacks Defender or Ignore_Missing_Channels:\n%s", sysmon, a.Config)
		}
		if !strings.Contains(strings.Join(a.Steps, "\n"), "Restart-Service fluent-bit") {
			t.Error("no step says how to restart an installed agent")
		}
	}

	a, err := Generate(Options{OS: "linux", ServerURL: "http://192.168.1.20:8080", Token: "tok-0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[INPUT]\n" + line("Name", "tail") + line("Tag", "linux.clamav") + line("Path", "/var/log/clamav/*.log") + line("Path_Key", "file") +
			line("DB", "/var/lib/fluent-bit/signalith-clamav.db") + line("storage.type", "filesystem"),
		"[FILTER]\n" + line("Name", "sysinfo") + line("Match", "linux.clamav") + line("hostname_key", "hostname"),
		"[FILTER]\n" + line("Name", "grep") + line("Match", "linux.clamav") + line("Exclude", "log SelfCheck"),
	} {
		if !strings.Contains(a.Config, want) {
			t.Errorf("file mode lacks\n%s\nin\n%s", want, a.Config)
		}
	}
	if strings.Contains(a.Config, "SYSLOG_IDENTIFIER=clamd") {
		t.Error("file mode reads the journal")
	}

	a, err = Generate(Options{OS: "linux", LinuxSource: "journal", ServerURL: "http://192.168.1.20:8080", Token: "tok-0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SYSLOG_IDENTIFIER=clamd\n", "SYSLOG_IDENTIFIER=clamonacc\n", "SYSLOG_IDENTIFIER=freshclam\n",
		"[FILTER]\n" + line("Name", "grep") + line("Match", "linux.journal") + line("Exclude", "MESSAGE ^SelfCheck"),
	} {
		if !strings.Contains(a.Config, want) {
			t.Errorf("journal mode lacks %q", want)
		}
	}
	if strings.Contains(a.Config, "linux.clamav") {
		t.Error("journal mode tails ClamAV files")
	}
}

// line is one setting as section writes it.
func line(k, v string) string { return fmt.Sprintf("    %-20s %s\n", k, v) }

// TestGenerateTiesAnIPAddressToTheServer checks agents that reach the
// server by IP address with a CA that vouches for other computers too: a
// company or public one. Checking only who issued the certificate would
// let anyone with another certificate from it take the token and events,
// so the agent checks a name the certificate carries, or there is no
// config.
func TestGenerateTiesAnIPAddressToTheServer(t *testing.T) {
	for _, o := range []Options{
		{CA: testCA},      // a company CA, in the certificate file
		{CAUnknown: true}, // a company CA the file leaves out
		{},                // a public CA
	} {
		o.OS, o.Token, o.ServerURL = "linux", "tok-0123456789abcdef", "https://192.168.1.20:8443"
		o.CertNames = []string{"*.corp.example", "localhost", "10.0.0.1", "Siem.Corp.Example.", "other.corp.example"}
		a, err := Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Host                 192.168.1.20\n", "tls.vhost            siem.corp.example\n", "tls.verify_hostname  On\n"} {
			if !strings.Contains(a.Config, want) {
				t.Errorf("%+v: config missing %q:\n%s", o, want, a.Config)
			}
		}
		// Nothing to check it against: refused, saying what to do.
		for _, names := range [][]string{nil, {"*.corp.example", "localhost"}} {
			o.CertNames = names
			a, err := Generate(o)
			if !errors.Is(err, ErrNoNameToCheck) || !strings.Contains(err.Error(), "Use a host name the certificate covers") {
				t.Errorf("%+v: no name to check: %v\n%v", o, err, a)
			}
		}
		// Over loopback nothing sits in between.
		o.ServerURL = "https://127.0.0.1:8443"
		if a, err := Generate(o); err != nil || strings.Contains(a.Config, "vhost") {
			t.Errorf("loopback: %v", err)
		}
		// Plain http has no certificate to check.
		o.ServerURL = "http://192.168.1.20:8080"
		if _, err := Generate(o); err != nil {
			t.Errorf("http: %v", err)
		}
	}
}

func TestFluentBitWindowsPowerShell(t *testing.T) {
	a, err := Generate(Options{OS: "windows", ServerURL: "https://siem.example.com:8080", Token: "tok-0123456789abcdef", Sysmon: true, PowerShell: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Config, "Channels             Security,System,Application,Microsoft-Windows-Windows Defender/Operational,Microsoft-Windows-CodeIntegrity/Operational,Microsoft-Windows-Windows Firewall With Advanced Security/Firewall,Microsoft-Windows-Bits-Client/Operational,Microsoft-Windows-AppXDeploymentServer/Operational,Microsoft-Windows-WMI-Activity/Operational,Microsoft-Windows-Sysmon/Operational,Microsoft-Windows-PowerShell/Operational") {
		t.Errorf("config:\n%s", a.Config)
	}
	if !strings.Contains(strings.Join(a.Steps, "\n"), `Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1`) {
		t.Errorf("steps: %q", a.Steps)
	}
}

func TestFluentBitSaysWhoItIs(t *testing.T) {
	for _, os := range []string{"linux", "windows"} {
		a, err := Generate(Options{OS: os, ServerURL: "https://siem.example.com:8080", Token: "t",
			CA: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", Version: "1.4.0", CAPin: "0123456789abcdef"})
		if err != nil {
			t.Fatal(err)
		}
		// Fluent Bit fills in ${HOSTNAME} itself on both systems. The
		// values have no spaces or quotes, so they need no quoting.
		for _, want := range []string{
			"Header               X-Signalith-Agent ${HOSTNAME}\n",
			"Header               X-Signalith-Config ca=0123456789abcdef;v=1.4.0\n",
		} {
			if !strings.Contains(a.Config, want) {
				t.Errorf("%s: config missing %q:\n%s", os, want, a.Config)
			}
		}
	}
	// No CA pinned: the version alone.
	a, err := Generate(Options{OS: "linux", ServerURL: "http://192.0.2.1:8080", Token: "t", Version: "1.4.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Config, "X-Signalith-Config v=1.4.0\n") || strings.Contains(a.Config, "ca=") {
		t.Errorf("no CA:\n%s", a.Config)
	}
}

func TestFluentBitLinuxSysmon(t *testing.T) {
	for _, source := range []string{"file", "journal"} {
		for _, sysmon := range []bool{false, true} {
			a, err := Generate(Options{OS: "linux", LinuxSource: source, ServerURL: "http://192.168.1.20:8080", Token: "tok-0123456789abcdef", Sysmon: sysmon})
			if err != nil {
				t.Fatal(err)
			}
			has := strings.Contains(a.Config, "SYSLOG_IDENTIFIER=sysmon")
			if has != sysmon {
				t.Errorf("%s, sysmon %v: config reads Sysmon for Linux = %v:\n%s", source, sysmon, has, a.Config)
			}
			step := strings.Contains(strings.Join(a.Steps, "\n"), "SysmonForLinux")
			if step != sysmon {
				t.Errorf("%s, sysmon %v: install step = %v", source, sysmon, step)
			}
		}
	}
	// A Wazuh manager's agent only sends alerts.
	a, err := Generate(Options{OS: "linux", LinuxSource: "wazuh", ServerURL: "http://192.168.1.20:8080", Token: "tok-0123456789abcdef", Sysmon: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(a.Config, "sysmon") {
		t.Errorf("wazuh config reads Sysmon:\n%s", a.Config)
	}
}

// Linux agents install Fluent Bit from its signed packages, never by piping
// a script into a shell.
func TestFluentBitLinuxInstallStep(t *testing.T) {
	for _, source := range []string{"file", "journal", "wazuh"} {
		a, err := Generate(Options{OS: "linux", LinuxSource: source, ServerURL: "http://192.168.1.20:8080", Token: "tok-0123456789abcdef"})
		if err != nil {
			t.Fatal(err)
		}
		steps := strings.Join(a.Steps, "\n")
		if strings.Contains(steps, "| sh") || !strings.Contains(steps, "docs.fluentbit.io/manual/installation/linux") {
			t.Errorf("%s: install step %q", source, a.Steps[0])
		}
	}
}
