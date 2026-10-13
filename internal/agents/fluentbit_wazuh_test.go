package agents

import (
	"strings"
	"testing"
)

func TestGenerateWazuhManager(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	a, err := Generate(Options{OS: "linux", LinuxSource: "wazuh", ServerURL: "https://siem.example.com:8080", Token: "tok-0123456789abcdef", CA: ca})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Name                 tail\n",
		"Tag                  wazuh\n",
		"Path                 /var/ossec/logs/alerts/alerts.json\n",
		"DB                   /var/lib/fluent-bit/signalith-wazuh.db\n",
		"Buffer_Max_Size      1M\n",
		"Skip_Long_Lines      On\n",
		"Header_Tag           X-Signalith-Tag\n",
		"tls.ca_file          " + LinuxCAPath + "\n",
		"tls.vhost            siem.example.com\n",
	} {
		if !strings.Contains(a.Config, want) {
			t.Errorf("config missing %q:\n%s", want, a.Config)
		}
	}
	// It sends the alert lines as they are: no parser, and none of the
	// auth log inputs.
	for _, not := range []string{"Parser", "auth.log", "systemd", "linux."} {
		if strings.Contains(a.Config, not) {
			t.Errorf("config has %q:\n%s", not, a.Config)
		}
	}
	if a.ConfigPath != "/etc/fluent-bit/fluent-bit.conf" || a.CAPath != LinuxCAPath || a.CAStep != 2 || a.ConfigStep != 3 {
		t.Errorf("paths and steps: %+v", a)
	}
	if !strings.Contains(a.Steps[0], "Wazuh manager") || !strings.Contains(a.Steps[len(a.Steps)-1], "sourcetype=wazuh:alerts") {
		t.Errorf("steps: %q", a.Steps)
	}
}

func TestGenerateWazuhLeavesOtherSourcesAlone(t *testing.T) {
	for _, src := range []string{"", "file", "journal"} {
		a, err := Generate(Options{OS: "linux", LinuxSource: src, ServerURL: "http://192.0.2.1:8080", Token: "t"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(a.Config), "wazuh") || strings.Contains(strings.ToLower(strings.Join(a.Steps, "\n")), "wazuh") {
			t.Errorf("source %q mentions Wazuh:\n%s\n%q", src, a.Config, a.Steps)
		}
	}
}
