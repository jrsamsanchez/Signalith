package agents

import (
	"strings"
	"testing"
)

func TestCustomInput(t *testing.T) {
	conf, err := CustomInput("custom.acme", "acme", "linux", []string{"/var/log/acme/*.log", "/opt/acme/audit.log"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[INPUT]", "Name", "tail", "custom.acme", "/var/log/acme/*.log,/opt/acme/audit.log", "/var/lib/fluent-bit/signalith-acme.db", "Path_Key"} {
		if !strings.Contains(conf, want) {
			t.Errorf("input lacks %q:\n%s", want, conf)
		}
	}
	// Logs near secrets are still fine.
	for _, ok := range [][2]string{{"linux", "/etc/myapp/*.log"}, {"linux", "/var/log/fluent-bit.log"}, {"linux", "/etc/ssh-audit.log"}, {"windows", `C:\ProgramData\Acme\fluent-bit.log`}} {
		if _, err := CustomInput("custom.acme", "acme", ok[0], []string{ok[1]}); err != nil {
			t.Errorf("%s refused: %v", ok[1], err)
		}
	}
	conf, err = CustomInput("custom.acme", "acme", "windows", []string{`C:\ProgramData\Acme\logs\*.log`})
	if err != nil || !strings.Contains(conf, `C:\ProgramData\fluent-bit\signalith-acme.sqlite`) {
		t.Errorf("windows: %v\n%s", err, conf)
	}
	for _, tc := range []struct {
		os    string
		paths []string
	}{
		{"linux", nil},
		{"linux", []string{"var/log/x.log"}},
		{"linux", []string{"/var/log/../../etc/shadow"}},
		{"linux", []string{"/var/log/a.log,/etc/shadow"}},
		{"linux", []string{"/var/log/a.log\n[OUTPUT]"}},
		{"linux", []string{"/var/log/$(id).log"}},
		{"linux", []string{"/" + strings.Repeat("a", 300)}},
		{"linux", strings.Split(strings.Repeat("/a.log ", MaxCustomPaths+1), " ")[:MaxCustomPaths+1]},
		{"windows", []string{"/var/log/a.log"}},
		{"linux", []string{"/etc/fluent-bit/fluent-bit.conf"}},
		{"linux", []string{"/etc/fluent-bit/*"}},
		{"linux", []string{"/etc/*/fluent-bit.conf"}},
		{"linux", []string{"/etc/shadow"}},
		{"linux", []string{"/etc/shado*"}},
		{"linux", []string{"/etc/sudoers.d/x"}},
		{"linux", []string{"/var/lib/signalith/state.json"}},
		{"linux", []string{"/opt/app/tls/server.key"}},
		{"linux", []string{"/root/app.log"}},
		{"windows", []string{`C:\ProgramData\fluent-bit\conf\fluent-bit.conf`}},
		{"windows", []string{`d:\programdata\Fluent-Bit\*`}},
		{"windows", []string{`C:\Windows\System32\config\SAM`}},
		{"windows", []string{`C:\Users\bob\.ssh\id_rsa`}},
		{"plan9", []string{"/a.log"}},
	} {
		if _, err := CustomInput("custom.acme", "acme", tc.os, tc.paths); err == nil {
			t.Errorf("%s %q accepted", tc.os, tc.paths)
		}
	}
}
