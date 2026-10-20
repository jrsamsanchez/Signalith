// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agents"
)

// testFluentBit is a Fluent Bit configuration the agent runs, sending to
// the test servers' host; note tells configurations apart.
func testFluentBit(note string) string {
	return "# " + note + "\n[INPUT]\n    Name tail\n    Path /var/log/syslog\n\n[OUTPUT]\n    Name http\n    Match *\n    Host 127.0.0.1\n    tls On\n    tls.verify On\n"
}

// testFluentBitJSON is testFluentBit as a JSON string.
func testFluentBitJSON(note string) string {
	b, _ := json.Marshal(testFluentBit(note))
	return string(b)
}

// TestCheckFluentBit: the agent runs a configuration that reads logs and
// sends them to its own server, and refuses one that runs programs,
// loads plugins, reads secrets or sends anywhere else (ASI-03).
func TestCheckFluentBit(t *testing.T) {
	state := filepath.Join(t.TempDir(), "fluent-bit")
	const server = "https://siem.example.com:7779"
	good := `# generated
[SERVICE]
    Flush                5
    storage.path         ` + filepath.Join(state, "buffer") + `

[INPUT]
    Name                 tail
    Tag                  linux.auth
    Path                 /var/log/auth.log,/var/log/secure
    DB                   ` + filepath.Join(state, "auth.db") + `
    storage.type         filesystem

[INPUT]
    Name                 systemd
    Systemd_Filter       _SYSTEMD_UNIT=sshd.service

[FILTER]
    Name                 sysinfo
    Match                *

[FILTER]
    Name                 grep
    Match                linux.*
    Exclude              log ^$

[OUTPUT]
    Name                 http
    Match                *
    Host                 SIEM.example.com
    Port                 7780
    Header               Authorization Bearer ${SIGNALITH_TOKEN}
    tls                  On
    tls.verify           On
`
	if err := checkFluentBit(good, server, []string{state}, "linux"); err != nil {
		t.Fatalf("good: %v", err)
	}
	if err := checkFluentBit(strings.ReplaceAll(good, "\n", "\r\n"), server, []string{state}, "linux"); err != nil {
		t.Fatalf("CRLF: %v", err)
	}
	for _, c := range []struct{ name, old, new, want string }{
		{"exec input", "Name                 systemd", "Name                 exec\n    Command cat /etc/shadow", `input "exec"`},
		{"lua filter", "Name                 sysinfo", "Name                 lua\n    script x.lua", `filter "lua"`},
		{"other host", "Host                 SIEM.example.com", "Host                 evil.example.net", "evil.example.net"},
		{"no tls", "tls                  On", "tls                  Off", "TLS"},
		{"no verify", "tls.verify           On", "tls.verify           Off", "TLS"},
		{"proxy", "tls.verify           On", "tls.verify           On\n    Proxy http://evil:3128", "proxy"},
		{"forward", "Name                 http", "Name                 forward", `output "forward"`},
		{"second output", "[OUTPUT]", "[OUTPUT]\n    Name stdout\n    Match *\n\n[OUTPUT]", `output "stdout"`},
		{"include", "# generated", "@INCLUDE /tmp/x.conf", "@INCLUDE"},
		{"plugins", "Flush                5", "Flush                5\n    plugins_file /tmp/p.conf", "plugins_file"},
		{"http server", "Flush                5", "Flush                5\n    HTTP_Server On", "http_server"},
		{"plugins section", "# generated", "[PLUGINS]\n    Path /tmp/evil.so", "PLUGINS"},
		{"secret path", "/var/log/auth.log,/var/log/secure", "/var/log/auth.log,/etc/shadow", "/etc/shadow"},
		{"agent token", "/var/log/auth.log,/var/log/secure", "/etc/signalith-agent/*", "secrets"},
		{"db outside", filepath.Join(state, "auth.db"), "/etc/cron.d/x", "outside"},
		{"buffer outside", filepath.Join(state, "buffer"), "/tmp/b", "outside"},
		{"setting outside", "# generated", "Name tail", "outside any section"},
	} {
		conf := strings.Replace(good, c.old, c.new, 1)
		if conf == good {
			t.Fatalf("%s: nothing replaced", c.name)
		}
		if err := checkFluentBit(conf, server, []string{state}, "linux"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	if err := checkFluentBit("[INPUT]\n    Name tail\n    Path /var/log/x\n", server, []string{state}, "linux"); err == nil || !strings.Contains(err.Error(), "one output") {
		t.Errorf("no output: %v", err)
	}

	// Windows: paths do not care about case or the kind of slash.
	win := `[INPUT]
    Name winevtlog
    Channels Security
    DB ` + `C:\ProgramData\Signalith Agent\fluent-bit\signalith-winevtlog.sqlite` + `

[INPUT]
    Name tail
    Path C:\Logs\app.log

[OUTPUT]
    Name http
    Host siem.example.com
    tls On
    tls.verify On
`
	if err := checkFluentBit(win, server, []string{`C:\ProgramData\Signalith Agent\fluent-bit`}, "windows"); err != nil {
		t.Errorf("windows: %v", err)
	}
	if err := checkFluentBit(strings.Replace(win, `C:\Logs\app.log`, `c:/programdata/SIGNALITH AGENT/token`, 1), server, []string{`C:\ProgramData\Signalith Agent\fluent-bit`}, "windows"); err == nil {
		t.Error("windows: tails the agent's token")
	}
}

// TestCheckFluentBitTakesWhatSignalithSends: every configuration the
// server hands the agent passes the agent's check.
func TestCheckFluentBitTakesWhatSignalithSends(t *testing.T) {
	const server = "https://siem.example.com:7779"
	ca := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	for _, c := range []struct {
		o     agents.Options
		state string
	}{
		{agents.Options{OS: "linux", LinuxSource: "file", Sysmon: true, Recycle: 3}, agents.ManagedLinuxStateDir},
		{agents.Options{OS: "linux", LinuxSource: "file", NoWebLogs: true, NoAuditLog: true}, agents.ManagedLinuxStateDir},
		{agents.Options{OS: "linux", LinuxSource: "journal", Sysmon: true}, agents.ManagedLinuxStateDir},
		{agents.Options{OS: "windows", PowerShell: true, Sysmon: true}, agents.ManagedWindowsDataDir},
		{agents.Options{OS: "windows", CA: ca, OwnCA: true}, agents.ManagedWindowsDataDir},
	} {
		o := c.o
		o.ServerURL, o.Token, o.Managed = server, agents.EnvToken, true
		a, err := agents.Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		state := c.state + "/fluent-bit"
		if o.OS == "windows" {
			state = c.state + `\fluent-bit`
		}
		if err := checkFluentBit(a.Config, "https://siem.example.com:443", []string{state}, o.OS); err != nil {
			t.Errorf("%s %s: %v\n%s", o.OS, o.LinuxSource, err, a.Config)
		}
	}
}

// TestAgentRefusesFluentBitConfig: a configuration that fails the check
// is not written, and the one in use keeps running (ASI-03).
func TestAgentRefusesFluentBitConfig(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	a := syncAgent(t, srv.URL)
	ctx := context.Background()
	body = `{"revision":"r1","fluentbit":{"config":` + testFluentBitJSON("r1") + `}}`
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	bad, _ := json.Marshal(strings.Replace(testFluentBit("r2"), "Name tail\n    Path /var/log/syslog", "Name exec\n    Command id", 1))
	body = `{"revision":"r2","fluentbit":{"config":` + string(bad) + `}}`
	if err := a.sync(ctx); err == nil || !strings.Contains(err.Error(), `refused the Fluent Bit configuration`) || !strings.Contains(err.Error(), `"exec"`) {
		t.Fatalf("sync = %v", err)
	}
	if b, _ := os.ReadFile(a.Paths.fluentBitConf()); string(b) != testFluentBit("r1") {
		t.Errorf("fluent-bit.conf = %q", b)
	}
	if a.Status().Revision != "r1" {
		t.Errorf("revision = %q", a.Status().Revision)
	}
}
