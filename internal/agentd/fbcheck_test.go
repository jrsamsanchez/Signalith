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
	"runtime"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/agents"
)

// testTail is the input testFluentBit reads, a log on this computer's
// system.
var testTail = func() string {
	if runtime.GOOS == "windows" {
		return `Name tail
    Path C:\Logs\syslog.log`
	}
	return "Name tail\n    Path /var/log/syslog"
}()

// testFluentBit is a Fluent Bit configuration the agent runs, sending to
// the test servers' host; note tells configurations apart.
func testFluentBit(note string) string {
	return "# " + note + "\n[INPUT]\n    " + testTail + "\n\n[OUTPUT]\n    Name http\n    Match *\n    Host 127.0.0.1\n    tls On\n    tls.verify On\n"
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
	state := "/var/lib/signalith-agent/fluent-bit"
	r := fbRules{server: "https://siem.example.com:7779", states: []string{state},
		caFile: []string{"/etc/signalith-agent/ca.pem"}, goos: "linux"}
	good := `# generated
[SERVICE]
    Flush                5
    Daemon               Off
    storage.path         ` + state + `/buffer

[INPUT]
    Name                 tail
    Tag                  linux.auth
    Path                 /var/log/auth.log,/var/log/secure
    DB                   ` + state + `/auth.db
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
    URI                  /api/ingest
    Header               Authorization Bearer ${SIGNALITH_TOKEN}
    Header               X-Signalith-Agent ${HOSTNAME}
    tls                  On
    tls.verify           On
    tls.ca_file          /etc/signalith-agent/ca.pem
`
	if err := checkFluentBit(good, r); err != nil {
		t.Fatalf("good: %v", err)
	}
	if err := checkFluentBit(strings.ReplaceAll(good, "\n", "\r\n"), r); err != nil {
		t.Fatalf("CRLF: %v", err)
	}
	const paths = "/var/log/auth.log,/var/log/secure"
	for _, c := range []struct{ name, old, new, want string }{
		{"exec input", "Name                 systemd", "Name                 exec\n    Command cat /etc/shadow", `input "exec"`},
		{"lua filter", "Name                 sysinfo", "Name                 lua\n    script x.lua", `filter "lua"`},
		{"other host", "Host                 SIEM.example.com", "Host                 evil.example.net", "evil.example.net"},
		{"no tls", "tls                  On", "tls                  Off", "TLS"},
		{"no verify", "tls.verify           On", "tls.verify           Off", "TLS"},
		{"proxy", "tls.verify           On", "tls.verify           On\n    Proxy http://evil:3128", "proxy"},
		{"basic auth", "tls.verify           On", "tls.verify           On\n    http_user x", "http_user"},
		{"client cert", "tls.verify           On", "tls.verify           On\n    tls.crt_file /tmp/c.pem", "tls.crt_file"},
		{"other ca", "tls.ca_file          /etc/signalith-agent/ca.pem", "tls.ca_file          /tmp/evil.pem", "tls.ca_file"},
		{"vhost", "tls.verify           On", "tls.verify           On\n    tls.vhost evil.example.net", "tls.vhost"},
		{"other uri", "URI                  /api/ingest", "URI                  /elsewhere", "/elsewhere"},
		{"other header", "Header               X-Signalith-Agent ${HOSTNAME}", "Header               X-Leak ${SIGNALITH_TOKEN}", "X-Leak"},
		{"token elsewhere", "Header               X-Signalith-Agent ${HOSTNAME}", "Header               X-Signalith-Agent ${SIGNALITH_TOKEN}", "X-Signalith-Agent"},
		{"forward", "Name                 http", "Name                 forward", `output "forward"`},
		{"second output", "[OUTPUT]", "[OUTPUT]\n    Name stdout\n    Match *\n\n[OUTPUT]", `output "stdout"`},
		{"include", "# generated", "@INCLUDE /tmp/x.conf", "@INCLUDE"},
		{"plugins", "Flush                5", "Flush                5\n    plugins_file /tmp/p.conf", "plugins_file"},
		{"parsers", "Flush                5", "Flush                5\n    Parsers_File /tmp/p.conf", "parsers_file"},
		{"log file", "Flush                5", "Flush                5\n    Log_File /etc/cron.d/x", "log_file"},
		{"pid file", "Flush                5", "Flush                5\n    pid_file /etc/cron.d/x", "pid_file"},
		{"http server", "Flush                5", "Flush                5\n    HTTP_Server On", "http_server"},
		{"daemon", "Daemon               Off", "Daemon               On", "daemon"},
		{"plugins section", "# generated", "[PLUGINS]\n    Path /tmp/evil.so", "PLUGINS"},
		{"parser section", "# generated", "[PARSER]\n    Name x", "PARSER"},
		{"secret path", paths, "/var/log/auth.log,/etc/shadow", "/etc/shadow"},
		{"agent token", paths, "/etc/signalith-agent/*", "secrets"},
		{"dot dot", paths, "/var/log/../../etc/shadow", ".."},
		{"relative", paths, "etc/shadow", "must start with /"},
		{"home", paths, "/root/~/.ssh/id_rsa", "~"},
		{"variable path", paths, "${HOME}/.ssh/id_rsa", "variable"},
		{"variable db", state + "/auth.db", "${STATE}/x.db", "variable"},
		{"variable buffer", state + "/buffer", "${STATE}/b", "variable"},
		{"braces", paths, "/var/log/{a,b}.log", "braces"},
		{"db outside", state + "/auth.db", "/etc/cron.d/x", "outside"},
		{"buffer outside", state + "/buffer", "/tmp/b", "outside"},
		{"db dot dot", state + "/auth.db", state + "/../../../etc/cron.d/x", ".."},
		{"unknown key", "Tag                  linux.auth", "Tag                  linux.auth\n    Key_Unknown x", "key_unknown"},
		{"setting outside", "# generated", "Name tail", "outside any section"},
		{"nul", "tls                  On", "tls                  On\x00", "control character"},
		{"lone cr", "Port                 7780\n", "Port                 7780\r    tls Off\n", "carriage return"},
		{"vertical tab", "Port                 7780", "Port                 7780\v", "control character"},
		{"bad utf-8", "# generated", "# generated \xff", "UTF-8"},
		{"long pattern", "Exclude              log ^$", "Exclude              log " + strings.Repeat("a", 600), "longer than"},
		{"uri dot dot", "URI                  /api/ingest", "URI                  /api/../x", "/api/../x"},
		{"uri query", "URI                  /api/ingest", "URI                  /api/ingest?x=1", "?x=1"},
	} {
		conf := strings.Replace(good, c.old, c.new, 1)
		if conf == good {
			t.Fatalf("%s: nothing replaced", c.name)
		}
		if err := checkFluentBit(conf, r); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	if err := checkFluentBit(strings.Replace(good, "# generated", "# généré", 1), r); err != nil {
		t.Errorf("non-ASCII comment: %v", err)
	}
	if err := checkFluentBit("[INPUT]\n    Name tail\n    Path /var/log/x\n", r); err == nil || !strings.Contains(err.Error(), "one output") {
		t.Errorf("no output: %v", err)
	}
	// An address with the agent's own certificate authority may check the
	// certificate against the server's name.
	ip := fbRules{server: "https://10.0.0.5:7779", states: r.states, caFile: r.caFile, goos: "linux"}
	byIP := strings.Replace(good, "SIEM.example.com", "10.0.0.5", 1) + "    tls.vhost siem.example.com\n"
	if err := checkFluentBit(byIP, ip); err != nil {
		t.Errorf("address with vhost: %v", err)
	}
	if err := checkFluentBit(strings.Replace(byIP, "    tls.ca_file          /etc/signalith-agent/ca.pem\n", "", 1), ip); err == nil {
		t.Error("vhost without the agent's certificate authority")
	}

	// Windows: paths do not care about case or the kind of slash.
	wr := fbRules{server: r.server, states: []string{`C:\ProgramData\Signalith Agent\fluent-bit`},
		caFile: []string{`C:\ProgramData\Signalith Agent\ca.pem`}, goos: "windows"}
	win := `[INPUT]
    Name winevtlog
    Channels Security
    DB c:/programdata/signalith agent/FLUENT-BIT/signalith-winevtlog.sqlite

[INPUT]
    Name tail
    Path C:\Logs\app.log

[OUTPUT]
    Name http
    Host siem.example.com
    tls On
    tls.verify On
    tls.ca_file C:\ProgramData\Signalith Agent\ca.pem
`
	if err := checkFluentBit(win, wr); err != nil {
		t.Errorf("windows: %v", err)
	}
	for _, p := range []string{`c:/programdata/SIGNALITH AGENT/token`, `C:\PROGRA~3\Signalith Agent\token`,
		`C:\WINDOWS\SYSTEM~1\config\SAM`, `C:\x.log:stream`, `\\server\share\x.log`, `Logs\app.log`} {
		if err := checkFluentBit(strings.Replace(win, `C:\Logs\app.log`, p, 1), wr); err == nil {
			t.Errorf("windows: tails %s", p)
		}
	}
}

// TestCheckFluentBitTakesWhatSignalithSends: every configuration the
// server hands the agent passes the agent's check.
func TestCheckFluentBitTakesWhatSignalithSends(t *testing.T) {
	const server = "https://siem.example.com:7779"
	ca := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	for _, o := range []agents.Options{
		{OS: "linux", LinuxSource: "file", Sysmon: true, Recycle: 3},
		{OS: "linux", LinuxSource: "file", NoWebLogs: true, NoAuditLog: true},
		{OS: "linux", LinuxSource: "journal", Sysmon: true},
		{OS: "linux", LinuxSource: "file", CA: ca, OwnCA: true},
		{OS: "windows", PowerShell: true, Sysmon: true},
		{OS: "windows", CA: ca, OwnCA: true},
	} {
		o.ServerURL, o.Token, o.Managed = server, agents.EnvToken, true
		a, err := agents.Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		r := fbRules{server: "https://siem.example.com:443", states: []string{agents.ManagedLinuxStateDir + "/fluent-bit"},
			caFile: []string{agents.ManagedLinuxConfDir + "/ca.pem"}, goos: o.OS}
		if o.OS == "windows" {
			r.states = []string{agents.ManagedWindowsDataDir + `\fluent-bit`}
			r.caFile = []string{agents.ManagedWindowsDataDir + `\ca.pem`}
		}
		if err := checkFluentBit(a.Config, r); err != nil {
			t.Errorf("%s %s: %v\n%s", o.OS, o.LinuxSource, err, a.Config)
		}
	}
}

// TestAgentRefusesFluentBitConfig: a configuration that fails the check
// is not written and the one in use keeps running, while the rest of the
// configuration still applies so updates still reach the agent; the
// refusal is reported until a configuration it takes arrives (ASI-03).
func TestAgentRefusesFluentBitConfig(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	a := syncAgent(t, srv.URL)
	ctx := context.Background()
	// stamped is body with its revision set to the sum of its bytes, the
	// one the agent keeps (TestAgentRecomputesRevision).
	stamped := func(body string) (string, string) {
		rev, ok := agentproto.RawRevision([]byte(body))
		if !ok {
			t.Fatalf("no revision in %s", body)
		}
		return strings.Replace(body, `"revision":""`, `"revision":"`+rev+`"`, 1), rev
	}
	body, _ = stamped(`{"revision":"","fluentbit":{"config":` + testFluentBitJSON("r1") + `}}`)
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	bad, _ := json.Marshal(strings.Replace(testFluentBit("r2"), testTail, "Name exec\n    Command id", 1))
	var r2 string
	body, r2 = stamped(`{"revision":"","poll_seconds":60,"fluentbit":{"config":` + string(bad) + `}}`)
	if err := a.sync(ctx); err != nil {
		t.Fatalf("sync = %v", err)
	}
	if b, _ := os.ReadFile(a.Paths.fluentBitConf()); string(b) != testFluentBit("r1") {
		t.Errorf("fluent-bit.conf = %q", b)
	}
	st := a.Status()
	if st.Revision != r2 || !strings.Contains(st.ConfigError, "refused the Fluent Bit configuration") || !strings.Contains(st.ConfigError, `"exec"`) {
		t.Errorf("status = %q, %q", st.Revision, st.ConfigError)
	}
	a.mu.Lock()
	kept, poll := a.cfg.FluentBit, a.cfg.PollSeconds
	a.mu.Unlock()
	if kept == nil || kept.Config != testFluentBit("r1") || poll != 60 {
		t.Errorf("config = %+v, poll %d", kept, poll)
	}
	// Kept on disk the same way, without the revision so the next start
	// asks again.
	if cfg, err := a.loadConfig(); err != nil || cfg.FluentBit == nil || cfg.FluentBit.Config != testFluentBit("r1") || cfg.Revision != "" {
		t.Errorf("config.json = %+v, %v", cfg, err)
	}
	var r3 string
	body, r3 = stamped(`{"revision":"","fluentbit":{"config":` + testFluentBitJSON("r3") + `}}`)
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	if st := a.Status(); st.ConfigError != "" || st.Revision != r3 {
		t.Errorf("after a good one: %q, %q", st.Revision, st.ConfigError)
	}
	if b, _ := os.ReadFile(a.Paths.fluentBitConf()); string(b) != testFluentBit("r3") {
		t.Errorf("fluent-bit.conf = %q", b)
	}
}

// TestAgentChecksFluentBitConfigAtStart: a Fluent Bit configuration on
// disk that fails the check does not run at startup, and the agent asks
// for its configuration again (ASI-03).
func TestAgentChecksFluentBitConfigAtStart(t *testing.T) {
	a := syncAgent(t, "https://127.0.0.1:7779")
	cfg := &agentproto.Config{Revision: "r1", FluentBit: &agentproto.FluentBit{Config: testFluentBit("r1")}}
	os.WriteFile(a.Paths.fluentBitConf(), []byte(testFluentBit("r1")), 0o600)
	a.checkLoaded(cfg)
	if cfg.FluentBit == nil || cfg.Revision != "r1" || a.Status().ConfigError != "" {
		t.Fatalf("good: %+v, %q", cfg, a.Status().ConfigError)
	}
	os.WriteFile(a.Paths.fluentBitConf(), []byte(strings.Replace(testFluentBit("r1"), testTail, "Name exec\n    Command id", 1)), 0o600)
	a.checkLoaded(cfg)
	if cfg.FluentBit != nil || cfg.Revision != "" || !strings.Contains(a.Status().ConfigError, "fails the agent's check") {
		t.Errorf("bad: %+v, %q", cfg, a.Status().ConfigError)
	}
}
