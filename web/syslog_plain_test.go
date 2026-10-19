// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"io/fs"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The Add data page's Syslog option turns on plain syslog with one click
// for admins: it saves syslog.udp and syslog.tcp with the Settings page's
// own save (PUT api/settings), warns that plain syslog is unencrypted and
// can be forged, and then offers the Settings page's Restart now.
func TestAddDataPlainSyslogButton(t *testing.T) {
	b, err := fs.ReadFile(FS(), "app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := strings.ReplaceAll(string(b), "\r\n", "\n")
	for _, want := range []string{
		"'Turn on plain syslog (UDP and TCP)'",
		"api('api/settings', { values }, 'PUT')",
		"if (!can('admin'))",
		"Plain syslog is unencrypted, and anyone who can reach the port can send fake events.",
		"window.openRestart",
		"values: { 'syslog.udp': addr, 'syslog.tcp': addr }",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	set, err := fs.ReadFile(FS(), "settings.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(set), "window.openRestart = () =>") {
		t.Error("settings.js does not define window.openRestart, which the Add data page opens Restart now with")
	}

	// The port each system listens on, run in Node when it is installed.
	fn := regexp.MustCompile(`(?s)\nfunction syslogPlainPlan\(rt\) \{.*?\n\}\n`).FindString(src)
	if fn == "" {
		t.Fatal("app.js has no function syslogPlainPlan(rt)")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	script := fn + `
const cases = {
  service: { os: 'linux', systemd: true, low_ports: true },
  serviceWithoutCapability: { os: 'linux', systemd: true, low_ports: false },
  byHand: { os: 'linux', systemd: false, low_ports: false },
  docker: { os: 'linux', container: true, low_ports: false },
  windows: { os: 'windows', low_ports: true },
};
const out = {};
for (const [k, rt] of Object.entries(cases)) out[k] = syslogPlainPlan(rt);
out.none = syslogPlainPlan(undefined);
console.log(JSON.stringify(out));
`
	cmd := exec.Command(node, "-e", script)
	res, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	type plan struct {
		Port       int               `json:"port"`
		SendTo     int               `json:"sendTo"`
		Capability bool              `json:"capability"`
		Values     map[string]string `json:"values"`
	}
	var got map[string]plan
	if err := json.Unmarshal(res, &got); err != nil {
		t.Fatalf("%v: %s", err, res)
	}
	for name, want := range map[string]plan{
		"service":                  {Port: 514, SendTo: 514},
		"serviceWithoutCapability": {Port: 514, SendTo: 514, Capability: true},
		"byHand":                   {Port: 1514, SendTo: 1514},
		"docker":                   {Port: 5514, SendTo: 514},
		"windows":                  {Port: 514, SendTo: 514},
		"none":                     {Port: 514, SendTo: 514},
	} {
		g := got[name]
		addr := "0.0.0.0:" + strconv.Itoa(want.Port)
		if g.Port != want.Port || g.SendTo != want.SendTo || g.Capability != want.Capability || g.Values["syslog.udp"] != addr || g.Values["syslog.tcp"] != addr || len(g.Values) != 2 {
			t.Errorf("%s: %+v, want %+v with syslog.udp and syslog.tcp %s", name, g, want, addr)
		}
	}
}
