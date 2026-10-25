// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agents"
)

// configMachine is a sensor the dry run installed into a folder, running
// the configuration Signalith generates, with a stub Signalith (curl) that
// serves $STUB/body as the next configuration.
type configMachine struct {
	root, stub, path, dest string
	conf                   string
}

func newConfigMachine(t *testing.T, layout string, args ...string) *configMachine {
	t.Helper()
	m := newSensorMachine(t)
	root, _ := m.install(t, "4", append([]string{"--name", "nsm-01"}, args...)...)
	a, err := agents.Generate(agents.Options{OS: "linux", LinuxSource: "sensor", SensorLayout: layout, Heartbeat: true,
		ServerURL: "https://siem.example.com:8443", Token: agents.EnvToken, Version: "1.6.0", Zeek: true, Suricata: true,
		CA: readFile(t, filepath.Join(m.dir, "ca.pem"))})
	if err != nil {
		t.Fatal(err)
	}
	cm := &configMachine{root: root, stub: filepath.Join(m.dir, "config-stub"), conf: a.Config,
		dest: filepath.Join(root, "etc/signalith-sensor/fluent-bit.conf")}
	if layout == agents.SensorDocker {
		cm.dest = filepath.Join(root, "etc/signalith-sensor/docker/fluent-bit.conf")
	}
	mustWrite(t, cm.dest, a.Config, 0o640)
	bin := filepath.Join(cm.stub, "bin")
	// curl: logs its arguments, checks the token in the header file it is
	// given, and answers with $STUB/body.
	mustWrite(t, filepath.Join(bin, "curl"), `#!/bin/sh
printf '%s\n' "$*" >>"$STUB/argv"
out='' hdr='' w=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -H) hdr=${2#@}; shift 2 ;;
    -w) w=$2; shift 2 ;;
    --cacert | --proto | --max-time | --max-filesize) shift 2 ;;
    *) shift ;;
  esac
done
if [ -f "$STUB/down" ]; then echo "curl: (7) Failed to connect" >&2; printf 000; exit 7; fi
if ! grep -q "^Authorization: Bearer $STUB_TOKEN\$" "$hdr"; then printf '{"error":"no"}' >"$out"; printf 401; exit 0; fi
cp "$STUB/body" "$out"
printf 200
`, 0o755)
	cm.path = bin + string(os.PathListSeparator) + m.path
	return cm
}

func (cm *configMachine) serve(t *testing.T, conf string) {
	t.Helper()
	mustWrite(t, filepath.Join(cm.stub, "body"), conf, 0o644)
}

func (cm *configMachine) run(t *testing.T) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", filepath.Join(cm.root, "usr/lib/signalith-sensor/config-update.sh"))
	cmd.Env = append(os.Environ(), "PATH="+cm.path, "STUB="+cm.stub, "STUB_TOKEN="+testToken, "SIGNALITH_SENSOR_ROOT="+cm.root, "SIGNALITH_TOKEN=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (cm *configMachine) state(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, l := range strings.Split(readFile(t, filepath.Join(cm.root, "var/lib/signalith-sensor/config.state")), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			out[k] = strings.Trim(v, "'")
		}
	}
	return out
}

// The install writes the hourly timer and the helper.
func TestSensorConfigInstalled(t *testing.T) {
	cm := newConfigMachine(t, agents.SensorPackages)
	for _, f := range []string{"etc/systemd/system/signalith-sensor-config.timer", "etc/systemd/system/signalith-sensor-config.service", "usr/lib/signalith-sensor/config-update.sh"} {
		if _, err := os.Stat(filepath.Join(cm.root, f)); err != nil {
			t.Error(err)
		}
	}
}

// The same configuration is left alone; a changed one Signalith
// generates is written, for both layouts, with the token from token.env
// and the question the install line asked.
func TestSensorConfigUpdates(t *testing.T) {
	for _, layout := range []string{agents.SensorPackages, agents.SensorDocker} {
		t.Run(layout, func(t *testing.T) {
			var args []string
			if layout == agents.SensorDocker {
				args = []string{"--docker"}
			}
			cm := newConfigMachine(t, layout, args...)
			cm.serve(t, cm.conf)
			if out, err := cm.run(t); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if st := cm.state(t); st["CONFIG_RESULT"] != "unchanged" {
				t.Fatalf("state %v", st)
			}
			argv := readFile(t, filepath.Join(cm.stub, "argv"))
			for _, want := range []string{"/api/sensor/config?server=https://siem.example.com:8443&layout=" + layout + "&zeek=true&suricata=true&protocols=false", "--proto =https", "--cacert"} {
				if !strings.Contains(argv, want) {
					t.Errorf("curl %q, want %q", argv, want)
				}
			}
			if strings.Contains(argv, testToken) {
				t.Error("the token is on curl's command line")
			}
			next := strings.Replace(cm.conf, "Mem_Buf_Limit        50MB", "Mem_Buf_Limit        80MB", 1)
			if next == cm.conf {
				t.Fatal("test configuration has no Mem_Buf_Limit 50MB")
			}
			cm.serve(t, strings.ReplaceAll(next, "\n", "\r\n"))
			if out, err := cm.run(t); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if st := cm.state(t); st["CONFIG_RESULT"] != "applied" || st["CONFIG_APPLIED"] == "" {
				t.Fatalf("state %v", st)
			}
			if got := readFile(t, cm.dest); got != next {
				t.Errorf("written:\n%s", got)
			}
			fi, err := os.Stat(cm.dest)
			want := os.FileMode(0o640)
			if layout == agents.SensorDocker {
				want = 0o644
			}
			if err != nil || fi.Mode().Perm() != want {
				t.Errorf("mode %v %v, want %v", fi.Mode().Perm(), err, want)
			}
		})
	}
}

// A configuration that would run a program, read other files, send
// elsewhere or drop the certificate check is refused, and the one in use
// kept.
func TestSensorConfigRefused(t *testing.T) {
	cm := newConfigMachine(t, agents.SensorPackages)
	out := "[OUTPUT]\n    Name                 http\n"
	for name, c := range map[string]struct{ old, new string }{
		"exec input":        {"    Name                 tail\n    Tag                  zeek.*", "    Name                 exec\n    Command              id\n    Tag                  zeek.*"},
		"other files":       {"/opt/zeek/logs/current/*.log", "/etc/shadow"},
		"dot dot":           {"/opt/zeek/logs/current/*.log", "/opt/zeek/logs/../../../etc/shadow"},
		"include":           {"[SERVICE]", "@INCLUDE /tmp/x.conf\n[SERVICE]"},
		"other host":        {"Host                 siem.example.com", "Host                 evil.example"},
		"other port":        {"Port                 8443", "Port                 9443"},
		"no tls verify":     {"tls.verify           On", "tls.verify           Off"},
		"other ca":          {"tls.ca_file          /etc/signalith-sensor/ca.pem", "tls.ca_file          /tmp/ca.pem"},
		"other header":      {"Header               X-Signalith-Agent ${HOSTNAME}", "Header               X-Signalith-Agent ${HOSTNAME}\n    Header               X-Forward ${SIGNALITH_TOKEN}"},
		"token elsewhere":   {"Record               hostname ${HOSTNAME}", "Record               hostname ${SIGNALITH_TOKEN}"},
		"second output":     {out, "[OUTPUT]\n    Name                 http\n    Match                *\n    Host                 siem.example.com\n\n" + out},
		"storage elsewhere": {"storage.path         /var/lib/signalith-sensor/agent/buffer", "storage.path         /etc/signalith-sensor"},
		"http server":       {"[SERVICE]\n", "[SERVICE]\n    HTTP_Server          On\n"},
		"debug log level":   {"Log_Level            info", "Log_Level            debug"},
		"no hostname check": {"    tls.verify_hostname  On\n", ""},
		"lua filter":        {"    Name                 record_modifier\n    Match                zeek.*", "    Name                 lua\n    Match                zeek.*\n    script               /tmp/x.lua"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(cm.conf, c.old, c.new, 1)
			if bad == cm.conf {
				t.Fatalf("%q not in the configuration", c.old)
			}
			cm.serve(t, bad)
			if _, err := cm.run(t); err == nil {
				t.Error("no error")
			}
			t.Log(cm.state(t)["CONFIG_ERROR"])
			if st := cm.state(t); st["CONFIG_RESULT"] != "refused" {
				t.Errorf("state %v", st)
			}
			if got := readFile(t, cm.dest); got != cm.conf {
				t.Error("the configuration in use was changed")
			}
		})
	}
}

// A failed fetch or a refused token keeps the configuration in use.
func TestSensorConfigFetchFails(t *testing.T) {
	cm := newConfigMachine(t, agents.SensorPackages)
	cm.serve(t, "anything")
	mustWrite(t, filepath.Join(cm.stub, "down"), "", 0o644)
	if _, err := cm.run(t); err == nil {
		t.Error("no error while Signalith is down")
	}
	if st := cm.state(t); st["CONFIG_RESULT"] != "failed" || !strings.Contains(st["CONFIG_ERROR"], "could not be reached") {
		t.Errorf("state %v", st)
	}
	if got := readFile(t, cm.dest); got != cm.conf {
		t.Error("the configuration in use was changed")
	}
}
