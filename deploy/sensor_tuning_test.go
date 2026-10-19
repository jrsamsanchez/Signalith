// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sensortune"
)

// tuningMachine is a sensor the dry run installed into a folder, with a
// stub Signalith that serves the rule tuning (curl) and a stub
// suricata-update that passes or fails as the test says.
type tuningMachine struct {
	m          *sensorMachine
	root, stub string
	path       string
}

func newTuningMachine(t *testing.T, args ...string) *tuningMachine {
	t.Helper()
	m := newSensorMachine(t)
	root, _ := m.install(t, "4", append([]string{"--name", "nsm-01"}, args...)...)
	tm := &tuningMachine{m: m, root: root, stub: filepath.Join(m.dir, "tuning-stub")}
	bin := filepath.Join(tm.stub, "bin")
	// curl: logs its arguments, checks the token in the header file it
	// is given, and answers with $STUB/body and its ETag, or 304 for the
	// ETag the sensor has.
	mustWrite(t, filepath.Join(bin, "curl"), `#!/bin/sh
printf '%s\n' "$*" >>"$STUB/argv"
out='' head='' hdr='' w=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -D) head=$2; shift 2 ;;
    -H) hdr=${2#@}; shift 2 ;;
    -w) w=$2; shift 2 ;;
    --cacert | --proto | --max-time | --max-filesize) shift 2 ;;
    *) shift ;;
  esac
done
cp "$hdr" "$STUB/last-header"
if [ -f "$STUB/down" ]; then echo "curl: (7) Failed to connect" >&2; printf 000; exit 7; fi
if ! grep -q "^Authorization: Bearer $STUB_TOKEN\$" "$hdr"; then printf '{"error":"no"}' >"$out"; printf 401; exit 0; fi
etag=$(cat "$STUB/etag")
if grep -q "^If-None-Match: \"$etag\"\$" "$hdr"; then : >"$out"; printf 'HTTP/1.1 304 Not Modified\r\n\r\n' >"$head"; printf 304; exit 0; fi
cp "$STUB/body" "$out"
printf 'HTTP/1.1 200 OK\r\nETag: "%s"\r\n\r\n' "$etag" >"$head"
printf 200
`, 0o755)
	// suricata-update: logs its arguments and the tuning it was given;
	// fails while $STUB/fail exists (a failed download), or while the
	// tuning holds the SID in $STUB/refuse (a refused tuning); hangs while
	// $STUB/hang exists.
	mustWrite(t, filepath.Join(bin, "suricata-update"), `#!/bin/sh
printf '%s\n' "$*" >>"$STUB/su-argv"
for a in "$@"; do
  case "$a" in */tuning/disable.conf) cp "$a" "$STUB/su-disable" ;; esac
done
if [ -f "$STUB/hang" ]; then sleep 30; fi
if [ -f "$STUB/fail" ]; then echo "1/1/2026 -- 10:00:00 - <Error> -- Failed to download https://rules.emergingthreats.net/: name resolution"; exit 1; fi
if [ -f "$STUB/refuse" ] && grep -q "$(cat "$STUB/refuse")" "$STUB/su-disable"; then echo "1/1/2026 -- 10:00:00 - <Error> -- Suricata test failed: bad threshold"; exit 1; fi
for a in "$@"; do last=$a; done
data=$(printf '%s\n' "$*" | sed -n 's/.*--data-dir \([^ ]*\).*/\1/p')
mkdir -p "$data/rules"
printf 'alert ip any any -> any any (sid:1;)\nalert ip any any -> any any (sid:2;)\n' >"$data/rules/suricata.rules"
exit 0
`, 0o755)
	mustWrite(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\nexit 1\n", 0o755)
	tm.path = bin + string(os.PathListSeparator) + m.path
	return tm
}

// serve makes the stub Signalith serve tuning, with its real ETag unless
// etag is given.
func (tm *tuningMachine) serve(t *testing.T, tu sensortune.Tuning, etag string) {
	t.Helper()
	if etag == "" {
		etag = tu.Hash()
	}
	mustWrite(t, filepath.Join(tm.stub, "body"), string(tu.Bundle()), 0o644)
	mustWrite(t, filepath.Join(tm.stub, "etag"), etag, 0o644)
}

// refuse makes the stub suricata-update fail while the disable.conf it
// is given holds sid, as a refused tuning; "" stops that.
func (tm *tuningMachine) refuse(t *testing.T, sid string) {
	t.Helper()
	p := filepath.Join(tm.stub, "refuse")
	if sid == "" {
		os.Remove(p)
		return
	}
	mustWrite(t, p, sid, 0o644)
}

func (tm *tuningMachine) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(tm.root, "usr/lib/signalith-sensor/rules-update.sh")}, args...)...)
	cmd.Env = append(os.Environ(), "PATH="+tm.path, "STUB="+tm.stub, "STUB_TOKEN="+testToken, "SIGNALITH_SENSOR_ROOT="+tm.root, "SIGNALITH_TOKEN=",
		"SIGNALITH_RULES_TIMEOUT=2")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (tm *tuningMachine) file(t *testing.T, name string) string {
	t.Helper()
	return readFile(t, filepath.Join(tm.root, "var/lib/signalith-sensor/tuning", name))
}

func (tm *tuningMachine) state(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, l := range strings.Split(tm.file(t, "tuning.state"), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			out[k] = strings.Trim(v, "'")
		}
	}
	return out
}

// The install writes the tuning folder Suricata reads, with your own
// disable.conf and threshold.config in it, and the tuning timer.
func TestSensorTuningInstalled(t *testing.T) {
	tm := newTuningMachine(t)
	yaml := readFile(t, filepath.Join(tm.root, "etc/suricata/signalith-sensor.yaml"))
	if !strings.Contains(yaml, "threshold-file: /var/lib/signalith-sensor/tuning/threshold.config\n") {
		t.Errorf("threshold-file:\n%s", yaml)
	}
	for _, f := range []string{"disable.conf", "threshold.config"} {
		got := tm.file(t, f)
		if !strings.HasPrefix(got, readFile(t, filepath.Join(tm.root, "etc/suricata", f))) || !strings.Contains(got, "# From Signalith") {
			t.Errorf("%s:\n%s", f, got)
		}
	}
	if fi, err := os.Stat(filepath.Join(tm.root, "var/lib/signalith-sensor/tuning/server.local.rules")); err != nil || fi.Size() != 0 {
		t.Errorf("server.local.rules: %v", err)
	}
	for unit, want := range map[string]string{
		"signalith-sensor-tuning.service":   "ExecStart=/usr/lib/signalith-sensor/rules-update.sh tuning\n# The sensor's token, to fetch the tuning (only root reads the file).\nEnvironmentFile=/etc/signalith-sensor/token.env\n",
		"signalith-sensor-tuning.timer":     "OnUnitActiveSec=10min\n",
		"signalith-suricata-update.service": "EnvironmentFile=/etc/signalith-sensor/token.env\n",
	} {
		got := readFile(t, filepath.Join(tm.root, "etc/systemd/system", unit))
		if !strings.Contains(got, want) || (strings.HasSuffix(unit, ".service") && !strings.Contains(got, "ProtectSystem=strict\n")) {
			t.Errorf("%s:\n%s", unit, got)
		}
	}
	// Docker: the containers read the same folder.
	tm = newTuningMachine(t, "--docker")
	yaml = readFile(t, filepath.Join(tm.root, "etc/signalith-sensor/docker/suricata/signalith-sensor.yaml"))
	if !strings.Contains(yaml, "threshold-file: /etc/suricata/signalith-tuning/threshold.config\n") {
		t.Errorf("Docker threshold-file:\n%s", yaml)
	}
	if got := tm.file(t, "disable.conf"); !strings.HasPrefix(got, readFile(t, filepath.Join(tm.root, "etc/signalith-sensor/docker/suricata/disable.conf"))) {
		t.Errorf("Docker disable.conf:\n%s", got)
	}
}

func TestSensorTuningFetch(t *testing.T) {
	tm := newTuningMachine(t)
	one := sensortune.Tuning{Disable: "2014520\n# noisy", Threshold: "suppress gen_id 1, sig_id 2013028, track by_src, ip 10.0.0.5",
		Local: "alert tcp any any -> $HOME_NET 23 (msg:\"Telnet\"; sid:1000001; rev:1;)"}
	tm.serve(t, one, "")
	if out, err := tm.run(t, "tuning"); err != nil {
		t.Fatalf("tuning: %v\n%s", err, out)
	}
	if got := tm.file(t, "server.disable.conf"); got != one.Disable+"\n" {
		t.Errorf("server.disable.conf: %q", got)
	}
	if got := tm.file(t, "server.local.rules"); got != one.Local+"\n" {
		t.Errorf("server.local.rules: %q", got)
	}
	if got := tm.file(t, "threshold.config"); !strings.HasSuffix(got, "# From Signalith (Settings > Network sensors), fetched by rules-update.sh:\n"+one.Threshold+"\n") {
		t.Errorf("threshold.config:\n%s", got)
	}
	if got := tm.file(t, "etag"); got != one.Hash()+"\n" {
		t.Errorf("etag: %q", got)
	}
	st := tm.state(t)
	if st["TUNING_HASH"] != one.Hash()[:12] || st["TUNING_RESULT"] != "ok" || st["TUNING_APPLIED"] == "" {
		t.Errorf("state: %v", st)
	}
	// suricata-update tested the merged disable.conf and both local files;
	// with no download kept yet, it downloaded.
	su := readFile(t, filepath.Join(tm.stub, "su-argv"))
	for _, want := range []string{"--disable-conf " + filepath.Join(tm.root, "var/lib/signalith-sensor/tuning/disable.conf"),
		"--local " + filepath.Join(tm.root, "var/lib/signalith-sensor/tuning/server.local.rules"), "--fail"} {
		if !strings.Contains(su, want) {
			t.Errorf("suricata-update %s: no %q", su, want)
		}
	}
	if strings.Contains(su, "--offline") || !strings.Contains(readFile(t, filepath.Join(tm.stub, "su-disable")), "2014520") {
		t.Errorf("suricata-update: %s", su)
	}
	if rs := readFile(t, filepath.Join(tm.root, "var/lib/signalith-sensor/rules.state")); !strings.Contains(rs, "RULES_UPDATE='ok'") || !strings.Contains(rs, "RULES_COUNT='2'") {
		t.Errorf("rules.state: %s", rs)
	}
	// The token went in a header file, never on curl's command line.
	if argv := readFile(t, filepath.Join(tm.stub, "argv")); strings.Contains(argv, testToken) || !strings.Contains(argv, "--proto =https") || !strings.Contains(argv, "--cacert") {
		t.Errorf("curl's arguments: %s", argv)
	}

	// Unchanged: 304, nothing run.
	os.Remove(filepath.Join(tm.stub, "su-argv"))
	if out, err := tm.run(t, "tuning"); err != nil {
		t.Fatalf("again: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(tm.stub, "su-argv")); err == nil {
		t.Error("suricata-update ran for an unchanged tuning")
	}
	if !strings.Contains(readFile(t, filepath.Join(tm.stub, "last-header")), `If-None-Match: "`+one.Hash()+`"`) {
		t.Error("no If-None-Match")
	}

	// A tuning that fails its test (the stub refuses 2014521 only, so the
	// rules pass without it): the one before stays, and is not tried
	// again until it changes. With a download kept, it rebuilds offline.
	mustWrite(t, filepath.Join(tm.root, "var/lib/signalith-sensor/suricata/update/cache/etopen.tar.gz"), "x", 0o644)
	two := sensortune.Tuning{Disable: "2014521"}
	tm.serve(t, two, "")
	tm.refuse(t, "2014521")
	if _, err := tm.run(t, "tuning"); err == nil {
		t.Error("a failed tuning exited 0")
	}
	if got := tm.file(t, "server.disable.conf"); got != one.Disable+"\n" {
		t.Errorf("after failure, server.disable.conf: %q", got)
	}
	if got := tm.file(t, "disable.conf"); !strings.Contains(got, "2014520") || strings.Contains(got, "2014521") {
		t.Errorf("after failure, disable.conf: %q", got)
	}
	if got := tm.file(t, "etag"); got != one.Hash()+"\n" {
		t.Errorf("after failure, etag: %q", got)
	}
	st = tm.state(t)
	if st["TUNING_RESULT"] != "failed" || st["TUNING_HASH"] != one.Hash()[:12] || !strings.Contains(st["TUNING_ERROR"], "Suricata test failed: bad threshold") {
		t.Errorf("failed state: %v", st)
	}
	if st["TUNING_FAILED"] != two.Hash() {
		t.Errorf("TUNING_FAILED: %v", st)
	}
	if su := readFile(t, filepath.Join(tm.stub, "su-argv")); strings.Count(su, "--offline") != 2 || strings.Count(su, "\n") != 2 {
		t.Errorf("not tried offline, with then without the tuning: %s", su)
	}
	os.Remove(filepath.Join(tm.stub, "su-argv"))
	tm.refuse(t, "")
	if out, err := tm.run(t, "tuning"); err != nil {
		t.Fatalf("the failed one again: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(tm.stub, "su-argv")); err == nil || tm.state(t)["TUNING_RESULT"] != "failed" {
		t.Error("the failed tuning was tried again unchanged")
	}

	// The status line reports it.
	if err := os.MkdirAll(filepath.Join(tm.root, "var/log/signalith-sensor"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join(tm.root, "usr/lib/signalith-sensor/status.sh"))
	cmd.Env = append(os.Environ(), "PATH="+tm.m.path, "SIGNALITH_SENSOR_ROOT="+tm.root, "SIGNALITH_SENSOR_SYSFS="+filepath.Join(tm.m.dir, "sys"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("status.sh: %v\n%s", err, out)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(readFile(t, filepath.Join(tm.root, "var/log/signalith-sensor/status.json")))), &line); err != nil {
		t.Fatal(err)
	}
	tu, _ := line["tuning"].(map[string]any)
	if tu["hash"] != one.Hash()[:12] || tu["result"] != "failed" || tu["failed"] != two.Hash()[:12] || !strings.Contains(tu["error"].(string), "bad threshold") || !strings.Contains(jsonString(t, line["warnings"]), `"tuning_failed"`) {
		t.Errorf("status line: %v", line)
	}

	// Fixed on Signalith: applied.
	three := sensortune.Tuning{Disable: "2014522"}
	tm.serve(t, three, "")
	if out, err := tm.run(t, "tuning"); err != nil || tm.state(t)["TUNING_RESULT"] != "ok" || tm.file(t, "server.disable.conf") != "2014522\n" {
		t.Errorf("fixed: %v %v\n%s", err, tm.state(t), out)
	}
}

// What does not come whole from Signalith is never applied.
func TestSensorTuningRefusesBadBodies(t *testing.T) {
	tm := newTuningMachine(t)
	good := sensortune.Tuning{Disable: "2014520"}
	cut := strings.TrimSuffix(string(good.Bundle()), "[end]\n")
	for name, c := range map[string]struct{ body, etag string }{
		"cut short":     {cut, ""},
		"wrong etag":    {string(good.Bundle()), strings.Repeat("0", 64)},
		"other format":  {"# something else\n[disable]\n1\n[end]\n", ""},
		"unknown block": {"# signalith-sensor-tuning 1\n[disable]\n1\n[shell]\nreboot\n[end]\n", ""},
	} {
		mustWrite(t, filepath.Join(tm.stub, "body"), c.body, 0o644)
		etag := c.etag
		if etag == "" {
			etag = sha256Hex(c.body)
		}
		mustWrite(t, filepath.Join(tm.stub, "etag"), etag, 0o644)
		if out, err := tm.run(t, "tuning"); err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		if _, err := os.Stat(filepath.Join(tm.root, "var/lib/signalith-sensor/tuning/server.disable.conf")); err == nil {
			t.Errorf("%s: applied", name)
		}
		if st := tm.state(t); st["TUNING_RESULT"] != "unreachable" || st["TUNING_ERROR"] == "" {
			t.Errorf("%s: state %v", name, st)
		}
	}
	// Signalith down: the tuning in use stays.
	mustWrite(t, filepath.Join(tm.stub, "down"), "", 0o644)
	if out, err := tm.run(t, "tuning"); err != nil || !strings.Contains(tm.state(t)["TUNING_ERROR"], "could not be reached") {
		t.Errorf("down: %v %v\n%s", err, tm.state(t), out)
	}
	if _, err := tm.run(t, "bogus"); err == nil {
		t.Error("an unknown mode ran")
	}
}

// The daily update applies a new tuning with the new rules, and when they
// fail together, updates the rules without it.
func TestSensorTuningDaily(t *testing.T) {
	tm := newTuningMachine(t)
	one := sensortune.Tuning{Disable: "2014520"}
	tm.serve(t, one, "")
	if out, err := tm.run(t); err != nil || tm.state(t)["TUNING_RESULT"] != "ok" || strings.Contains(readFile(t, filepath.Join(tm.stub, "su-argv")), "--offline") {
		t.Fatalf("daily: %v %v\n%s", err, tm.state(t), out)
	}
	// A tuning suricata-update refuses (the stub fails only when it sees
	// 2014521): the rules still update, without it.
	tm.refuse(t, "2014521")
	tm.serve(t, sensortune.Tuning{Disable: "2014521"}, "")
	out, err := tm.run(t)
	if err != nil {
		t.Fatalf("daily with a bad tuning: %v\n%s", err, out)
	}
	if st := tm.state(t); st["TUNING_RESULT"] != "failed" || st["TUNING_HASH"] != one.Hash()[:12] {
		t.Errorf("state: %v", st)
	}
	if rs := readFile(t, filepath.Join(tm.root, "var/lib/signalith-sensor/rules.state")); !strings.Contains(rs, "RULES_UPDATE='ok'") {
		t.Errorf("rules.state: %s", rs)
	}
	if got := tm.file(t, "server.disable.conf"); got != "2014520\n" {
		t.Errorf("server.disable.conf: %q", got)
	}
}

// A failed download is not a refused tuning: when the rules fail without
// the tuning too, the tuning is not marked as failed, and the next run
// tries it again.
func TestSensorTuningDownloadFails(t *testing.T) {
	for _, mode := range []string{"tuning", "daily"} {
		t.Run(mode, func(t *testing.T) {
			tm := newTuningMachine(t)
			var args []string
			if mode == "tuning" {
				args = []string{"tuning"}
			}
			one := sensortune.Tuning{Disable: "2014520", Local: "alert tcp any any -> $HOME_NET 23 (msg:\"Telnet\"; sid:1000001; rev:1;)"}
			tm.serve(t, one, "")
			mustWrite(t, filepath.Join(tm.stub, "fail"), "", 0o644)
			if _, err := tm.run(t, args...); err == nil {
				t.Error("a failed download exited 0")
			}
			st := tm.state(t)
			if st["TUNING_FAILED"] != "" || st["TUNING_RESULT"] != "unreachable" || !strings.Contains(st["TUNING_ERROR"], "Failed to download") {
				t.Errorf("state: %v", st)
			}
			if got := tm.file(t, "server.disable.conf"); got != "" {
				t.Errorf("server.disable.conf: %q", got)
			}
			if su := readFile(t, filepath.Join(tm.stub, "su-argv")); strings.Count(su, "\n") != 2 || strings.Contains(su, "--offline") {
				t.Errorf("suricata-update: %s", su)
			}
			// The download works again: the same tuning is applied.
			os.Remove(filepath.Join(tm.stub, "fail"))
			if out, err := tm.run(t, args...); err != nil {
				t.Fatalf("again: %v\n%s", err, out)
			}
			if st := tm.state(t); st["TUNING_RESULT"] != "ok" || st["TUNING_HASH"] != one.Hash()[:12] || tm.file(t, "server.disable.conf") != "2014520\n" {
				t.Errorf("again: %v", st)
			}
		})
	}
}

// The daily update tests a new tuning from the last download first, then
// downloads the rules with the tuning that passed.
func TestSensorTuningDailyOfflineFirst(t *testing.T) {
	tm := newTuningMachine(t)
	mustWrite(t, filepath.Join(tm.root, "var/lib/signalith-sensor/suricata/update/cache/etopen.tar.gz"), "x", 0o644)
	one := sensortune.Tuning{Disable: "2014520"}
	tm.serve(t, one, "")
	if out, err := tm.run(t); err != nil {
		t.Fatalf("daily: %v\n%s", err, out)
	}
	su := strings.Split(strings.TrimSpace(readFile(t, filepath.Join(tm.stub, "su-argv"))), "\n")
	if len(su) != 2 || !strings.Contains(su[0], "--offline") || strings.Contains(su[1], "--offline") {
		t.Errorf("suricata-update: %q", su)
	}
	if st := tm.state(t); st["TUNING_RESULT"] != "ok" || !strings.Contains(readFile(t, filepath.Join(tm.stub, "su-disable")), "2014520") {
		t.Errorf("state: %v", st)
	}
}

// A suricata-update that never ends (a rule pattern that backtracks
// forever) is stopped, and the tuning that made it hang is refused.
func TestSensorTuningHangs(t *testing.T) {
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("no timeout command")
	}
	tm := newTuningMachine(t)
	mustWrite(t, filepath.Join(tm.root, "var/lib/signalith-sensor/suricata/update/cache/etopen.tar.gz"), "x", 0o644)
	bad := sensortune.Tuning{Disable: "re:2014521"}
	tm.serve(t, bad, "")
	// It hangs with the tuning only.
	stub := filepath.Join(tm.stub, "bin", "suricata-update")
	mustWrite(t, stub, strings.Replace(readFile(t, stub), `if [ -f "$STUB/hang" ]`, `if grep -q 're:2014521' "$STUB/su-disable"`, 1), 0o755)
	if _, err := tm.run(t, "tuning"); err == nil {
		t.Error("a hung update exited 0")
	}
	st := tm.state(t)
	if st["TUNING_RESULT"] != "failed" || st["TUNING_FAILED"] != bad.Hash() || !strings.Contains(st["TUNING_ERROR"], "ran longer than 2 seconds") {
		t.Errorf("state: %v", st)
	}
	if got := tm.file(t, "server.disable.conf"); got != "" {
		t.Errorf("server.disable.conf: %q", got)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
