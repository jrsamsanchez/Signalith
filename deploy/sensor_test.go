// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// lf drops Windows line endings, as a checkout on Windows may add them
// to the files compared here (the script itself must have none).
func lf(b []byte) string {
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// sensorFiles are the files the sensor script carries copies of: its
// systemd units, helpers and Compose file, by the heredoc marker that
// holds each.
func sensorFiles(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{"sensor/docker-compose.yml": "COMPOSE"}
	for dir, marker := range map[string]string{"sensor/systemd": "UNIT", "sensor/lib": "HELPER"} {
		var fsys fs.FS = SensorUnits
		if dir == "sensor/lib" {
			fsys = SensorHelpers
		}
		names, err := fs.Glob(fsys, dir+"/*")
		if err != nil || len(names) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, n := range names {
			files[n] = marker
		}
	}
	return files
}

func sensorFile(t *testing.T, name string) []byte {
	t.Helper()
	var b []byte
	var err error
	switch {
	case name == "sensor/docker-compose.yml":
		b = SensorCompose
	case strings.HasPrefix(name, "sensor/lib/"):
		b, err = SensorHelpers.ReadFile(name)
	default:
		b, err = SensorUnits.ReadFile(name)
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The sensor script writes its units, helpers and Compose file as the
// files in deploy/sensor have them, byte for byte.
func TestSensorScriptHasTheFiles(t *testing.T) {
	script := string(SensorInstallSH)
	for name, marker := range sensorFiles(t) {
		want := "<<'" + marker + "'\n" + strings.TrimRight(lf(sensorFile(t, name)), "\n") + "\n" + marker + "\n"
		if !strings.Contains(script, want) {
			t.Errorf("deploy/sensor/install.sh's copy of deploy/%s differs: copy the file between <<'%s' and %s", name, marker, marker)
		}
	}
}

// The script keeps Unix line endings everywhere (.gitattributes): its
// SHA-256 is checked, and sh cannot run it with CRLF.
func TestSensorScriptLineEndings(t *testing.T) {
	if bytes.Contains(SensorInstallSH, []byte("\r")) {
		t.Fatal("deploy/sensor/install.sh has CRLF line endings")
	}
}

// Every repository signing key the script adds is pinned by its full
// fingerprint, all in one place near the top of the script. A filled-in
// one must be a whole fingerprint. An empty one was not checked against
// its publisher when the script was written: the script then stops in
// its checklist, before it installs anything, and the Add data page says
// to use Docker. That is logged here, and fails where
// SIGNALITH_SENSOR_KEYS=required is set (CI's sensor-script job, which
// also checks every pin against what its publisher serves), so it is
// seen until each is filled in.
func TestSensorKeyFingerprintsSet(t *testing.T) {
	re := regexp.MustCompile(`(?m)^(KEY_FPR_[A-Z_]+)=(.*)$`)
	found := re.FindAllStringSubmatch(string(SensorInstallSH), -1)
	if len(found) < 4 {
		t.Fatalf("found %d KEY_FPR_ constants, want the 4 publishers' keys", len(found))
	}
	hex40 := regexp.MustCompile(`^[0-9A-F]{40}$`)
	required := os.Getenv("SIGNALITH_SENSOR_KEYS") == "required"
	for _, m := range found {
		v := strings.Trim(m[2], `'"`)
		switch {
		case v == "" && !required:
			t.Logf("%s is not pinned yet: fill it in from its publisher (docs/network-sensor.md, Signing keys)", m[1])
		case !hex40.MatchString(v):
			t.Errorf("%s is %q: it must be the key's full fingerprint, 40 upper-case hexadecimal characters, checked against the publisher (docs/network-sensor.md, Signing keys)", m[1], v)
		}
	}
}

// shells lists the POSIX shells at hand, as the command line that runs a
// script with each.
func shells() [][]string {
	var out [][]string
	for _, sh := range []string{"sh", "dash", "bash", "busybox"} {
		bin, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		args := []string{bin}
		switch sh {
		case "busybox":
			args = append(args, "sh")
		case "bash":
			args = append(args, "--posix")
		}
		out = append(out, args)
	}
	return out
}

// The script and its helpers parse in every POSIX shell at hand
// (Debian's dash among them).
func TestSensorScriptParses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	dir := t.TempDir()
	scripts := map[string][]byte{"install.sh": SensorInstallSH}
	for name := range sensorFiles(t) {
		if strings.HasPrefix(name, "sensor/lib/") {
			scripts[filepath.Base(name)] = sensorFile(t, name)
		}
	}
	sh := shells()
	if len(sh) == 0 {
		t.Skip("no POSIX shell")
	}
	for name, b := range scripts {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o666); err != nil {
			t.Fatal(err)
		}
		for _, s := range sh {
			args := append(append([]string{}, s[1:]...), "-n", path)
			if out, err := exec.Command(s[0], args...).CombinedOutput(); err != nil {
				t.Errorf("%s -n %s: %v\n%s", s[0], name, err, out)
			}
		}
	}
}

const testToken = "sgl_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"

// sensorMachine is a fake machine for the script: /sys, /proc and
// os-release of its own, and stub curl (a Signalith answering with a test
// CA and configuration), ip (the default route through eth0) and nproc.
type sensorMachine struct {
	dir, caSHA, path string
	env              []string
}

func newSensorMachine(t *testing.T, ports ...string) *sensorMachine {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("runs the script against a fake Linux machine")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	m := &sensorMachine{dir: t.TempDir()}
	if len(ports) == 0 {
		ports = []string{"eth0", "eth1"}
	}
	for _, p := range ports {
		mustWrite(t, filepath.Join(m.dir, "sys/class/net", p, "operstate"), "up\n", 0o644)
		mustWrite(t, filepath.Join(m.dir, "sys/class/net", p, "statistics/rx_packets"), "1000\n", 0o644)
		mustWrite(t, filepath.Join(m.dir, "sys/class/net", p, "statistics/rx_dropped"), "0\n", 0o644)
		if err := os.MkdirAll(filepath.Join(m.dir, "sys/class/net", p, "device"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(m.dir, "proc/meminfo"), "MemTotal:       16384000 kB\n", 0o644)
	m.os("ubuntu", "24.04")

	// The test CA, and its fingerprint computed here, which the script's
	// own (sed, base64, sha256sum) must agree with.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Signalith test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	m.caSHA = hex.EncodeToString(sum[:])
	mustWrite(t, filepath.Join(m.dir, "ca.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)

	bin := filepath.Join(m.dir, "bin")
	mustWrite(t, filepath.Join(bin, "curl"), `#!/bin/sh
out=/dev/stdout w='' url='' hdr=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -w) w=$2; shift 2 ;;
    -H) hdr=$2; shift 2 ;;
    --cacert | --proto | --max-time) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
code=200
case "$url" in
  */api/tls/ca.pem) cat "$STUB/ca.pem" >"$out" ;;
  */api/sensor/config*)
    if grep -q "Bearer $STUB_TOKEN\$" "${hdr#@}"; then
      printf '# stub agent configuration for %s\n' "$url" >"$out"
    else
      code=401
      echo '{"error":"Signalith does not know this token."}' >"$out"
    fi ;;
  */api/sensor/seen) echo '{"last_seen":null,"events_1h":0}' >"$out" ;;
  *) : >"$out" ;;
esac
[ -z "$w" ] || printf '%s' "$code"
`, 0o755)
	// ip: the default route through eth0, and an address on each port
	// named in $STUB_ADDR.
	mustWrite(t, filepath.Join(bin, "ip"), `#!/bin/sh
case "$*" in
  *"-6 route"*) ;;
  *route*) echo "default via 10.0.0.1 dev eth0 proto dhcp" ;;
  *"addr show dev "*)
    for a in $STUB_ADDR; do
      case "$*" in *"dev $a "*) echo "3: $a    inet 192.0.2.9/24 scope global $a" ;; esac
    done ;;
esac
`, 0o755)
	mustWrite(t, filepath.Join(bin, "nproc"), "#!/bin/sh\necho \"${STUB_CORES:-4}\"\n", 0o755)
	// The fake machine runs Ubuntu, whatever the test runs on (CI runs
	// these tests in Rocky and Alma containers too): --uninstall picks
	// apt-get when it is there.
	mustWrite(t, filepath.Join(bin, "apt-get"), "#!/bin/sh\nexit 0\n", 0o755)
	m.path = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	return m
}

func mustWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// os sets the machine's /etc/os-release.
func (m *sensorMachine) os(id, version string) {
	_ = os.WriteFile(filepath.Join(m.dir, "os-release"), []byte("ID="+id+"\nVERSION_ID=\""+version+"\"\nPRETTY_NAME=\""+id+" "+version+"\"\n"), 0o644)
}

// run runs the script with the token on its standard input.
func (m *sensorMachine) run(t *testing.T, cores, stdin string, args ...string) (string, error) {
	t.Helper()
	script := filepath.Join(m.dir, "install.sh")
	if err := os.WriteFile(script, SensorInstallSH, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Dir = m.dir
	cmd.Stdin = strings.NewReader(stdin + "\n")
	cmd.Env = append(os.Environ(), "PATH="+m.path, "STUB="+m.dir, "STUB_TOKEN="+testToken, "STUB_CORES="+cores,
		"SIGNALITH_SENSOR_SYSFS="+filepath.Join(m.dir, "sys"), "SIGNALITH_SENSOR_OS_RELEASE="+filepath.Join(m.dir, "os-release"),
		"SIGNALITH_SENSOR_PROC="+filepath.Join(m.dir, "proc"), "SIGNALITH_SENSOR_SAMPLE_SECONDS=0")
	cmd.Env = append(cmd.Env, m.env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// install runs a dry run into a new folder, and returns it.
func (m *sensorMachine) install(t *testing.T, cores string, args ...string) (string, string) {
	t.Helper()
	root := filepath.Join(m.dir, "root-"+strings.NewReplacer("-", "", " ", "", "/", "").Replace(cores+strings.Join(args, "")))
	out, err := m.run(t, cores, testToken, append([]string{"--role", "sensor", "--from", "https://siem.example.com:8443",
		"--ca-sha256", m.caSHA, "--version", "1.6.0", "--token", "-", "--dry-run", root}, args...)...)
	if err != nil {
		t.Fatalf("dry run %v: %v\n%s", args, err, out)
	}
	return root, out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The script refuses a bad line before it changes anything.
func TestSensorScriptRefuses(t *testing.T) {
	m := newSensorMachine(t)
	line := []string{"--role", "sensor", "--from", "https://siem.example.com:8443", "--token", "-"}
	with := func(args ...string) []string { return append(append([]string{}, line...), args...) }
	for name, c := range map[string]struct {
		args  []string
		stdin string
		says  string
	}{
		"no role":         {[]string{"--from", "https://siem.example.com", "--token", "-"}, testToken, "--role is missing"},
		"bad role":        {append([]string{"--role", "scanner"}, line[2:]...), testToken, "Unknown role: scanner"},
		"http":            {[]string{"--role", "sensor", "--from", "http://siem.example.com", "--token", "-"}, testToken, "must be an https:// address"},
		"path":            {[]string{"--role", "sensor", "--from", "https://siem.example.com/x", "--token", "-"}, testToken, "no path"},
		"quote in from":   {[]string{"--role", "sensor", "--from", "https://siem'x", "--token", "-"}, testToken, "no path"},
		"token prefix":    {line, "SJ1.abc", "not a Signalith agent token"},
		"token cut short": {line, "sgl_abc", "not whole"},
		"token charset":   {line, "sgl_" + strings.Repeat("A", 52), "not whole"},
		"no token":        {line, "", "No token on the standard input"},
		"fingerprint":     {with("--ca-sha256", "abc"), testToken, "64 hexadecimal"},
		"fingerprint $":   {with("--ca-sha256", strings.Repeat("a", 63)+"$"), testToken, "64 hexadecimal"},
		"iface spaces":    {with("--interface", "eth1 eth2"), testToken, "network port's name"},
		"iface semicolon": {with("--interface", "eth1;reboot"), testToken, "network port's name"},
		"iface long":      {with("--interface", "abcdefghijklmnop"), testToken, "at most 15"},
		"cidr junk":       {with("--networks", "10.0.0.0/8,$(reboot)"), testToken, "is not a network"},
		"cidr no prefix":  {with("--networks", "10.0.0.0"), testToken, "needs a prefix length"},
		"cidr too long":   {with("--networks", "10.0.0.0/33"), testToken, "longer than 32"},
		"nothing to run":  {with("--no-zeek", "--no-suricata"), testToken, "nothing to run"},
		"workers":         {with("--zeek-workers", "0"), testToken, "from 1 to 64"},
		"unknown flag":    {with("--bogus"), testToken, "Unknown option: --bogus"},
		"flag value":      {[]string{"--role"}, testToken, "--role needs a value"},
	} {
		out, err := m.run(t, "4", c.stdin, c.args...)
		if err == nil || !strings.Contains(out, c.says) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		if strings.Contains(out, "Installing") {
			t.Errorf("%s: got as far as installing\n%s", name, out)
		}
	}
	if os.Geteuid() != 0 {
		out, err := m.run(t, "4", testToken, line...)
		if err == nil || !strings.Contains(out, "Run this with sudo") {
			t.Errorf("not root: %v\n%s", err, out)
		}
	}
	// Signalith refuses the token, or is not the one the line names.
	out, err := m.run(t, "4", "sgl_"+strings.Repeat("b", 52), with("--dry-run", filepath.Join(m.dir, "refused"))...)
	if err == nil || !strings.Contains(out, "Signalith refused the token: Signalith does not know this token.") {
		t.Errorf("refused token: %v\n%s", err, out)
	}
	out, err = m.run(t, "4", testToken, with("--ca-sha256", strings.Repeat("a", 64), "--dry-run", filepath.Join(m.dir, "mitm"))...)
	if err == nil || !strings.Contains(out, "is not the one the line names") {
		t.Errorf("other CA: %v\n%s", err, out)
	}
	for _, d := range []string{"refused", "mitm"} {
		if entries, _ := os.ReadDir(filepath.Join(m.dir, d)); len(entries) != 0 {
			t.Errorf("%s: the script wrote %v before stopping", d, entries)
		}
	}
	// Systems without packages for it.
	m.os("ubuntu", "20.04")
	if out, err := m.run(t, "4", testToken, with("--dry-run", filepath.Join(m.dir, "focal"))...); err == nil || !strings.Contains(out, "not supported yet") {
		t.Errorf("Ubuntu 20.04: %v\n%s", err, out)
	}
	m.os("rocky", "9.4")
	if out, err := m.run(t, "4", testToken, with("--dry-run", filepath.Join(m.dir, "rocky"))...); err == nil || !strings.Contains(out, "Zeek publishes no packages") {
		t.Errorf("Rocky with Zeek: %v\n%s", err, out)
	}
}

// A dry run writes every file under its folder: the capture port the
// script chose, Zeek's workers for the cores, Suricata's EVE types, the
// units with their hardening, and the token in token.env only. Run
// again, it has nothing to change.
func TestSensorScriptDryRun(t *testing.T) {
	m := newSensorMachine(t)
	root, out := m.install(t, "4")
	for _, want := range []string{"capture port: eth1 (the only port that does not reach the network)",
		"Signalith at https://siem.example.com:8443, its certificate authority is the one the line names",
		"would run: env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zeek-8.0",
		"would run: systemctl mask --now suricata.service", "would run: systemctl restart signalith-fluent-bit.service"} {
		if !strings.Contains(out, want) {
			t.Errorf("output has no %q:\n%s", want, out)
		}
	}
	node := readFile(t, filepath.Join(root, "opt/zeek/etc/node.cfg"))
	if !strings.Contains(node, "type=standalone") || !strings.Contains(node, "interface=af_packet::eth1") {
		t.Errorf("node.cfg with 4 cores:\n%s", node)
	}
	yaml := readFile(t, filepath.Join(root, "etc/suricata/signalith-sensor.yaml"))
	for _, want := range []string{"include: suricata.yaml", "  - interface: eth1\n    threads: 2\n", "community-id: true", "        - anomaly\n        - files\n",
		`vars.address-groups.HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8]"`, "run-as:", "default-log-dir: /var/log/suricata/signalith/"} {
		if !strings.Contains(yaml, want) {
			t.Errorf("signalith-sensor.yaml has no %q:\n%s", want, yaml)
		}
	}
	// suricata-update tests new rules as root: its copy has no run-as.
	if got := readFile(t, filepath.Join(root, "etc/suricata/signalith-sensor-test.yaml")); strings.Contains(got, "run-as:") || got != strings.Replace(yaml, "run-as:\n  user: suricata\n  group: suricata\n", "", 1) {
		t.Errorf("signalith-sensor-test.yaml:\n%s", got)
	}
	if strings.Contains(yaml, "- flow") || strings.Contains(yaml, "- dns") {
		t.Errorf("with Zeek, Suricata logs no protocols:\n%s", yaml)
	}
	if got := readFile(t, filepath.Join(root, "etc/signalith-sensor/fluent-bit.conf")); !strings.Contains(got, "/api/sensor/config?server=https://siem.example.com:8443&layout=packages&zeek=true&suricata=true&protocols=false") {
		t.Errorf("agent configuration: %s", got)
	}
	if got := readFile(t, filepath.Join(root, "etc/signalith-sensor/ca.pem")); got != readFile(t, filepath.Join(m.dir, "ca.pem")) {
		t.Errorf("ca.pem: %s", got)
	}

	// The units as deploy/sensor/systemd has them, with the capture port.
	for name := range sensorFiles(t) {
		if !strings.HasPrefix(name, "sensor/systemd/") {
			continue
		}
		want := strings.NewReplacer("@IFACE_UNIT@", "sys-subsystem-net-devices-eth1.device", "@IFACE@", "eth1").Replace(lf(sensorFile(t, name)))
		if got := readFile(t, filepath.Join(root, "etc/systemd/system", filepath.Base(name))); got != want {
			t.Errorf("%s differs from deploy/%s:\n%s", filepath.Base(name), name, got)
		}
	}
	for unit, want := range map[string]string{
		// Zeek: capture only, not the network settings.
		"signalith-zeek.service":         "AmbientCapabilities=CAP_NET_RAW\nCapabilityBoundingSet=CAP_NET_RAW\nNoNewPrivileges=yes\nProtectSystem=strict\n",
		"signalith-zeekctl-cron.service": "AmbientCapabilities=CAP_NET_RAW\nCapabilityBoundingSet=CAP_NET_RAW\nNoNewPrivileges=yes\n",
		"signalith-fluent-bit.service":   "CapabilityBoundingSet=\nAmbientCapabilities=\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths=/var/lib/signalith-sensor/agent\n",
		// Suricata needs SETPCAP, CHOWN and DAC_OVERRIDE until it drops to
		// its user (libcap-ng's capng_change_id adds SETPCAP).
		"signalith-suricata.service": "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_SYS_NICE CAP_IPC_LOCK CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE\nNoNewPrivileges=yes\nProtectSystem=strict\n",
		// The rules update writes only root's folders.
		"signalith-suricata-update.service": "ReadWritePaths=/var/lib/signalith-sensor -/run/suricata -/run/docker.sock\n",
		"signalith-sensor-capture.service":  "ExecStop=/usr/lib/signalith-sensor/capture-up.sh --undo eth1\n",
	} {
		if got := readFile(t, filepath.Join(root, "etc/systemd/system", unit)); !strings.Contains(got, want) {
			t.Errorf("%s is missing its hardening %q", unit, want)
		}
	}
	for _, h := range []string{"capture-up.sh", "status.sh", "rules-update.sh", "install.sh"} {
		if fi, err := os.Stat(filepath.Join(root, "usr/lib/signalith-sensor", h)); err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v", h, err)
		}
	}
	// A copy of the script itself, for --uninstall.
	if got := readFile(t, filepath.Join(root, "usr/lib/signalith-sensor/install.sh")); got != string(SensorInstallSH) {
		t.Error("usr/lib/signalith-sensor/install.sh is not the script")
	}
	// The rules are root's, in a folder only root writes, never under
	// /var/lib/suricata, which the suricata user owns.
	if !strings.Contains(yaml, "default-rule-path: /var/lib/signalith-sensor/suricata/rules\n") {
		t.Errorf("signalith-sensor.yaml: rules not in /var/lib/signalith-sensor/suricata/rules:\n%s", yaml)
	}
	if fi, err := os.Stat(filepath.Join(root, "var/lib/signalith-sensor/suricata/rules/suricata.rules")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the empty suricata.rules for Suricata's first test: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/suricata/rules")); err == nil {
		t.Error("the script made /var/lib/suricata/rules")
	}
	// While Zeek's signing key is not pinned, the checklist says so (a
	// real run stops there), and the end says warnings scrolled past.
	if strings.Contains(string(SensorInstallSH), "\nKEY_FPR_ZEEK_OBS=''\n") {
		if !strings.Contains(out, "cannot install Zeek from packages") || !strings.Contains(out, "warning(s) above") {
			t.Errorf("unpinned Zeek key not in the checklist:\n%s", out)
		}
	}

	// The token is in token.env (0600) and in no other file.
	env := filepath.Join(root, "etc/signalith-sensor/token.env")
	if fi, err := os.Stat(env); err != nil || fi.Mode().Perm() != 0o600 || !strings.Contains(readFile(t, env), "SIGNALITH_TOKEN="+testToken+"\n") {
		t.Errorf("token.env: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(root, "etc/signalith-sensor/manifest")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("manifest: %v", err)
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path == env {
			return err
		}
		if strings.Contains(readFile(t, path), testToken) {
			t.Errorf("%s holds the token", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Again: nothing to change.
	out2, err := m.run(t, "4", testToken, "--role", "sensor", "--from", "https://siem.example.com:8443", "--ca-sha256", m.caSHA,
		"--version", "1.6.0", "--token", "-", "--dry-run", root)
	if err != nil || !strings.Contains(out2, "Nothing to change") || strings.Contains(out2, "restart") {
		t.Errorf("re-run: %v\n%s", err, out2)
	}

	// --uninstall takes away every file it wrote.
	out3, err := m.run(t, "4", "", "--uninstall", "--dry-run", root)
	if err != nil || !strings.Contains(out3, "would run: env DEBIAN_FRONTEND=noninteractive apt-get purge -y --autoremove fluent-bit suricata zeek-8.0") ||
		!strings.Contains(out3, "would run: systemctl unmask suricata.service") || !strings.Contains(out3, "Revoke its token") {
		t.Errorf("uninstall: %v\n%s", err, out3)
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			t.Errorf("left after --uninstall: %s", path)
		}
		return nil
	})
}

// Zeek runs a cluster of workers from 8 cores, Suricata half the cores
// in threads; the options and the tools chosen show in the files.
func TestSensorScriptDryRunOptions(t *testing.T) {
	m := newSensorMachine(t)
	for cores, want := range map[string]string{"8": "lb_procs=2\n", "16": "lb_procs=4\n", "64": "lb_procs=8\n"} {
		root, _ := m.install(t, cores)
		if node := readFile(t, filepath.Join(root, "opt/zeek/etc/node.cfg")); !strings.Contains(node, want) || !strings.Contains(node, "interface=eth1\nlb_method=af_packet\n") {
			t.Errorf("%s cores: node.cfg\n%s", cores, node)
		}
	}
	root, _ := m.install(t, "16", "--zeek-workers", "3", "--suricata-threads", "5", "--networks", "10.9.0.0/16,fd12::/16", "--name", "nsm-01")
	if node := readFile(t, filepath.Join(root, "opt/zeek/etc/node.cfg")); !strings.Contains(node, "lb_procs=3\n") {
		t.Errorf("--zeek-workers: %s", node)
	}
	if nets := readFile(t, filepath.Join(root, "opt/zeek/etc/networks.cfg")); !strings.Contains(nets, "10.9.0.0/16\tYour network\nfd12::/16\tYour network\n") {
		t.Errorf("networks.cfg: %s", nets)
	}
	yaml := readFile(t, filepath.Join(root, "etc/suricata/signalith-sensor.yaml"))
	if !strings.Contains(yaml, "threads: 5\n") || !strings.Contains(yaml, `HOME_NET: "[10.9.0.0/16,fd12::/16]"`) || !strings.Contains(yaml, "sensor-name: nsm-01\n") {
		t.Errorf("signalith-sensor.yaml: %s", yaml)
	}
	if env := readFile(t, filepath.Join(root, "etc/signalith-sensor/token.env")); !strings.Contains(env, "HOSTNAME=nsm-01\n") {
		t.Errorf("token.env: %s", env)
	}

	// Suricata only: it logs the protocols itself, and there is no Zeek.
	root, _ = m.install(t, "4", "--no-zeek")
	yaml = readFile(t, filepath.Join(root, "etc/suricata/signalith-sensor.yaml"))
	if !strings.Contains(yaml, "        - flow\n        - dns\n        - http\n        - tls\n") {
		t.Errorf("Suricata only: %s", yaml)
	}
	if _, err := os.Stat(filepath.Join(root, "opt/zeek")); err == nil {
		t.Error("Suricata only: Zeek configured")
	}
	if conf := readFile(t, filepath.Join(root, "etc/signalith-sensor/fluent-bit.conf")); !strings.Contains(conf, "zeek=false&suricata=true&protocols=true") {
		t.Errorf("Suricata only: agent configuration asked for %s", conf)
	}
	// Zeek only.
	root, _ = m.install(t, "4", "--no-suricata")
	if _, err := os.Stat(filepath.Join(root, "etc/suricata")); err == nil {
		t.Error("Zeek only: Suricata configured")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/signalith-suricata-update.timer")); err == nil {
		t.Error("Zeek only: rules timer written")
	}
	// Docker: the Compose file as the repository has it, and the pins.
	root, _ = m.install(t, "4", "--docker")
	if got := readFile(t, filepath.Join(root, "etc/signalith-sensor/docker/docker-compose.yml")); got != lf(SensorCompose) {
		t.Errorf("docker-compose.yml differs from deploy/sensor/docker-compose.yml")
	}
	dotenv := readFile(t, filepath.Join(root, "etc/signalith-sensor/docker/.env"))
	for _, want := range []string{"SIGNALITH_INTERFACE=eth1\n", "SIGNALITH_IMAGE_ZEEK=zeek/zeek:", "@sha256:"} {
		if !strings.Contains(dotenv, want) {
			t.Errorf(".env has no %q:\n%s", want, dotenv)
		}
	}
	yaml = readFile(t, filepath.Join(root, "etc/signalith-sensor/docker/suricata/signalith-sensor.yaml"))
	if strings.Contains(yaml, "run-as:") || !strings.Contains(yaml, "default-log-dir: /var/log/suricata/\n") || !strings.Contains(yaml, "default-rule-path: /var/lib/suricata/rules\n") {
		t.Errorf("Docker's Suricata configuration: %s", yaml)
	}
	if z := readFile(t, filepath.Join(root, "etc/signalith-sensor/docker/zeek/signalith.zeek")); !strings.Contains(z, "redef Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, [fd00::]/8 };") {
		t.Errorf("Docker's Zeek script: %s", z)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/signalith-zeek.service")); err == nil {
		t.Error("Docker: Zeek's unit written")
	}
	// Rocky Linux, Suricata only.
	m.os("rocky", "9.4")
	root, out := m.install(t, "4", "--no-zeek", "--interface", "eth1")
	if repo := readFile(t, filepath.Join(root, "etc/yum.repos.d/signalith-fluent-bit.repo")); !strings.Contains(repo, "gpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/signalith-fluentbit.asc\n") {
		t.Errorf("Fluent Bit repo: %s", repo)
	}
	if !strings.Contains(out, "would run: dnf install -y suricata") {
		t.Errorf("Rocky: %s", out)
	}
}

// With two ports that could be the capture port and nobody to ask, the
// script says to add --interface; a port it does not have is refused.
func TestSensorScriptPortChoice(t *testing.T) {
	m := newSensorMachine(t, "eth0", "eth1", "eth2")
	args := []string{"--role", "sensor", "--from", "https://siem.example.com:8443", "--ca-sha256", m.caSHA, "--token", "-", "--dry-run", filepath.Join(m.dir, "root")}
	out, err := m.run(t, "4", testToken, args...)
	if err == nil || !strings.Contains(out, "1) eth1") || !strings.Contains(out, "2) eth2") || !strings.Contains(out, "Add --interface <name> to the line") {
		t.Errorf("two ports: %v\n%s", err, out)
	}
	out, err = m.run(t, "4", testToken, append(args, "--interface", "eth9")...)
	if err == nil || !strings.Contains(out, "no network port named eth9") || !strings.Contains(out, "eth0 eth1 eth2") {
		t.Errorf("unknown port: %v\n%s", err, out)
	}
	out, err = m.run(t, "4", testToken, append(args, "--interface", "eth0", "--check-only")...)
	if err != nil || !strings.Contains(out, "SSH may drop") || !strings.Contains(out, "nothing was changed (--check-only)") {
		t.Errorf("routed port: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "root/etc")); err == nil {
		t.Error("--check-only wrote files")
	}
}

// The status line is valid JSON with the fields the ingest parser reads,
// as in internal/ingest/testdata/sensor/status.json.
func TestSensorStatusLine(t *testing.T) {
	m := newSensorMachine(t)
	root, _ := m.install(t, "4", "--name", "nsm-01")
	mustWrite(t, filepath.Join(root, "var/lib/signalith-sensor/rules.state"), "RULES_UPDATE='ok'\nRULES_UPDATED='2026-10-15T03:41:00Z'\nRULES_COUNT='48211'\n", 0o644)
	if err := os.MkdirAll(filepath.Join(root, "var/log/signalith-sensor"), 0o755); err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(root, "usr/lib/signalith-sensor/status.sh")
	runStatus := func() map[string]any {
		t.Helper()
		cmd := exec.Command("sh", status)
		cmd.Env = append(os.Environ(), "PATH="+m.path, "SIGNALITH_SENSOR_ROOT="+root, "SIGNALITH_SENSOR_SYSFS="+filepath.Join(m.dir, "sys"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("status.sh: %v\n%s", err, out)
		}
		lines := strings.Split(strings.TrimSpace(readFile(t, filepath.Join(root, "var/log/signalith-sensor/status.json"))), "\n")
		var v map[string]any
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &v); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, lines[len(lines)-1])
		}
		return v
	}
	runStatus()
	mustWrite(t, filepath.Join(m.dir, "sys/class/net/eth1/statistics/rx_packets"), "1900\n", 0o644)
	mustWrite(t, filepath.Join(m.dir, "sys/class/net/eth1/statistics/rx_dropped"), "100\n", 0o644)
	v := runStatus()
	if v["kind"] != "signalith-sensor-status" || v["v"] != 1.0 || v["host"] != "nsm-01" || v["role"] != "sensor" || v["sensor_version"] != "1.6.0" || v["layout"] != "packages" {
		t.Errorf("status line: %v", v)
	}
	iface, _ := v["interface"].(map[string]any)
	// 900 packets and 100 dropped since the line before: 10%.
	if iface["name"] != "eth1" || iface["link"] != "up" || iface["rx_packets"] != 1900.0 || iface["drop_percent"] != 10.0 {
		t.Errorf("interface: %v", iface)
	}
	rules, _ := v["rules"].(map[string]any)
	if rules["count"] != 48211.0 || rules["update"] != "ok" || rules["updated"] != "2026-10-15T03:41:00Z" {
		t.Errorf("rules: %v", rules)
	}
	warnings, _ := v["warnings"].([]any)
	if !strings.Contains(jsonString(t, warnings), `"drops"`) {
		t.Errorf("warnings: %v", warnings)
	}

	// A virtual port (VXLAN) says unknown: with a carrier it is up, and
	// without one it stays unknown and is warned about.
	mustWrite(t, filepath.Join(m.dir, "sys/class/net/eth1/operstate"), "unknown\n", 0o644)
	mustWrite(t, filepath.Join(m.dir, "sys/class/net/eth1/carrier"), "1\n", 0o644)
	v = runStatus()
	if iface, _ := v["interface"].(map[string]any); iface["link"] != "up" || strings.Contains(jsonString(t, v["warnings"]), "capture_link") {
		t.Errorf("unknown with a carrier: %v %v", iface, v["warnings"])
	}
	if err := os.Remove(filepath.Join(m.dir, "sys/class/net/eth1/carrier")); err != nil {
		t.Fatal(err)
	}
	v = runStatus()
	if iface, _ := v["interface"].(map[string]any); iface["link"] != "unknown" || !strings.Contains(jsonString(t, v["warnings"]), "capture_link") {
		t.Errorf("unknown without a carrier: %v %v", iface, v["warnings"])
	}

	// The same keys as the ingest parser's test line.
	golden := readFile(t, filepath.Join("..", "internal", "ingest", "testdata", "sensor", "status.json"))
	var g map[string]any
	if err := json.Unmarshal([]byte(golden), &g); err != nil {
		t.Fatal(err)
	}
	for k, gv := range g {
		if _, ok := v[k]; !ok {
			t.Errorf("status.sh writes no %q, which internal/ingest/testdata/sensor/status.json has", k)
			continue
		}
		if sub, ok := gv.(map[string]any); ok {
			have, _ := v[k].(map[string]any)
			for sk := range sub {
				if _, ok := have[sk]; !ok {
					t.Errorf("status.sh writes no %s.%s", k, sk)
				}
			}
		}
	}
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Signalith hands out one certificate authority at a time: a file with a
// second one after it is refused, though the first matches the line, and
// only the certificate the line names is ever kept.
func TestSensorScriptCAOneCertificate(t *testing.T) {
	m := newSensorMachine(t)
	ca := readFile(t, filepath.Join(m.dir, "ca.pem"))
	args := []string{"--role", "sensor", "--from", "https://siem.example.com:8443", "--ca-sha256", m.caSHA, "--token", "-", "--check-only"}
	mustWrite(t, filepath.Join(m.dir, "ca.pem"), ca+ca, 0o644)
	out, err := m.run(t, "4", testToken, append(args, "--dry-run", filepath.Join(m.dir, "two"))...)
	if err == nil || !strings.Contains(out, "handed out 2 certificates where it hands out one") {
		t.Errorf("two certificates: %v\n%s", err, out)
	}
	// Another kind of block after it (OpenSSL trusts a TRUSTED
	// CERTIFICATE too): dropped from the CA the sensor keeps.
	extra := strings.ReplaceAll(ca, "CERTIFICATE", "TRUSTED CERTIFICATE")
	mustWrite(t, filepath.Join(m.dir, "ca.pem"), "junk before\n"+ca+extra, 0o644)
	root, _ := m.install(t, "4")
	if got := readFile(t, filepath.Join(root, "etc/signalith-sensor/ca.pem")); got != ca {
		t.Errorf("ca.pem kept:\n%s", got)
	}
}

// The script picks a capture port on its own only when exactly one is
// free: not the one the machine reaches the network with, not one in a
// bridge or bond, not one with an address (storage, backups).
func TestSensorScriptBusyPorts(t *testing.T) {
	m := newSensorMachine(t, "eth0", "eth1", "eth2", "eth3")
	mustWrite(t, filepath.Join(m.dir, "sys/class/net/eth3/master"), "br0\n", 0o644)
	m.env = []string{"STUB_ADDR=eth1"}
	root, out := m.install(t, "4")
	if !strings.Contains(out, "capture port: eth2 (the only port that does not reach the network)") {
		t.Errorf("eth1 has an address, eth3 is in a bridge: %s", out)
	}
	if got := readFile(t, filepath.Join(root, "etc/signalith-sensor/sensor.conf")); !strings.Contains(got, "INTERFACE='eth2'") {
		t.Errorf("sensor.conf: %s", got)
	}
	m.env = []string{"STUB_ADDR=eth1 eth2"}
	out, err := m.run(t, "4", testToken, "--role", "sensor", "--from", "https://siem.example.com:8443", "--ca-sha256", m.caSHA,
		"--token", "-", "--dry-run", filepath.Join(m.dir, "busy"))
	if err == nil || !strings.Contains(out, "No port is free for capture") || !strings.Contains(out, "eth1 eth2 eth3") || !strings.Contains(out, "name it with --interface") {
		t.Errorf("no free port: %v\n%s", err, out)
	}
	// Named with --interface, a port in a bridge is used, with a warning.
	_, out = m.install(t, "4", "--interface", "eth3")
	if !strings.Contains(out, "eth3 is part of a bridge or bond") {
		t.Errorf("--interface eth3: %s", out)
	}
}

// A port with "-" in its name: systemd writes its device unit with \x2d,
// which reaches the unit as it is.
func TestSensorScriptDashedPort(t *testing.T) {
	m := newSensorMachine(t, "eth0", "mirror-1")
	root, _ := m.install(t, "4")
	unit := readFile(t, filepath.Join(root, "etc/systemd/system/signalith-sensor-capture.service"))
	if !strings.Contains(unit, `BindsTo=sys-subsystem-net-devices-mirror\x2d1.device`+"\n") || !strings.Contains(unit, "capture-up.sh mirror-1\n") {
		t.Errorf("capture unit:\n%s", unit)
	}
}

// Debian 13 takes Suricata from Debian itself, without backports.
func TestSensorScriptDebian13(t *testing.T) {
	m := newSensorMachine(t)
	m.os("debian", "13")
	root, out := m.install(t, "4", "--no-zeek")
	if !strings.Contains(out, "would run: env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends suricata suricata-update") {
		t.Errorf("Debian 13: %s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/apt/sources.list.d/signalith-debian-backports.list")); err == nil {
		t.Error("Debian 13: backports added")
	}
	if got := readFile(t, filepath.Join(root, "etc/apt/sources.list.d/signalith-fluent-bit.list")); !strings.Contains(got, "/debian/trixie trixie main") {
		t.Errorf("Fluent Bit's repository: %s", got)
	}
	m.os("debian", "12")
	root, out = m.install(t, "4", "--no-zeek")
	if !strings.Contains(out, "-t bookworm-backports suricata suricata-update") || !strings.Contains(readFile(t, filepath.Join(root, "etc/apt/sources.list.d/signalith-debian-backports.list")), "bookworm-backports main") {
		t.Errorf("Debian 12: %s", out)
	}
}

// Run again: the programs get their publishers' newest packages, and
// changed rules of your own are loaded now, not at the next daily update.
func TestSensorScriptRunAgain(t *testing.T) {
	m := newSensorMachine(t)
	rules := filepath.Join(m.dir, "my.rules")
	mustWrite(t, rules, "alert ip any any -> any any (msg:\"one\"; sid:9900001; rev:1;)\n", 0o644)
	root, out := m.install(t, "4", "--local-rules", rules)
	if !strings.Contains(out, "downloading the Suricata rules") {
		t.Errorf("first run downloads the rules: %s", out)
	}
	again := func() string {
		t.Helper()
		out, err := m.run(t, "4", testToken, "--role", "sensor", "--from", "https://siem.example.com:8443", "--ca-sha256", m.caSHA,
			"--version", "1.6.0", "--token", "-", "--local-rules", rules, "--dry-run", root)
		if err != nil {
			t.Fatalf("again: %v\n%s", err, out)
		}
		return out
	}
	out = again()
	if !strings.Contains(out, "would run: env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade --no-install-recommends zeek-8.0") ||
		!strings.Contains(out, "--only-upgrade --no-install-recommends fluent-bit") || !strings.Contains(out, "Nothing to change") || strings.Contains(out, "Suricata rules") {
		t.Errorf("again, unchanged: %s", out)
	}
	mustWrite(t, rules, "alert ip any any -> any any (msg:\"two\"; sid:9900002; rev:1;)\n", 0o644)
	out = again()
	if !strings.Contains(out, "updating the Suricata rules with your own") || !strings.Contains(out, "the Suricata rules, with your own") {
		t.Errorf("again, rules changed: %s", out)
	}
}

// Root never follows a symbolic link where it writes: one put in place of
// a file or folder stops the script.
func TestSensorScriptRefusesLinks(t *testing.T) {
	m := newSensorMachine(t)
	root, _ := m.install(t, "4")
	target := filepath.Join(m.dir, "shadow")
	mustWrite(t, target, "secret\n", 0o600)
	conf := filepath.Join(root, "etc/signalith-sensor/sensor.conf")
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, conf); err != nil {
		t.Fatal(err)
	}
	out, err := m.run(t, "4", testToken, "--role", "sensor", "--from", "https://siem.example.com:8443", "--ca-sha256", m.caSHA,
		"--token", "-", "--dry-run", root)
	if err == nil || !strings.Contains(out, "is a symbolic link, which the script does not follow") {
		t.Errorf("link: %v\n%s", err, out)
	}
	if got := readFile(t, target); got != "secret\n" {
		t.Errorf("the link's target was written: %q", got)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o600 {
		t.Errorf("the link's target's mode changed: %v", fi.Mode())
	}
}

// capture-up.sh keeps what the port was like before, and --undo puts it
// back: promiscuous mode, ARP, IPv6 and the offloads that were on.
func TestSensorCaptureUndo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX shells only")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "capture-up.sh")
	mustWrite(t, script, lf(sensorFile(t, "sensor/lib/capture-up.sh")), 0o755)
	root := filepath.Join(dir, "root")
	mustWrite(t, filepath.Join(root, "proc/sys/net/ipv6/conf/eth1/disable_ipv6"), "0\n", 0o644)
	if err := os.MkdirAll(filepath.Join(root, "var/lib/signalith-sensor"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Up, ARP on, not promiscuous.
	mustWrite(t, filepath.Join(dir, "sys/class/net/eth1/flags"), "0x1003\n", 0o644)
	bin := filepath.Join(dir, "bin")
	calls := filepath.Join(dir, "calls")
	mustWrite(t, filepath.Join(bin, "ip"), "#!/bin/sh\necho \"ip $*\" >>\"$CALLS\"\n", 0o755)
	mustWrite(t, filepath.Join(bin, "ethtool"), `#!/bin/sh
if [ "$1" = -k ]; then
  printf 'Features for %s:\ngeneric-receive-offload: on\nlarge-receive-offload: off [fixed]\ngeneric-segmentation-offload: on\ntcp-segmentation-offload: off\nrx-gro-hw: off [fixed]\n' "$2"
  exit 0
fi
echo "ethtool $*" >>"$CALLS"
`, 0o755)
	run := func(args ...string) string {
		t.Helper()
		_ = os.Remove(calls)
		cmd := exec.Command("sh", append([]string{script}, args...)...)
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "CALLS="+calls,
			"SIGNALITH_SENSOR_ROOT="+root, "SIGNALITH_SENSOR_SYSFS="+filepath.Join(dir, "sys"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("capture-up.sh %v: %v\n%s", args, err, out)
		}
		b, _ := os.ReadFile(calls)
		return string(b)
	}
	got := run("eth1")
	if !strings.Contains(got, "ip link set dev eth1 up promisc on arp off\n") || !strings.Contains(got, "ethtool -K eth1 gro off\n") {
		t.Errorf("up: %s", got)
	}
	saved := filepath.Join(root, "var/lib/signalith-sensor/capture-eth1.before")
	if s := readFile(t, saved); s != "off on 0 gro,gso\n" {
		t.Errorf("saved: %q", s)
	}
	if v := readFile(t, filepath.Join(root, "proc/sys/net/ipv6/conf/eth1/disable_ipv6")); v != "1\n" {
		t.Errorf("IPv6: %q", v)
	}
	// A restart keeps what it was before the sensor.
	mustWrite(t, filepath.Join(dir, "sys/class/net/eth1/flags"), "0x1183\n", 0o644)
	run("eth1")
	if s := readFile(t, saved); s != "off on 0 gro,gso\n" {
		t.Errorf("saved after a restart: %q", s)
	}
	got = run("--undo", "eth1")
	if !strings.Contains(got, "ip link set dev eth1 promisc off arp on\n") || !strings.Contains(got, "ethtool -K eth1 gro on\n") ||
		!strings.Contains(got, "ethtool -K eth1 gso on\n") || strings.Contains(got, "tso on") {
		t.Errorf("undo: %s", got)
	}
	if v := readFile(t, filepath.Join(root, "proc/sys/net/ipv6/conf/eth1/disable_ipv6")); v != "0\n" {
		t.Errorf("IPv6 after undo: %q", v)
	}
	if _, err := os.Stat(saved); err == nil {
		t.Error("undo kept the saved state")
	}
}

// With no stats line in the end of eve.json (a busy link), Suricata's
// drops count from the last line that had one, not from zero.
func TestSensorStatusNoStatsLine(t *testing.T) {
	m := newSensorMachine(t)
	root, _ := m.install(t, "4", "--name", "nsm-01")
	if err := os.MkdirAll(filepath.Join(root, "var/log/signalith-sensor"), 0o755); err != nil {
		t.Fatal(err)
	}
	eve := filepath.Join(root, "var/log/suricata/signalith/eve.json")
	status := filepath.Join(root, "usr/lib/signalith-sensor/status.sh")
	packets := 1000
	drop := func(eveText string) float64 {
		t.Helper()
		packets += 1000
		mustWrite(t, filepath.Join(m.dir, "sys/class/net/eth1/statistics/rx_packets"), fmt.Sprintf("%d\n", packets), 0o644)
		mustWrite(t, eve, eveText, 0o644)
		cmd := exec.Command("sh", status)
		cmd.Env = append(os.Environ(), "PATH="+m.path, "SIGNALITH_SENSOR_ROOT="+root, "SIGNALITH_SENSOR_SYSFS="+filepath.Join(m.dir, "sys"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("status.sh: %v\n%s", err, out)
		}
		lines := strings.Split(strings.TrimSpace(readFile(t, filepath.Join(root, "var/log/signalith-sensor/status.json"))), "\n")
		var v map[string]any
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &v); err != nil {
			t.Fatal(err)
		}
		return v["interface"].(map[string]any)["drop_percent"].(float64)
	}
	stats := func(n int) string {
		return fmt.Sprintf(`{"event_type":"stats","stats":{"capture":{"kernel_drops":%d}}}`+"\n", n)
	}
	drop(stats(50000))
	if d := drop(`{"event_type":"alert"}` + "\n"); d != 0 {
		t.Errorf("no stats line: %v%% dropped", d)
	}
	// 10 more drops since the last stats line, over 1000 packets.
	if d := drop(stats(50010)); d != 1.0 {
		t.Errorf("next stats line: %v%% dropped, want 1", d)
	}
}

// Run again with another capture port: the capture service stops as
// written for the old port, which puts that port back as it was.
// A run again with other networks restarts Zeek and Suricata, which read
// them only when they start; their files are written at the end of a
// pipeline, in a subshell.
func TestSensorScriptNewNetworks(t *testing.T) {
	m := newSensorMachine(t)
	root, _ := m.install(t, "4")
	out, err := m.run(t, "4", testToken, "--role", "sensor", "--from", "https://siem.example.com:8443", "--ca-sha256", m.caSHA,
		"--version", "1.6.0", "--token", "-", "--networks", "10.0.0.0/8,203.0.113.7/32", "--dry-run", root)
	if err != nil {
		t.Fatalf("again: %v\n%s", err, out)
	}
	for _, want := range []string{"would run: systemctl restart signalith-zeek.service", "would run: systemctl restart signalith-suricata.service"} {
		if !strings.Contains(out, want) {
			t.Errorf("output has no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Nothing to change") || strings.Contains(out, "restart signalith-fluent-bit.service") {
		t.Errorf("new networks:\n%s", out)
	}
	if got := readFile(t, filepath.Join(root, "opt/zeek/etc/networks.cfg")); !strings.Contains(got, "203.0.113.7/32") {
		t.Errorf("networks.cfg:\n%s", got)
	}
}

func TestSensorScriptNewPort(t *testing.T) {
	m := newSensorMachine(t, "eth0", "eth1", "eth2")
	root, _ := m.install(t, "4", "--interface", "eth1")
	again := func(port string) string {
		t.Helper()
		out, err := m.run(t, "4", testToken, "--role", "sensor", "--from", "https://siem.example.com:8443", "--ca-sha256", m.caSHA,
			"--version", "1.6.0", "--token", "-", "--interface", port, "--dry-run", root)
		if err != nil {
			t.Fatalf("again with %s: %v\n%s", port, err, out)
		}
		return out
	}
	const stop = "would run: systemctl stop signalith-sensor-capture.service"
	if out := again("eth1"); strings.Contains(out, stop) {
		t.Errorf("same port: %s", out)
	}
	if out := again("eth2"); !strings.Contains(out, stop) {
		t.Errorf("new port: %s", out)
	}
}
