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
// fingerprint. An empty one means it was not verified when the script
// was written: this test fails until it is, on purpose, so a release
// cannot ship a sensor that refuses to install its packages.
func TestSensorKeyFingerprintsSet(t *testing.T) {
	re := regexp.MustCompile(`(?m)^(KEY_FPR_[A-Z_]+)=(.*)$`)
	found := re.FindAllStringSubmatch(string(SensorInstallSH), -1)
	if len(found) < 4 {
		t.Fatalf("found %d KEY_FPR_ constants, want the 4 publishers' keys", len(found))
	}
	hex40 := regexp.MustCompile(`^[0-9A-F]{40}$`)
	for _, m := range found {
		if v := strings.Trim(m[2], `'"`); !hex40.MatchString(v) {
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
	mustWrite(t, filepath.Join(bin, "ip"), `#!/bin/sh
case "$*" in
  *"-6 route"*) ;;
  *route*) echo "default via 10.0.0.1 dev eth0 proto dhcp" ;;
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
		"signalith-zeek.service":       "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\nCapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\nNoNewPrivileges=yes\nProtectSystem=strict\n",
		"signalith-fluent-bit.service": "CapabilityBoundingSet=\nAmbientCapabilities=\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths=/var/lib/signalith-sensor/agent\n",
		"signalith-suricata.service":   "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_SYS_NICE CAP_IPC_LOCK\nNoNewPrivileges=yes\nProtectSystem=strict\n",
	} {
		if got := readFile(t, filepath.Join(root, "etc/systemd/system", unit)); !strings.Contains(got, want) {
			t.Errorf("%s is missing its hardening %q", unit, want)
		}
	}
	for _, h := range []string{"capture-up.sh", "status.sh", "rules-update.sh"} {
		if fi, err := os.Stat(filepath.Join(root, "usr/lib/signalith-sensor", h)); err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v", h, err)
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
	if strings.Contains(yaml, "run-as:") || !strings.Contains(yaml, "default-log-dir: /var/log/suricata/\n") {
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
