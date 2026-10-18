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

func TestAgentScriptLineEndings(t *testing.T) {
	if bytes.Contains(AgentInstallSH, []byte("\r")) {
		t.Fatal("deploy/agent/install.sh has CRLF line endings")
	}
}

// The agent's script pins Fluent Bit's key as the sensor's does.
func TestAgentScriptPinsFluentBitKey(t *testing.T) {
	re := regexp.MustCompile(`(?m)^KEY_FPR_FLUENTBIT=([0-9A-F]{40})$`)
	a, s := re.FindSubmatch(AgentInstallSH), re.FindSubmatch(SensorInstallSH)
	if a == nil || s == nil || string(a[1]) != string(s[1]) {
		t.Errorf("agent pins %q, sensor %q", a, s)
	}
}

func TestAgentScriptParses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, AgentInstallSH, 0o666); err != nil {
		t.Fatal(err)
	}
	sh := shells()
	if len(sh) == 0 {
		t.Skip("no POSIX shell")
	}
	for _, s := range sh {
		args := append(append([]string{}, s[1:]...), "-n", path)
		if out, err := exec.Command(s[0], args...).CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v\n%s", s[0], err, out)
		}
	}
}

// agentMachine is a fake Linux computer for the agent's script: its own
// os-release and a stub curl that answers as Signalith, with a test CA
// and agent program.
type agentMachine struct {
	dir, caSHA, path string
	program          []byte
}

func newAgentMachine(t *testing.T) *agentMachine {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("runs the script against a fake Linux machine")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
	default:
		t.Skip("the agent runs on amd64 and arm64")
	}
	m := &agentMachine{dir: t.TempDir(), program: []byte("#!/bin/sh\necho agent\n")}
	m.os("ubuntu", "24.04")
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
	mustWrite(t, filepath.Join(m.dir, "program"), string(m.program), 0o644)
	psum := sha256.Sum256(m.program)
	mustWrite(t, filepath.Join(m.dir, "program.sha"), hex.EncodeToString(psum[:]), 0o644)

	bin := filepath.Join(m.dir, "bin")
	mustWrite(t, filepath.Join(bin, "curl"), `#!/bin/sh
out=/dev/stdout w='' url='' hdr='' dump=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -w) w=$2; shift 2 ;;
    -H) hdr=$2; shift 2 ;;
    -D) dump=$2; shift 2 ;;
    --cacert | --proto | --max-time) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
code=200
[ -z "$dump" ] || : >"$dump"
authed() { grep -q "Bearer $STUB_TOKEN\$" "${hdr#@}"; }
case "$url" in
  */api/tls/ca.pem) cat "$STUB/ca.pem" >"$out" ;;
  */api/agent/config*)
    if authed; then
      printf '%s\n' "$url" >"$STUB/config-url"
      echo '{"revision":"x","poll_seconds":300}' >"$out"
    else
      code=401
      echo '{"error":"Signalith does not know this token."}' >"$out"
    fi ;;
  */api/agent/program*)
    if [ -n "$STUB_NO_PROGRAM" ]; then
      code=404
      echo '{"error":"this server has no agent program for linux/amd64"}' >"$out"
    else
      cat "$STUB/program" >"$out"
      printf 'HTTP/1.1 200 OK\r\nX-Signalith-SHA256: %s\r\n\r\n' "${STUB_SHA:-$(cat "$STUB/program.sha")}" >"$dump"
    fi ;;
  *) : >"$out" ;;
esac
[ -z "$w" ] || printf '%s' "$code"
`, 0o755)
	mustWrite(t, filepath.Join(bin, "apt-get"), "#!/bin/sh\nexit 0\n", 0o755)
	m.path = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	return m
}

func (m *agentMachine) os(id, version string) {
	_ = os.WriteFile(filepath.Join(m.dir, "os-release"), []byte("ID="+id+"\nVERSION_ID=\""+version+"\"\nPRETTY_NAME=\""+id+" "+version+"\"\n"), 0o644)
}

func (m *agentMachine) run(t *testing.T, stdin string, env []string, args ...string) (string, error) {
	t.Helper()
	script := filepath.Join(m.dir, "install.sh")
	if err := os.WriteFile(script, AgentInstallSH, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Dir = m.dir
	cmd.Stdin = strings.NewReader(stdin + "\n")
	cmd.Env = append(os.Environ(), "PATH="+m.path, "STUB="+m.dir, "STUB_TOKEN="+testToken,
		"SIGNALITH_AGENT_OS_RELEASE="+filepath.Join(m.dir, "os-release"))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (m *agentMachine) line(root string) []string {
	return []string{"--from", "https://siem.example.com:7779", "--ca-sha256", m.caSHA, "--version", "0.4.0", "--token", "-", "--dry-run", root}
}

func TestAgentScriptRefuses(t *testing.T) {
	m := newAgentMachine(t)
	line := []string{"--from", "https://siem.example.com:7779", "--token", "-"}
	with := func(args ...string) []string { return append(append([]string{}, line...), args...) }
	for name, c := range map[string]struct {
		args  []string
		stdin string
		says  string
	}{
		"no from":         {[]string{"--token", "-"}, testToken, "--from is missing"},
		"http":            {[]string{"--from", "http://siem.example.com", "--token", "-"}, testToken, "must be an https:// address"},
		"path":            {[]string{"--from", "https://siem.example.com/x", "--token", "-"}, testToken, "no path"},
		"quote in from":   {[]string{"--from", "https://siem'x", "--token", "-"}, testToken, "no path"},
		"token prefix":    {line, "SJ1.abc", "not a Signalith agent token"},
		"token cut short": {line, "sgl_abc", "not whole"},
		"no token":        {line, "", "No token on the standard input"},
		"fingerprint":     {with("--ca-sha256", "abc"), testToken, "64 hexadecimal"},
		"next alone":      {with("--next-ca-sha256", strings.Repeat("a", 64)), testToken, "needs --ca-sha256 too"},
		"version":         {with("--version", "1;reboot"), testToken, "must be a version number"},
		"unknown flag":    {with("--bogus"), testToken, "Unknown option: --bogus"},
		"flag value":      {[]string{"--from"}, testToken, "--from needs a value"},
	} {
		out, err := m.run(t, c.stdin, nil, c.args...)
		if err == nil || !strings.Contains(out, c.says) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		if strings.Contains(out, "Installing") {
			t.Errorf("%s: got as far as installing\n%s", name, out)
		}
	}
	if os.Geteuid() != 0 {
		out, err := m.run(t, testToken, nil, line...)
		if err == nil || !strings.Contains(out, "Run this with sudo") {
			t.Errorf("not root: %v\n%s", err, out)
		}
	}
	stopped := map[string]struct {
		stdin string
		env   []string
		args  []string
		says  string
	}{
		"refused": {"sgl_" + strings.Repeat("b", 52), nil, nil, "Signalith refused the token: Signalith does not know this token."},
		"mitm":    {testToken, nil, []string{"--ca-sha256", strings.Repeat("a", 64)}, "is not the one the line names"},
		"focal":   {testToken, nil, nil, "not supported yet"},
	}
	for name, c := range stopped {
		if name == "focal" {
			m.os("ubuntu", "20.04")
		}
		root := filepath.Join(m.dir, name)
		out, err := m.run(t, c.stdin, c.env, append(m.line(root), c.args...)...)
		if err == nil || !strings.Contains(out, c.says) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		if entries, _ := os.ReadDir(root); len(entries) != 0 {
			t.Errorf("%s: the script wrote %v before stopping", name, entries)
		}
		m.os("ubuntu", "24.04")
	}
	// A program that is not whole, or none.
	for name, env := range map[string][]string{"sha": {"STUB_SHA=" + strings.Repeat("0", 64)}, "none": {"STUB_NO_PROGRAM=1"}} {
		root := filepath.Join(m.dir, "prog-"+name)
		out, err := m.run(t, testToken, env, m.line(root)...)
		if err == nil || (!strings.Contains(out, "is not whole") && !strings.Contains(out, "has no agent program")) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		if _, err := os.Stat(filepath.Join(root, "usr/local/sbin/signalith-agent")); err == nil {
			t.Errorf("%s: program written", name)
		}
	}
}

// A dry run writes the agent's files, with the token in its own file
// only; run again it has nothing to change; --uninstall takes it all.
func TestAgentScriptDryRun(t *testing.T) {
	m := newAgentMachine(t)
	root := filepath.Join(m.dir, "root")
	out, err := m.run(t, testToken, nil, m.line(root)...)
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	for _, want := range []string{"Signalith at https://siem.example.com:7779, its certificate authority is the one the line names",
		"the token is an agent token Signalith knows", "would download https://packages.fluentbit.io/fluentbit.key",
		"https://packages.fluentbit.io/ubuntu/noble noble main", "would run: env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends fluent-bit",
		"would run: systemctl mask --now fluent-bit.service", "would run: systemctl enable --now signalith-agent.service"} {
		if !strings.Contains(out, want) && !strings.Contains(readFile(t, filepath.Join(root, "etc/apt/sources.list.d/signalith-fluent-bit.list")), want) {
			t.Errorf("output has no %q:\n%s", want, out)
		}
	}
	if got := readFile(t, filepath.Join(m.dir, "config-url")); !strings.Contains(got, "/api/agent/config?os=linux&arch="+runtime.GOARCH+"&server=https://siem.example.com:7779") {
		t.Errorf("config asked as %s", got)
	}
	if got := readFile(t, filepath.Join(root, "usr/local/sbin/signalith-agent")); got != string(m.program) {
		t.Errorf("program: %q", got)
	}
	if fi, _ := os.Stat(filepath.Join(root, "usr/local/sbin/signalith-agent")); fi == nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("program mode: %v", fi)
	}
	if got := readFile(t, filepath.Join(root, "usr/local/lib/signalith-agent/install.sh")); got != string(AgentInstallSH) {
		t.Error("no copy of the script for --uninstall")
	}
	conf := readFile(t, filepath.Join(root, "etc/signalith-agent/agent.conf"))
	if !strings.Contains(conf, "\nSERVER=https://siem.example.com:7779\n") || !strings.Contains(conf, "SIGNALITH_VERSION=0.4.0") || !strings.Contains(conf, "\nOSQUERY=no\n") {
		t.Errorf("agent.conf:\n%s", conf)
	}
	if got := readFile(t, filepath.Join(root, "etc/signalith-agent/ca.pem")); got != readFile(t, filepath.Join(m.dir, "ca.pem")) {
		t.Errorf("ca.pem: %s", got)
	}
	unit := readFile(t, filepath.Join(root, "etc/systemd/system/signalith-agent.service"))
	for _, want := range []string{"ExecStart=/usr/local/sbin/signalith-agent run\n", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH\n", "NoNewPrivileges=yes\n",
		"ProtectSystem=strict\n", "ReadWritePaths=/etc/signalith-agent /var/lib/signalith-agent\n"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit has no %q", want)
		}
	}
	if fi, err := os.Stat(filepath.Join(root, "var/lib/signalith-agent")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state folder: %v", err)
	}
	tok := filepath.Join(root, "etc/signalith-agent/token")
	if fi, err := os.Stat(tok); err != nil || fi.Mode().Perm() != 0o600 || readFile(t, tok) != testToken+"\n" {
		t.Errorf("token: %v", err)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path == tok {
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

	// Again, without the token: it keeps its own, nothing to change.
	again := m.line(root)
	again = append(again[:6], again[8:]...) // no --token -
	out, err = m.run(t, "", nil, again...)
	if err != nil || !strings.Contains(out, "Nothing to change") {
		t.Errorf("again: %v\n%s", err, out)
	}

	out, err = m.run(t, "", nil, "--uninstall", "--dry-run", root)
	if err != nil || !strings.Contains(out, "would run: env DEBIAN_FRONTEND=noninteractive apt-get purge -y --autoremove fluent-bit") ||
		!strings.Contains(out, "would run: systemctl unmask fluent-bit.service") || !strings.Contains(out, "would run: systemctl disable --now signalith-agent.service") {
		t.Errorf("uninstall: %v\n%s", err, out)
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			t.Errorf("left after --uninstall: %s", path)
		}
		return nil
	})
}

// With --osquery the script adds osquery's signed repository, installs
// osquery, masks its own service and adds the services that run it with
// the agent's flags; a run again keeps it, and --uninstall removes it.
func TestAgentScriptDryRunOsquery(t *testing.T) {
	for _, c := range []struct {
		id, version, repoFile, repo string
	}{
		{"ubuntu", "24.04", "etc/apt/sources.list.d/signalith-osquery.list", "signed-by=/etc/apt/keyrings/signalith-osquery.gpg] https://pkg.osquery.io/deb deb main"},
		{"rocky", "9.4", "etc/yum.repos.d/signalith-osquery.repo", "baseurl=https://pkg.osquery.io/rpm/$basearch/\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/signalith-osquery.asc\n"},
	} {
		t.Run(c.id, func(t *testing.T) {
			m := newAgentMachine(t)
			m.os(c.id, c.version)
			mustWrite(t, filepath.Join(m.dir, "bin", "dnf"), "#!/bin/sh\nexit 0\n", 0o755)
			root := filepath.Join(m.dir, "root")
			out, err := m.run(t, testToken, nil, append(m.line(root), "--osquery")...)
			if err != nil {
				t.Fatalf("dry run: %v\n%s", err, out)
			}
			for _, want := range []string{"would download https://pkg.osquery.io/", "and check its fingerprint is 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B",
				"would run: systemctl mask --now osqueryd.service", "would run: systemctl enable --now signalith-osquery-flags.path",
				"would run: systemctl enable signalith-osquery.service"} {
				if !strings.Contains(out, want) {
					t.Errorf("output has no %q:\n%s", want, out)
				}
			}
			if !strings.Contains(out, "install -y osquery") && !strings.Contains(out, "--no-install-recommends osquery") {
				t.Errorf("osquery not installed:\n%s", out)
			}
			if got := readFile(t, filepath.Join(root, "etc/signalith-agent/agent.conf")); !strings.Contains(got, "\nOSQUERY=yes\n") {
				t.Errorf("agent.conf:\n%s", got)
			}
			if got := readFile(t, filepath.Join(root, c.repoFile)); !strings.Contains(got, c.repo) {
				t.Errorf("%s:\n%s", c.repoFile, got)
			}
			unit := readFile(t, filepath.Join(root, "etc/systemd/system/signalith-osquery.service"))
			for _, want := range []string{"ConditionPathExists=/etc/signalith-agent/osquery.flags\n",
				"ExecStartPre=/usr/local/sbin/signalith-agent osquery-flags /etc/signalith-agent/osquery.flags /run/signalith-osquery/osquery.flags\n",
				"ExecStart=/opt/osquery/bin/osqueryd --flagfile=/run/signalith-osquery/osquery.flags --disable_extensions=true\n",
				"RuntimeDirectoryMode=0700\n", "NoNewPrivileges=yes\n", "Restart=always\n"} {
				if !strings.Contains(unit, want) {
					t.Errorf("osquery unit has no %q:\n%s", want, unit)
				}
			}
			if got := readFile(t, filepath.Join(root, "etc/systemd/system/signalith-osquery-flags.path")); !strings.Contains(got, "PathChanged=/etc/signalith-agent/osquery.flags\nUnit=signalith-osquery-flags.service\n") {
				t.Errorf("path unit:\n%s", got)
			}
			if got := readFile(t, filepath.Join(root, "etc/systemd/system/signalith-osquery-flags.service")); !strings.Contains(got, "ExecStart=/usr/bin/systemctl restart signalith-osquery.service\n") {
				t.Errorf("restart unit:\n%s", got)
			}

			// Again, without --osquery: osquery stays.
			out, err = m.run(t, "", nil, append(m.line(root)[:6], m.line(root)[8:]...)...)
			if err != nil || !strings.Contains(out, "Nothing to change") {
				t.Errorf("again: %v\n%s", err, out)
			}

			out, err = m.run(t, "", nil, "--uninstall", "--dry-run", root)
			for _, want := range []string{"removed the packages osquery fluent-bit", "would run: systemctl unmask osqueryd.service",
				"would run: systemctl disable --now signalith-osquery.service", "would run: systemctl disable --now signalith-osquery-flags.path"} {
				if err != nil || !strings.Contains(out, want) {
					t.Errorf("uninstall has no %q: %v\n%s", want, err, out)
				}
			}
		})
	}
}
