package deploy

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAgentMacScriptParses(t *testing.T) {
	if bytes.Contains(AgentInstallMacOS, []byte("\r")) {
		t.Fatal("deploy/agent/install-macos.sh has CRLF line endings")
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	path := filepath.Join(t.TempDir(), "install-macos.sh")
	if err := os.WriteFile(path, AgentInstallMacOS, 0o666); err != nil {
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

// newMacMachine is the fake Linux computer of the agent's script, made to
// look like a Mac to the macOS script: its version and a shasum.
func newMacMachine(t *testing.T) *agentMachine {
	m := newAgentMachine(t)
	mustWrite(t, filepath.Join(m.dir, "bin", "shasum"), "#!/bin/sh\n[ \"$1 $2\" = '-a 256' ] || exit 2\nshift 2\nexec sha256sum \"$@\"\n", 0o755)
	return m
}

func (m *agentMachine) runMac(t *testing.T, stdin string, env []string, args ...string) (string, error) {
	t.Helper()
	script := filepath.Join(m.dir, "install-macos.sh")
	if err := os.WriteFile(script, AgentInstallMacOS, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Dir = m.dir
	cmd.Stdin = strings.NewReader(stdin + "\n")
	cmd.Env = append(os.Environ(), "PATH="+m.path, "STUB="+m.dir, "STUB_TOKEN="+testToken, "SIGNALITH_AGENT_MACOS_VERSION=15.1")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestAgentMacScriptRefuses(t *testing.T) {
	m := newMacMachine(t)
	line := []string{"--from", "https://siem.example.com:7779", "--token", "-"}
	for name, c := range map[string]struct {
		args  []string
		stdin string
		env   []string
		says  string
	}{
		"no from":     {[]string{"--token", "-"}, testToken, nil, "--from is missing"},
		"http":        {[]string{"--from", "http://siem.example.com", "--token", "-"}, testToken, nil, "must be an https:// address"},
		"token":       {line, "sgl_abc", nil, "not whole"},
		"osquery sha": {append(append([]string{}, line...), "--osquery-sha256", "abc"), testToken, nil, "64 hexadecimal"},
		"old macOS":   {append(append([]string{}, line...), "--dry-run", filepath.Join(m.dir, "old")), testToken, []string{"SIGNALITH_AGENT_MACOS_VERSION=11.7"}, "this Mac runs macOS 11.7"},
		"unknown":     {append(append([]string{}, line...), "--bogus"), testToken, nil, "Unknown option: --bogus"},
	} {
		out, err := m.runMac(t, c.stdin, c.env, c.args...)
		if err == nil || !strings.Contains(out, c.says) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		if strings.Contains(out, "Installing") {
			t.Errorf("%s: got as far as installing\n%s", name, out)
		}
	}
	root := filepath.Join(m.dir, "mitm")
	out, err := m.runMac(t, testToken, nil, append(macLine(m, root), "--ca-sha256", strings.Repeat("a", 64))...)
	if err == nil || !strings.Contains(out, "is not the one the line names") {
		t.Errorf("mitm: %v\n%s", err, out)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("mitm: the script wrote %v before stopping", entries)
	}
	root = filepath.Join(m.dir, "sha")
	out, err = m.runMac(t, testToken, []string{"STUB_SHA=" + strings.Repeat("0", 64)}, macLine(m, root)...)
	if err == nil || !strings.Contains(out, "is not whole") {
		t.Errorf("program sha: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "opt/signalith-agent/bin/signalith-agent")); err == nil {
		t.Error("program written")
	}
}

func macLine(m *agentMachine, root string) []string {
	return []string{"--from", "https://siem.example.com:7779", "--ca-sha256", m.caSHA, "--version", "0.4.0", "--token", "-", "--dry-run", root}
}

// A dry run installs osquery's package, checked, writes the agent's files
// and launchd service, with the token in its own file only; run again it
// has nothing to change; --uninstall takes it all.
func TestAgentMacScriptDryRun(t *testing.T) {
	m := newMacMachine(t)
	root := filepath.Join(m.dir, "root")
	out, err := m.runMac(t, testToken, nil, append(macLine(m, root), "--osquery")...)
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	for _, want := range []string{"system: macOS 15.1", "its certificate authority is the one the line names", "the token is an agent token Signalith knows",
		"would download https://pkg.osquery.io/darwin/osquery-5.12.1.pkg and check it is signed by osquery (3522FA9PXF)",
		"would run: installer -pkg ", `certificate leaf[subject.OU] = "3522FA9PXF"`,
		"would run: launchctl bootstrap system /Library/LaunchDaemons/io.signalith.agent.plist", "give osquery Full Disk Access"} {
		if !strings.Contains(out, want) {
			t.Errorf("output has no %q:\n%s", want, out)
		}
	}
	if got := readFile(t, filepath.Join(m.dir, "config-url")); !strings.Contains(got, "/api/agent/config?os=darwin&arch="+runtime.GOARCH+"&server=https://siem.example.com:7779") {
		t.Errorf("config asked as %s", got)
	}
	prog := filepath.Join(root, "opt/signalith-agent/bin/signalith-agent")
	if got := readFile(t, prog); got != string(m.program) {
		t.Errorf("program: %q", got)
	}
	if fi, _ := os.Stat(prog); fi == nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("program mode: %v", fi)
	}
	if got := readFile(t, filepath.Join(root, "opt/signalith-agent/lib/install-macos.sh")); got != string(AgentInstallMacOS) {
		t.Error("no copy of the script for --uninstall")
	}
	conf := readFile(t, filepath.Join(root, "etc/signalith-agent/agent.conf"))
	if !strings.Contains(conf, "\nSERVER=https://siem.example.com:7779\n") || !strings.Contains(conf, "\nOSQUERY=yes\n") {
		t.Errorf("agent.conf:\n%s", conf)
	}
	plist := readFile(t, filepath.Join(root, "Library/LaunchDaemons/io.signalith.agent.plist"))
	for _, want := range []string{"<string>io.signalith.agent</string>", "<string>/opt/signalith-agent/bin/signalith-agent</string>\n\t\t<string>run</string>",
		"<key>KeepAlive</key>\n\t<true/>", "<key>AbandonProcessGroup</key>\n\t<true/>"} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist has no %q:\n%s", want, plist)
		}
	}
	if fi, err := os.Stat(filepath.Join(root, "var/lib/signalith-agent")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state folder: %v", err)
	}
	tok := filepath.Join(root, "etc/signalith-agent/token")
	if fi, err := os.Stat(tok); err != nil || fi.Mode().Perm() != 0o600 || readFile(t, tok) != testToken+"\n" {
		t.Errorf("token: %v", err)
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && path != tok && strings.Contains(readFile(t, path), testToken) {
			t.Errorf("%s holds the token", path)
		}
		return nil
	})

	// Again, without the token: osquery stays, nothing to change.
	again := macLine(m, root)
	again = append(again[:6], again[8:]...)
	out, err = m.runMac(t, "", nil, again...)
	if err != nil || !strings.Contains(out, "Nothing to change") || !strings.Contains(out, "osquery is installed") {
		t.Errorf("again: %v\n%s", err, out)
	}

	out, err = m.runMac(t, "", nil, "--uninstall", "--dry-run", root)
	if err != nil || !strings.Contains(out, "would run: launchctl bootout system/io.signalith.agent") || !strings.Contains(out, "removed osquery") ||
		!strings.Contains(out, "would run: pkgutil --forget io.osquery.agent") {
		t.Errorf("uninstall: %v\n%s", err, out)
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			t.Errorf("left after --uninstall: %s", path)
		}
		return nil
	})
}

// The osquery package is installed only when the first certificate in
// pkgutil's chain is a Developer ID Installer one ending in osquery's team.
func TestAgentMacOsquerySigner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	script := string(AgentInstallMacOS)
	start := strings.Index(script, "\nosquery_pkg_signed() {")
	end := strings.Index(script[start:], "\n}\n")
	team := "3522FA9PXF"
	if start < 0 || end < 0 || !strings.Contains(script, "OSQUERY_TEAM="+team+"\n") {
		t.Fatal("no osquery_pkg_signed function or team ID")
	}
	fn := script[start : start+end+3]
	out := func(status, leaf string) string {
		return "Package \"osquery-5.12.1.pkg\":\n   Status: " + status + "\n   Notarization: trusted by the Apple notary service\n" +
			"   Certificate Chain:\n    1. " + leaf + "\n       Expires: 2027-09-14 21:30:09 +0000\n" +
			"    2. Developer ID Certification Authority\n    3. Apple Root CA\n"
	}
	apple := "signed by a developer certificate issued by Apple for distribution"
	for name, c := range map[string]struct {
		text string
		ok   bool
	}{
		"osquery":       {out(apple, "Developer ID Installer: OSQUERY A Series of LF Projects, LLC ("+team+")"), true},
		"decoy team":    {out(apple, "Developer ID Installer: Evil ("+team+") (ABCDE12345)"), false},
		"other team":    {out(apple, "Developer ID Installer: Someone (ABCDE12345)"), false},
		"application":   {out(apple, "Developer ID Application: OSQUERY ("+team+")"), false},
		"not apple":     {out("signed by a certificate trusted by Mac OS X", "Developer ID Installer: OSQUERY ("+team+")"), false},
		"unsigned":      {"Package \"osquery.pkg\":\n   Status: no signature\n", false},
		"second in row": {strings.Replace(out(apple, "Developer ID Installer: Evil (ABCDE12345)"), "3. Apple Root CA", "3. Developer ID Installer: X ("+team+")", 1), false},
	} {
		f := filepath.Join(t.TempDir(), "sig")
		if err := os.WriteFile(f, []byte(c.text), 0o644); err != nil {
			t.Fatal(err)
		}
		err := exec.Command("sh", "-c", "OSQUERY_TEAM="+team+fn+"osquery_pkg_signed \"$1\"", "sh", f).Run()
		if (err == nil) != c.ok {
			t.Errorf("%s: signed=%v, want %v", name, err == nil, c.ok)
		}
	}
}
