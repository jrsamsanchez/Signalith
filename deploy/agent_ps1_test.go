// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestAgentPS1IsASCIIWithLFLineEndings(t *testing.T) {
	// Windows PowerShell 5.1 reads a script without a byte order mark as
	// the system's code page, so the script keeps to ASCII.
	for i, b := range AgentInstallPS1 {
		if b > 0x7e || (b < 0x20 && b != '\n' && b != '\t') {
			t.Fatalf("deploy/agent/install.ps1 byte %d is %#x: keep it ASCII with LF line endings", i, b)
		}
	}
}

// powershell finds a PowerShell to run the script with: Windows PowerShell
// on Windows, else PowerShell 7 when installed (the GitHub runners have
// it).
func powershell(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"powershell.exe", "pwsh"} {
		if name == "powershell.exe" && runtime.GOOS != "windows" {
			continue
		}
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("no PowerShell")
	return ""
}

// agentWindows is Signalith as the Windows script sees it, with a test
// agent token and program.
type agentWindows struct {
	ts      *httptest.Server
	caSHA   string
	program []byte
	token   string
	shell   string
	script  string

	mu       sync.Mutex
	requests []string
}

func newAgentWindows(t *testing.T) *agentWindows {
	t.Helper()
	w := &agentWindows{shell: powershell(t), program: []byte("MZ agent program for the test"),
		token: "sgl_" + strings.Repeat("abcdefghijklmnopqrstuvwxyz234567", 2)[:52]}
	w.script = filepath.Join(t.TempDir(), "install.ps1")
	if err := os.WriteFile(w.script, AgentInstallPS1, 0o666); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			w.mu.Lock()
			w.requests = append(w.requests, r.URL.RequestURI())
			w.mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer "+w.token {
				rw.Header().Set("Content-Type", "application/json")
				rw.WriteHeader(http.StatusUnauthorized)
				rw.Write([]byte(`{"error":"this agent token was revoked"}`))
				return
			}
			h(rw, r)
		}
	}
	mux.HandleFunc("GET /api/tls/ca.pem", func(rw http.ResponseWriter, r *http.Request) {
		pem.Encode(rw, &pem.Block{Type: "CERTIFICATE", Bytes: w.ts.Certificate().Raw})
	})
	mux.HandleFunc("GET /api/agent/config", authed(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(`{"revision":"r1","poll_seconds":300}`))
	}))
	mux.HandleFunc("GET /api/agent/program", authed(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("os") != "windows" || r.URL.Query().Get("arch") != "amd64" {
			http.NotFound(rw, r)
			return
		}
		sum := sha256.Sum256(w.program)
		rw.Header().Set("X-Signalith-SHA256", hex.EncodeToString(sum[:]))
		rw.Write(w.program)
	}))
	// Set before the server starts, so its handlers see it.
	w.ts = httptest.NewUnstartedServer(mux)
	w.ts.StartTLS()
	t.Cleanup(w.ts.Close)
	sum := sha256.Sum256(w.ts.Certificate().Raw)
	w.caSHA = hex.EncodeToString(sum[:])
	return w
}

// run runs the script with token on the pipeline (none when empty).
func (w *agentWindows) run(t *testing.T, token string, args ...string) (string, error) {
	t.Helper()
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	cmd := "& " + quote(w.script)
	if token != "" {
		cmd = quote(token) + " | " + cmd
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			cmd += " " + a
		} else {
			cmd += " " + quote(a)
		}
	}
	cmd += "; exit $LASTEXITCODE"
	c := exec.Command(w.shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd)
	// Windows PowerShell started from PowerShell 7 (as go test is on the
	// runners) would load 7's modules; a person's Windows PowerShell has
	// its own.
	c.Env = withoutPSModulePath(os.Environ())
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	return out.String(), err
}

func (w *agentWindows) line(root string) []string {
	return []string{"-From", w.ts.URL, "-CaSha256", w.caSHA, "-Version", "0.4.0", "-Token", "-", "-DryRun", root}
}

func TestAgentPS1Parses(t *testing.T) {
	shell := powershell(t)
	path := filepath.Join(t.TempDir(), "install.ps1")
	if err := os.WriteFile(path, AgentInstallPS1, 0o666); err != nil {
		t.Fatal(err)
	}
	cmd := `$t = $null; $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('` + path + `', [ref]$t, [ref]$e); ` +
		`if ($e) { $e | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }; exit 1 }`
	if out, err := exec.Command(shell, "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput(); err != nil {
		t.Fatalf("install.ps1 does not parse: %v\n%s", err, out)
	}
}

func TestAgentPS1DryRun(t *testing.T) {
	w := newAgentWindows(t)
	root := t.TempDir()
	out, err := w.run(t, w.token, w.line(root)...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"its certificate authority is the one the line names", "the token is an agent token Signalith knows",
		"would download https://packages.fluentbit.io/windows/fluent-bit-", "the agent program (", "New-Service -Name SignalithAgent", "Done.",
		// Process creation auditing with the command line (BUY-03).
		"auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable", "ProcessCreationIncludeCmdLine_Enabled 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	conf := filepath.Join(root, "ProgramData", "Signalith Agent")
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := strings.TrimSpace(read(filepath.Join(conf, "token"))); got != w.token {
		t.Errorf("token file = %q", got)
	}
	if got := read(filepath.Join(conf, "agent.conf")); !strings.Contains(got, "SERVER="+w.ts.URL+"\n") || !strings.Contains(got, "SIGNALITH_VERSION=0.4.0\n") {
		t.Errorf("agent.conf:\n%s", got)
	}
	block, _ := pem.Decode([]byte(read(filepath.Join(conf, "ca.pem"))))
	if block == nil || !bytes.Equal(block.Bytes, w.ts.Certificate().Raw) {
		t.Error("ca.pem is not the server's certificate authority")
	}
	prog := filepath.Join(root, "Program Files", "Signalith Agent")
	if got := read(filepath.Join(prog, "signalith-agent.exe")); got != string(w.program) {
		t.Errorf("the agent program = %q", got)
	}
	if got := read(filepath.Join(prog, "install.ps1")); got != string(AgentInstallPS1) {
		t.Error("the copy of the script for -Uninstall differs from the script")
	}
	// Nothing about the token on the command line Signalith saw.
	w.mu.Lock()
	requests := append([]string(nil), w.requests...)
	w.mu.Unlock()
	for _, r := range requests {
		if strings.Contains(r, w.token) {
			t.Errorf("a request carried the token in its address: %s", r)
		}
	}

	// A run again, without a token, keeps the agent's and changes
	// nothing.
	again := w.line(root)
	again = append(again[:6:6], again[8:]...) // without -Token -
	out, err = w.run(t, "", again...)
	if err != nil || !strings.Contains(out, "Nothing to change") {
		t.Fatalf("run again: %v\n%s", err, out)
	}

	// -Sysmon is added on a run again.
	out, err = w.run(t, "", append(again, "-Sysmon")...)
	if err != nil || !strings.Contains(out, "would download https://download.sysinternals.com/files/Sysmon.zip") {
		t.Fatalf("-Sysmon: %v\n%s", err, out)
	}

	// -EnableLogs turns on script block logging and the logs that are off
	// by default (BUY-04), and -Uninstall turns them off again.
	out, err = w.run(t, "", append(again, "-EnableLogs")...)
	if err != nil || !strings.Contains(out, "EnableScriptBlockLogging 1") || !strings.Contains(out, `wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true`) {
		t.Fatalf("-EnableLogs: %v\n%s", err, out)
	}

	// -Osquery too; a run again after it keeps osquery.
	out, err = w.run(t, "", append(again, "-Osquery")...)
	if err != nil || !strings.Contains(out, "would download https://pkg.osquery.io/windows/osquery-") {
		t.Fatalf("-Osquery: %v\n%s", err, out)
	}
	out, err = w.run(t, "", again...)
	if err != nil || !strings.Contains(out, "Nothing to change") {
		t.Fatalf("run again after -Osquery: %v\n%s", err, out)
	}

	out, err = w.run(t, "", "-Uninstall", "-DryRun", root)
	if err != nil || !strings.Contains(out, "sc.exe delete SignalithAgent") || !strings.Contains(out, "Sysmon64.exe -u force") ||
		!strings.Contains(out, "Remove-ItemProperty") || !strings.Contains(out, `wevtutil sl "Microsoft-Windows-CAPI2/Operational" /e:false`) {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	for _, p := range []string{conf, prog} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is still there after -Uninstall", p)
		}
	}
}

func TestAgentPS1Refuses(t *testing.T) {
	w := newAgentWindows(t)
	cases := []struct {
		name, token string
		args        []string
		want        string
	}{
		{"no from", w.token, []string{"-Token", "-"}, "-From is missing"},
		{"http", w.token, []string{"-From", "http://siem:7779", "-Token", "-"}, "must be an https:// address"},
		{"path", w.token, []string{"-From", "https://siem:7779/x", "-Token", "-"}, "no path"},
		{"short token", "sgl_abc", []string{"-From", w.ts.URL, "-Token", "-"}, "not whole"},
		{"not a token", "SJ1.abc", []string{"-From", w.ts.URL, "-Token", "-"}, "not a Signalith agent token"},
		{"no token", "", []string{"-From", w.ts.URL}, "-Token is missing"},
		{"bad ca", w.token, []string{"-From", w.ts.URL, "-CaSha256", "abc", "-Token", "-"}, "64 hexadecimal"},
		{"bad osquery sha", w.token, []string{"-From", w.ts.URL, "-OsquerySha256", "abc", "-Token", "-"}, "-OsquerySha256 must be 64 hexadecimal"},
		{"no osquery msi", w.token, []string{"-From", w.ts.URL, "-OsqueryMsi", "no-such.msi", "-Token", "-"}, "-OsqueryMsi no-such.msi: there is no such file"},
		{"other ca", w.token, []string{"-From", w.ts.URL, "-CaSha256", strings.Repeat("0", 64), "-Token", "-"}, "not the one the line names"},
		{"revoked", "sgl_" + strings.Repeat("a", 52), []string{"-From", w.ts.URL, "-CaSha256", w.caSHA, "-Token", "-"}, "Signalith refused the token: this agent token was revoked"},
		// Without -CaSha256 the computer's own authorities check the
		// certificate, which they do not know.
		{"untrusted", w.token, []string{"-From", w.ts.URL, "-Token", "-"}, "trusted certificate authorities"},
		// The certificate covers 127.0.0.1, not localhost.
		{"other name", w.token, []string{"-From", strings.Replace(w.ts.URL, "127.0.0.1", "localhost", 1), "-CaSha256", w.caSHA, "-Token", "-"}, "Could not reach Signalith"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			out, err := w.run(t, c.token, append(c.args, "-DryRun", root)...)
			if err == nil {
				t.Fatalf("the script did not stop:\n%s", out)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("output lacks %q:\n%s", c.want, out)
			}
			if _, err := os.Stat(filepath.Join(root, "ProgramData", "Signalith Agent", "token")); err == nil {
				t.Error("the script wrote the token before it stopped")
			}
		})
	}
}

// The agent's data folder, or the folder it is in, swapped for a link
// (a junction on Windows) to a folder someone else controls is refused
// before anything is written.
func TestAgentPS1RefusesLinkedFolders(t *testing.T) {
	w := newAgentWindows(t)
	link := func(t *testing.T, target, name string) {
		t.Helper()
		if runtime.GOOS == "windows" {
			if out, err := exec.Command("cmd", "/c", "mklink", "/J", name, target).CombinedOutput(); err != nil {
				t.Skipf("mklink /J: %v %s", err, out)
			}
			return
		}
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ name, linked string }{
		{"data folder", filepath.Join("ProgramData", "Signalith Agent")},
		{"folder above it", "ProgramData"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			theirs := t.TempDir()
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, c.linked)), 0o755); err != nil {
				t.Fatal(err)
			}
			link(t, theirs, filepath.Join(root, c.linked))
			out, err := w.run(t, w.token, w.line(root)...)
			if err == nil || !strings.Contains(out, "is a link or junction") {
				t.Fatalf("not refused: %v\n%s", err, out)
			}
			if entries, _ := os.ReadDir(theirs); len(entries) != 0 {
				t.Errorf("the script wrote into the linked folder: %v", entries)
			}
		})
	}
}

func withoutPSModulePath(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(strings.ToUpper(kv), "PSMODULEPATH=") {
			out = append(out, kv)
		}
	}
	return out
}
