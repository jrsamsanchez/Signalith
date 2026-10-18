package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
)

func TestPrintSyslogPorts(t *testing.T) {
	out := func(c *config.Config) string {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout := os.Stdout
		os.Stdout = w
		printSyslogPorts(c)
		os.Stdout = stdout
		w.Close()
		b, _ := io.ReadAll(r)
		return string(b)
	}
	c := &config.Config{Syslog: config.Syslog{UDP: "0.0.0.0:514", TLS: "[::]:6514"}}
	if got := out(c); got != "udp 514 any\ntls 6514 any\n" {
		t.Errorf("got %q", got)
	}
	c.Syslog.Allow = []string{"10.0.0.0/8", " 192.0.2.10 "}
	if got := out(c); got != "udp 514 10.0.0.0/8,192.0.2.10/32\ntls 6514 10.0.0.0/8,192.0.2.10/32\n" {
		t.Errorf("got %q", got)
	}
}

// captureStdout runs f and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	f()
	os.Stdout = stdout
	w.Close()
	return string(<-done)
}

func TestPasswdKeepsEnvironmentSecretsOutOfTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-admin-password", "first-password"}); err != nil {
			t.Fatal(err)
		}
	})
	before, _ := os.ReadFile(path)
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "OS-SECRET-PW")
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-ant-ENV-ONLY")
	t.Setenv("SIGNALITH_INGEST_TOKEN", "env-token-0123456789abcdef")
	t.Setenv("SIGNALITH_OPENSEARCH_URL", "http://127.0.0.1:9201")
	t.Setenv("SIGNALITH_NEW_PASSWORD", "second password")
	var err error
	out := captureStdout(t, func() { err = cmdPasswd([]string{"-c", path}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "second password") {
		t.Errorf("the password was printed: %s", out)
	}
	after, _ := os.ReadFile(path)
	for _, secret := range []string{"OS-SECRET-PW", "sk-ant-ENV-ONLY", "env-token-0123456789abcdef", "9201"} {
		if strings.Contains(string(after), secret) {
			t.Errorf("%q from the environment was written to the file", secret)
		}
	}
	// Only the hash line changed.
	b, a := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	if len(a) != len(b) {
		t.Fatalf("line count %d -> %d", len(b), len(a))
	}
	for i := range a {
		if a[i] != b[i] && !strings.Contains(a[i], "admin_password_hash:") {
			t.Errorf("line %d changed: %q -> %q", i+1, b[i], a[i])
		}
	}
	for _, k := range []string{"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_ASSISTANT_API_KEY", "SIGNALITH_INGEST_TOKEN", "SIGNALITH_OPENSEARCH_URL"} {
		os.Unsetenv(k)
	}
	c, err := config.Load(path)
	if err != nil || !c.CheckPassword("signalithadmin", "second password") {
		t.Fatalf("new password does not work: %v", err)
	}
}

// signalith passwd run from a shell, which does not have the service's
// environment, changes the password the service uses: when the service is
// given the admin password (SIGNALITH_ADMIN_PASSWORD_FILE or
// SIGNALITH_ADMIN_PASSWORD), which replaces the one in signalith.yaml, the
// new one is kept in the service's state folder, which replaces both.
func TestPasswdUsesTheServiceEnvironment(t *testing.T) {
	for _, k := range []string{"SIGNALITH_STATE_DIR", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_ADMIN_PASSWORD", "SIGNALITH_ADMIN_PASSWORD_FILE"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "etc", "signalith.yaml")
	h, _ := config.HashPassword("password in the file")
	os.MkdirAll(filepath.Dir(path), 0o750)
	os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\n"), 0o600)
	state := filepath.Join(dir, "var")
	os.MkdirAll(state, 0o700)
	first := filepath.Join(dir, "admin-password")
	os.WriteFile(first, []byte("password from the service\n"), 0o600)
	hashFile := filepath.Join(state, "admin-password-hash")
	before, _ := os.ReadFile(path)

	saved := readServiceSettings
	t.Cleanup(func() { readServiceSettings = saved })
	for _, env := range []map[string]string{
		{"SIGNALITH_STATE_DIR": state, "SIGNALITH_ADMIN_PASSWORD_FILE": first},
		{"SIGNALITH_STATE_DIR": state, "SIGNALITH_ADMIN_PASSWORD": "password from the service"},
	} {
		os.Remove(hashFile)
		os.Setenv("SIGNALITH_STATE_DIR", "")
		readServiceSettings = func() *serviceSettings {
			return &serviceSettings{where: "the test unit", args: []string{"serve", "-c", path}, env: env}
		}
		name := "SIGNALITH_ADMIN_PASSWORD_FILE"
		if env[name] == "" {
			name = "SIGNALITH_ADMIN_PASSWORD"
		}
		t.Setenv("SIGNALITH_NEW_PASSWORD", "new break-glass password")
		out, err := capture(t, func() error { return cmdPasswd([]string{"-c", path}) })
		if err != nil || !strings.Contains(out, hashFile) || !strings.Contains(out, "the signalith service is given "+name) || strings.Contains(out, "new break-glass password") {
			t.Errorf("%s: passwd: %v\n%s", name, err, out)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Errorf("%s: passwd changed signalith.yaml, whose password the service does not use", name)
		}
		// The server, with the service's environment.
		for k, v := range env {
			t.Setenv(k, v)
		}
		c, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if !c.CheckPassword("admin", "new break-glass password") || c.CheckPassword("admin", "password from the service") {
			t.Errorf("%s: the new password does not work, or the service's still does", name)
		}
		t.Setenv(name, "")
	}
}

// Commands that only read (validate, secrets status and the others) never
// write in a fallback state folder, so one run as root cannot leave a note
// the server's own account cannot read. signalith passwd, which keeps the
// password there, notes the folder as this install's first, and finds it
// where the service does: a unit's StateDirectory= is its
// $STATE_DIRECTORY, which a shell does not have.
func TestFallbackStateDirIsNotedOnlyWhenWritten(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd's StateDirectory is Linux only")
	}
	for _, k := range []string{"SIGNALITH_STATE_DIR", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_ADMIN_PASSWORD", "SIGNALITH_ADMIN_PASSWORD_FILE", "STATE_DIRECTORY"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	// The usual state folder cannot be made: a file is where its folder
	// would be.
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(filepath.Join(dir, "data"), []byte("not a folder"), 0o600)
	h, _ := config.HashPassword("password in the file")
	os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\nlookups:\n  dir: data/lookups\n"), 0o600)
	fallback := filepath.Join(dir, "service-state")
	first := filepath.Join(dir, "admin-password")
	os.WriteFile(first, []byte("first password\n"), 0o600)
	saved := readServiceSettings
	t.Cleanup(func() { readServiceSettings = saved })
	readServiceSettings = func() *serviceSettings {
		return &serviceSettings{where: "the test unit", args: []string{"serve", "-c", path},
			env: map[string]string{"STATE_DIRECTORY": fallback, "SIGNALITH_ADMIN_PASSWORD_FILE": first}}
	}
	useServiceEnv(path, io.Discard)
	if got := os.Getenv("STATE_DIRECTORY"); got != fallback {
		t.Fatalf("STATE_DIRECTORY = %q", got)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := config.StateDirFor(path); got != fallback {
		t.Fatalf("state folder %q, want %q", got, fallback)
	}
	if _, err := os.Stat(fallback); !os.IsNotExist(err) {
		t.Fatalf("reading the config made the fallback folder: %v", err)
	}
	t.Setenv("SIGNALITH_NEW_PASSWORD", "new break-glass password")
	if out, err := capture(t, func() error { return cmdPasswd([]string{"-c", path}) }); err != nil {
		t.Fatalf("passwd: %v\n%s", err, out)
	}
	note, err := os.ReadFile(filepath.Join(fallback, "used_instead_of"))
	if err != nil || !strings.Contains(string(note), filepath.Join(dir, "data")+"\n") {
		t.Errorf("note: %v %q", err, note)
	}
	if fi, err := os.Stat(filepath.Join(fallback, "admin-password-hash")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("password hash: %v", err)
	}
}

func TestReadNewPasswordFromAPipe(t *testing.T) {
	r, w, _ := os.Pipe()
	io.WriteString(w, "a pass phrase with spaces\r\n")
	w.Close()
	pw, err := readNewPassword(r, io.Discard)
	if err != nil || pw != "a pass phrase with spaces" {
		t.Errorf("%q %v", pw, err)
	}
	r2, w2, _ := os.Pipe()
	w2.Close()
	if _, err := readNewPassword(r2, io.Discard); err == nil {
		t.Error("empty input accepted")
	}
}

func TestSyslogSummary(t *testing.T) {
	for _, c := range []struct {
		syslog config.Syslog
		want   string
	}{
		{config.Syslog{}, ""},
		{config.Syslog{UDP: "0.0.0.0:514", TCP: "0.0.0.0:514"}, "UDP 0.0.0.0:514, TCP 0.0.0.0:514"},
		{config.Syslog{UDP: "0.0.0.0:5514", TCP: "0.0.0.0:5514", PublicPort: 514}, "UDP 0.0.0.0:5514, TCP 0.0.0.0:5514 (devices send UDP and TCP to port 514)"},
		{config.Syslog{UDP: "0.0.0.0:5514", PublicPort: 514}, "UDP 0.0.0.0:5514 (devices send UDP to port 514)"},
		{config.Syslog{TCP: "0.0.0.0:5514", TLS: "0.0.0.0:6514", PublicPort: 514}, "TCP 0.0.0.0:5514, TLS 0.0.0.0:6514 (devices send TCP to port 514)"},
		{config.Syslog{TLS: "0.0.0.0:6514", PublicPort: 514}, "TLS 0.0.0.0:6514"},
	} {
		if got := syslogSummary(&config.Config{Syslog: c.syslog}); got != c.want {
			t.Errorf("%+v: %q, want %q", c.syslog, got, c.want)
		}
	}
}

// init's agent port listens on -listen's host, so a server whose web page
// is on loopback only takes agents on loopback only too, and the
// installers open no firewall port for either.
func TestInitAgentPortFollowsListen(t *testing.T) {
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	for listen, want := range map[string]string{"127.0.0.1:9000": "127.0.0.1:7779", "0.0.0.0:9000": "0.0.0.0:7779"} {
		path := filepath.Join(t.TempDir(), "signalith.yaml")
		captureStdout(t, func() {
			if err := cmdInit([]string{"-c", path, "-admin-password", "first-password", "-listen", listen}); err != nil {
				t.Fatal(err)
			}
		})
		raw, _ := os.ReadFile(path)
		if !strings.Contains(string(raw), "agent_listen: "+want) {
			t.Errorf("-listen %s: config lacks agent_listen %s:\n%s", listen, want, raw)
		}
	}
	for host, want := range map[string]string{"127.0.0.1": "local", "::1": "local", "localhost": "local", "0.0.0.0": "any", "": "any", "10.0.0.5": "any"} {
		if got := listenScope(host); got != want {
			t.Errorf("listenScope(%q) = %q, want %q", host, got, want)
		}
	}
	c := config.Default()
	c.Server.Listen, c.Server.AgentListen = "0.0.0.0:9000", "127.0.0.1:7779"
	if out := captureStdout(t, func() { printWebPorts(c) }); out != "web 9000 any\nagents 7779 local\n" {
		t.Errorf("printWebPorts:\n%s", out)
	}
}

// A new config serves HTTPS with Signalith's own certificate, refuses
// agents over plain HTTP and receives syslog over TLS on 6514.
// A new install's built-in admin is signalithadmin, while a config file
// that names none (one written by hand before 0.3.1) keeps admin.
func TestInitNamesBuiltinAdminSignalithadmin(t *testing.T) {
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	out := captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-admin-password", "first-password"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "User:        signalithadmin") {
		t.Errorf("init output does not name signalithadmin:\n%s", out)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.AdminUser != config.DefaultAdminUser || config.DefaultAdminUser != "signalithadmin" {
		t.Errorf("auth.admin_user %q, want signalithadmin", c.Auth.AdminUser)
	}
	if !c.CheckPassword("signalithadmin", "first-password") || c.CheckPassword("admin", "first-password") {
		t.Error("the first password should sign in as signalithadmin only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), "admin_user: signalithadmin", "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := config.LoadFile(path); err != nil || c.Auth.AdminUser != "admin" {
		t.Errorf("a file naming no admin: %v, %+v; want admin", err, c)
	}
}

func TestInitTurnsOnHTTPS(t *testing.T) {
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	out := captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-admin-password", "first-password", "-listen", "0.0.0.0:8080"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Web UI:      https://") || !strings.Contains(out, "docs/https.md") {
		t.Errorf("init output does not point to HTTPS:\n%s", out)
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{"mode: auto", "plaintext_ingest: deny", "tls: 0.0.0.0:6514"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config lacks %q:\n%s", want, raw)
		}
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.TLSMode() != config.TLSAuto || c.Server.PlaintextIngest() || c.Syslog.TLS != "0.0.0.0:6514" {
		t.Errorf("mode %s, plaintext %v, syslog.tls %q", c.Server.TLSMode(), c.Server.PlaintextIngest(), c.Syslog.TLS)
	}
	if got := httpsSummary(c); !strings.Contains(got, "own certificate") || !strings.Contains(got, "Agents must send over HTTPS") {
		t.Errorf("summary %q", got)
	}
	// -syslog-tls "" leaves it off.
	path2 := filepath.Join(t.TempDir(), "signalith.yaml")
	captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path2, "-admin-password", "first-password", "-syslog-tls="}); err != nil {
			t.Fatal(err)
		}
	})
	if c2, err := config.Load(path2); err != nil || c2.Syslog.TLS != "" {
		t.Errorf("syslog.tls %v %v", c2, err)
	}
}
