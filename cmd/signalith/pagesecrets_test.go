package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// useTestKeyring makes k the keyring secrets.Seal uses for the rest of the
// test, as the server and the commands make their config's.
func useTestKeyring(t *testing.T, k *secrets.Keyring) {
	t.Helper()
	before := secrets.Default()
	secrets.SetDefault(k)
	t.Cleanup(func() { secrets.SetDefault(before) })
}

// The secrets commands find the Settings page's settings.yaml with the
// other files the server writes: status lists it, encrypt and
// rotate-master encrypt its values, and a link put in its place is
// replaced, as the server replaces it, not followed.
func TestSecretsCommandsCoverTheSettingsPage(t *testing.T) {
	path, lookups := secretsSetup(t)
	file := filepath.Join(lookups, "settings.yaml")
	page := "settings:\n  opensearch.password:\n    secret: page-plain-pw\n    sent_to: https://os.lab.example.com:9200\n    changed_by: ann\n"
	if err := os.WriteFile(file, []byte(page), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCmd(t, "", "status", "-c", path)
	if err != nil || !strings.Contains(out, file+"\n  opensearch.password  plain text\n") || !strings.Contains(out, "0 encrypted, 6 plain text.") {
		t.Fatalf("status (%v):\n%s", err, out)
	}
	out, err = runCmd(t, "", "encrypt", "-c", path)
	if err != nil || !strings.Contains(out, "Encrypted 1 value in "+file) {
		t.Fatalf("encrypt (%v):\n%s", err, out)
	}
	data, _ := os.ReadFile(file)
	if strings.Contains(string(data), "page-plain-pw") || !regexp.MustCompile(`secret: enc:v1:[0-9a-f]{8}:`).Match(data) ||
		!strings.Contains(string(data), "sent_to: https://os.lab.example.com:9200") || !strings.Contains(string(data), "changed_by: ann") {
		t.Fatalf("settings.yaml after encrypt:\n%s", data)
	}
	if st, _ := os.Stat(file); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	// The page's password replaces the one in signalith.yaml.
	if c, err := config.Load(path); err != nil || c.OpenSearch.Password != "page-plain-pw" || len(c.PageUnreadable()) != 0 {
		t.Fatalf("load: %v", err)
	}
	out, err = runCmd(t, "", "status", "-c", path)
	if err != nil || !strings.Contains(out, "6 encrypted, 0 plain text.") {
		t.Errorf("status after encrypt (%v):\n%s", err, out)
	}

	out, err = runCmd(t, "", "rotate-master", "-c", path)
	newID := regexp.MustCompile(`New master key ([0-9a-f]{8}) in `).FindStringSubmatch(out)
	if err != nil || newID == nil || !strings.Contains(out, "Encrypted 1 value again in "+file) {
		t.Fatalf("rotate (%v):\n%s", err, out)
	}
	data, _ = os.ReadFile(file)
	if !strings.Contains(string(data), "secret: enc:v1:"+newID[1]+":") {
		t.Errorf("settings.yaml after rotate:\n%s", data)
	}
	if c, err := config.Load(path); err != nil || c.OpenSearch.Password != "page-plain-pw" {
		t.Errorf("load after rotate: %v", err)
	}

	// One others can read, such as one copied in by hand, is made private
	// when it is written again.
	if runtime.GOOS != "windows" {
		os.WriteFile(file, []byte(page), 0o644)
		os.Chmod(file, 0o644)
		if out, err := runCmd(t, "", "encrypt", "-c", path); err != nil || !strings.Contains(out, "Encrypted 1 value in "+file) {
			t.Fatalf("encrypt over a 0644 file (%v):\n%s", err, out)
		}
		if st, _ := os.Stat(file); st.Mode().Perm() != 0o600 {
			t.Errorf("mode after encrypting a 0644 file: %v", st.Mode().Perm())
		}
	}

	// A link in place of settings.yaml is replaced; the file it points to
	// is left as it is, and the command says it still holds the plain
	// value.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.yaml")
	os.WriteFile(elsewhere, []byte(page), 0o644)
	os.Remove(file)
	if err := os.Symlink(elsewhere, file); err != nil {
		t.Skip("cannot make links here:", err)
	}
	target, _ := filepath.EvalSymlinks(elsewhere)
	out, err = runCmd(t, "", "encrypt", "-c", path)
	if err != nil || !strings.Contains(out, "Encrypted 1 value in "+file) ||
		!strings.Contains(out, "Note: "+file+" was a link to "+target+", and is now a file of its own; "+target+" still holds the old text, with 1 password or key as plain text.") {
		t.Fatalf("encrypt through a link (%v):\n%s", err, out)
	}
	if fi, err := os.Lstat(file); err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		t.Errorf("the link is still there: %v", err)
	}
	if b, _ := os.ReadFile(elsewhere); string(b) != page {
		t.Errorf("the file the link pointed to changed:\n%s", b)
	}
}

// "secrets set" writes signalith.yaml, which a value saved on the Settings
// page overrides: it says so, also when that one cannot be decrypted, so a
// restart is not expected to use the new value.
func TestSecretsSetNamesThePageValue(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	path, lookups := secretsSetup(t)
	file := filepath.Join(lookups, "settings.yaml")
	write := func(secret, extra string) {
		t.Helper()
		body := "settings:\n  opensearch.password:\n    secret: " + secret + "\n    sent_to: https://os.lab.example.com:9200\n" + extra
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("page-pw", "")
	out, err := runCmd(t, "new-file-pw\n", "set", "opensearch.password", "-c", path)
	if err != nil || !strings.Contains(out, "Note: opensearch.password is also set on the Settings page (in "+file+"), and the server uses that one instead of the one in signalith.yaml.\n") ||
		!strings.Contains(out, "signalith settings reset opensearch.password") || strings.Contains(out, "Restart the server to use it.") {
		t.Errorf("set with a page value (%v):\n%s", err, out)
	}
	if c, err := config.Load(path); err != nil || c.OpenSearch.Password != "page-pw" {
		t.Errorf("load: %v", err)
	}

	// One that cannot be decrypted still overrides signalith.yaml.
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal("settings.opensearch.password", "lost-pw")
	if err != nil {
		t.Fatal(err)
	}
	write(sealed, "")
	out, err = runCmd(t, "newer-file-pw\n", "set", "opensearch.password", "-c", path)
	if err != nil || !strings.Contains(out, "it cannot be decrypted with this master key, so until it is removed the server runs without one") {
		t.Errorf("set with an unreadable page value (%v):\n%s", err, out)
	}

	// One a restart set aside is not used: no note.
	write("page-pw", "    refused: OpenSearch did not answer\n")
	out, err = runCmd(t, "newest-file-pw\n", "set", "opensearch.password", "-c", path)
	if err != nil || strings.Contains(out, "Settings page") || !strings.Contains(out, "Restart the server to use it.") {
		t.Errorf("set with a page value set aside (%v):\n%s", err, out)
	}
	// Nor for a setting the page does not have.
	out, err = runCmd(t, "sk-new\n", "set", "assistant.api_key", "-c", path)
	if err != nil || strings.Contains(out, "Settings page") || !strings.Contains(out, "Restart the server to use it.") {
		t.Errorf("set assistant.api_key (%v):\n%s", err, out)
	}
}

// The server encrypts a plain value in settings.yaml, such as one written
// by hand or by a version from before, when it starts.
func TestStartupEncryptsPageSecrets(t *testing.T) {
	path, lookups := secretsSetup(t)
	file := filepath.Join(lookups, "settings.yaml")
	os.WriteFile(file, []byte("settings:\n  opensearch.password:\n    secret: by-hand-pw\n    sent_to: https://os.lab.example.com:9200\n"), 0o600)
	c, err := config.Load(path)
	if err != nil || c.OpenSearch.Password != "by-hand-pw" {
		t.Fatalf("load: %v", err)
	}
	logs := &syncBuffer{}
	log := newLogger(logs)
	useKeys(c, log)
	encryptStores(c, log)
	data, _ := os.ReadFile(file)
	if strings.Contains(string(data), "by-hand-pw") || !strings.Contains(string(data), "secret: enc:v1:") {
		t.Errorf("settings.yaml after startup:\n%s", data)
	}
	if !strings.Contains(logs.String(), `msg="encrypted the passwords and keys stored in a file" file=`+file+" values=1") {
		t.Errorf("log:\n%s", logs.String())
	}
	if c, err := config.Load(path); err != nil || c.OpenSearch.Password != "by-hand-pw" {
		t.Errorf("load after: %v", err)
	}
	if st, _ := os.Stat(file); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}

	// A link in place of settings.yaml is replaced by the encrypted file,
	// and the log says the file it pointed to still holds the plain value.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.yaml")
	os.WriteFile(elsewhere, []byte("settings:\n  opensearch.password:\n    secret: by-hand-pw\n    sent_to: https://os.lab.example.com:9200\n"), 0o600)
	os.Remove(file)
	if err := os.Symlink(elsewhere, file); err != nil {
		t.Skip("cannot make links here:", err)
	}
	encryptStores(c, log)
	if fi, err := os.Lstat(file); err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		t.Errorf("the link is still there: %v", err)
	}
	if b, _ := os.ReadFile(elsewhere); !strings.Contains(string(b), "by-hand-pw") {
		t.Errorf("the file the link pointed to changed:\n%s", b)
	}
	target, _ := filepath.EvalSymlinks(elsewhere)
	if l := logs.String(); !strings.Contains(l, "the file was a link, and is now a file of its own") ||
		!strings.Contains(l, "link_target="+target) || !strings.Contains(l, "plain_values=1") {
		t.Errorf("log:\n%s", l)
	}
}

// "signalith validate" says when a password saved on the Settings page
// cannot be decrypted, and the config is still valid.
func TestValidateReportsUnreadablePageSecret(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	fos := newFakeOpenSearch(t)
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("opensearch:\n  url: "+fos.URL+"\nauth:\n  admin_password_hash: "+h+"\n"), 0o600)
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal("settings.opensearch.password", "lost-pw")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "lookups", "settings.yaml")
	os.MkdirAll(filepath.Dir(file), 0o750)
	os.WriteFile(file, []byte("settings:\n  opensearch.password:\n    secret: "+sealed+"\n    sent_to: "+fos.URL+"\n"), 0o600)
	out, err := capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	for _, want := range []string{
		path + " is valid.",
		"Warning: 1 password or key saved on the Settings page cannot be decrypted, so Signalith runs without it",
		"Warning: On the Settings page (" + file + "), opensearch.password is encrypted with master key " + other.KeyID(),
		"signalith settings reset opensearch.password",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate lacks %q (%v):\n%s", want, err, out)
		}
	}
	if strings.Contains(out, "lost-pw") {
		t.Errorf("validate shows the password:\n%s", out)
	}
}

// The settings commands and validate read the signalith service's unit,
// as the secrets commands do, and so find the file the service keeps;
// a unit for another config file is not used, and only pointed to.
func TestSettingsCommandsReadTheUnit(t *testing.T) {
	for _, k := range []string{"SIGNALITH_SETTINGS_FILE", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_STATE_DIR",
		"SIGNALITH_OPENSEARCH_PASSWORD_FILE", "SIGNALITH_ADMIN_PASSWORD_FILE", "SIGNALITH_INGEST_TOKEN_FILE"} {
		t.Setenv(k, "")
	}
	fos := newFakeOpenSearch(t)
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "etc", "signalith.yaml")
	os.MkdirAll(filepath.Dir(path), 0o750)
	os.WriteFile(path, []byte("opensearch:\n  url: "+fos.URL+"\nauth:\n  admin_password_hash: "+h+"\n"), 0o600)
	svcLookups := filepath.Join(dir, "var", "lookups")
	svcFile := filepath.Join(svcLookups, "settings.yaml")
	page := &config.PageSettings{}
	page.Set("search.max_events", 4321, "alice", time.Now())
	if err := config.WritePageSettings(svcFile, page); err != nil {
		t.Fatal(err)
	}
	served := path
	saved := readServiceSettings
	readServiceSettings = func() *serviceSettings {
		return &serviceSettings{where: "the test unit", args: []string{"serve", "-c", served},
			env: map[string]string{"SIGNALITH_LOOKUPS_DIR": svcLookups, "SIGNALITH_OPENSEARCH_PASSWORD": "never-taken",
				// Secrets in files the service reads, such as systemd
				// credentials that exist only while it runs, are not taken.
				"SIGNALITH_OPENSEARCH_PASSWORD_FILE": "/nonexistent/os-pass", "SIGNALITH_ADMIN_PASSWORD_FILE": "/nonexistent/admin",
				"SIGNALITH_INGEST_TOKEN_FILE": "/nonexistent/token"}}
	}
	t.Cleanup(func() { readServiceSettings = saved })

	out, err := capture(t, func() error { return cmdSettings([]string{"list", "-c", path}) })
	if err != nil || !strings.Contains(out, "Using the settings the signalith service is given (the test unit):\n  SIGNALITH_LOOKUPS_DIR="+svcLookups) ||
		!strings.Contains(out, "Changed on the Settings page ("+svcFile+"):") || !strings.Contains(out, "4321") || strings.Contains(out, "never-taken") {
		t.Errorf("list: %v\n%s", err, out)
	}
	os.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	out, err = capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "Changed on the Settings page ("+svcFile+"): search.max_events.") || strings.Contains(out, "Note: The Signalith service keeps") ||
		strings.Contains(out, "PASSWORD_FILE") || strings.Contains(out, "TOKEN_FILE") {
		t.Errorf("validate: %v\n%s", err, out)
	}
	os.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	var status strings.Builder
	if err := runSecrets([]string{"status", "-c", path}, os.Stdin, &status); err != nil || strings.Contains(status.String(), "PASSWORD_FILE") || strings.Contains(status.String(), "TOKEN_FILE") {
		t.Errorf("secrets status: %v\n%s", err, status.String())
	}
	os.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	out, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "search.max_events"}) })
	if err != nil || !strings.Contains(out, "Reset search.max_events in "+svcFile) {
		t.Errorf("reset: %v\n%s", err, out)
	}
	if err := config.WritePageSettings(svcFile, page); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"SIGNALITH_OPENSEARCH_PASSWORD_FILE", "SIGNALITH_ADMIN_PASSWORD_FILE", "SIGNALITH_INGEST_TOKEN_FILE"} {
		if v := os.Getenv(k); v != "" {
			t.Errorf("%s=%s was taken from the service", k, v)
		}
	}

	// The service runs another config file: its folders are not used, and
	// on Linux the commands point to the file it keeps.
	served = filepath.Join(dir, "other", "signalith.yaml")
	os.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	own := filepath.Join(dir, "etc", "lookups", "settings.yaml")
	out, err = capture(t, func() error { return cmdSettings([]string{"list", "-c", path}) })
	if err != nil || strings.Contains(out, "Using the settings") || !strings.Contains(out, "There is no settings file at "+own) {
		t.Errorf("list for another config: %v\n%s", err, out)
	}
	if runtime.GOOS == "linux" && !strings.Contains(out, "The Signalith service keeps its settings in "+svcFile) {
		t.Errorf("list for another config, no pointer to the service's file:\n%s", out)
	}
	if got := serviceSettingsPath(); got != svcFile {
		t.Errorf("serviceSettingsPath() = %q", got)
	}
	// A unit that moves neither folder: the service keeps the file where
	// the commands look already.
	readServiceSettings = func() *serviceSettings {
		return &serviceSettings{where: "the test unit", args: []string{"serve", "-c", path}, env: map[string]string{}}
	}
	if got := serviceSettingsPath(); got != "" {
		t.Errorf("serviceSettingsPath() without folders = %q", got)
	}
}

// A restart in place sets the master key up again from the config it
// loads, logs where it comes from only when that changed, and encrypts a
// plain value written in the meantime.
func TestRestartSetsUpTheMasterKey(t *testing.T) {
	rs := startRunner(t, nil, nil)
	dir := filepath.Dir(rs.r.path)
	file := filepath.Join(dir, "lookups", "settings.yaml")
	// master.key, or master.key.dpapi on Windows.
	if got := secrets.Default().DefaultPath(); filepath.Dir(got) != filepath.Join(dir, "keys") || !strings.HasPrefix(filepath.Base(got), "master.key") {
		t.Errorf("the default keyring is not the config's: %s", got)
	}
	rs.save(`{"opensearch.password":"page-pw"}`)
	data, _ := os.ReadFile(file)
	if strings.Contains(string(data), "page-pw") || !strings.Contains(string(data), "secret: enc:v1:") {
		t.Fatalf("settings.yaml:\n%s", data)
	}
	if st, _ := os.Stat(file); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	count := func(s string) int { return strings.Count(rs.logs.String(), s) }
	if count("no master key yet") != 1 || count("made a new master key") != 1 || count(`msg="master key for stored passwords and keys"`) != 0 {
		t.Errorf("log before the restart:\n%s", rs.logs.String())
	}
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	if count(`msg="master key for stored passwords and keys"`) != 1 || count("no master key yet") != 1 {
		t.Errorf("log after the restart:\n%s", rs.logs.String())
	}
	if c, err := config.Load(rs.r.path); err != nil || c.OpenSearch.Password != "page-pw" {
		t.Errorf("load: %v", err)
	}
	// Written by hand in the meantime.
	p, err := config.ReadPageSettings(file)
	if err != nil {
		t.Fatal(err)
	}
	plain := "by-hand-pw"
	p.Settings["opensearch.password"].Secret = &plain
	if err := config.WritePageSettings(file, p); err != nil {
		t.Fatal(err)
	}
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("second restart %+v\n%s", res, rs.logs.String())
	}
	data, _ = os.ReadFile(file)
	if strings.Contains(string(data), "by-hand-pw") || !strings.Contains(string(data), "secret: enc:v1:") {
		t.Errorf("settings.yaml after the second restart:\n%s", data)
	}
	if count(`msg="master key for stored passwords and keys"`) != 1 || count("encrypted the passwords and keys stored in a file") != 1 {
		t.Errorf("log after the second restart:\n%s", rs.logs.String())
	}
	if !rs.signedIn("") {
		t.Error("signed out by the restarts")
	}
}

// newLockedOpenSearch is a fake OpenSearch that refuses requests without
// the password pw.
func newLockedOpenSearch(t *testing.T, pw string) *httptest.Server {
	t.Helper()
	inner := newFakeOpenSearch(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, p, ok := r.BasicAuth(); !ok || p != pw {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"Unauthorized"}`)
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// lockPageSecret replaces the secret saved on the Settings page for key
// with one encrypted with another master key, as after "secrets
// rotate-master" while the server still has the previous one, and returns
// a function that puts the readable one back.
func lockPageSecret(t *testing.T, file, key string) func() {
	t.Helper()
	p, err := config.ReadPageSettings(file)
	if err != nil || p.Settings[key] == nil || p.Settings[key].Secret == nil {
		t.Fatalf("no %s in %s: %v", key, file, err)
	}
	was := *p.Settings[key].Secret
	sealed, err := secrets.NewKeyring(t.TempDir()).Seal("settings."+key, "page-pw")
	if err != nil {
		t.Fatal(err)
	}
	p.Settings[key].Secret = &sealed
	if err := config.WritePageSettings(file, p); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		p, err := config.ReadPageSettings(file)
		if err != nil {
			t.Fatal(err)
		}
		p.Settings[key].Secret = &was
		if err := config.WritePageSettings(file, p); err != nil {
			t.Fatal(err)
		}
	}
}

// A restart in place that OpenSearch refuses because the password saved
// on the Settings page cannot be decrypted says so, and sets nothing
// aside: once the master key is back, the password is used again.
func TestRestartDoesNotSetAsideAnUnreadablePagePassword(t *testing.T) {
	rs := startRunner(t, nil, nil)
	locked := newLockedOpenSearch(t, "page-pw")
	file := filepath.Join(filepath.Dir(rs.r.path), "lookups", "settings.yaml")
	rs.save(`{"opensearch.url":"` + locked.URL + `","opensearch.username":"signalith","opensearch.password":"page-pw"}`)
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart with the page's password %+v\n%s", res, rs.logs.String())
	}
	unlock := lockPageSecret(t, file, "opensearch.password")
	_, res := rs.restart()
	if res.OK || !strings.Contains(res.Error, "OpenSearch did not answer with the new settings") ||
		!strings.Contains(res.Error, "But the opensearch.password saved on the Settings page cannot be used, which may be why.") ||
		len(res.Refused) != 0 || strings.Join(res.ProblemKeys, ",") != "opensearch.password" {
		t.Fatalf("restart without the password %+v", res)
	}
	if data, _ := os.ReadFile(file); strings.Contains(string(data), "refused") {
		t.Errorf("settings.yaml has something set aside:\n%s", data)
	}
	if !rs.signedIn("") {
		t.Error("the server stopped answering")
	}
	unlock()
	c, err := config.Load(rs.r.path)
	if err != nil || c.OpenSearch.URL != locked.URL || c.OpenSearch.Password != "page-pw" || len(c.Refused()) != 0 {
		t.Errorf("with the key back: %v %s %d", err, c.OpenSearch.URL, len(c.Refused()))
	}
}

// At startup, the OpenSearch settings saved on the page are not set aside
// when OpenSearch refuses them only because their password cannot be
// decrypted: the next start with the master key back uses them all.
func TestStartupCheckKeepsAnUnreadablePagePassword(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	t.Setenv("SIGNALITH_OPENSEARCH_URL", "")
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "")
	bootCheckTimeout = 2 * time.Second
	t.Cleanup(func() { bootCheckTimeout = 10 * time.Second })
	old := newFakeOpenSearch(t)
	locked := newLockedOpenSearch(t, "page-pw")
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("opensearch:\n  url: "+old.URL+"\n  username: signalith\nauth:\n  admin_password_hash: "+h+"\n"), 0o600)
	sealed, err := secrets.NewKeyring(t.TempDir()).Seal("settings.opensearch.password", "page-pw")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "lookups", "settings.yaml")
	os.MkdirAll(filepath.Dir(file), 0o750)
	os.WriteFile(file, []byte("settings:\n  opensearch.url:\n    value: "+locked.URL+"\n  opensearch.password:\n    secret: "+sealed+"\n    sent_to: "+locked.URL+"\n"), 0o600)
	c, err := config.Load(path)
	if err != nil || c.PageSecretProblem("opensearch.password") == "" {
		t.Fatalf("load: %v", err)
	}
	r := newRunner(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := r.checkPageOpenSearch(context.Background(), c); got != c {
		t.Error("the page's OpenSearch settings were replaced")
	}
	if data, _ := os.ReadFile(file); strings.Contains(string(data), "refused") {
		t.Errorf("settings.yaml has something set aside:\n%s", data)
	}
	if c, err := config.Load(path); err != nil || c.OpenSearch.URL != locked.URL || len(c.Refused()) != 0 {
		t.Errorf("next start: %v", err)
	}
}

// A start that fails does not blame a password saved on the page that
// cannot be decrypted, which is not in use.
func TestBlameLeavesOutUnreadablePageSecrets(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "")
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("opensearch:\n  url: https://os.example:9200\n  password: file-pw\nauth:\n  admin_password_hash: "+h+"\n"), 0o600)
	sealed, _ := secrets.NewKeyring(t.TempDir()).Seal("settings.opensearch.password", "page-pw")
	file := filepath.Join(dir, "lookups", "settings.yaml")
	os.MkdirAll(filepath.Dir(file), 0o750)
	os.WriteFile(file, []byte("settings:\n  opensearch.index_prefix:\n    value: other\n  opensearch.password:\n    secret: "+sealed+"\n    sent_to: https://os.example:9200\n"), 0o600)
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(blame(errors.New("no start"), c, nil), ","); got != "opensearch.index_prefix" {
		t.Errorf("blame = %s", got)
	}
	if got := blame(keyed(errors.New("refused"), "opensearch.password"), c, nil); len(got) != 1 || got[0] != "opensearch.index_prefix" {
		t.Errorf("blame for the password = %v", got)
	}
}

// Once settings are shared, a start that fails blames only the shared
// values that changed since the configuration in use (prev), never one
// merely because it differs from signalith.yaml, which does not set it;
// with no configuration known before (a start), only one the error names.
func TestBlameSharedValues(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("syslog:\n  udp: 0.0.0.0:5514\nauth:\n  admin_password_hash: "+h+"\n"), 0o600)
	raw := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	layer := func(maxEvents int) *config.Shared {
		return &config.Shared{Self: "siem-a", Server: map[string]*config.PageEntry{}, Cluster: map[string]config.SharedValue{
			"search.max_events":    {Value: raw(maxEvents), Rev: 1},
			"auth.session_timeout": {Value: raw("12h"), Rev: 1},
		}}
	}
	prev, err := config.LoadShared(path, layer(1000))
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadShared(path, layer(500))
	if err != nil {
		t.Fatal(err)
	}
	if got := blame(errors.New("boom"), c, nil); len(got) != 0 {
		t.Errorf("blame at a start = %v", got)
	}
	if got := blame(keyed(errors.New("boom"), "syslog.udp"), c, nil); len(got) != 0 {
		t.Errorf("blame for a setting of signalith.yaml = %v", got)
	}
	if got := strings.Join(blame(errors.New("boom"), c, prev), ","); got != "search.max_events" {
		t.Errorf("blame at a restart = %s", got)
	}
	if got := strings.Join(blame(keyed(errors.New("boom"), "auth.session_timeout"), c, prev), ","); got != "auth.session_timeout" {
		t.Errorf("blame for a named shared setting = %s", got)
	}
}
