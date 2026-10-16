package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// firstPasswordConfig loads a config file in a folder of its own, with
// the state folder next to it, after env sets the environment.
func firstPasswordConfig(t *testing.T, env func(root string)) (*config.Config, string) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_STATE_DIR", state)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "")
	path := filepath.Join(root, "signalith.yaml")
	if env != nil {
		env(root)
	}
	if _, err := os.Stat(path); err != nil {
		if err := os.WriteFile(path, []byte("ingest:\n  tokens: [tok-0123456789abcdef]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c, root
}

// The Docker quick start: the first password comes from the file the
// setup step made, which the server reads (and may not remove). Signing
// in with it allows only choosing a new one, which then works at once, as
// for a local user with a temporary password.
func TestBuiltinFirstPasswordFromFile(t *testing.T) {
	const first = "abcd-efgh-jkmn-pqrs"
	var secret string
	c, root := firstPasswordConfig(t, func(root string) {
		secret = filepath.Join(root, "secrets", config.InitialPasswordFileName)
		os.MkdirAll(filepath.Dir(secret), 0o700)
		os.WriteFile(secret, []byte(first+"\n"), 0o400)
		t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", secret)
	})
	ts, s := newUsersServer(t, func(s *Server) { s.Config = c })

	code, me, cookie := login(t, ts, "admin", first)
	if code != 200 || me["must_change_password"] != true || me["source"] != "builtin" || cookie == nil {
		t.Fatalf("login = %d %v", code, me)
	}
	if code, body, _ := call(t, ts, "GET", "/api/health", "", "", "", cookie); code != 403 || body["code"] != "password_change_required" {
		t.Errorf("health before the change = %d %v", code, body)
	}
	if code, body := doAs(t, ts, "admin", first, "GET", "/api/users", ""); code != 403 || body["code"] != "password_change_required" {
		t.Errorf("Basic auth before the change = %d %v", code, body)
	}
	if code, body, _ := call(t, ts, "GET", "/api/me", "", "", "", cookie); code != 200 || body["must_change_password"] != true || body["can_change_password"] != true {
		t.Errorf("me = %d %v", code, body)
	}
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"`+first+`","new_password":"`+first+`"}`, "", "", cookie); code != 400 || body["code"] != "same_password" {
		t.Errorf("same password = %d %v", code, body)
	}
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"`+first+`","new_password":"my-own-chosen-pass"}`, "", "", cookie); code != 200 || body["must_change_password"] != false {
		t.Fatalf("change = %d %v", code, body)
	}
	if code, _, _ := call(t, ts, "GET", "/api/health", "", "", "", cookie); code != 200 {
		t.Errorf("health after the change = %d", code)
	}
	if code, body := doAs(t, ts, "admin", "my-own-chosen-pass", "GET", "/api/me", ""); code != 200 || body["must_change_password"] != false || body["can_change_password"] != false {
		t.Errorf("Basic auth with the new password = %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", first, "GET", "/api/me", ""); code != 401 {
		t.Errorf("the first password after the change = %d", code)
	}
	// Once changed, it is the server's again: signalith passwd changes it.
	if code, body := doAs(t, ts, "admin", "my-own-chosen-pass", "POST", "/api/me/password", `{"current_password":"my-own-chosen-pass","new_password":"yet-another-pass"}`); code != 400 || body["code"] != "builtin" {
		t.Errorf("a second change = %d %v", code, body)
	}

	// The new password is kept where signalith passwd keeps it, and used
	// after a restart; the setup step's file stays.
	if _, err := os.Stat(secret); err != nil {
		t.Errorf("the environment's file was removed: %v", err)
	}
	fp, err := config.ReadFirstPassword(filepath.Join(root, "state"))
	if err != nil || fp.Changed.IsZero() || fp.Hash != "" {
		t.Errorf("first password noted as %+v, %v", fp, err)
	}
	again, err := config.Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	if again.AdminPasswordChanged() == "" || !again.CheckPassword("admin", "my-own-chosen-pass") || again.CheckPassword("admin", first) {
		t.Error("the new password is not used after a restart")
	}
	if s.builtinFirstPassword() {
		t.Error("still the first password")
	}
}

// The packages: the file that keeps the first password is root's, so
// signalith init notes its hash in the state folder. The file is removed
// once the password is changed, where the server may.
func TestBuiltinFirstPasswordNoted(t *testing.T) {
	const first = "first-pass-from-init"
	h, _ := users.HashPassword(first)
	c, root := firstPasswordConfig(t, func(root string) {
		os.WriteFile(filepath.Join(root, "signalith.yaml"), []byte("auth:\n  admin_password_hash: "+h+"\ningest:\n  tokens: [tok-0123456789abcdef]\n"), 0o600)
		os.WriteFile(filepath.Join(root, config.InitialPasswordFileName), []byte("not readable here\n"), 0o600)
		if err := config.RecordFirstPassword(filepath.Join(root, "state"), h); err != nil {
			t.Fatal(err)
		}
	})
	if c.FirstPasswordHash() != h {
		t.Fatalf("noted hash %q", c.FirstPasswordHash())
	}
	ts, _ := newUsersServer(t, func(s *Server) { s.Config = c })
	if code, body := doAs(t, ts, "admin", first, "GET", "/api/health", ""); code != 403 || body["code"] != "password_change_required" {
		t.Errorf("before the change = %d %v", code, body)
	}
	if code, body := doAs(t, ts, "admin", first, "POST", "/api/me/password", `{"current_password":"`+first+`","new_password":"chosen-by-the-owner"}`); code != 200 || body["must_change_password"] != false {
		t.Fatalf("change = %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "chosen-by-the-owner", "GET", "/api/health", ""); code != 200 {
		t.Errorf("after the change = %d", code)
	}
	if _, err := os.Stat(filepath.Join(root, config.InitialPasswordFileName)); !os.IsNotExist(err) {
		t.Errorf("the first password's file is still there: %v", err)
	}
	if fp, _ := config.ReadFirstPassword(filepath.Join(root, "state")); fp.Hash != "" || fp.Changed.IsZero() {
		t.Errorf("first password noted as %+v", fp)
	}
}

// A password someone chose is never asked to be changed, though a file
// with another password is next to the config file.
func TestBuiltinChosenPassword(t *testing.T) {
	c, root := firstPasswordConfig(t, func(root string) {
		t.Setenv("SIGNALITH_ADMIN_PASSWORD", "chosen-in-the-environment")
		os.WriteFile(filepath.Join(root, config.InitialPasswordFileName), []byte("some-other-password\n"), 0o600)
	})
	ts, _ := newUsersServer(t, func(s *Server) { s.Config = c })
	if code, body, _ := login(t, ts, "admin", "chosen-in-the-environment"); code != 200 || body["must_change_password"] != false || body["can_change_password"] != false {
		t.Errorf("login = %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "chosen-in-the-environment", "GET", "/api/health", ""); code != 200 {
		t.Errorf("health = %d", code)
	}
	if b, _ := os.ReadFile(filepath.Join(root, config.InitialPasswordFileName)); !strings.Contains(string(b), "some-other-password") {
		t.Error("the file was changed")
	}
}

// With shared users, the cluster's built-in admin is asked on every server
// that holds the first password's file, and one change, on any server,
// is the cluster's.
func TestBuiltinFirstPasswordShared(t *testing.T) {
	c := newMemberCluster(t, func(s *Server) {
		s.Config, _ = firstPasswordConfig(t, func(root string) {
			secret := filepath.Join(root, config.InitialPasswordFileName)
			os.WriteFile(secret, []byte("s3cret-pass\n"), 0o400)
			t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", secret)
		})
	})
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	if code, out, _ := c.a.call("GET", "/api/me", "", admin, nil); code != 200 || out["must_change_password"] != true || out["can_change_password"] != true {
		t.Fatalf("me on A: %d %v", code, out)
	}
	if code, out, _ := c.a.call("GET", "/api/health", "", admin, nil); code != 403 || out["code"] != "password_change_required" {
		t.Errorf("health on A: %d %v", code, out)
	}
	onB, _ := c.b.signIn("admin", "s3cret-pass")
	if code, out, _ := c.b.call("GET", "/api/health", "", onB, nil); code != 403 || out["code"] != "password_change_required" {
		t.Errorf("health on B: %d %v", code, out)
	}
	code, out, resp := c.a.call("POST", "/api/me/password", `{"current_password":"s3cret-pass","new_password":"the-cluster-chosen-pass"}`, admin, nil)
	if code != 200 || out["must_change_password"] != false {
		t.Fatalf("change on A: %d %v", code, out)
	}
	var fresh *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			fresh = ck
		}
	}
	if code, _, _ := c.a.call("GET", "/api/health", "", fresh, nil); code != 200 {
		t.Errorf("health on A after the change: %d", code)
	}
	c.b.cycle()
	onB, _ = c.b.signIn("admin", "the-cluster-chosen-pass")
	if code, out, _ := c.b.call("GET", "/api/health", "", onB, nil); code != 200 {
		t.Errorf("health on B after the change: %d %v", code, out)
	}
}
