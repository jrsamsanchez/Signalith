package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// signInAs signs in on the sign-in page with user and pass, keeps the
// session cookie when it works, and returns the status.
func (rs *running) signInAs(user, pass string) int {
	rs.t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := rs.client.Post(rs.scheme+"://"+rs.addr+"/api/login", "application/json", strings.NewReader(string(b)))
	if err != nil {
		rs.t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if (c.Name == "signalith_session" || c.Name == "__Host-signalith_session") && resp.StatusCode == http.StatusOK {
			rs.cookie = c.Name + "=" + c.Value
		}
	}
	return resp.StatusCode
}

// usersShared waits for rs to keep its users in the shared settings, and
// signs in again: the switch signs everyone out once.
func (rs *running) usersShared() {
	rs.t.Helper()
	eventually(rs.t, rs.r.node.Name()+" keeps its users in the shared settings", func() bool {
		return rs.r.sharedContent.users.on.Load() && rs.r.sharedContent.users.cur.Load() != nil
	})
	eventually(rs.t, "signed in to "+rs.r.node.Name()+" with a shared session", func() bool {
		if rs.signInAs("admin", "s3cret-pass") != http.StatusOK {
			return false
		}
		code, _, err := rs.call("", "GET", "/api/me", "")
		return err == nil && code == http.StatusOK && strings.Contains(rs.cookie, "=s1.")
	})
}

// V30: a new install founds the cluster at level 2 and moves its users
// in during founding, so it switches to shared users with the content, in
// one restart in place; a later restart in place keeps the session cache,
// and the session works on.
func TestSharedUsersAcrossRestarts(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	rs.usersShared()
	if !rs.r.sharedContent.on.Load() {
		t.Fatal("the users are shared, the content is not")
	}
	l := rs.logs.String()
	if n := strings.Count(l, `msg="restarted in place"`); n != 1 {
		t.Errorf("%d restarts in place to take the shared settings, want 1:\n%s", n, l)
	}
	if !strings.Contains(l, `msg="users loaded from the shared settings"`) {
		t.Errorf("the users were not loaded from the shared settings:\n%s", l)
	}
	cache := rs.r.sharedContent.users.cache
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	if rs.r.sharedContent.users.cache != cache {
		t.Error("the restart made a new session cache")
	}
	if code, out, err := rs.call("", "GET", "/api/me", ""); err != nil || code != http.StatusOK || out["can_change_password"] != true {
		t.Errorf("the session after the restart: %d %v %v", code, out, err)
	}
	code, out, _ := rs.call("", "GET", "/api/users", "")
	if code != http.StatusOK || out["shared"] != true {
		t.Errorf("users: %d %v", code, out)
	}
}

// V31: signalith passwd on a member changes the built-in admin's
// password in the shared settings, which the other server takes within a
// poll without a restart; -local writes only the state folder's file,
// which works only while the shared settings cannot be used.
func TestPasswdOnAMember(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	fos := ostest.New(t)
	a := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a"})
	a.usersShared()
	giveKey(t, a)
	b := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-b"})
	b.usersShared()

	path := filepath.Join(a.dir, "signalith.yaml")
	hashFile := config.AdminHashFileIn(a.dir)
	localFile := config.AdminLocalHashFileIn(a.dir)
	t.Setenv("SIGNALITH_NEW_PASSWORD", "a-new-admin-pass")
	out, err := capture(t, func() error { return cmdPasswd([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "every server of the cluster") || !strings.Contains(out, "no restart needed") {
		t.Fatalf("passwd: %v\n%s", err, out)
	}
	if _, err := os.Stat(hashFile); err == nil {
		t.Error("passwd on a member wrote the state folder's hash file")
	}
	eventually(t, "B reads the new password", func() bool {
		_, h, ok := b.r.sharedContent.users.docs.Builtin()
		return ok && bcrypt.CompareHashAndPassword([]byte(h), []byte("a-new-admin-pass")) == nil
	})
	if code := b.signInAs("admin", "s3cret-pass"); code != http.StatusUnauthorized {
		t.Errorf("the old password on B: %d", code)
	}
	if code := b.signInAs("admin", "a-new-admin-pass"); code != http.StatusOK {
		t.Errorf("the new password on B: %d", code)
	}

	t.Setenv("SIGNALITH_NEW_PASSWORD", "break-glass-pass")
	out, err = capture(t, func() error { return cmdPasswd([]string{"-c", path, "-local"}) })
	if err != nil || !strings.Contains(out, "on this server only") {
		t.Fatalf("passwd -local: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(localFile)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(strings.TrimSpace(string(raw))), []byte("break-glass-pass")) != nil {
		t.Fatalf("the -local file: %v", err)
	}
	if _, err := os.Stat(hashFile); err == nil {
		t.Error("passwd -local on a member wrote admin-password-hash")
	}
	if _, h, _ := a.r.sharedContent.users.docs.Builtin(); bcrypt.CompareHashAndPassword([]byte(h), []byte("break-glass-pass")) == nil {
		t.Error("-local changed the shared password")
	}
	if code := a.signInAs("admin", "break-glass-pass"); code != http.StatusUnauthorized {
		t.Errorf("the -local password while the shared settings work: %d", code)
	}

	// An admin-password-hash an earlier passwd wrote is no break-glass
	// password of a member.
	old, err := config.HashPassword("old-file-pass")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAdminHash(hashFile, old); err != nil {
		t.Fatal(err)
	}
	// OpenSearch refuses writes (a full disk): the -local password works
	// on A, without a restart, and nowhere else.
	fos.Block(true)
	eventually(t, "A sees OpenSearch refuse writes", a.r.node.WritesRefused)
	eventually(t, "B sees OpenSearch refuse writes", b.r.node.WritesRefused)
	if code := a.signInAs("admin", "old-file-pass"); code != http.StatusUnauthorized {
		t.Errorf("an old admin-password-hash while writes are refused: %d", code)
	}
	if code := a.signInAs("admin", "break-glass-pass"); code != http.StatusOK {
		t.Errorf("the -local password on A while writes are refused: %d", code)
	}
	if code := b.signInAs("admin", "break-glass-pass"); code != http.StatusUnauthorized {
		t.Errorf("A's -local password on B: %d", code)
	}
	fos.Block(false)
}
