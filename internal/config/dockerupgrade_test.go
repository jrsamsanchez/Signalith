package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The decision about the example token is kept as it was made, and a
// missing or damaged file means none.
func TestDockerUpgradeFile(t *testing.T) {
	dir := t.TempDir()
	if u, err := ReadDockerUpgrade(dir); u != nil || err != nil {
		t.Fatalf("missing: %+v %v", u, err)
	}
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	want := &DockerUpgrade{Upgraded: true, Setup: at, Index: "signalith-authentication-2026.09.30",
		IndexMade: at.AddDate(0, 0, -13), Decided: at.Add(time.Minute)}
	if err := WriteDockerUpgrade(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDockerUpgrade(dir)
	if err != nil || got == nil || *got != *want {
		t.Fatalf("read back: %+v %v", got, err)
	}
	// An install that started new keeps no index.
	if err := WriteDockerUpgrade(dir, &DockerUpgrade{Setup: at, Decided: at}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(DockerUpgradeFileIn(dir)); string(b) != "{\n  \"upgraded\": false,\n  \"setup\": \"2026-10-13T09:00:00Z\",\n  \"decided\": \"2026-10-13T09:00:00Z\"\n}\n" {
		t.Errorf("file:\n%s", b)
	}
	for _, bad := range []string{"{", "{}", "[]"} {
		if err := os.WriteFile(DockerUpgradeFileIn(dir), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if u, err := ReadDockerUpgrade(dir); u != nil || err == nil {
			t.Errorf("damaged %q: %+v %v", bad, u, err)
		}
	}
}

// What a server does with the example token, and whether agents on plain
// HTTP are accepted when plaintext_ingest is not set, follow the decision
// in the state folder; one set in signalith.yaml wins.
func TestOldTokenStates(t *testing.T) {
	const https = "server:\n  listen: 0.0.0.0:8080\n  tls:\n    mode: auto\n"
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	upgraded := &DockerUpgrade{Upgraded: true, Setup: at, Decided: at}
	for _, tc := range []struct {
		name       string
		extra      string
		quickStart bool
		decision   *DockerUpgrade
		damaged    bool
		want       OldToken
		plain      bool
		accepted   bool
	}{
		{name: "not the quick start", extra: https, want: OldTokenRefused},
		{name: "quick start, not decided", extra: https, quickStart: true, want: OldTokenUndecided},
		{name: "quick start, damaged file", extra: https, quickStart: true, damaged: true, want: OldTokenUndecided},
		{name: "started new", extra: https, quickStart: true, decision: &DockerUpgrade{Setup: at, Decided: at}, want: OldTokenRefused},
		{name: "upgraded", extra: https, quickStart: true, decision: upgraded, want: OldTokenAccepted, plain: true, accepted: true},
		{name: "upgraded, plain refused in signalith.yaml", extra: https + "    plaintext_ingest: deny\n", quickStart: true, decision: upgraded,
			want: OldTokenAccepted},
		{name: "upgraded, HTTPS off", extra: "server:\n  listen: 127.0.0.1:8080\n  tls:\n    mode: off\n", quickStart: true, decision: upgraded,
			want: OldTokenAccepted, plain: true},
		{name: "upgraded, ended", extra: https, quickStart: true, decision: &DockerUpgrade{Upgraded: true, Setup: at, Decided: at, Ended: at.Add(time.Hour)},
			want: OldTokenEnded},
		{name: "upgraded, ended, plain accepted again", extra: https + "    plaintext_ingest: allow\n", quickStart: true,
			decision: &DockerUpgrade{Upgraded: true, Setup: at, Decided: at, Ended: at.Add(time.Hour)}, want: OldTokenEnded, plain: true},
		// A decision kept elsewhere than the quick start still holds.
		{name: "upgraded, kept, not the quick start", extra: https, decision: upgraded, want: OldTokenAccepted, plain: true, accepted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			t.Setenv("SIGNALITH_STATE_DIR", state)
			old := dockerQuickStartHere
			dockerQuickStartHere = func() bool { return tc.quickStart }
			defer func() { dockerQuickStartHere = old }()
			if tc.decision != nil {
				if err := WriteDockerUpgrade(state, tc.decision); err != nil {
					t.Fatal(err)
				}
			}
			if tc.damaged {
				if err := os.WriteFile(filepath.Join(state, dockerUpgradeFile), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c, err := Load(writeConfig(t, tc.extra))
			if err != nil {
				t.Fatal(err)
			}
			if got := c.OldToken(); got != tc.want {
				t.Errorf("old token %v, want %v", got, tc.want)
			}
			if c.Server.PlaintextIngest() != tc.plain || c.OldTokenAccepted() != tc.accepted {
				t.Errorf("plain %v accepted %v", c.Server.PlaintextIngest(), c.OldTokenAccepted())
			}
			// The Settings page shows what is in effect.
			want := "deny"
			if tc.plain {
				want = "allow"
			}
			if v := c.Value("server.tls.plaintext_ingest"); v != want {
				t.Errorf("page value %v", v)
			}
			if w := c.Warnings(); len(w) != 0 && tc.extra == https {
				t.Errorf("warnings %q", w)
			}
		})
	}
}

// A decision made after the config was loaded, or the token ending, is
// put into use on a copy, which the server then runs with.
func TestWithDockerUpgrade(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	c, err := Load(writeConfig(t, "server:\n  listen: 0.0.0.0:8080\n  tls:\n    mode: auto\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.OldToken() != OldTokenRefused || c.Server.PlaintextIngest() {
		t.Fatalf("loaded: %v", c.OldToken())
	}
	if u := c.WithDockerUpgrade(nil); u.OldToken() != OldTokenUndecided || u.Server.PlaintextIngest() {
		t.Errorf("undecided: %v", u.OldToken())
	}
	up := c.WithDockerUpgrade(&DockerUpgrade{Upgraded: true, Decided: time.Now()})
	if up.OldToken() != OldTokenAccepted || !up.Server.PlaintextIngest() || !up.OldTokenAccepted() {
		t.Errorf("upgraded: %v", up.OldToken())
	}
	ended := up.WithDockerUpgrade(&DockerUpgrade{Upgraded: true, Decided: time.Now(), Ended: time.Now()})
	if ended.OldToken() != OldTokenEnded || ended.Server.PlaintextIngest() || ended.OldTokenAccepted() {
		t.Errorf("ended: %v", ended.OldToken())
	}
	// The copies leave the original as it was.
	if c.OldToken() != OldTokenRefused || c.Server.PlaintextIngest() || up.OldToken() != OldTokenAccepted {
		t.Error("the original changed")
	}
}

// Only secrets in the Docker quick start's own folder make it the quick
// start, and its setup step ran when the first of them was written.
func TestDockerQuickStartSetup(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	quick := map[string]string{"SIGNALITH_INGEST_TOKEN_FILE": DockerSecretsDir + "ingest-token", "SIGNALITH_ADMIN_PASSWORD_FILE": DockerSecretsDir + "initial-admin-password"}
	if !DockerQuickStart(env(quick)) || DockerQuickStart(env(map[string]string{"SIGNALITH_INGEST_TOKEN_FILE": "/run/secrets/token"})) || DockerQuickStart(env(nil)) {
		t.Error("quick start detection")
	}
	if _, err := DockerSetupTime(env(map[string]string{"SIGNALITH_INGEST_TOKEN_FILE": "/run/secrets/token"})); err == nil {
		t.Error("a setup time outside the quick start")
	}
	dir := t.TempDir()
	first, later := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC), time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	pw, token := filepath.Join(dir, "initial-admin-password"), filepath.Join(dir, "ingest-token")
	for p, at := range map[string]time.Time{pw: later, token: first} {
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := firstWritten([]string{pw, token}); err != nil || !got.Equal(first) {
		t.Errorf("setup %v %v", got, err)
	}
	if _, err := firstWritten([]string{filepath.Join(dir, "missing")}); err == nil {
		t.Error("a missing file")
	}
}
