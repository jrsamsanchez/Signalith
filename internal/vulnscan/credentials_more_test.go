package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestLoginText(t *testing.T) {
	var l *Login
	if l.String() != "<no login>" {
		t.Errorf("nil = %q", l.String())
	}
	l = &Login{Kind: LoginSSH, Username: "scan", Secret: "pw"}
	if v := l.LogValue(); v.Kind() != slog.KindString || v.String() != "ssh login scan" {
		t.Errorf("log value = %v", v)
	}
}

func TestScanLoginStoreFailures(t *testing.T) {
	ctx := context.Background()
	d := newErrDocs()
	st := NewStore(d, "sig")
	st.Keys = testKey(t, 1)
	boom := errors.New("opensearch down")
	in := LoginInput{ID: "l1", Name: "Linux", Kind: LoginSSH, Username: "scan", Auth: AuthPassword, Secret: "pw"}

	d.fail(&d.get, boom)
	if _, err := st.SaveLogin(ctx, in, "alice"); !errors.Is(err, boom) {
		t.Errorf("save get = %v", err)
	}
	if _, err := st.DeleteLogin(ctx, "l1"); !errors.Is(err, boom) {
		t.Errorf("delete settings = %v", err)
	}
	if err := st.ResealLogins(ctx, nil); !errors.Is(err, boom) {
		t.Errorf("reseal get = %v", err)
	}
	if err := st.CheckLogins(ctx, Settings{Targets: []Target{{SSHLogin: "l1"}}}); !errors.Is(err, boom) {
		t.Errorf("check get = %v", err)
	}
	if _, err := st.OpenLogin(ctx, "l1"); !errors.Is(err, boom) {
		t.Errorf("open get = %v", err)
	}
	d.fail(&d.get, nil)
	// No network names a login: nothing is read.
	d.fail(&d.get, boom)
	if err := st.CheckLogins(ctx, Settings{Targets: []Target{target("192.0.2.1")}}); err != nil {
		t.Errorf("check with no logins = %v", err)
	}
	d.fail(&d.get, nil)

	d.fail(&d.create, boom)
	if _, err := st.SaveLogin(ctx, in, "alice"); !errors.Is(err, boom) {
		t.Errorf("save create = %v", err)
	}
	d.fail(&d.create, store.ErrExists)
	if _, err := st.SaveLogin(ctx, in, "alice"); err == nil || !strings.Contains(err.Error(), "at the same time") {
		t.Errorf("save raced = %v", err)
	}
	d.fail(&d.create, nil)
	if _, err := st.SaveLogin(ctx, in, "alice"); err != nil {
		t.Fatal(err)
	}

	d.fail(&d.put, store.ErrConflict)
	in.Name = "Linux servers"
	if _, err := st.SaveLogin(ctx, in, "alice"); err == nil || !strings.Contains(err.Error(), "at the same time") {
		t.Errorf("save conflict = %v", err)
	}
	if _, err := st.DeleteLogin(ctx, "l1"); err == nil || !strings.Contains(err.Error(), "at the same time") {
		t.Errorf("delete conflict = %v", err)
	}
	reseal := func(_, sealed string) (string, error) { return sealed + "x", nil }
	if err := st.ResealLogins(ctx, reseal); err == nil || !strings.Contains(err.Error(), "at the same time") {
		t.Errorf("reseal conflict = %v", err)
	}
	d.fail(&d.put, boom)
	if _, err := st.SaveLogin(ctx, in, "alice"); !errors.Is(err, boom) {
		t.Errorf("save put = %v", err)
	}
	if _, err := st.DeleteLogin(ctx, "l1"); !errors.Is(err, boom) {
		t.Errorf("delete put = %v", err)
	}
	if err := st.ResealLogins(ctx, reseal); !errors.Is(err, boom) {
		t.Errorf("reseal put = %v", err)
	}
	d.fail(&d.put, nil)

	// A failing reseal names the login and the part that failed.
	for _, part := range []string{"secret", "passphrase", "privacy"} {
		err := st.ResealLogins(ctx, func(field, sealed string) (string, error) {
			if strings.HasSuffix(field, "."+part) {
				return "", boom
			}
			return sealed, nil
		})
		if !errors.Is(err, boom) || !strings.Contains(err.Error(), "the scan login Linux") {
			t.Errorf("%s reseal = %v", part, err)
		}
	}

	// A stored document that is not one is reported.
	putRaw(t, d, st.Index, credentialsID, "not logins")
	if _, _, err := st.Logins(ctx); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("bad logins = %v", err)
	}
}

func TestScanLoginChecks(t *testing.T) {
	ctx := context.Background()
	d := newErrDocs()
	st := NewStore(d, "sig")
	st.Keys = testKey(t, 1)
	var ie *InputError
	for want, in := range map[string]LoginInput{
		"no valid ID":       {ID: "bad id!", Name: "x", Kind: LoginSSH, Username: "scan", Auth: AuthPassword, Secret: "pw"},
		"give the login":    {ID: "l1", Name: "a\nb", Kind: LoginSSH, Username: "scan", Auth: AuthPassword, Secret: "pw"},
		"from 1 to 65535":   {ID: "l1", Name: "x", Kind: LoginSSH, Username: "scan", Auth: AuthPassword, Port: 70000, Secret: "pw"},
		"a key or a passwo": {ID: "l1", Name: "x", Kind: LoginSSH, Username: "scan", Auth: AuthCommunity, Secret: "pw"},
		"too long":          {ID: "l1", Name: "x", Kind: LoginSMB, Username: "scan", Secret: strings.Repeat("p", 20000)},
	} {
		if _, err := st.SaveLogin(ctx, in, "alice"); !errors.As(err, &ie) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}

	// A key's passphrase can be given again, or taken off a key without one.
	locked := testPrivateKey(t, "phrase")
	key := LoginInput{ID: "k1", Name: "Keys", Kind: LoginSSH, Username: "scan", Auth: AuthKey, Secret: locked, Passphrase: "phrase"}
	if _, err := st.SaveLogin(ctx, key, "alice"); err != nil {
		t.Fatal(err)
	}
	if c, err := st.SaveLogin(ctx, LoginInput{ID: "k1", Name: "Keys", Kind: LoginSSH, Username: "scan", Auth: AuthKey, Passphrase: "phrase"}, "bob"); err != nil || c.Passphrase == "" {
		t.Errorf("same passphrase = %+v %v", c, err)
	}
	if _, err := st.SaveLogin(ctx, LoginInput{ID: "k2", Name: "Plain", Kind: LoginSSH, Username: "scan", Auth: AuthKey, Secret: testPrivateKey(t, "")}, "alice"); err != nil {
		t.Fatal(err)
	}
	if c, err := st.SaveLogin(ctx, LoginInput{ID: "k2", Name: "Plain", Kind: LoginSSH, Username: "scan", Auth: AuthKey, ClearPassphrase: true}, "bob"); err != nil || c.Passphrase != "" {
		t.Errorf("cleared passphrase = %+v %v", c, err)
	}
	v3 := LoginInput{ID: "s1", Name: "Switches", Kind: LoginSNMP, Username: "signalith-scan", Auth: AuthSNMPv3, Secret: "auth-pass-1", Privacy: "priv-pass-1"}
	if _, err := st.SaveLogin(ctx, v3, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveLogin(ctx, LoginInput{ID: "w1", Name: "Windows", Kind: LoginSMB, Username: "scan", Secret: "pw"}, "alice"); err != nil {
		t.Fatal(err)
	}
	// A login of the wrong kind is refused for a scan.
	if _, err := st.loginsFor(ctx, Target{SSHLogin: "w1"}); err == nil || !strings.Contains(err.Error(), "another kind") {
		t.Errorf("wrong kind = %v", err)
	}
	// Only OpenVAS scans sign in.
	tg := target("192.0.2.1")
	tg.SSHLogin = "k1"
	if err := st.CheckLogins(ctx, Settings{Targets: []Target{tg}}); !errors.As(err, &ie) || !strings.Contains(err.Error(), "only OpenVAS scans") {
		t.Errorf("without OpenVAS = %v", err)
	}

	// Saved secrets this server cannot open.
	good := st.Keys
	st.Keys = testKey(t, 2)
	for want, in := range map[string]LoginInput{
		"saved key cannot be decrypted":                     {ID: "k1", Name: "Keys", Kind: LoginSSH, Username: "scan", Auth: AuthKey, Passphrase: "phrase"},
		"saved privacy password cannot be decrypted":        {ID: "s1", Name: "Switches", Kind: LoginSNMP, Username: "signalith-scan", Auth: AuthSNMPv3, Secret: "auth-pass-2"},
		"saved authentication password cannot be decrypted": {ID: "s1", Name: "Switches", Kind: LoginSNMP, Username: "signalith-scan", Auth: AuthSNMPv3, Privacy: "priv-pass-2"},
	} {
		if _, err := st.SaveLogin(ctx, in, "alice"); !errors.As(err, &ie) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
	st.Keys = nil
	if _, err := st.OpenLogin(ctx, "k1"); err == nil || !strings.Contains(err.Error(), "no key for it") {
		t.Errorf("no keys = %v", err)
	}
	st.Keys = good

	// Stored secrets moved between fields are not opened.
	list, v, err := st.Logins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range list {
		switch list[i].ID {
		case "k1":
			list[i].Passphrase = list[i].Secret
		case "s1":
			list[i].Privacy = list[i].Secret
		}
	}
	if err := st.putLogins(ctx, list, v); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"k1", "s1"} {
		if _, err := st.OpenLogin(ctx, id); err == nil || !strings.Contains(err.Error(), "cannot be decrypted on this server") {
			t.Errorf("%s swapped = %v", id, err)
		}
	}
	list, v, _ = st.Logins(ctx)
	for i := range list {
		if list[i].ID == "s1" {
			list[i].Privacy = "plain"
		}
	}
	if err := st.putLogins(ctx, list, v); err != nil {
		t.Fatal(err)
	}
	if _, err := st.OpenLogin(ctx, "s1"); err == nil || !strings.Contains(err.Error(), "enter its passwords again") {
		t.Errorf("privacy in the clear = %v", err)
	}
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "auth-pass-1") {
		t.Error("a secret is stored in the clear")
	}
}
