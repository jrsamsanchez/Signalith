package vulnscan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func testKey(t *testing.T, b byte) *secrets.Key {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	k, err := secrets.NewKey(raw, "cluster key")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testPrivateKey(t *testing.T, phrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b *pem.Block
	if phrase != "" {
		b, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "scan", []byte(phrase))
	} else {
		b, err = ssh.MarshalPrivateKey(priv, "scan")
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(b))
}

func TestScanLogins(t *testing.T) {
	ctx := context.Background()
	docs := endpoint.NewMemoryDocs()
	st := NewStore(docs, "signalith")
	if _, err := st.SaveLogin(ctx, LoginInput{ID: "l1", Name: "Linux", Kind: LoginSSH, Username: "scan", Auth: AuthPassword, Secret: "pw"}, "alice"); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("saved with no key: %v", err)
	}
	st.Keys = testKey(t, 1)
	key := testPrivateKey(t, "")
	locked := testPrivateKey(t, "open sesame")
	bad := func(in LoginInput, want string) {
		t.Helper()
		var ie *InputError
		if _, err := st.SaveLogin(ctx, in, "alice"); !errors.As(err, &ie) || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", in, err, want)
		}
	}
	ssh := LoginInput{ID: "l1", Name: "Linux servers", Kind: LoginSSH, Username: "signalith-scan", Auth: AuthKey, Secret: key}
	bad(LoginInput{ID: "l1", Name: "x", Kind: "telnet", Username: "u", Secret: "p"}, "SSH (Linux) or SMB")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: "u", Auth: AuthKey, Secret: "ssh-ed25519 AAAA scan"}, "public key")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: "u", Auth: AuthKey, Secret: "not a key"}, "not a private key")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: "u", Auth: AuthKey, Secret: locked}, "enter it too")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: "u", Auth: AuthKey, Secret: locked, Passphrase: "wrong"}, "does not open")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: "u x", Auth: AuthPassword, Secret: "p"}, "user name")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: `CORP\u`, Auth: AuthPassword, Secret: "p"}, "no DOMAIN")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: "u", Auth: AuthPassword}, "enter the password")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: "u", Auth: AuthPassword, Secret: "enc:v1:abc:def"}, "not an encrypted value")
	bad(LoginInput{ID: "l1", Name: "x", Kind: LoginSMB, Username: "u", Secret: "two\nlines"}, "line break")

	saved, err := st.SaveLogin(ctx, ssh, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Port != 22 || saved.UpdatedBy != "alice" || !secrets.IsSealed(saved.Secret) || strings.Contains(saved.Secret, "PRIVATE") {
		t.Fatalf("saved = %+v", saved)
	}
	win, err := st.SaveLogin(ctx, LoginInput{ID: "l2", Name: "Windows", Kind: LoginSMB, Username: `CORP\signalith-scan`, Secret: "Win-pass-1"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Nothing in OpenSearch is in the clear.
	raw, _, _, _ := docs.Get(ctx, st.Index, credentialsID)
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "Win-pass-1") {
		t.Fatalf("a secret is stored in the clear: %s", raw)
	}
	// The view has no secret at all.
	vb, _ := json.Marshal(win.View(st.Keys))
	if strings.Contains(string(vb), "enc:") || strings.Contains(string(vb), "secret") || !strings.Contains(string(vb), `"readable":true`) {
		t.Errorf("view = %s", vb)
	}
	bad(LoginInput{ID: "l3", Name: "windows", Kind: LoginSMB, Username: "u", Secret: "p"}, "another login is named")
	bad(LoginInput{ID: "l2", Name: "Windows", Kind: LoginSSH, Username: "u", Auth: AuthPassword, Secret: "p"}, "cannot change between")

	// Keeping the secret: an empty one keeps it; a new passphrase must
	// open the saved key.
	ssh.Secret, ssh.Name = "", "Linux"
	if _, err := st.SaveLogin(ctx, ssh, "bob"); err != nil {
		t.Fatal(err)
	}
	l, err := st.OpenLogin(ctx, "l1")
	if err != nil || l.Secret != key || l.Username != "signalith-scan" || l.Port != 22 {
		t.Fatalf("login = %v %v", l, err)
	}
	ssh.Passphrase = "nope"
	bad(ssh, "does not open")
	ssh.Secret, ssh.Passphrase = locked, "open sesame"
	if _, err := st.SaveLogin(ctx, ssh, "bob"); err != nil {
		t.Fatal(err)
	}
	if l, err = st.OpenLogin(ctx, "l1"); err != nil || l.Secret != locked || l.Passphrase != "open sesame" {
		t.Fatalf("locked login = %v %v", l, err)
	}
	// Changing to a password needs the password.
	bad(LoginInput{ID: "l1", Name: "Linux", Kind: LoginSSH, Username: "u", Auth: AuthPassword}, "now signs in with one")

	// A secret copied into another login does not open there.
	list, _, _ := st.Logins(ctx)
	if _, err := st.Keys.Open(secretField(Credential{ID: "l2", Kind: LoginSMB, Auth: AuthPassword}, "secret"), list[0].Secret); err == nil {
		t.Error("a secret opened as another login's")
	}
	// Another server's key cannot open it: enter it again.
	other := NewStore(docs, "signalith")
	other.Keys = testKey(t, 2)
	if v := list[0].View(other.Keys); v.Readable {
		t.Error("readable with the wrong key")
	}
	if _, err := other.OpenLogin(ctx, "l1"); err == nil || !strings.Contains(err.Error(), "enter its private key again") {
		t.Errorf("open with the wrong key: %v", err)
	}

	// Networks: only OpenVAS ones, and only logins of the right kind.
	tg := target("192.0.2.0/24")
	tg.SSHLogin = "l1"
	if err := tg.Validate(); err == nil || !strings.Contains(err.Error(), "only OpenVAS scans sign in") {
		t.Errorf("login without OpenVAS: %v", err)
	}
	tg.OpenVAS = true
	tg.SMBLogin = "l1"
	if err := st.CheckLogins(ctx, Settings{Targets: []Target{tg}}); err == nil || !strings.Contains(err.Error(), "Windows login") {
		t.Errorf("SSH login as Windows: %v", err)
	}
	tg.SMBLogin = "l2"
	if err := st.CheckLogins(ctx, Settings{Targets: []Target{tg}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, Settings{Targets: []Target{tg}}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	logins, err := st.loginsFor(ctx, tg)
	if err != nil || logins.SSH.Secret != locked || logins.SMB.Username != `CORP\signalith-scan` {
		t.Fatalf("logins for the network = %+v %v", logins, err)
	}
	// In use: not deleted.
	st.settings = nil
	if _, err := st.DeleteLogin(ctx, "l2"); err == nil || !strings.Contains(err.Error(), tg.Name) {
		t.Errorf("deleted a login in use: %v", err)
	}
	if _, err := st.SaveSettings(ctx, Settings{Targets: nil}, mustVersion(t, st), "alice"); err != nil {
		t.Fatal(err)
	}
	st.settings = nil
	if gone, err := st.DeleteLogin(ctx, "l2"); err != nil || gone.Name != "Windows" {
		t.Fatalf("delete = %+v %v", gone, err)
	}
	if _, err := st.DeleteLogin(ctx, "l2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("delete again: %v", err)
	}
	if _, err := st.OpenLogin(ctx, "l2"); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Errorf("open a removed login: %v", err)
	}
}

func mustVersion(t *testing.T, st *Store) store.Version {
	t.Helper()
	_, v, err := st.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A network whose login cannot be decrypted still gets its Nmap scan,
// and says why OpenVAS did not run.
func TestScanLoginUnreadable(t *testing.T) {
	var args []string
	s, _ := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	f := &fakeGVMD{password: "pw"}
	s.OpenVAS = &OpenVAS{Address: "/run/gvmd/gvmd.sock", Username: "signalith", Password: "pw", Poll: time.Millisecond, Dial: f.dial}
	ctx := context.Background()
	s.Store.Keys = testKey(t, 1)
	if _, err := s.Store.SaveLogin(ctx, LoginInput{ID: "l1", Name: "Linux", Kind: LoginSSH, Username: "scan", Auth: AuthPassword, Secret: "pw1"}, "alice"); err != nil {
		t.Fatal(err)
	}
	s.Store.Keys = testKey(t, 2)
	tg := target("192.0.2.0/24")
	tg.OpenVAS, tg.SSHLogin = true, "l1"
	set, _ := s.Store.SaveSettings(ctx, Settings{Targets: []Target{tg}}, store.Version{}, "alice")
	sc, _ := s.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Store.Scan(ctx, sc.ID)
	if got.State != StateDone || !strings.Contains(got.OpenVASError, "Linux cannot be decrypted") || got.Counts.Hosts != 2 {
		t.Fatalf("scan = %+v", got)
	}
	if strings.Contains(f.sent(), "create_target") {
		t.Errorf("OpenVAS ran without its login: %s", f.sent())
	}
}

// After a key rotation the logins are sealed with the new key, and a
// value reseal leaves alone stays as it was.
func TestResealLogins(t *testing.T) {
	ctx := context.Background()
	st := NewStore(endpoint.NewMemoryDocs(), "signalith")
	oldKey, newKey := testKey(t, 1), testKey(t, 2)
	st.Keys = oldKey
	locked := testPrivateKey(t, "phrase")
	if _, err := st.SaveLogin(ctx, LoginInput{ID: "l1", Name: "Linux", Kind: LoginSSH, Username: "scan", Auth: AuthKey, Secret: locked, Passphrase: "phrase"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := st.ResealLogins(ctx, func(field, sealed string) (string, error) {
		if sealed == "" {
			return "", nil
		}
		plain, err := oldKey.Open(field, sealed)
		if err != nil {
			return "", err
		}
		return newKey.Seal(field, plain)
	}); err != nil {
		t.Fatal(err)
	}
	st.Keys = newKey
	if l, err := st.OpenLogin(ctx, "l1"); err != nil || l.Secret != locked || l.Passphrase != "phrase" {
		t.Fatalf("after the rotation: %v %v", l, err)
	}
	st.Keys = oldKey
	if _, err := st.OpenLogin(ctx, "l1"); err == nil {
		t.Error("the old key still opens the login")
	}
	// Nothing to change: nothing written.
	list, v, _ := st.Logins(ctx)
	if err := st.ResealLogins(ctx, func(_, sealed string) (string, error) { return sealed, nil }); err != nil {
		t.Fatal(err)
	}
	if _, v2, _ := st.Logins(ctx); v2 != v || len(list) != 1 {
		t.Errorf("rewrote unchanged logins")
	}
}

// User names cannot pass for options, passwords carry no control
// characters, and a key asking for too many bcrypt rounds is refused
// before it is opened.
func TestScanLoginInput(t *testing.T) {
	ctx := context.Background()
	st := NewStore(endpoint.NewMemoryDocs(), "signalith")
	st.Keys = testKey(t, 1)
	for _, in := range []LoginInput{
		{Kind: LoginSSH, Username: "-oProxyCommand=x", Auth: AuthPassword, Secret: "p"},
		{Kind: LoginSMB, Username: `CORP\-x`, Secret: "p"},
		{Kind: LoginSMB, Username: "scan", Secret: "a\x01b"},
		{Kind: LoginSSH, Username: "scan", Auth: AuthKey, Secret: testPrivateKey(t, ""), Passphrase: "a\tb"},
	} {
		in.ID, in.Name = "l1", "x"
		var ie *InputError
		if _, err := st.SaveLogin(ctx, in, "alice"); !errors.As(err, &ie) {
			t.Errorf("%q %q: %v", in.Username, in.Secret, err)
		}
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "scan", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := keyRounds(string(pem.EncodeToMemory(b))); !ok || n != 16 {
		t.Fatalf("rounds = %d %v", n, ok)
	}
	// Set the rounds to a million: refused at once, not opened.
	raw := b.Bytes
	i := strings.Index(string(raw), "bcrypt") + len("bcrypt")
	// kdf options: length, then salt (length + bytes), then rounds.
	saltLen := int(raw[i+4])<<24 | int(raw[i+5])<<16 | int(raw[i+6])<<8 | int(raw[i+7])
	r := i + 8 + saltLen
	raw[r], raw[r+1], raw[r+2], raw[r+3] = 0, 0x0f, 0x42, 0x40
	start := time.Now()
	_, err = st.SaveLogin(ctx, LoginInput{ID: "l1", Name: "x", Kind: LoginSSH, Username: "scan", Auth: AuthKey, Secret: string(pem.EncodeToMemory(b)), Passphrase: "p"}, "alice")
	if err == nil || !strings.Contains(err.Error(), "1000000 rounds") || time.Since(start) > 5*time.Second {
		t.Errorf("a key with a million rounds: %v after %s", err, time.Since(start))
	}
	for _, s := range []string{"", "x", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"} {
		if _, ok := keyRounds(s); ok {
			t.Errorf("rounds read from %q", s)
		}
	}
}

// FuzzScanLoginSecret checks that no pasted key, password or user name
// makes saving a login panic, hang on bcrypt, or store it in the clear.
func FuzzScanLoginSecret(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "scan", []byte("p"))
	f.Add("scan", "key", string(pem.EncodeToMemory(b)), "p")
	f.Add("CORP\\scan", "password", "Win-pass-1", "")
	f.Add("-o", "key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0\n-----END OPENSSH PRIVATE KEY-----\n", "x")
	keys := secretsKeyForFuzz()
	f.Fuzz(func(t *testing.T, user, auth, secret, phrase string) {
		st := NewStore(endpoint.NewMemoryDocs(), "signalith")
		st.Keys = keys
		kind := LoginSSH
		if strings.Contains(user, `\`) {
			kind = LoginSMB
		}
		start := time.Now()
		c, err := st.SaveLogin(context.Background(), LoginInput{ID: "l1", Name: "x", Kind: kind, Username: user, Auth: auth, Secret: secret, Passphrase: phrase}, "a")
		if time.Since(start) > 10*time.Second {
			t.Fatalf("saving took %s", time.Since(start))
		}
		if err == nil && (!secrets.IsSealed(c.Secret) || strings.HasPrefix(c.Username, "-")) {
			t.Fatalf("saved %+v", c)
		}
	})
}

func secretsKeyForFuzz() *secrets.Key {
	k, err := secrets.NewKey(make([]byte, 32), "cluster key")
	if err != nil {
		panic(err)
	}
	return k
}
