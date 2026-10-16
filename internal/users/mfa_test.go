package users

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// The test vectors of RFC 6238, appendix B (SHA-1), cut to six digits.
func TestTOTPMatchesRFC6238(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for _, c := range []struct {
		at   int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		got, err := TOTP(secret, time.Unix(c.at, 0))
		if err != nil || got != c.want {
			t.Errorf("at %d: %q, %v; want %q", c.at, got, err, c.want)
		}
	}
	link := OTPAuthURL("Signalith", "jdoe@siem.example.com", secret)
	if !strings.HasPrefix(link, "otpauth://totp/Signalith:jdoe@siem.example.com?") || !strings.Contains(link, "secret="+secret) ||
		!strings.Contains(link, "issuer=Signalith") {
		t.Errorf("link %s", link)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, digests := newRecoveryCodes()
	if len(codes) != RecoveryCodes || len(digests) != RecoveryCodes {
		t.Fatalf("%d codes, %d digests", len(codes), len(digests))
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] || strings.ContainsAny(c, "01ilo") {
			t.Errorf("code %q", c)
		}
		seen[c] = true
		if recoveryDigest(strings.ToUpper(strings.ReplaceAll(c, "-", " "))) != digests[i] {
			t.Errorf("%q typed in upper case with a space does not match", c)
		}
	}
}

// mfaClock is a store clock tests move by hand.
type mfaClock struct{ t time.Time }

func (c *mfaClock) now() time.Time { return c.t }

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := TOTP(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMFAFlow(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.BuiltinAdmin = "admin"
	clock := &mfaClock{time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)}
	s.Now = clock.now
	u, err := s.Create(ctx, newUser("jdoe", Analyst))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseMFACode(ctx, "jdoe", "123456"); !errors.Is(err, ErrMFAOff) {
		t.Errorf("code without two-step sign-in: %v", err)
	}
	secret, err := s.BeginMFA(ctx, "jdoe")
	if err != nil {
		t.Fatal(err)
	}
	if s.MFAOn("jdoe") {
		t.Error("on before it was confirmed")
	}
	if _, err := s.ConfirmMFA(ctx, "jdoe", "000000"); !errors.Is(err, ErrWrongCode) {
		t.Errorf("wrong code: %v", err)
	}
	clock.t = clock.t.Add(time.Minute)
	codes, err := s.ConfirmMFA(ctx, "jdoe", code(t, secret, clock.t))
	if err != nil {
		t.Fatal(err)
	}
	if !s.MFAOn("JDOE") || len(codes) != RecoveryCodes {
		t.Fatalf("on %v, %d codes", s.MFAOn("jdoe"), len(codes))
	}
	if after, _ := s.Get("jdoe"); after.SessionEpoch != u.SessionEpoch+1 {
		t.Errorf("session epoch %d, was %d: turning it on ends the sessions", after.SessionEpoch, u.SessionEpoch)
	}
	if _, err := s.BeginMFA(ctx, "jdoe"); !errors.Is(err, ErrMFAOn) {
		t.Errorf("set up again while on: %v", err)
	}

	// The code that confirmed it, and older ones, are refused; the next
	// one works once.
	if _, err := s.UseMFACode(ctx, "jdoe", code(t, secret, clock.t)); !errors.Is(err, ErrWrongCode) {
		t.Errorf("the confirming code again: %v", err)
	}
	clock.t = clock.t.Add(30 * time.Second)
	next := code(t, secret, clock.t)
	if res, err := s.UseMFACode(ctx, "jdoe", next[:3]+" "+next[3:]); err != nil || res.Kind != CodeApp || res.Left != RecoveryCodes {
		t.Errorf("next code: %+v, %v", res, err)
	}
	if _, err := s.UseMFACode(ctx, "jdoe", next); !errors.Is(err, ErrWrongCode) {
		t.Errorf("same code twice: %v", err)
	}
	// A phone whose clock is 30 seconds behind still works.
	clock.t = clock.t.Add(90 * time.Second)
	if _, err := s.UseMFACode(ctx, "jdoe", code(t, secret, clock.t.Add(-30*time.Second))); err != nil {
		t.Errorf("code from a slow phone: %v", err)
	}
	clock.t = clock.t.Add(5 * time.Minute)
	if _, err := s.UseMFACode(ctx, "jdoe", code(t, secret, clock.t.Add(-2*time.Minute))); !errors.Is(err, ErrWrongCode) {
		t.Errorf("code two minutes old: %v", err)
	}

	// A recovery code works once.
	if res, err := s.UseMFACode(ctx, "jdoe", strings.ToUpper(codes[3])); err != nil || res.Kind != CodeRecovery || res.Left != RecoveryCodes-1 {
		t.Errorf("recovery code: %+v, %v", res, err)
	}
	if _, err := s.UseMFACode(ctx, "jdoe", codes[3]); !errors.Is(err, ErrWrongCode) {
		t.Errorf("recovery code twice: %v", err)
	}
	for _, bad := range []string{"", "abcde-fghjk", strings.Repeat("x", 200)} {
		if _, err := s.UseMFACode(ctx, "jdoe", bad); !errors.Is(err, ErrWrongCode) {
			t.Errorf("code %q: %v", bad, err)
		}
	}

	// The file holds the key encrypted, never the key or the codes.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), codes[0]) || !strings.Contains(string(data), `"secret": "enc:v1:`) {
		t.Errorf("users file:\n%s", data)
	}
	// Another server reading the file gets the same.
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := other.MFA("jdoe")
	if !ok || !m.On() || m.Secret != secret || len(m.Recovery) != RecoveryCodes-1 || m.Problem != "" {
		t.Errorf("read back %+v", m)
	}
	// Writing the user again keeps the key as it was encrypted.
	if _, err := s.Update(ctx, "jdoe", Change{Name: ptr("Jane")}); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if sealedIn(t, data) != sealedIn(t, again) {
		t.Error("the key was encrypted again on an unrelated change")
	}

	fresh, err := s.NewRecoveryCodes(ctx, "jdoe")
	if err != nil || len(fresh) != RecoveryCodes {
		t.Fatalf("new codes %v, %v", fresh, err)
	}
	if _, err := s.UseMFACode(ctx, "jdoe", codes[0]); !errors.Is(err, ErrWrongCode) {
		t.Errorf("old recovery code after new ones: %v", err)
	}
	if had, err := s.RemoveMFA(ctx, "jdoe"); !had || err != nil {
		t.Errorf("remove: %v, %v", had, err)
	}
	if had, err := s.RemoveMFA(ctx, "jdoe"); had || err != nil {
		t.Errorf("remove again: %v, %v", had, err)
	}
	if s.MFAOn("jdoe") {
		t.Error("still on")
	}
}

func ptr[T any](v T) *T { return &v }

// sealedIn returns the encrypted key of the one user with one in a users
// file.
func sealedIn(t *testing.T, data []byte) string {
	t.Helper()
	_, rest, ok := strings.Cut(string(data), `"secret": "`)
	if !ok {
		t.Fatal("no key in the file")
	}
	v, _, _ := strings.Cut(rest, `"`)
	return v
}

func TestMFASetupExpires(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	clock := &mfaClock{time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)}
	s.Now = clock.now
	if _, err := s.Create(ctx, newUser("jdoe", Viewer)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmMFA(ctx, "jdoe", "123456"); !errors.Is(err, ErrNoSetup) {
		t.Errorf("confirm without set-up: %v", err)
	}
	secret, err := s.BeginMFA(ctx, "jdoe")
	if err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(SetupFor + time.Minute)
	if _, err := s.ConfirmMFA(ctx, "jdoe", code(t, secret, clock.t)); !errors.Is(err, ErrNoSetup) {
		t.Errorf("confirm after the QR code expired: %v", err)
	}
	// Starting again replaces the key.
	again, err := s.BeginMFA(ctx, "jdoe")
	if err != nil || again == secret {
		t.Fatalf("again %q, %v", again, err)
	}
	if _, err := s.ConfirmMFA(ctx, "jdoe", code(t, again, clock.t)); err != nil {
		t.Errorf("confirm the new one: %v", err)
	}
}

func TestBuiltinMFAInUsersFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.BuiltinAdmin = "admin"
	secret, err := s.BeginMFA(ctx, "Admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmMFA(ctx, "admin", code(t, secret, time.Now())); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.BuiltinAdmin = "admin"
	if !reopened.MFAOn("admin") {
		t.Fatal("the built-in admin's two-step sign-in was not kept")
	}
	if m, err := ReadFileBuiltinMFA(path); err != nil || !m.On() || m.Secret != secret {
		t.Errorf("ReadFileBuiltinMFA: %+v, %v", m, err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), secret) || !strings.Contains(string(data), `"builtin_mfa"`) {
		t.Errorf("users file:\n%s", data)
	}
	if had, err := reopened.RemoveMFA(ctx, "admin"); !had || err != nil {
		t.Errorf("remove: %v, %v", had, err)
	}
	s.recheck = 0 // look at the file now, not within a second
	if s.MFAOn("admin") {
		t.Error("still on for the first store")
	}
}

func TestMFAKeyFromAnotherMasterKey(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, newUser("jdoe", Viewer)); err != nil {
		t.Fatal(err)
	}
	secret, _ := s.BeginMFA(ctx, "jdoe")
	codes, err := s.ConfirmMFA(ctx, "jdoe", code(t, secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	// The file is read where its master key is not.
	prev := secrets.Default()
	secrets.SetDefault(secrets.NewKeyring(t.TempDir()))
	defer secrets.SetDefault(prev)
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := other.MFA("jdoe")
	if !ok || !m.On() || m.Problem == "" || m.Secret != "" {
		t.Fatalf("read without its key: %+v", m)
	}
	if _, err := other.UseMFACode(ctx, "jdoe", code(t, secret, time.Now().Add(30*time.Second))); !errors.Is(err, ErrWrongCode) {
		t.Errorf("app code without the key: %v", err)
	}
	// Recovery codes still work, and the key is kept as it was.
	if _, err := other.UseMFACode(ctx, "jdoe", codes[0]); err != nil {
		t.Errorf("recovery code: %v", err)
	}
	secrets.SetDefault(prev)
	back, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := back.MFA("jdoe"); m.Secret != secret {
		t.Error("the key was lost")
	}
}

func TestResealUsersFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.BuiltinAdmin = "admin"
	if _, err := s.Create(ctx, newUser("jdoe", Viewer)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"jdoe", "admin"} {
		secret, _ := s.BeginMFA(ctx, name)
		if _, err := s.ConfirmMFA(ctx, name, code(t, secret, time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	var fields []string
	out, n, err := ResealUsersFile(data, func(st secrets.Stored) (string, error) {
		fields = append(fields, st.Field)
		return st.Value, nil
	})
	if err != nil || n != 0 || string(out) != string(data) {
		t.Errorf("unchanged: %d, %v", n, err)
	}
	if strings.Join(fields, ",") != BuiltinMFAField+","+MFAField("jdoe") {
		t.Errorf("fields %v", fields)
	}
	out, n, err = ResealUsersFile(data, func(st secrets.Stored) (string, error) { return "plain-" + st.Field, nil })
	if err != nil || n != 2 || !strings.Contains(string(out), "plain-"+MFAField("jdoe")) {
		t.Errorf("changed: %d, %v\n%s", n, err, out)
	}
}
