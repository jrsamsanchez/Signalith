// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// authenticator is a passkey authenticator for tests: one ES256 key per
// passkey, made the way a phone or security key makes it.
type authenticator struct {
	t      *testing.T
	origin string
	rpID   string
	keys   map[string]*vkey
	// uv says whether it checks the user (fingerprint, face or PIN).
	uv bool
}

type vkey struct {
	id     []byte
	key    *ecdsa.PrivateKey
	handle []byte
	count  uint32
	// synced keys keep no counter (it stays 0), as iCloud, Google and
	// password managers do.
	synced bool
}

func newAuthenticator(t *testing.T) *authenticator {
	return &authenticator{t: t, origin: "http://localhost", rpID: "localhost", keys: map[string]*vkey{}, uv: true}
}

var b64 = base64.RawURLEncoding

func (a *authenticator) authData(rpID string, flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, count)
	return append(out, attested...)
}

func (a *authenticator) flags() byte {
	f := byte(0x01) // user present
	if a.uv {
		f |= 0x04
	}
	return f
}

func (a *authenticator) clientData(kind, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// create answers registration options (the server's JSON) with a new
// passkey.
func (a *authenticator) create(opts map[string]any) (map[string]any, *vkey) {
	a.t.Helper()
	pk := opts["publicKey"].(map[string]any)
	user := pk["user"].(map[string]any)
	handle, err := b64.DecodeString(user["id"].(string))
	if err != nil {
		a.t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	pub := priv.PublicKey
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7}, Curve: 1,
		XCoord: pub.X.FillBytes(make([]byte, 32)), YCoord: pub.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		a.t.Fatal(err)
	}
	attested := make([]byte, 16) // AAGUID: none
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(id)))
	attested = append(append(attested, id...), cose...)
	ad := a.authData(a.rpID, a.flags()|0x40, 0, attested)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		a.t.Fatal(err)
	}
	k := &vkey{id: id, key: priv, handle: handle}
	a.keys[string(id)] = k
	return map[string]any{"id": b64.EncodeToString(id), "rawId": b64.EncodeToString(id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", pk["challenge"].(string), a.origin)),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal"},
		}}, k
}

// get answers request options with passkey k.
func (a *authenticator) get(opts map[string]any, k *vkey) map[string]any {
	a.t.Helper()
	pk := opts["publicKey"].(map[string]any)
	if !k.synced {
		k.count++
	}
	ad := a.authData(a.rpID, a.flags(), k.count, nil)
	cd := a.clientData("webauthn.get", pk["challenge"].(string), a.origin)
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte(nil), ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return map[string]any{"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(k.handle),
		}}
}

// pkCall is callWith for the host localhost, where passkeys work over
// plain HTTP.
func pkCall(t *testing.T, ts *httptest.Server, method, path string, body any, cookies ...*http.Cookie) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	return pkCallAt(t, ts, "localhost", method, path, body, cookies...)
}

// pkCallAt is pkCall with the browser at host.
func pkCallAt(t *testing.T, ts *httptest.Server, host, method, path string, body any, cookies ...*http.Cookie) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	var r *strings.Reader
	switch b := body.(type) {
	case string:
		r = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		r = strings.NewReader(string(j))
	}
	req, _ := http.NewRequest(method, ts.URL+path, r)
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Cookies()
}

func sessionOf(cs []*http.Cookie) *http.Cookie {
	for _, c := range cs {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestPasskeys(t *testing.T) {
	var back atomic.Int64
	ts, s := newUsersServer(t, func(s *Server) {
		s.Sessions = auth.NewSessions(12 * time.Hour)
		s.Sessions.Now = func() time.Time { return time.Now().Add(-time.Duration(back.Load())) }
	})
	ctx := context.Background()
	if _, err := s.Users.Create(ctx, users.NewUser{Username: "ann", Role: users.Admin, Password: "Harbor-maple-63"}); err != nil {
		t.Fatal(err)
	}
	a := newAuthenticator(t)
	login := func(body map[string]any) (int, map[string]any, *http.Cookie) {
		t.Helper()
		code, out, cs := pkCall(t, ts, "POST", "/api/login", body)
		return code, out, sessionOf(cs)
	}
	_, _, ann := login(map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	if ann == nil {
		t.Fatal("no session")
	}
	_, _, other := login(map[string]any{"username": "ann", "password": "Harbor-maple-63"})

	// By IP address, no passkeys: browsers refuse them there.
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/passkeys/options", "{}", ann); code != 409 || out["code"] != "passkey_unavailable" {
		t.Errorf("by IP = %d %v", code, out)
	}
	_, mfa, _ := pkCall(t, ts, "GET", "/api/me/mfa", "", ann)
	if mfa["on"] != false || mfa["passkey_host"] != "localhost" || mfa["passkey_alone"] != true {
		t.Errorf("mfa before = %v", mfa)
	}

	// Adding the first passkey turns two-step sign-in on, with recovery
	// codes, and signs the other sessions out.
	code, opts, _ := pkCall(t, ts, "POST", "/api/me/passkeys/options", "{}", ann)
	if code != 200 || opts["token"] == "" {
		t.Fatalf("options = %d %v", code, opts)
	}
	sel := opts["publicKey"].(map[string]any)["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "required" {
		t.Errorf("selection = %v", sel)
	}
	cred, key := a.create(opts)
	code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", map[string]any{"name": " Laptop\n", "token": opts["token"], "credential": cred}, ann)
	if code != 200 {
		t.Fatalf("add = %d %v", code, out)
	}
	if codes, _ := out["recovery_codes"].([]any); len(codes) != users.RecoveryCodes {
		t.Errorf("recovery codes = %v", out["recovery_codes"])
	}
	m := out["mfa"].(map[string]any)
	keys := m["passkeys"].([]any)
	if m["on"] != true || m["app"] != false || len(keys) != 1 || keys[0].(map[string]any)["name"] != "Laptop" || keys[0].(map[string]any)["here"] != true {
		t.Errorf("mfa after = %v", m)
	}
	if code, _, _ := pkCall(t, ts, "GET", "/api/me", "", other); code != 401 {
		t.Errorf("other session after = %d", code)
	}
	// The same answer again is refused.
	if code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", map[string]any{"token": opts["token"], "credential": cred}, ann); code == 200 {
		t.Errorf("added twice = %d %v", code, out)
	}
	// So is a token for someone else's session.
	_, _, ann2 := login(map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	if ann2 != nil {
		t.Fatal("password alone signed in")
	}

	// The password now asks for the passkey.
	code, step, _ := login(map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	if code != 401 || step["code"] != "mfa_required" || step["app"] != false || step["passkey"] == nil {
		t.Fatalf("step = %d %v", code, step)
	}
	stepOpts := step["passkey"].(map[string]any)
	allow := stepOpts["publicKey"].(map[string]any)["allowCredentials"].([]any)
	if len(allow) != 1 || allow[0].(map[string]any)["id"] != b64.EncodeToString(key.id) {
		t.Errorf("allow = %v", allow)
	}
	ans := a.get(stepOpts, key)
	code, out, sess := login(map[string]any{"username": "ann", "password": "Harbor-maple-63", "passkey": map[string]any{"token": stepOpts["token"], "credential": ans}})
	if code != 200 || sess == nil {
		t.Fatalf("passkey step = %d %v", code, out)
	}
	// Seen once, the same answer is refused.
	if code, out, _ := login(map[string]any{"username": "ann", "password": "Harbor-maple-63", "passkey": map[string]any{"token": stepOpts["token"], "credential": ans}}); code != 401 || out["code"] != "passkey_wrong" {
		t.Errorf("replay = %d %v", code, out)
	}
	// Nor on another server, or after a restart, which have not seen it:
	// the user's record has.
	s.passkeyChallenges = challengeSet{}
	if code, out, _ := login(map[string]any{"username": "ann", "password": "Harbor-maple-63", "passkey": map[string]any{"token": stepOpts["token"], "credential": ans}}); code != 401 || out["code"] != "passkey_wrong" {
		t.Errorf("replay elsewhere = %d %v", code, out)
	}
	// A wrong password with the passkey signs nobody in.
	if code, out, _ := login(map[string]any{"username": "ann", "password": "nope", "passkey": map[string]any{"token": stepOpts["token"], "credential": a.get(stepOpts, key)}}); code != 401 || out["code"] != "wrong_credentials" {
		t.Errorf("wrong password = %d %v", code, out)
	}

	// On its own: the passkey must check the user, and comes from this
	// site only.
	passwordless := func() (int, map[string]any, *http.Cookie) {
		t.Helper()
		code, opts, _ := pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
		if code != 200 {
			t.Fatalf("login options = %d %v", code, opts)
		}
		pk := opts["publicKey"].(map[string]any)
		if pk["userVerification"] != "required" || pk["allowCredentials"] != nil {
			t.Errorf("login options = %v", pk)
		}
		code, out, cs := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": opts["token"], "credential": a.get(opts, key)})
		return code, out, sessionOf(cs)
	}
	code, out, sess = passwordless()
	if code != 200 || sess == nil || out["username"] != "ann" {
		t.Fatalf("passwordless = %d %v", code, out)
	}
	{
		// A synced passkey keeps no counter: its answer is still good
		// once only, on any server.
		_, ao, _ := pkCall(t, ts, "POST", "/api/me/passkeys/options", "{}", sess)
		cred, synced := a.create(ao)
		synced.synced = true
		if code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", map[string]any{"name": "Phone", "token": ao["token"], "credential": cred}, sess); code != 200 {
			t.Fatalf("add synced = %d %v", code, out)
		}
		_, lo, _ := pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
		body := map[string]any{"token": lo["token"], "credential": a.get(lo, synced)}
		if code, out, _ := pkCall(t, ts, "POST", "/api/login/passkey", body); code != 200 {
			t.Fatalf("no counter = %d %v", code, out)
		}
		s.passkeyChallenges = challengeSet{}
		if code, out, _ := pkCall(t, ts, "POST", "/api/login/passkey", body); code != 401 || out["code"] != "passkey_wrong" {
			t.Errorf("no counter, replayed elsewhere = %d %v", code, out)
		}
		// A challenge made for one host is no good at another.
		_, lo, _ = pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
		if code, out, _ := pkCallAt(t, ts, "x.localhost", "POST", "/api/login/passkey", map[string]any{"token": lo["token"], "credential": a.get(lo, key)}); code != 401 || out["code"] != "passkey_expired" {
			t.Errorf("other host = %d %v", code, out)
		}
		if code, out, _ := pkCall(t, ts, "DELETE", "/api/me/passkeys/"+b64.EncodeToString(synced.id), "", sess); code != 200 {
			t.Fatalf("remove synced = %d %v", code, out)
		}
	}
	a.uv = false
	if code, out, _ := passwordless(); code != 401 || out["code"] != "passkey_wrong" {
		t.Errorf("without user verification = %d %v", code, out)
	}
	a.uv = true
	a.origin = "http://evil.localhost"
	if code, out, _ := passwordless(); code != 401 || out["code"] != "passkey_wrong" {
		t.Errorf("another origin = %d %v", code, out)
	}
	a.origin = "http://localhost"
	// A step token does not sign in on its own, nor the other way round.
	code, step, _ = login(map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	stepOpts = step["passkey"].(map[string]any)
	if code, out, _ := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": stepOpts["token"], "credential": a.get(stepOpts, key)}); code != 401 || out["code"] != "passkey_expired" {
		t.Errorf("step token alone = %d %v", code, out)
	}
	// A counter that goes backwards means a copy.
	// (failed tries above still ticked the key's counter, so go back to
	// what the server last saw.)
	if mm, _ := s.Users.MFA("ann"); len(mm.Passkeys) == 1 {
		key.count = mm.Passkeys[0].SignCount - 1
	}
	if code, out, _ := passwordless(); code != 401 || out["code"] != "passkey_cloned" {
		t.Errorf("copied passkey = %d %v", code, out)
	}
	key.count += 10

	// Confirming it's you with the passkey.
	back.Store(int64(20 * time.Minute))
	code, out, old := passwordless()
	back.Store(0)
	if code != 200 {
		t.Fatalf("old session = %d %v", code, out)
	}
	if code, out, _ := pkCall(t, ts, "POST", "/api/users", `{"username":"bob"}`, old); code != 403 || out["code"] != "recheck_required" || out["passkey"] != true {
		t.Errorf("recheck asked = %d %v", code, out)
	}
	code, ch, _ := pkCall(t, ts, "POST", "/api/me/passkeys/challenge", "{}", old)
	if code != 200 {
		t.Fatalf("challenge = %d %v", code, ch)
	}
	code, out, set := pkCall(t, ts, "POST", "/api/me/recheck", map[string]any{"passkey": map[string]any{"token": ch["token"], "credential": a.get(ch, key)}}, old)
	if code != 200 || len(set) != 1 {
		t.Fatalf("recheck = %d %v", code, out)
	}
	if code, out, _ := pkCall(t, ts, "POST", "/api/users", `{"username":"bob","password":"Quartz-meadow-28"}`, old, set[0]); code != 201 {
		t.Errorf("after recheck = %d %v", code, out)
	}
	// Another session's challenge is no good here.
	if code, out, _ := pkCall(t, ts, "POST", "/api/me/recheck", map[string]any{"passkey": map[string]any{"token": ch["token"], "credential": a.get(ch, key)}}, sess); code != 401 || out["code"] != "passkey_expired" {
		t.Errorf("other session's challenge = %d %v", code, out)
	}

	// Removing the only passkey turns two-step sign-in off.
	code, out, _ = pkCall(t, ts, "DELETE", "/api/me/passkeys/"+b64.EncodeToString(key.id), "", sess)
	if code != 200 || out["mfa"].(map[string]any)["on"] != false {
		t.Fatalf("remove = %d %v", code, out)
	}
	if code, out, _ := passwordless(); code != 401 || out["code"] != "passkey_wrong" {
		t.Errorf("removed passkey = %d %v", code, out)
	}
	if _, _, c := login(map[string]any{"username": "ann", "password": "Harbor-maple-63"}); c == nil {
		t.Error("password alone after removing")
	}
}

// Directory users always give their password first; disabled users get
// nowhere; and with an app too, either works as the second step.
func TestPasskeyWithApp(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	ctx := context.Background()
	if _, err := s.Users.Create(ctx, users.NewUser{Username: "ann", Role: users.Analyst, Password: "Harbor-maple-63"}); err != nil {
		t.Fatal(err)
	}
	a := newAuthenticator(t)
	_, _, cs := pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	ann := sessionOf(cs)
	secret, _ := setUpMFAAt(t, ts, ann)
	_, _, cs = pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "ann", "password": "Harbor-maple-63", "code": mustTOTP(t, secret, 30*time.Second)})
	ann = sessionOf(cs)
	if ann == nil {
		t.Fatal("no session after the app")
	}
	_, opts, _ := pkCall(t, ts, "POST", "/api/me/passkeys/options", "{}", ann)
	cred, key := a.create(opts)
	code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", map[string]any{"token": opts["token"], "credential": cred}, ann)
	if code != 200 || out["recovery_codes"] != nil || out["mfa"].(map[string]any)["app"] != true {
		t.Fatalf("add with app = %d %v", code, out)
	}
	code, step, _ := pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	if code != 401 || step["app"] != true || step["passkey"] == nil {
		t.Fatalf("step = %d %v", code, step)
	}
	// Turning the app off keeps the passkey.
	ch := func() map[string]any {
		_, ch, _ := pkCall(t, ts, "POST", "/api/me/passkeys/challenge", "{}", ann)
		return ch
	}
	c := ch()
	code, out, _ = pkCall(t, ts, "POST", "/api/me/mfa/off", map[string]any{"passkey": map[string]any{"token": c["token"], "credential": a.get(c, key)}}, ann)
	if m, _ := out["mfa"].(map[string]any); code != 200 || m["on"] != true || m["app"] != false {
		t.Fatalf("app off = %d %v", code, out)
	}
	// New recovery codes with the passkey.
	c = ch()
	code, out, _ = pkCall(t, ts, "POST", "/api/me/mfa/recovery", map[string]any{"passkey": map[string]any{"token": c["token"], "credential": a.get(c, key)}}, ann)
	if codes, _ := out["recovery_codes"].([]any); code != 200 || len(codes) != users.RecoveryCodes {
		t.Fatalf("recovery = %d %v", code, out)
	}
	recovery := out["recovery_codes"].([]any)[0].(string)
	// A recovery code still works as the second step.
	if code, out, cs := pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "ann", "password": "Harbor-maple-63", "code": recovery}); code != 200 || sessionOf(cs) == nil {
		t.Errorf("recovery code = %d %v", code, out)
	}
	// Setting the app up again keeps the passkey and its recovery codes.
	_, _ = setUpMFAAt(t, ts, ann)
	if mm, _ := s.Users.MFA("ann"); len(mm.Passkeys) != 1 || !mm.AppOn() {
		t.Errorf("after the app again: %+v", mm)
	}

	// Disabled: the passkey does not sign in.
	if _, err := s.Users.Update(ctx, "ann", users.Change{Disabled: func() *bool { b := true; return &b }()}); err != nil {
		t.Fatal(err)
	}
	_, lo, _ := pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
	if code, out, _ := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": lo["token"], "credential": a.get(lo, key)}); code != 403 || out["code"] != "disabled" {
		t.Errorf("disabled = %d %v", code, out)
	}
	// An admin's reset removes the passkeys too.
	if _, err := s.Users.RemoveMFA(ctx, "ann"); err != nil {
		t.Fatal(err)
	}
	if mm, ok := s.Users.MFA("ann"); ok {
		t.Errorf("after reset: %+v", mm)
	}
}

func mustTOTP(t *testing.T, secret string, ahead time.Duration) string {
	t.Helper()
	c, err := users.TOTP(secret, time.Now().Add(ahead))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// setUpMFAAt sets up the app over the host localhost.
func setUpMFAAt(t *testing.T, ts *httptest.Server, c *http.Cookie) (string, []string) {
	t.Helper()
	code, out, _ := pkCall(t, ts, "POST", "/api/me/mfa/setup", "{}", c)
	if code != 200 {
		t.Fatalf("setup = %d %v", code, out)
	}
	secret := strings.ReplaceAll(out["secret"].(string), " ", "")
	code, out, _ = pkCall(t, ts, "POST", "/api/me/mfa/confirm", map[string]any{"code": mustTOTP(t, secret, 0)}, c)
	if code != 200 {
		t.Fatalf("confirm = %d %v", code, out)
	}
	var codes []string
	for _, v := range out["recovery_codes"].([]any) {
		codes = append(codes, v.(string))
	}
	return secret, codes
}

// An admin's password reset removes the user's passkeys: whoever added
// one must not keep a way in past the new password.
func TestPasswordResetRemovesPasskeys(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	ctx := context.Background()
	for _, u := range []users.NewUser{
		{Username: "boss", Role: users.Admin, Password: "Harbor-maple-63"},
		{Username: "cara", Role: users.Analyst, Password: "Quartz-meadow-28"},
	} {
		if _, err := s.Users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	a := newAuthenticator(t)
	_, _, cs := pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "cara", "password": "Quartz-meadow-28"})
	cara := sessionOf(cs)
	_, opts, _ := pkCall(t, ts, "POST", "/api/me/passkeys/options", "{}", cara)
	cred, key := a.create(opts)
	if code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", map[string]any{"token": opts["token"], "credential": cred}, cara); code != 200 {
		t.Fatalf("add = %d %v", code, out)
	}
	_, _, cs = pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "boss", "password": "Harbor-maple-63"})
	if code, out, _ := pkCall(t, ts, "POST", "/api/users/cara/password", "{}", sessionOf(cs)); code != 200 {
		t.Fatalf("reset = %d %v", code, out)
	}
	if mm, ok := s.Users.MFA("cara"); ok {
		t.Errorf("after reset: %+v", mm)
	}
	_, lo, _ := pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
	if code, out, _ := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": lo["token"], "credential": a.get(lo, key)}); code != 401 || out["code"] != "passkey_wrong" {
		t.Errorf("passkey after reset = %d %v", code, out)
	}
}
