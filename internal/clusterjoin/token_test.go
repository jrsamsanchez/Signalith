package clusterjoin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

func newToken(t *testing.T) Token {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return Token{URL: "https://siem-a.plant.local:8443", CA: Pin([]byte("certificate")), ID: id, Secret: secret}
}

// wireText makes a token's text from its JSON, for tokens Token cannot
// make.
func wireText(v any) string {
	raw, _ := json.Marshal(v)
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func TestTokenRoundTrip(t *testing.T) {
	tok := newToken(t)
	if !ValidID(tok.ID) || len(tok.ID) != len(IDPrefix)+20 {
		t.Fatalf("id %q", tok.ID)
	}
	s := tok.String()
	if !strings.HasPrefix(s, TokenPrefix) {
		t.Fatalf("token %q", s)
	}
	for _, in := range []string{s, "  '" + s + "'\n", `"` + s + `"`} {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got.URL != tok.URL || got.CA != tok.CA || got.ID != tok.ID || !bytes.Equal(got.Secret, tok.Secret) {
			t.Errorf("Parse = %+v", got)
		}
	}
	// A trailing slash on the address is dropped.
	tok.URL += "/"
	if got, err := Parse(tok.String()); err != nil || got.URL != "https://siem-a.plant.local:8443" {
		t.Errorf("Parse = %q, %v", got.URL, err)
	}
}

func TestTokenParseRefuses(t *testing.T) {
	good := newToken(t)
	s64 := base64.RawURLEncoding.EncodeToString(good.Secret)
	w := func(change func(*wire)) string {
		v := wire{U: good.URL, CA: good.CA, ID: good.ID, S: s64}
		change(&v)
		return wireText(v)
	}
	cases := map[string]string{
		"empty":             "",
		"bad prefix":        "SJ2." + strings.TrimPrefix(good.String(), TokenPrefix),
		"no prefix":         strings.TrimPrefix(good.String(), TokenPrefix),
		"not base64":        TokenPrefix + "!!!",
		"not JSON":          TokenPrefix + base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"unknown field":     wireText(map[string]string{"u": good.URL, "ca": good.CA, "id": good.ID, "s": s64, "x": "1"}),
		"http address":      w(func(v *wire) { v.U = "http://siem-a:8443" }),
		"no host":           w(func(v *wire) { v.U = "https://" }),
		"user in address":   w(func(v *wire) { v.U = "https://sam:pw@siem-a:8443" }),
		"query in address":  w(func(v *wire) { v.U = "https://siem-a:8443/?x=1" }),
		"fragment":          w(func(v *wire) { v.U = "https://siem-a:8443/#x" }),
		"pin without sha":   w(func(v *wire) { v.CA = strings.TrimPrefix(good.CA, "sha256:") }),
		"pin upper case":    w(func(v *wire) { v.CA = strings.ToUpper(good.CA) }),
		"pin short":         w(func(v *wire) { v.CA = good.CA[:20] }),
		"pin with colons":   w(func(v *wire) { v.CA = "sha256:AB:CD" }),
		"bad id":            w(func(v *wire) { v.ID = "jt_short" }),
		"id upper":          w(func(v *wire) { v.ID = strings.ToUpper(good.ID) }),
		"short secret":      w(func(v *wire) { v.S = base64.RawURLEncoding.EncodeToString(good.Secret[:16]) }),
		"long secret":       w(func(v *wire) { v.S = base64.RawURLEncoding.EncodeToString(append(good.Secret, 1)) }),
		"secret not base64": w(func(v *wire) { v.S = "***" }),
		"too long":          TokenPrefix + strings.Repeat("A", maxToken),
	}
	for name, in := range cases {
		if _, err := Parse(in); !errors.Is(err, ErrBadToken) {
			t.Errorf("%s: Parse = %v, want ErrBadToken", name, err)
		}
	}
}

func TestTokenNeverShowsItsSecret(t *testing.T) {
	tok := newToken(t)
	full := tok.String()
	secret := base64.RawURLEncoding.EncodeToString(tok.Secret)
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	log.Info("joining", "token", tok, "ptr", &tok)
	log.Info("text", slog.Any("token", tok))
	tlog := slog.New(slog.NewTextHandler(&logs, nil))
	tlog.Info("joining", "token", tok)
	js, _ := json.Marshal(struct{ T Token }{tok})
	shown := []string{
		fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v %s %q %x", tok, tok, tok, tok, tok, tok), fmt.Sprintf("%v", &tok),
		fmt.Sprintf("%+v", struct{ T Token }{tok}), fmt.Errorf("with %v", tok).Error(),
		logs.String(), string(js),
	}
	for _, s := range shown {
		if strings.Contains(s, secret) || strings.Contains(s, full) || strings.Contains(s, strings.TrimPrefix(full, TokenPrefix)) {
			t.Errorf("the secret shows in %q", s)
		}
		if !strings.Contains(s, tok.ID) {
			t.Errorf("the id does not show in %q", s)
		}
	}
	tok.Clear()
	if !bytes.Equal(tok.Secret, make([]byte, SecretSize)) {
		t.Error("Clear left the secret")
	}
}

func TestTokenPin(t *testing.T) {
	tok := newToken(t)
	if !tok.MatchesPin([]byte("certificate")) {
		t.Error("the pinned certificate does not match")
	}
	if tok.MatchesPin([]byte("another")) || tok.MatchesPin(nil) {
		t.Error("another certificate matches")
	}
}

func TestProof(t *testing.T) {
	tok := newToken(t)
	nk, err := shared.NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := shared.NewNodeKey()
	nonce, _ := NewNonce()
	p := Proof(tok.Secret, tok.ID, nonce, nk.Public())
	if !CheckProof(tok.Secret, tok.ID, nonce, nk.Public(), p) {
		t.Fatal("a good proof is refused")
	}
	otherID, _ := NewID()
	nonce2, _ := NewNonce()
	wrongSecret, _ := NewSecret()
	bad := map[string]bool{
		"wrong secret":   CheckProof(wrongSecret, tok.ID, nonce, nk.Public(), p),
		"another token":  CheckProof(tok.Secret, otherID, nonce, nk.Public(), p),
		"another nonce":  CheckProof(tok.Secret, tok.ID, nonce2, nk.Public(), p),
		"another key":    CheckProof(tok.Secret, tok.ID, nonce, other.Public(), p),
		"short nonce":    CheckProof(tok.Secret, tok.ID, nonce[:16], nk.Public(), Proof(tok.Secret, tok.ID, nonce[:16], nk.Public())),
		"short key":      CheckProof(tok.Secret, tok.ID, nonce, nk.Public()[:16], Proof(tok.Secret, tok.ID, nonce, nk.Public()[:16])),
		"empty proof":    CheckProof(tok.Secret, tok.ID, nonce, nk.Public(), nil),
		"truncated":      CheckProof(tok.Secret, tok.ID, nonce, nk.Public(), p[:31]),
		"empty secret":   CheckProof(nil, tok.ID, nonce, nk.Public(), Proof(nil, tok.ID, nonce, nk.Public())),
		"bad token id":   CheckProof(tok.Secret, "jt_x", nonce, nk.Public(), Proof(tok.Secret, "jt_x", nonce, nk.Public())),
		"flipped bit":    CheckProof(tok.Secret, tok.ID, nonce, nk.Public(), append(append([]byte{}, p[:31]...), p[31]^1)),
		"nonce for pubs": CheckProof(tok.Secret, tok.ID, nk.Public(), nonce, Proof(tok.Secret, tok.ID, nonce, nk.Public())),
	}
	for name, ok := range bad {
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRequestCheck(t *testing.T) {
	tok := newToken(t)
	nk, _ := shared.NewNodeKey()
	r, err := NewRequest(tok, "n_0123456789abcdef0123", nk.Public())
	if err != nil {
		t.Fatal(err)
	}
	r.Name, r.Version, r.OS, r.Arch, r.LevelMax = "siem-c", "1.5.0", "linux", "amd64", shared.LevelMax
	p, err := r.Check()
	if err != nil {
		t.Fatal(err)
	}
	if !CheckProof(tok.Secret, r.TokenID, p.Nonce, p.NodePub, p.Proof) {
		t.Error("the request's proof does not check")
	}
	for name, change := range map[string]func(*Request){
		"token id":   func(r *Request) { r.TokenID = "x" },
		"nonce":      func(r *Request) { r.Nonce = "AAAA" },
		"proof":      func(r *Request) { r.Proof = "" },
		"node key":   func(r *Request) { r.NodePub = "!!" },
		"node id":    func(r *Request) { r.NodeID = "../etc" },
		"node id n_": func(r *Request) { r.NodeID = "abc" },
		"name":       func(r *Request) { r.Name = "siem c" },
		"level":      func(r *Request) { r.LevelMax = 0 },
		"version":    func(r *Request) { r.Version = "" },
		"long os":    func(r *Request) { r.OS = strings.Repeat("x", 17) },
	} {
		c := *r
		change(&c)
		if _, err := c.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
