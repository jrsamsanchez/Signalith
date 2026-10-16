package clusterauth

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

func TestAPITokens(t *testing.T) {
	_, a, b, clk := pair(t)
	ctx := context.Background()
	tok, secret, err := a.docs.CreateAPIToken(ctx, "admin", "Claude Desktop", users.Viewer, 0, clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !IsAPIToken(secret) || !regexp.MustCompile(APITokenPattern).MatchString(secret) {
		t.Fatalf("token %q has the wrong shape", secret)
	}
	if tok.Hint != secret[len(secret)-4:] || strings.Contains(tok.Hash, secret) || tok.Hash != apiTokenHash(secret) {
		t.Errorf("stored token %+v", tok)
	}
	b.cycle()
	got, ok := b.docs.LookupAPIToken(secret, clk.Now())
	if !ok || got.Name != "Claude Desktop" || got.Role != users.Viewer || got.CreatedBy != "admin" {
		t.Fatalf("B's lookup = %+v %v", got, ok)
	}
	other := secret[:len(secret)-1] + "a"
	if strings.HasSuffix(secret, "a") {
		other = secret[:len(secret)-1] + "b"
	}
	if _, ok := b.docs.LookupAPIToken(other, clk.Now()); ok {
		t.Error("a different token was accepted")
	}
	if _, ok := b.docs.LookupAPIToken("sgl_api_short", clk.Now()); ok {
		t.Error("a malformed token was accepted")
	}

	for _, c := range []struct {
		name string
		role users.Role
		want error
	}{
		{"claude desktop", users.Viewer, ErrAPITokenTaken},
		{"", users.Viewer, ErrAPITokenName},
		{" padded", users.Viewer, ErrAPITokenName},
		{"semi;colon", users.Viewer, ErrAPITokenName},
		{strings.Repeat("x", MaxAPITokenName+1), users.Viewer, ErrAPITokenName},
		{"Admin token", users.Admin, ErrAPITokenRole},
	} {
		if _, _, err := a.docs.CreateAPIToken(ctx, "admin", c.name, c.role, 90, clk.Now()); !errors.Is(err, c.want) {
			t.Errorf("create %q %s = %v, want %v", c.name, c.role, err, c.want)
		}
	}
	if _, _, err := a.docs.CreateAPIToken(ctx, "admin", "Ana's laptop (Cursor) v1.2_a-b@x", users.Analyst, 90, clk.Now()); err != nil {
		t.Errorf("a name with allowed punctuation: %v", err)
	}

	r, err := b.docs.RevokeAPIToken(ctx, "admin", tok.ID, clk.Now())
	if err != nil || r.Active(clk.Now()) || r.RevokedBy != "admin" {
		t.Fatalf("revoke = %+v %v", r, err)
	}
	if _, err := b.docs.RevokeAPIToken(ctx, "admin", tok.ID, clk.Now()); err != nil {
		t.Errorf("revoking again: %v", err)
	}
	a.cycle()
	if _, ok := a.docs.LookupAPIToken(secret, clk.Now()); ok {
		t.Error("A accepts a token revoked on B after one poll")
	}
	if _, err := a.docs.RevokeAPIToken(ctx, "admin", "000000000000", clk.Now()); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("revoking an unknown token = %v", err)
	}
	if _, err := a.docs.RevokeAPIToken(ctx, "admin", "../users", clk.Now()); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("revoking a bad id = %v", err)
	}
	if _, _, err := a.docs.CreateAPIToken(ctx, "admin", "Claude Desktop", users.Viewer, 90, clk.Now()); err != nil {
		t.Errorf("reusing a revoked token's name: %v", err)
	}
	if n := len(a.docs.APITokens()); n != 3 {
		t.Errorf("%d tokens listed, want 3", n)
	}
}

// A token expires after the days it was made for, on every server; a
// token without an expiry, as every one made before expiry existed, is
// accepted until it is revoked.
func TestAPITokenExpiry(t *testing.T) {
	_, a, b, clk := pair(t)
	ctx := context.Background()
	for _, days := range []int{-1, MaxAPITokenDays + 1} {
		if _, _, err := a.docs.CreateAPIToken(ctx, "admin", "Bad", users.Viewer, days, clk.Now()); !errors.Is(err, ErrAPITokenExpiry) {
			t.Errorf("a token for %d days = %v", days, err)
		}
	}
	short, shortSecret, err := a.docs.CreateAPIToken(ctx, "admin", "Short", users.Viewer, 1, clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	if short.Expires == nil || !short.Expires.Equal(clk.Now().UTC().AddDate(0, 0, 1)) {
		t.Fatalf("expires %v", short.Expires)
	}
	_, longSecret, err := a.docs.CreateAPIToken(ctx, "admin", "Long", users.Viewer, MaxAPITokenDays, clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	never, neverSecret, err := a.docs.CreateAPIToken(ctx, "admin", "Never", users.Viewer, 0, clk.Now())
	if err != nil || never.Expires != nil {
		t.Fatalf("a token that never expires: %+v %v", never, err)
	}
	b.cycle()
	if _, ok := b.docs.LookupAPIToken(shortSecret, clk.Now()); !ok {
		t.Error("a new token was refused")
	}
	clk.Advance(25 * time.Hour)
	got, ok := b.docs.LookupAPIToken(shortSecret, clk.Now())
	if ok || got.ID != short.ID || !got.Expired(clk.Now()) || got.Revoked != nil {
		t.Errorf("an expired token: %+v %v", got, ok)
	}
	if _, ok := b.docs.LookupAPIToken(longSecret, clk.Now()); !ok {
		t.Error("a token for a year was refused after a day")
	}
	clk.Advance(5 * 365 * 24 * time.Hour)
	if _, ok := b.docs.LookupAPIToken(neverSecret, clk.Now()); !ok {
		t.Error("a token that never expires was refused")
	}
	// An expired token's name is free, and it can still be revoked.
	if _, _, err := a.docs.CreateAPIToken(ctx, "admin", "Short", users.Viewer, 30, clk.Now()); err != nil {
		t.Errorf("reusing an expired token's name: %v", err)
	}
	if r, err := a.docs.RevokeAPIToken(ctx, "admin", short.ID, clk.Now()); err != nil || r.Revoked == nil {
		t.Errorf("revoking an expired token: %+v %v", r, err)
	}

	// A document written before expiry existed holds no expires field.
	oldSecret := "sgl_api_" + strings.Repeat("a", 52)
	c, _ := a.docs.apiTokens()
	old := APITokenBody{ID: "0123456789ab", Name: "Old", Role: users.Viewer, Hash: apiTokenHash(oldSecret),
		Hint: "aaaa", CreatedBy: "admin", Created: clk.Now().Add(-1000 * 24 * time.Hour)}
	if _, err := c.Create(ctx, "admin", old.ID, &old); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if got, ok := b.docs.LookupAPIToken(oldSecret, clk.Now()); !ok || got.Expires != nil {
		t.Errorf("an old token without an expiry: %+v %v", got, ok)
	}
	// One that expires before it was made is refused as a document.
	bad := old
	bad.ID, bad.Name, bad.Hash = "0123456789ac", "Bad", apiTokenHash("x")
	e := bad.Created.Add(-time.Hour)
	bad.Expires = &e
	if _, err := c.Create(ctx, "admin", bad.ID, &bad); err == nil {
		t.Error("a token that expires before it was made was saved")
	}
}

// A token's last use is written at most once an hour.
func TestAPITokenLastUsed(t *testing.T) {
	_, a, b, clk := pair(t)
	ctx := context.Background()
	tok, secret, err := a.docs.CreateAPIToken(ctx, "admin", "Used", users.Viewer, 90, clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if !b.docs.APITokenUseDue(&tok, clk.Now()) {
		t.Error("the first use is not due")
	}
	if wrote, err := b.docs.NoteAPITokenUse(ctx, tok.ID, clk.Now()); !wrote || err != nil {
		t.Fatalf("first use: %v %v", wrote, err)
	}
	if b.docs.APITokenUseDue(&tok, clk.Now()) {
		t.Error("a use is due again at once")
	}
	used := clk.Now().UTC()
	clk.Advance(time.Minute)
	if wrote, err := b.docs.NoteAPITokenUse(ctx, tok.ID, clk.Now()); wrote || err != nil {
		t.Errorf("a use a minute later wrote: %v %v", wrote, err)
	}
	a.cycle()
	// The other server reads the last use and does not write it again
	// within the hour either.
	got, _ := a.docs.LookupAPIToken(secret, clk.Now())
	if got.LastUsed == nil || !got.LastUsed.Equal(used) {
		t.Fatalf("last used %v, want %v", got.LastUsed, used)
	}
	if wrote, _ := a.docs.NoteAPITokenUse(ctx, tok.ID, clk.Now()); wrote {
		t.Error("the other server wrote again within the hour")
	}
	clk.Advance(time.Hour)
	if wrote, err := b.docs.NoteAPITokenUse(ctx, tok.ID, clk.Now()); !wrote || err != nil {
		t.Errorf("a use an hour later: %v %v", wrote, err)
	}
	if _, err := b.docs.NoteAPITokenUse(ctx, "../x", clk.Now()); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("a bad id: %v", err)
	}
}
