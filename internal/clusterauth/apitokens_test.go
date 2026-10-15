package clusterauth

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

func TestAPITokens(t *testing.T) {
	_, a, b, clk := pair(t)
	ctx := context.Background()
	tok, secret, err := a.docs.CreateAPIToken(ctx, "admin", "Claude Desktop", users.Viewer, clk.Now())
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
	got, ok := b.docs.LookupAPIToken(secret)
	if !ok || got.Name != "Claude Desktop" || got.Role != users.Viewer || got.CreatedBy != "admin" {
		t.Fatalf("B's lookup = %+v %v", got, ok)
	}
	other := secret[:len(secret)-1] + "a"
	if strings.HasSuffix(secret, "a") {
		other = secret[:len(secret)-1] + "b"
	}
	if _, ok := b.docs.LookupAPIToken(other); ok {
		t.Error("a different token was accepted")
	}
	if _, ok := b.docs.LookupAPIToken("sgl_api_short"); ok {
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
		if _, _, err := a.docs.CreateAPIToken(ctx, "admin", c.name, c.role, clk.Now()); !errors.Is(err, c.want) {
			t.Errorf("create %q %s = %v, want %v", c.name, c.role, err, c.want)
		}
	}
	if _, _, err := a.docs.CreateAPIToken(ctx, "admin", "Ana's laptop (Cursor) v1.2_a-b@x", users.Analyst, clk.Now()); err != nil {
		t.Errorf("a name with allowed punctuation: %v", err)
	}

	r, err := b.docs.RevokeAPIToken(ctx, "admin", tok.ID, clk.Now())
	if err != nil || r.Active() || r.RevokedBy != "admin" {
		t.Fatalf("revoke = %+v %v", r, err)
	}
	if _, err := b.docs.RevokeAPIToken(ctx, "admin", tok.ID, clk.Now()); err != nil {
		t.Errorf("revoking again: %v", err)
	}
	a.cycle()
	if _, ok := a.docs.LookupAPIToken(secret); ok {
		t.Error("A accepts a token revoked on B after one poll")
	}
	if _, err := a.docs.RevokeAPIToken(ctx, "admin", "000000000000", clk.Now()); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("revoking an unknown token = %v", err)
	}
	if _, err := a.docs.RevokeAPIToken(ctx, "admin", "../users", clk.Now()); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("revoking a bad id = %v", err)
	}
	if _, _, err := a.docs.CreateAPIToken(ctx, "admin", "Claude Desktop", users.Viewer, clk.Now()); err != nil {
		t.Errorf("reusing a revoked token's name: %v", err)
	}
	if n := len(a.docs.APITokens()); n != 3 {
		t.Errorf("%d tokens listed, want 3", n)
	}
}
