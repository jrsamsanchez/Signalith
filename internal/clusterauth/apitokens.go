package clusterauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// API tokens let a program read through the API without a person's
// password: the read-only AI tools server (signalith mcp) first. An admin
// makes one on Settings > API tokens with a name and a role (viewer or
// analyst), sees it once, and revokes it there. Each is a signed document
// of the shared settings, api_token:<id>, holding only the token's
// SHA-256 fingerprint, so every server of the cluster accepts it and a
// revocation reaches all of them within a poll. A token is "sgl_api_"
// and 52 characters of lowercase base32: 32 random bytes, so a plain
// SHA-256 is as safe as a keyed hash, and secret scanners find a leaked
// one by its prefix. Whatever its role, the API lets a token only read
// (see the api package).

// Document kind and watch of the API tokens.
const (
	APITokenKind  = "api_token"
	APITokenWatch = "api_tokens"
)

const (
	// APITokenPrefix starts every API token.
	APITokenPrefix = "sgl_api_"
	// APITokenLength is a token's length: the prefix and 52 characters.
	APITokenLength = len(APITokenPrefix) + 52
	// APITokenPattern finds API tokens in text, for secret scanners.
	APITokenPattern = `\bsgl_api_[a-z2-7]{52}\b`
	// MaxAPITokens is how many tokens there may be, revoked ones
	// included; MaxAPITokenName the longest name, in characters.
	MaxAPITokens    = 200
	MaxAPITokenName = 64
)

// APITokenBody is api_token:<id>.
type APITokenBody struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	Role users.Role `json:"role"`
	// Hash is the token's SHA-256, in hex; Hint its last four characters,
	// to tell tokens apart.
	Hash         string     `json:"hash"`
	Hint         string     `json:"hint"`
	CreatedBy    string     `json:"created_by"`
	Created      time.Time  `json:"created"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	Revoked      *time.Time `json:"revoked,omitempty"`
	shared.Extra `json:"-"`
}

// Active reports whether the token is accepted.
func (b *APITokenBody) Active() bool { return b.Revoked == nil }

var apiB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newAPIToken makes a new token.
func newAPIToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return APITokenPrefix + strings.ToLower(apiB32.EncodeToString(b)), nil
}

// IsAPIToken reports whether s has the shape of an API token.
func IsAPIToken(s string) bool {
	if len(s) != APITokenLength || !strings.HasPrefix(s, APITokenPrefix) {
		return false
	}
	for _, c := range s[len(APITokenPrefix):] {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func apiTokenHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func newAPITokenID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validAPITokenID(id string) bool {
	if len(id) != 12 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Errors of the API tokens.
var (
	ErrAPITokenName    = fmt.Errorf("name the token: up to %d letters, digits, spaces and . _ - characters, such as Claude Desktop on Ana's laptop", MaxAPITokenName)
	ErrAPITokenRole    = errors.New("an API token is a viewer or an analyst")
	ErrAPITokenTaken   = errors.New("another active token has that name")
	ErrAPITokenMany    = fmt.Errorf("there are %d API tokens already, revoked ones included", MaxAPITokens)
	ErrAPITokenMissing = errors.New("there is no such API token")
	ErrAPITokensOff    = errors.New("API tokens are kept in the shared settings, which this server cannot use now")
)

// ValidAPITokenName checks a token's name.
func ValidAPITokenName(name string) error {
	if name == "" || utf8.RuneCountInString(name) > MaxAPITokenName || strings.TrimSpace(name) != name {
		return ErrAPITokenName
	}
	for _, r := range name {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" ._-'()@", r)) {
			return ErrAPITokenName
		}
	}
	return nil
}

func validAPITokenRole(r users.Role) bool { return r == users.Viewer || r == users.Analyst }

func (d *Docs) validateAPIToken(name string, b *APITokenBody) error {
	switch {
	case b.ID != name || !validAPITokenID(name):
		return fmt.Errorf("it holds the token %q", b.ID)
	case !validAPITokenRole(b.Role):
		return fmt.Errorf("its role %q is not one an API token may have", b.Role)
	case len(b.Hash) != sha256.Size*2:
		return errors.New("it holds no token fingerprint")
	case ValidAPITokenName(b.Name) != nil:
		return fmt.Errorf("its name %q is not one a token may have", b.Name)
	}
	return nil
}

func (d *Docs) apiTokens() (*shared.Collection[APITokenBody], error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tokens == nil {
		return nil, ErrAPITokensOff
	}
	return d.tokens, nil
}

// APITokens lists the API tokens, newest first.
func (d *Docs) APITokens() []APITokenBody {
	c, err := d.apiTokens()
	if err != nil {
		return nil
	}
	var out []APITokenBody
	for _, it := range c.List() {
		out = append(out, *it.Value)
	}
	slices.SortFunc(out, func(a, b APITokenBody) int { return b.Created.Compare(a.Created) })
	return out
}

// CreateAPIToken makes a token named name with role, for the user by, and
// returns it with its secret, which is shown once and kept nowhere.
func (d *Docs) CreateAPIToken(ctx context.Context, by, name string, role users.Role, now time.Time) (APITokenBody, string, error) {
	c, err := d.apiTokens()
	if err != nil {
		return APITokenBody{}, "", err
	}
	if err := ValidAPITokenName(name); err != nil {
		return APITokenBody{}, "", err
	}
	if !validAPITokenRole(role) {
		return APITokenBody{}, "", ErrAPITokenRole
	}
	all := c.List()
	if len(all) >= MaxAPITokens {
		return APITokenBody{}, "", ErrAPITokenMany
	}
	for _, it := range all {
		if it.Value.Active() && strings.EqualFold(it.Value.Name, name) {
			return APITokenBody{}, "", ErrAPITokenTaken
		}
	}
	secret, err := newAPIToken()
	if err != nil {
		return APITokenBody{}, "", err
	}
	id, err := newAPITokenID()
	if err != nil {
		return APITokenBody{}, "", err
	}
	b := APITokenBody{ID: id, Name: name, Role: role, Hash: apiTokenHash(secret), Hint: secret[len(secret)-4:],
		CreatedBy: by, Created: now.UTC()}
	if _, err := c.Create(ctx, by, id, &b); err != nil {
		return APITokenBody{}, "", err
	}
	return b, secret, nil
}

// RevokeAPIToken stops accepting the token id, for the user by. Revoking
// a revoked token changes nothing.
func (d *Docs) RevokeAPIToken(ctx context.Context, by, id string, now time.Time) (APITokenBody, error) {
	c, err := d.apiTokens()
	if err != nil {
		return APITokenBody{}, err
	}
	if !validAPITokenID(id) {
		return APITokenBody{}, ErrAPITokenMissing
	}
	var out APITokenBody
	errSame := errors.New("already revoked")
	_, err = c.Mutate(ctx, by, id, func(b *APITokenBody) error {
		out = *b
		if !b.Active() {
			return errSame
		}
		t := now.UTC()
		b.Revoked, b.RevokedBy = &t, by
		out = *b
		return nil
	})
	switch {
	case errors.Is(err, errSame):
		return out, nil
	case errors.Is(err, store.ErrNotFound):
		return APITokenBody{}, ErrAPITokenMissing
	}
	return out, err
}

// LookupAPIToken returns the active token whose secret is secret.
func (d *Docs) LookupAPIToken(secret string) (APITokenBody, bool) {
	if !IsAPIToken(secret) {
		return APITokenBody{}, false
	}
	c, err := d.apiTokens()
	if err != nil {
		return APITokenBody{}, false
	}
	h := []byte(apiTokenHash(secret))
	for _, it := range c.List() {
		if subtle.ConstantTimeCompare(h, []byte(it.Value.Hash)) == 1 {
			return *it.Value, it.Value.Active()
		}
	}
	return APITokenBody{}, false
}
