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
//
// A token expires after the days chosen when it is made, 90 unless the
// admin picks another number up to 365, or never when the admin says so.
// Tokens made before expiry existed hold no expiry and are accepted until
// they are revoked. Each server records when a token was last used in its
// document, at most once an hour (NoteAPITokenUse), so a busy program
// costs one write an hour and not one a request. A server of a version
// before expiry keeps the expiry in the document's Extra but does not
// check it, so an expired token is refused only once every server runs
// this version or later.

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
	// DefaultAPITokenDays is how long a new token lasts unless the admin
	// picks another number of days, up to MaxAPITokenDays, or never.
	DefaultAPITokenDays = 90
	MaxAPITokenDays     = 365
	// APITokenUseEvery is how often a token's last use is written.
	APITokenUseEvery = time.Hour
)

// APITokenBody is api_token:<id>.
type APITokenBody struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	Role users.Role `json:"role"`
	// Hash is the token's SHA-256, in hex; Hint its last four characters,
	// to tell tokens apart.
	Hash      string     `json:"hash"`
	Hint      string     `json:"hint"`
	CreatedBy string     `json:"created_by"`
	Created   time.Time  `json:"created"`
	RevokedBy string     `json:"revoked_by,omitempty"`
	Revoked   *time.Time `json:"revoked,omitempty"`
	// Expires is when the token stops being accepted; nil for a token
	// that never expires, as every token made before expiry existed.
	Expires *time.Time `json:"expires,omitempty"`
	// LastUsed is when a server last accepted the token, written at most
	// once every APITokenUseEvery.
	LastUsed     *time.Time `json:"last_used,omitempty"`
	shared.Extra `json:"-"`
}

// Active reports whether the token is accepted at now: not revoked and
// not expired.
func (b *APITokenBody) Active(now time.Time) bool { return b.Revoked == nil && !b.Expired(now) }

// Expired reports whether the token has expired by now.
func (b *APITokenBody) Expired(now time.Time) bool {
	return b.Expires != nil && !now.Before(*b.Expires)
}

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
	ErrAPITokenExpiry  = fmt.Errorf("a token lasts from 1 to %d days, or never expires", MaxAPITokenDays)
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

// ValidAPITokenDays checks how many days a new token lasts: 1 to
// MaxAPITokenDays, or 0 for a token that never expires.
func ValidAPITokenDays(days int) error {
	if days < 0 || days > MaxAPITokenDays {
		return ErrAPITokenExpiry
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
	case b.Expires != nil && !b.Expires.After(b.Created):
		return errors.New("it expires before it was made")
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

// CreateAPIToken makes a token named name with role, lasting days (0 for
// one that never expires), for the user by, and returns it with its
// secret, which is shown once and kept nowhere.
func (d *Docs) CreateAPIToken(ctx context.Context, by, name string, role users.Role, days int, now time.Time) (APITokenBody, string, error) {
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
	if err := ValidAPITokenDays(days); err != nil {
		return APITokenBody{}, "", err
	}
	all := c.List()
	if len(all) >= MaxAPITokens {
		return APITokenBody{}, "", ErrAPITokenMany
	}
	for _, it := range all {
		if it.Value.Active(now) && strings.EqualFold(it.Value.Name, name) {
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
	if days > 0 {
		t := b.Created.AddDate(0, 0, days)
		b.Expires = &t
	}
	if _, err := c.Create(ctx, by, id, &b); err != nil {
		return APITokenBody{}, "", err
	}
	return b, secret, nil
}

// RevokeAPIToken stops accepting the token id, for the user by. Revoking
// a revoked token changes nothing; an expired one can still be revoked,
// so the list says an admin cut it off.
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
		if b.Revoked != nil {
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

// LookupAPIToken returns the token whose secret is secret and whether it
// is accepted at now. A revoked or expired token is returned too, with
// false, so the caller can say why it was refused; an unknown one is the
// zero token.
func (d *Docs) LookupAPIToken(secret string, now time.Time) (APITokenBody, bool) {
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
			return *it.Value, it.Value.Active(now)
		}
	}
	return APITokenBody{}, false
}

// APITokenUseDue reports whether NoteAPITokenUse would write the last use
// of b at now. It is cheap, for the request's path.
func (d *Docs) APITokenUseDue(b *APITokenBody, now time.Time) bool {
	if b.LastUsed != nil && now.Sub(*b.LastUsed) < APITokenUseEvery {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	last, ok := d.tokenUse[b.ID]
	return !ok || now.Sub(last) >= APITokenUseEvery
}

// NoteAPITokenUse records that the token id was accepted at now. It
// writes the token's LastUsed only when that is older than
// APITokenUseEvery, and this server tries at most once in that time
// whatever the outcome, so a busy program does not cost a write per
// request. It reports whether it wrote. It may be slow: call it off the
// request's path.
func (d *Docs) NoteAPITokenUse(ctx context.Context, id string, now time.Time) (bool, error) {
	c, err := d.apiTokens()
	if err != nil {
		return false, err
	}
	if !validAPITokenID(id) {
		return false, ErrAPITokenMissing
	}
	d.mu.Lock()
	if d.tokenUse == nil {
		d.tokenUse = map[string]time.Time{}
	}
	if last, ok := d.tokenUse[id]; ok && now.Sub(last) < APITokenUseEvery {
		d.mu.Unlock()
		return false, nil
	}
	for k, t := range d.tokenUse {
		if now.Sub(t) >= APITokenUseEvery {
			delete(d.tokenUse, k)
		}
	}
	d.tokenUse[id] = now
	d.mu.Unlock()
	errSkip := errors.New("not due")
	_, err = c.Mutate(ctx, "signalith", id, func(b *APITokenBody) error {
		if !b.Active(now) || b.LastUsed != nil && now.Sub(*b.LastUsed) < APITokenUseEvery {
			return errSkip
		}
		t := now.UTC()
		b.LastUsed = &t
		return nil
	})
	switch {
	case errors.Is(err, errSkip):
		return false, nil
	case errors.Is(err, store.ErrNotFound):
		return false, ErrAPITokenMissing
	case err != nil:
		return false, err
	}
	return true, nil
}
