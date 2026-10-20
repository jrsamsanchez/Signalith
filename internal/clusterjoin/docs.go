// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterjoin

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The token documents, <prefix>_config/jointoken:<id>.
const (
	Kind   = "jointoken"
	Watch  = "jointokens"
	Format = 1
)

// Lifetimes of a token.
const (
	DefaultTTL = 60 * time.Minute
	MaxTTL     = 24 * time.Hour
	MinTTL     = time.Minute
)

// Platforms a token is made for (the dialog's tab); "" says none.
var Platforms = []string{"linux", "windows", "docker"}

// RoleScanner is the role of a server that joins as a scanner: it only
// scans the networks picked for it and never runs the background jobs
// (cluster.role). "" joins a cluster server.
const RoleScanner = "scanner"

// checkRole checks the role a token gives the server that uses it.
func checkRole(r string) error {
	if r != "" && r != RoleScanner {
		return fmt.Errorf("the role is empty (a cluster server) or scanner, not %q", r)
	}
	return nil
}

// systemUser writes the changes Signalith makes by itself.
const systemUser = "signalith"

// Errors of Consume. Every one of them reaches the joining server as
// the same text (Refused); the log has the real reason.
var (
	ErrTokenUnknown = errors.New("no such join token")
	ErrTokenExpired = errors.New("the join token expired")
	ErrTokenUsed    = errors.New("the join token was used already")
	ErrProof        = errors.New("the proof does not match the join token's secret")
)

// JoinTokenBody is a token document's body.
type JoinTokenBody struct {
	// Secret is the token's secret, sealed with the cluster key for the
	// field SecretField(id): only members can check a proof with it.
	Secret    string    `json:"secret"`
	ExpiresAt time.Time `json:"expires_at"`
	// UsesLeft is 1 until a join uses it.
	UsesLeft int `json:"uses_left"`
	// Platform is the dialog's tab, Note what the admin wrote, NodeURL
	// the address the new server will be reached at (for Docker).
	Platform string `json:"platform,omitempty"`
	Note     string `json:"note,omitempty"`
	NodeURL  string `json:"node_url,omitempty"`
	// Role is the role the new server takes: "" a cluster server, or
	// RoleScanner.
	Role string `json:"role,omitempty"`
	// CreatedBy is the user who made it, CreatedOn the server.
	CreatedBy string `json:"created_by"`
	CreatedOn string `json:"created_on"`
	// UsedBy is the server that joined with it.
	UsedBy       *UsedBy `json:"used_by,omitempty"`
	shared.Extra `json:"-"`
}

// UsedBy is the server that used a token.
type UsedBy struct {
	NodeID string    `json:"node_id"`
	Name   string    `json:"name"`
	At     time.Time `json:"at"`
}

// SecretField is the field a token's secret is sealed for, so a sealed
// value moved to another token cannot be opened.
func SecretField(id string) string { return "jointoken.secret@" + id }

func validate(b *JoinTokenBody) error {
	switch {
	case !secrets.IsSealed(b.Secret):
		return errors.New("the join token's secret is not sealed")
	case b.ExpiresAt.IsZero():
		return errors.New("the join token has no expiry")
	case b.UsesLeft < 0 || b.UsesLeft > 1:
		return errors.New("a join token is used once")
	case b.UsedBy == nil && b.UsesLeft == 0:
		return errors.New("a used join token does not say who used it")
	}
	if err := checkRole(b.Role); err != nil {
		return err
	}
	return nil
}

func validateItem(name string, _ *JoinTokenBody) error {
	if !ValidID(name) {
		return fmt.Errorf("%q is not a join token id", name)
	}
	return nil
}

// Tokens holds the token documents, made again on each hub the runtime
// builds (Track).
type Tokens struct {
	// Writable says why tokens cannot be made or used on this server now
	// (shared.Runtime.Writable): only a member does.
	Writable func() error
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu  sync.Mutex
	hub *shared.Hub
	c   *shared.Collection[JoinTokenBody]
}

// New returns the holder; Track makes the collection.
func New(writable func() error) *Tokens { return &Tokens{Writable: writable} }

// Track makes the collection on h.
func (t *Tokens) Track(h *shared.Hub) {
	c := shared.NewCollection[JoinTokenBody](h, Kind, Watch, Format)
	c.Validate, c.ValidateItem = validate, validateItem
	t.mu.Lock()
	t.hub, t.c = h, c
	t.mu.Unlock()
}

// Reset is for the sharedTracker interface: a token holder keeps no
// subscribers.
func (t *Tokens) Reset() {}

func (t *Tokens) now() time.Time {
	if t.Now != nil {
		return t.Now().UTC()
	}
	return time.Now().UTC()
}

func (t *Tokens) parts() (*shared.Hub, *shared.Collection[JoinTokenBody], error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.c == nil {
		return nil, nil, errors.New("the shared settings are not open")
	}
	return t.hub, t.c, nil
}

func (t *Tokens) writable() error {
	if t.Writable == nil {
		return nil
	}
	return t.Writable()
}

// IssueArgs are what Issue makes a token from.
type IssueArgs struct {
	// By is the user, Node this server's name.
	By, Node string
	// URL is this server's address, which the new server reaches
	// (https), and CADER the certificate it must find there (GET
	// /api/cluster/join/ca).
	URL   string
	CADER []byte
	// TTL is the token's lifetime: 0 is DefaultTTL, at most MaxTTL.
	TTL      time.Duration
	Platform string
	Note     string
	NodeURL  string
	// Role is the role the new server takes ("" or RoleScanner).
	Role string
}

// Issued is a token Issue made. Token holds the secret: show it once and
// Clear it.
type Issued struct {
	Token     Token
	ExpiresAt time.Time
}

// Issue makes a token. Its secret is kept sealed with the cluster key
// and is in the answer only.
func (t *Tokens) Issue(ctx context.Context, a IssueArgs) (*Issued, error) {
	if err := t.writable(); err != nil {
		return nil, err
	}
	h, c, err := t.parts()
	if err != nil {
		return nil, err
	}
	ttl := a.TTL
	switch {
	case ttl == 0:
		ttl = DefaultTTL
	case ttl < MinTTL:
		return nil, errors.New("a join token lasts at least a minute")
	case ttl > MaxTTL:
		return nil, errors.New("a join token lasts at most 24 hours")
	}
	if a.Platform != "" && !slices.Contains(Platforms, a.Platform) {
		return nil, fmt.Errorf("the platform is linux, windows or docker, not %q", a.Platform)
	}
	note, err := cleanNote(a.Note)
	if err != nil {
		return nil, err
	}
	if err := checkRole(a.Role); err != nil {
		return nil, err
	}
	if a.NodeURL != "" {
		if err := checkNodeURL(a.NodeURL); err != nil {
			return nil, err
		}
	}
	u, err := CheckURL(a.URL)
	if err != nil {
		return nil, fmt.Errorf("this server's address for the token: %w", err)
	}
	if len(a.CADER) == 0 {
		return nil, errors.New("this server has no certificate authority the new server could check it by")
	}
	k := h.Keys().Active()
	if k == nil {
		return nil, errors.New("this server has no cluster key")
	}
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	secret, err := NewSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := k.SecretsKey().Seal(SecretField(id), base64.RawURLEncoding.EncodeToString(secret))
	if err != nil {
		clear(secret)
		return nil, err
	}
	exp := t.now().Add(ttl)
	body := &JoinTokenBody{Secret: sealed, ExpiresAt: exp, UsesLeft: 1, Platform: a.Platform, Note: note,
		NodeURL: a.NodeURL, Role: a.Role, CreatedBy: a.By, CreatedOn: a.Node}
	if _, err := c.Create(ctx, a.By, id, body); err != nil {
		clear(secret)
		return nil, err
	}
	return &Issued{Token: Token{URL: u, CA: Pin(a.CADER), ID: id, Secret: secret}, ExpiresAt: exp}, nil
}

// cleanNote checks an admin's note: one line of at most 200 characters.
func cleanNote(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > 200 {
		return "", errors.New("the note is longer than 200 characters")
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", errors.New("the note must be one line of text")
	}
	return s, nil
}

// checkNodeURL checks the address a new server will be reached at.
func checkNodeURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the new server's address must be like https://siem-c.example.com:8443")
	}
	return nil
}

// Revoke deletes the token id, leaving a signed tombstone: it cannot be
// used from then on.
func (t *Tokens) Revoke(ctx context.Context, by, id string) error {
	if err := t.writable(); err != nil {
		return err
	}
	_, c, err := t.parts()
	if err != nil {
		return err
	}
	if !ValidID(id) {
		return ErrTokenUnknown
	}
	if err := c.Refresh(ctx, id); err != nil {
		return err
	}
	_, etag, ok := c.Get(id)
	if !ok {
		return ErrTokenUnknown
	}
	_, err = c.Delete(ctx, by, id, etag)
	if errors.Is(err, store.ErrNotFound) {
		return ErrTokenUnknown
	}
	return err
}

// Consumed is a token a join used. Secret is the token's secret, for
// sealing the answer; Clear it once sealed.
type Consumed struct {
	Body   *JoinTokenBody
	Secret []byte
}

// Clear overwrites the secret.
func (c *Consumed) Clear() { clear(c.Secret) }

// Consume uses the token id for the server used, once: it reads the
// token from OpenSearch now, checks its expiry and that it was not used,
// opens its secret and asks proofCheck whether the joining server's proof
// matches it, then sets uses_left from 1 to 0 by compare-and-set on the
// copy it read, so of two joins with one token exactly one wins. A
// wrong proof leaves the token as it was.
func (t *Tokens) Consume(ctx context.Context, id string, used UsedBy, proofCheck func(secret []byte) bool) (*Consumed, error) {
	if err := t.writable(); err != nil {
		return nil, err
	}
	h, c, err := t.parts()
	if err != nil {
		return nil, err
	}
	if !ValidID(id) {
		return nil, ErrTokenUnknown
	}
	if err := c.Refresh(ctx, id); err != nil {
		return nil, err
	}
	b, etag, ok := c.Get(id)
	if !ok {
		return nil, ErrTokenUnknown
	}
	now := t.now()
	switch {
	case !now.Before(b.ExpiresAt):
		return nil, ErrTokenExpired
	case b.UsesLeft < 1:
		return nil, ErrTokenUsed
	}
	plain, err := opener(h.Keys()).Open(SecretField(id), b.Secret)
	if err != nil {
		return nil, fmt.Errorf("%w: its secret cannot be opened with this server's cluster keys (%v)", ErrTokenUnknown, err)
	}
	secret, err := base64.RawURLEncoding.DecodeString(plain)
	if err != nil || len(secret) != SecretSize {
		return nil, fmt.Errorf("%w: its secret is damaged", ErrTokenUnknown)
	}
	if !proofCheck(secret) {
		clear(secret)
		return nil, ErrProof
	}
	used.At = now
	_, err = c.MutateIf(ctx, systemUser, id, etag, func(v *JoinTokenBody) error {
		switch {
		case v.UsesLeft < 1:
			return ErrTokenUsed
		case !now.Before(v.ExpiresAt):
			return ErrTokenExpired
		}
		v.UsesLeft--
		v.UsedBy = &used
		return nil
	})
	var stale *shared.StaleError
	switch {
	case errors.As(err, &stale):
		err = ErrTokenUsed
	case errors.Is(err, store.ErrNotFound):
		err = ErrTokenUnknown
	}
	if err != nil {
		clear(secret)
		return nil, err
	}
	b.UsesLeft, b.UsedBy, b.Secret = 0, &used, ""
	return &Consumed{Body: b, Secret: secret}, nil
}

// opener opens values sealed with any of the cluster keys this server
// has.
func opener(keys *shared.KeySet) secrets.Opener {
	var out []secrets.Opener
	if keys != nil {
		for _, id := range keys.IDs() {
			if k := keys.Get(id); k != nil {
				out = append(out, k.SecretsKey())
			}
		}
	}
	return secrets.Chain(out...)
}

// TokenInfo is a token as the Servers page lists it, without its secret.
type TokenInfo struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
	Platform  string    `json:"platform,omitempty"`
	Note      string    `json:"note,omitempty"`
	NodeURL   string    `json:"node_url,omitempty"`
	Role      string    `json:"role,omitempty"`
	CreatedBy string    `json:"created_by"`
	CreatedOn string    `json:"created_on"`
	UsedBy    *UsedBy   `json:"used_by,omitempty"`
	// State is open, used or expired.
	State string `json:"state"`
}

// List lists the tokens, newest first, without their secrets.
func (t *Tokens) List() []TokenInfo {
	_, c, err := t.parts()
	if err != nil {
		return nil
	}
	now := t.now()
	var out []TokenInfo
	for _, it := range c.List() {
		b := it.Value
		if b == nil {
			continue
		}
		state := "open"
		switch {
		case b.UsesLeft < 1:
			state = "used"
		case !now.Before(b.ExpiresAt):
			state = "expired"
		}
		out = append(out, TokenInfo{ID: it.Name, ExpiresAt: b.ExpiresAt, Platform: b.Platform, Note: b.Note, NodeURL: b.NodeURL, Role: b.Role,
			CreatedBy: b.CreatedBy, CreatedOn: b.CreatedOn, UsedBy: b.UsedBy, State: state})
	}
	// Newest first (the one that expires last), the ids breaking ties.
	slices.SortFunc(out, func(a, b TokenInfo) int {
		return cmp.Or(b.ExpiresAt.Compare(a.ExpiresAt), strings.Compare(a.ID, b.ID))
	})
	return out
}

// Expire deletes the tokens that expired before now, used or not,
// leaving signed tombstones the collection's housekeeping removes
// later. The server that runs the background jobs calls it with its
// housekeeping. It returns how many it deleted.
func (t *Tokens) Expire(ctx context.Context, now time.Time) (int, error) {
	if err := t.writable(); err != nil {
		return 0, nil
	}
	_, c, err := t.parts()
	if err != nil {
		return 0, nil
	}
	n := 0
	var errs []error
	for _, it := range c.List() {
		if it.Value == nil || now.Before(it.Value.ExpiresAt) {
			continue
		}
		if _, err := c.Delete(ctx, systemUser, it.Name, it.ETag); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, fmt.Errorf("%s: %w", it.Name, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}
