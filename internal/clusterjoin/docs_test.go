// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterjoin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const prefix = "signalith"

// env is one fake OpenSearch with the cluster key, and a hub per server.
type env struct {
	t    *testing.T
	fake *ostest.Server
	cl   *store.Client
	key  *shared.ClusterKey
	now  atomic.Pointer[time.Time]
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	if err := shared.EnsureConfig(context.Background(), cl, prefix); err != nil {
		t.Fatal(err)
	}
	key, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, fake: fake, cl: cl, key: key}
	start := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	e.now.Store(&start)
	return e
}

func (e *env) clock() time.Time { return *e.now.Load() }

func (e *env) advance(d time.Duration) {
	n := e.clock().Add(d)
	e.now.Store(&n)
}

// server returns a token holder tracked on a new hub of server name,
// with key (the cluster's when nil).
func (e *env) server(name string, key *shared.ClusterKey) *Tokens {
	e.t.Helper()
	if key == nil {
		key = e.key
	}
	h := shared.NewHub(shared.Options{NodeName: name})
	h.SetKeys(shared.NewKeySet(key))
	h.Use(e.cl, prefix)
	tk := New(func() error { return nil })
	tk.Now = e.clock
	tk.Track(h)
	if err := h.Cycle(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return tk
}

var caDER = []byte("the CA certificate")

func (e *env) issue(tk *Tokens, change func(*IssueArgs)) *Issued {
	e.t.Helper()
	a := IssueArgs{By: "sam", Node: "siem-a", URL: "https://siem-a:8443", CADER: caDER, Platform: "linux", Note: "rack 4"}
	if change != nil {
		change(&a)
	}
	is, err := tk.Issue(context.Background(), a)
	if err != nil {
		e.t.Fatal(err)
	}
	return is
}

// proofFor returns the proof check a joining server with node key pub
// passes for token tok.
func proofFor(tok Token, pub []byte) func([]byte) bool {
	nonce, _ := NewNonce()
	p := Proof(tok.Secret, tok.ID, nonce, pub)
	return func(secret []byte) bool { return CheckProof(secret, tok.ID, nonce, pub, p) }
}

var pub = make([]byte, NodePubSize)

func TestIssueAndConsume(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	is := e.issue(a, nil)
	tok := is.Token
	if err := tok.Check(); err != nil || tok.URL != "https://siem-a:8443" || !tok.MatchesPin(caDER) {
		t.Fatalf("token %v: %v", tok, err)
	}
	if !is.ExpiresAt.Equal(e.clock().Add(DefaultTTL)) {
		t.Errorf("expires %v", is.ExpiresAt)
	}
	// The secret is stored sealed only.
	raw, _ := json.Marshal(e.fake.Source(shared.ConfigIndex(prefix), Kind+":"+tok.ID))
	for _, s := range []string{base64.RawURLEncoding.EncodeToString(tok.Secret), base64.StdEncoding.EncodeToString(tok.Secret), tok.String()} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("the stored token shows its secret: %s", raw)
		}
	}
	list := a.List()
	if len(list) != 1 || list[0].ID != tok.ID || list[0].State != "open" || list[0].Note != "rack 4" || list[0].CreatedBy != "sam" {
		t.Fatalf("list = %+v", list)
	}
	js, _ := json.Marshal(list)
	if strings.Contains(string(js), "secret") || strings.Contains(string(js), base64.RawURLEncoding.EncodeToString(tok.Secret)) {
		t.Errorf("the list shows the secret: %s", js)
	}

	// Another member answers the join.
	b := e.server("siem-b", nil)
	// A wrong proof leaves the token usable.
	wrong := tok
	wrong.Secret, _ = NewSecret()
	if _, err := b.Consume(ctx, tok.ID, UsedBy{NodeID: "n_c", Name: "siem-c"}, proofFor(wrong, pub)); !errors.Is(err, ErrProof) {
		t.Fatalf("wrong proof: %v", err)
	}
	got, err := b.Consume(ctx, tok.ID, UsedBy{NodeID: "n_c", Name: "siem-c"}, proofFor(tok, pub))
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Secret) != string(tok.Secret) || got.Body.UsedBy == nil || got.Body.UsedBy.Name != "siem-c" || got.Body.Secret != "" {
		t.Errorf("consumed %+v", got.Body)
	}
	got.Clear()
	// Used once only.
	if _, err := b.Consume(ctx, tok.ID, UsedBy{NodeID: "n_d", Name: "siem-d"}, proofFor(tok, pub)); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("second use: %v", err)
	}
	if err := a.Refresh(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if l := a.List(); l[0].State != "used" || l[0].UsedBy == nil || l[0].UsedBy.NodeID != "n_c" {
		t.Errorf("after use: %+v", l)
	}
	if _, err := b.Consume(ctx, "jt_aaaaaaaaaaaaaaaaaaaa", UsedBy{}, proofFor(tok, pub)); !errors.Is(err, ErrTokenUnknown) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := b.Consume(ctx, "../x", UsedBy{}, proofFor(tok, pub)); !errors.Is(err, ErrTokenUnknown) {
		t.Errorf("bad id: %v", err)
	}
}

// Refresh reads one token now, for tests.
func (t *Tokens) Refresh(ctx context.Context, id string) error {
	_, c, err := t.parts()
	if err != nil {
		return err
	}
	return c.Refresh(ctx, id)
}

func TestConsumeRaceOneWins(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	for range 5 {
		tok := e.issue(a, nil).Token
		servers := []*Tokens{e.server("siem-b", nil), e.server("siem-c", nil), e.server("siem-d", nil)}
		var wins, used atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i, s := range servers {
			wg.Go(func() {
				<-start
				_, err := s.Consume(ctx, tok.ID, UsedBy{NodeID: "n_" + string(rune('x'+i)), Name: "siem-x"}, proofFor(tok, pub))
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, ErrTokenUsed):
					used.Add(1)
				default:
					t.Errorf("consume: %v", err)
				}
			})
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || used.Load() != int32(len(servers)-1) {
			t.Fatalf("wins %d, used %d", wins.Load(), used.Load())
		}
	}
}

func TestTokenExpiresAndIsRevoked(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	short := e.issue(a, func(x *IssueArgs) { x.TTL = 2 * time.Minute })
	long := e.issue(a, func(x *IssueArgs) { x.TTL = 3 * time.Hour })
	revoked := e.issue(a, nil)
	if err := a.Revoke(ctx, "sam", revoked.Token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, revoked.Token.ID, UsedBy{}, proofFor(revoked.Token, pub)); !errors.Is(err, ErrTokenUnknown) {
		t.Errorf("revoked: %v", err)
	}
	if err := a.Revoke(ctx, "sam", revoked.Token.ID); !errors.Is(err, ErrTokenUnknown) {
		t.Errorf("revoked twice: %v", err)
	}
	e.advance(2 * time.Minute)
	if _, err := a.Consume(ctx, short.Token.ID, UsedBy{}, proofFor(short.Token, pub)); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired: %v", err)
	}
	if l := a.List(); len(l) != 2 || l[0].ID != long.Token.ID || l[1].State != "expired" {
		t.Errorf("list = %+v", l)
	}
	n, err := a.Expire(ctx, e.clock())
	if err != nil || n != 1 {
		t.Fatalf("expired %d, %v", n, err)
	}
	if l := a.List(); len(l) != 1 || l[0].ID != long.Token.ID {
		t.Errorf("after expiry: %+v", l)
	}
	if _, err := a.Consume(ctx, long.Token.ID, UsedBy{NodeID: "n_c", Name: "siem-c"}, proofFor(long.Token, pub)); err != nil {
		t.Errorf("a token within its lifetime: %v", err)
	}
}

func TestIssueRefuses(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	ctx := context.Background()
	good := IssueArgs{By: "sam", URL: "https://siem-a:8443", CADER: caDER}
	for name, change := range map[string]func(*IssueArgs){
		"too long":        func(x *IssueArgs) { x.TTL = 25 * time.Hour },
		"too short":       func(x *IssueArgs) { x.TTL = time.Second },
		"platform":        func(x *IssueArgs) { x.Platform = "solaris" },
		"http address":    func(x *IssueArgs) { x.URL = "http://siem-a:8080" },
		"no CA":           func(x *IssueArgs) { x.CADER = nil },
		"long note":       func(x *IssueArgs) { x.Note = strings.Repeat("x", 201) },
		"two-line note":   func(x *IssueArgs) { x.Note = "a\nb" },
		"node url":        func(x *IssueArgs) { x.NodeURL = "siem-c:8443" },
		"node url w/user": func(x *IssueArgs) { x.NodeURL = "https://u:p@siem-c:8443" },
		"role":            func(x *IssueArgs) { x.Role = "sensor" },
	} {
		x := good
		change(&x)
		if _, err := a.Issue(ctx, x); err == nil {
			t.Errorf("%s: issued", name)
		}
	}
	x := good
	x.TTL = MaxTTL
	if _, err := a.Issue(ctx, x); err != nil {
		t.Errorf("24 hours: %v", err)
	}
	// Outside member mode nothing is made or used.
	paused := &shared.PausedError{Why: "legacy"}
	a.Writable = func() error { return paused }
	if _, err := a.Issue(ctx, good); !errors.Is(err, paused) {
		t.Errorf("not writable: %v", err)
	}
	if _, err := a.Consume(ctx, "jt_aaaaaaaaaaaaaaaaaaaa", UsedBy{}, nil); !errors.Is(err, paused) {
		t.Errorf("consume not writable: %v", err)
	}
	if err := a.Revoke(ctx, "sam", "jt_aaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, paused) {
		t.Errorf("revoke not writable: %v", err)
	}
}

// A server of another cluster (another key) cannot use the tokens.
func TestConsumeNeedsTheClusterKey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	tok := e.issue(a, nil).Token
	other, _ := shared.NewClusterKey()
	x := e.server("siem-x", other)
	if _, err := x.Consume(ctx, tok.ID, UsedBy{}, proofFor(tok, pub)); !errors.Is(err, ErrTokenUnknown) {
		t.Errorf("consume with another key: %v", err)
	}
	if _, err := a.Consume(ctx, tok.ID, UsedBy{NodeID: "n_c", Name: "siem-c"}, proofFor(tok, pub)); err != nil {
		t.Errorf("the token was spent by the other key: %v", err)
	}
}

func TestRequireSecured(t *testing.T) {
	good := config.OpenSearch{URL: "https://os:9200", Username: "signalith", Password: "pw", CAFile: "/ca.pem"}
	if err := RequireSecured(good); err != nil {
		t.Fatal(err)
	}
	cert := config.OpenSearch{URL: "https://os:9200", CertFile: "c.pem", KeyFile: "k.pem"}
	if err := RequireSecured(cert); err != nil {
		t.Errorf("client certificate: %v", err)
	}
	if err := RequireSecured(good, "https://os2:9200"); err != nil {
		t.Errorf("two addresses: %v", err)
	}
	for name, o := range map[string]config.OpenSearch{
		"http":          {URL: "http://os:9200", Username: "u", Password: "p"},
		"no credential": {URL: "https://os:9200"},
		"user only":     {URL: "https://os:9200", Username: "u"},
		"cert only":     {URL: "https://os:9200", CertFile: "c.pem"},
		"skip verify":   {URL: "https://os:9200", Username: "u", Password: "p", TLSSkipVerify: true},
		"no url":        {Username: "u", Password: "p"},
	} {
		if err := RequireSecured(o); !errors.Is(err, ErrNotSecured) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := RequireSecured(good, "http://os2:9200"); !errors.Is(err, ErrNotSecured) {
		t.Errorf("an http second address: %v", err)
	}
}
