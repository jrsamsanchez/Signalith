package agenttokens

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func newReg(t *testing.T, url, node string, legacy ...Legacy) *Registry {
	t.Helper()
	r := &Registry{Client: store.New(store.Config{URL: url}), Prefix: "tt", Node: func() string { return node },
		Legacy: func() []Legacy { return legacy }, Poll: 20 * time.Millisecond}
	return r
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("err = %v, want code %s", err, code)
	}
}

func TestTokenFormat(t *testing.T) {
	re := regexp.MustCompile(`^` + strings.TrimSuffix(strings.TrimPrefix(ScannerPattern, `\b`), `\b`) + `$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != 56 || !strings.HasPrefix(s, "sgl_") || !re.MatchString(s) || !IsToken(s) {
			t.Fatalf("bad token %q", s)
		}
		if seen[s] {
			t.Fatal("repeated token")
		}
		seen[s] = true
		if IDOf(s) != Fingerprint(s)[:12] {
			t.Fatal("id")
		}
	}
	for _, bad := range []string{"", "sgl_", "sgl_" + strings.Repeat("A", 52), "sgl_" + strings.Repeat("a", 51), "xgl_" + strings.Repeat("a", 52), "sgl_" + strings.Repeat("1", 52)} {
		if IsToken(bad) {
			t.Errorf("%q is a token", bad)
		}
	}
}

func TestCleanName(t *testing.T) {
	for in, want := range map[string]string{"  Linux   web servers ": "Linux web servers", "a.b_c-(d)/e:f#g@h": "a.b_c-(d)/e:f#g@h", "Serveurs Montréal": "Serveurs Montréal"} {
		if got, ok := CleanName(in); !ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "   ", "a\tb", "a\nb", "<script>", "x;y", strings.Repeat("a", 65), "a\x00"} {
		if _, ok := CleanName(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCreateCheckRevoke(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	r := newReg(t, fake.URL, "n1")
	if _, res := r.Check("sgl_" + strings.Repeat("a", 52)); res != NotLoaded {
		t.Fatalf("before load: %v", res)
	}
	tok, secret, err := r.Create(ctx, " Linux  servers ", PurposeLinux, "sam")
	if err != nil {
		t.Fatal(err)
	}
	if tok.Name != "Linux servers" || tok.Status != StateActive || tok.Hint != secret[52:] || tok.ID != IDOf(secret) || tok.CreatedBy != "sam" {
		t.Fatalf("token = %+v", tok)
	}
	// Only the fingerprint is stored.
	src := fake.Source("tt_runtime", "agenttoken:"+tok.ID)
	raw, _ := json.Marshal(src)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), secret[4:]) || src["hash"] != Fingerprint(secret) {
		t.Fatalf("stored: %s", raw)
	}
	id, res := r.Check(secret)
	if res != Valid || id.Name != "Linux servers" || id.ID != tok.ID || id.Legacy {
		t.Fatalf("check: %+v %v", id, res)
	}
	// A forged token with the same ID's fingerprint prefix can't exist,
	// but one whose first characters match differs in its hash.
	forged := secret[:len(secret)-1] + map[bool]string{true: "b", false: "a"}[secret[len(secret)-1] == 'a']
	if _, res := r.Check(forged); res != Unknown {
		t.Errorf("forged: %v", res)
	}
	if _, _, err := r.Create(ctx, "LINUX SERVERS", "", "sam"); err == nil {
		t.Fatal("same name accepted")
	} else {
		wantCode(t, err, CodeNameTaken)
	}
	_, _, err = r.Create(ctx, "x", "mac", "sam")
	wantCode(t, err, CodePurposeInvalid)
	_, _, err = r.Create(ctx, "<b>", "", "sam")
	wantCode(t, err, CodeNameInvalid)

	calls := 0
	r.OnRevoke(func(_ context.Context, id string) (int, error) {
		calls++
		if id != tok.ID {
			t.Errorf("hook id %s", id)
		}
		return 3, nil
	})
	rt, hosts, err := r.Revoke(ctx, tok.ID, "sam")
	if err != nil || rt.Status != StateRevoked || hosts != 3 || calls != 1 || rt.RevokedBy != "sam" {
		t.Fatalf("revoke: %+v %d %v %d", rt, hosts, err, calls)
	}
	if id, res := r.Check(secret); res != Revoked || id.Name != "Linux servers" {
		t.Fatalf("after revoke: %v", res)
	}
	if r.Active(tok.ID) {
		t.Error("active after revoke")
	}
	// Idempotent.
	if _, _, err := r.Revoke(ctx, tok.ID, "sam"); err != nil {
		t.Fatal(err)
	}
	_, _, err = r.Rename(ctx, tok.ID, "new", "sam")
	wantCode(t, err, CodeRevoked)
	_, _, err = r.Revoke(ctx, "000000000000", "sam")
	wantCode(t, err, CodeNotFound)
	_, _, err = r.Revoke(ctx, "../../x", "sam")
	wantCode(t, err, CodeNotFound)
	// The name is free again once revoked.
	if _, _, err := r.Create(ctx, "Linux servers", "", "sam"); err != nil {
		t.Fatal(err)
	}
	l := r.List(ctx)
	if !l.Loaded || len(l.Tokens) != 2 || l.Tokens[0].Status != StateActive || l.Tokens[1].Status != StateRevoked {
		t.Fatalf("list: %+v", l)
	}
	raw, _ = json.Marshal(l)
	if strings.Contains(string(raw), secret) {
		t.Fatal("list holds the secret")
	}
}

func TestRename(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	r := newReg(t, fake.URL, "n1")
	a, _, _ := r.Create(ctx, "A", "", "sam")
	if _, _, err := r.Create(ctx, "B", "", "sam"); err != nil {
		t.Fatal(err)
	}
	_, _, err := r.Rename(ctx, a.ID, "b", "sam")
	wantCode(t, err, CodeNameTaken)
	got, old, err := r.Rename(ctx, a.ID, "Web servers", "kim")
	if err != nil || got.Name != "Web servers" || old != "A" {
		t.Fatalf("%+v %s %v", got, old, err)
	}
	if r.Name(a.ID) != "Web servers" {
		t.Error("name not applied")
	}
	// Renaming to its own name in another case is allowed.
	if _, _, err := r.Rename(ctx, a.ID, "web servers", "kim"); err != nil {
		t.Fatal(err)
	}
}

func TestLegacy(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	shared := "a-long-shared-ingest-token-0123456789"
	r := newReg(t, fake.URL, "n1", Legacy{Secret: shared, Source: "SIGNALITH_INGEST_TOKEN_FILE"}, Legacy{Secret: "change-this-ingest-token", Source: "signalith.yaml", Public: true})
	// Shared tokens wait for the tokens to be read: one may be refused.
	if id, res := r.Check(shared); res != NotLoaded || id.ID != "" {
		t.Fatalf("before load: %+v %v", id, res)
	}
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	// The ID is keyed: not one anyone could make from a guess.
	id, res := r.Check(shared)
	if res != Valid || !id.Legacy || !validID(id.ID) || id.ID == IDOf(shared) || id.ID != r.LegacyID(shared) || id.Name != "Shared token "+id.ID[:6] {
		t.Fatalf("%+v %v", id, res)
	}
	// An osquery host enrolled with it before has its old ID: still
	// matched, and recorded under the new one.
	if got, ok := r.Lookup(IDOf(shared)); !ok || got.ID != id.ID || !r.Active(IDOf(shared)) {
		t.Fatalf("old ID: %+v %v", got, ok)
	}
	if _, _, err := r.Refuse(ctx, IDOf(shared), "sam"); err == nil {
		t.Fatal("refused by its old ID")
	}
	if id, _ := r.Check("change-this-ingest-token"); !id.Public {
		t.Error("public not flagged")
	}
	if _, res := r.Check("wrong"); res != Unknown {
		t.Error("wrong token")
	}
	var removed []string
	r.OnRevoke(func(_ context.Context, id string) (int, error) { removed = append(removed, id); return 1, nil })
	lt, hosts, err := r.Refuse(ctx, id.ID, "sam")
	if err != nil || lt.Status != "refused" || hosts != 2 || lt.Source != "SIGNALITH_INGEST_TOKEN_FILE" || lt.ID != id.ID ||
		strings.Join(removed, ",") != id.ID+","+IDOf(shared) {
		t.Fatalf("%+v %d %v %v", lt, hosts, err, removed)
	}
	if r.Active(IDOf(shared)) {
		t.Error("old ID of a refused token is active")
	}
	if _, res := r.Check(shared); res != Refused {
		t.Fatalf("after refuse: %v", res)
	}
	if r.Active(id.ID) {
		t.Error("refused is active")
	}
	// A second server sees the refusal, with the same ID; before it read
	// the tokens (a restart with OpenSearch slow) the refused token is not
	// let back in.
	r2 := newReg(t, fake.URL, "n2", Legacy{Secret: shared, Source: "signalith.yaml"})
	if _, res := r2.Check(shared); res != NotLoaded {
		t.Fatalf("other server before load: %v", res)
	}
	if err := r2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if got, res := r2.Check(shared); res != Refused || got.ID != id.ID {
		t.Fatalf("other server: %+v %v", got, res)
	}
	if _, err := r.Accept(ctx, id.ID, "sam"); err != nil {
		t.Fatal(err)
	}
	if _, res := r.Check(shared); res != Valid {
		t.Fatalf("after accept: %v", res)
	}
	_, _, err = r.Refuse(ctx, "000000000000", "sam")
	wantCode(t, err, CodeNotFound)
	if a, l := r.Counts(); a != 0 || l != 2 {
		t.Errorf("counts %d %d", a, l)
	}
}

// TestRevocationReachesOtherServers: a revocation on one server is
// refused on another within two polls, with no restart.
func TestRevocationReachesOtherServers(t *testing.T) {
	fake := ostest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newReg(t, fake.URL, "a")
	b := newReg(t, fake.URL, "b")
	go b.Run(ctx)
	tok, secret, err := a.Create(ctx, "Linux", "", "sam")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, res := b.Check(secret); return res == Valid })
	calls := 0
	b.OnRevoke(func(context.Context, string) (int, error) { calls++; return 0, nil })
	if _, _, err := a.Revoke(ctx, tok.ID, "sam"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	waitFor(t, func() bool { _, res := b.Check(secret); return res == Revoked })
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %s", d)
	}
	if calls != 0 {
		t.Error("OnRevoke ran on the other server")
	}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestKeepsTokensWhenOpenSearchIsDown: once read, tokens keep working
// while OpenSearch can't be reached; changes fail.
func TestKeepsTokensWhenOpenSearchIsDown(t *testing.T) {
	fake := ostest.New(t)
	plug := fake.Plug(t)
	ctx := context.Background()
	r := newReg(t, plug.URL, "n1")
	_, secret, err := r.Create(ctx, "Linux", "", "sam")
	if err != nil {
		t.Fatal(err)
	}
	plug.Pull()
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { r.Run(rctx); close(done) }()
	time.Sleep(60 * time.Millisecond)
	if _, res := r.Check(secret); res != Valid {
		t.Fatalf("while down: %v", res)
	}
	_, _, err = r.Create(ctx, "Other", "", "sam")
	wantCode(t, err, CodeStoreUnavailable)
	cancel()
	<-done
}

func TestWriteBeforeLoadWhenDown(t *testing.T) {
	fake := ostest.New(t)
	plug := fake.Plug(t)
	plug.Pull()
	r := newReg(t, plug.URL, "n1")
	_, _, err := r.Create(context.Background(), "x", "", "sam")
	var e *Error
	if !errors.As(err, &e) || e.Status != 503 {
		t.Fatalf("err = %v", err)
	}
}

func TestUsageFlushAndMerge(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	var clock atomic.Int64
	clock.Store(time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC).Unix())
	now := func() time.Time { return time.Unix(clock.Load(), 0) }
	a := newReg(t, fake.URL, "a")
	a.Now = now
	b := newReg(t, fake.URL, "b")
	b.Now = now
	tok, _, err := a.Create(ctx, "Linux", "", "sam")
	if err != nil {
		t.Fatal(err)
	}
	a.Note(tok.ID, "203.0.113.7", 10)
	clock.Add(30)
	b.Note(tok.ID, "198.51.100.2", 5)
	a.flushUse(ctx)
	b.flushUse(ctx)
	if fake.Source("tt_runtime", "agenttokenuse:"+tok.ID+":a") == nil || fake.Source("tt_runtime", "agenttokenuse:"+tok.ID+":b") == nil {
		t.Fatal("usage documents missing")
	}
	if err := b.Load(ctx); err != nil {
		t.Fatal(err)
	}
	// A third view, from neither server.
	c := newReg(t, fake.URL, "c")
	c.Now = now
	if err := c.Load(ctx); err != nil {
		t.Fatal(err)
	}
	l := c.List(ctx)
	if len(l.Tokens) != 1 || l.Tokens[0].Events1h != 15 || l.Tokens[0].LastUsedFrom != "198.51.100.2" {
		t.Fatalf("merged: %+v", l.Tokens)
	}
	// Server a after a restart: nothing in memory, but what it wrote
	// before still counts.
	a2 := newReg(t, fake.URL, "a")
	a2.Now = now
	if err := a2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if l := a2.List(ctx); l.Tokens[0].Events1h != 15 || l.Tokens[0].LastUsedAt == nil {
		t.Fatalf("after a restart: %+v", l.Tokens[0])
	}
	clock.Add(10)
	a2.Note(tok.ID, "203.0.113.7", 1)
	if l := a2.List(ctx); l.Tokens[0].Events1h != 6 || l.Tokens[0].LastUsedFrom != "203.0.113.7" {
		t.Fatalf("used again after a restart: %+v", l.Tokens[0])
	}
	// An hour later the counts are gone, the last use stays.
	clock.Add(3700)
	l = c.List(ctx)
	if l.Tokens[0].Events1h != 0 || l.Tokens[0].LastUsedAt == nil {
		t.Fatalf("later: %+v", l.Tokens[0])
	}
}

func TestLimits(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	r := newReg(t, fake.URL, "n1")
	if err := r.fresh(ctx); err != nil {
		t.Fatal(err)
	}
	r.apply(func(s *snapshot) {
		for i := 0; i < MaxActive; i++ {
			id := strings.Repeat("0", 6) + hex6(i)
			s.tokens[id] = &tokenDoc{ID: id, State: StateActive, Name: "t" + id}
		}
	})
	// fresh reads them again, so put them in the fake too.
	for id, d := range r.current().tokens {
		d.Kind, d.Hash = kindToken, id+strings.Repeat("0", 52)
		raw, _ := json.Marshal(d)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		fake.Put("tt_runtime", "agenttoken:"+id, m)
	}
	_, _, err := r.Create(ctx, "one more", "", "sam")
	wantCode(t, err, CodeTooMany)
}

func hex6(i int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 6)
	for j := 5; j >= 0; j-- {
		b[j] = digits[i%16]
		i /= 16
	}
	return string(b)
}

// TestNoSharedTokens: with no shared token configured, no key is made.
func TestNoSharedTokens(t *testing.T) {
	fake := ostest.New(t)
	r := newReg(t, fake.URL, "n1")
	if err := r.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := r.Client.Get(context.Background(), r.index(), legacyDocID); found {
		t.Error("key made with no shared token")
	}
}

// TestLoadRacingRevoke: a Load that read the tokens before a revoke on
// the same server must not put the token back.
func TestLoadRacingRevoke(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	gate := make(chan struct{})
	searching := make(chan struct{}, 1)
	var hold atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u, _ := url.Parse(fake.URL)
		rp := httputil.NewSingleHostReverseProxy(u)
		if hold.Load() && strings.Contains(req.URL.Path, "_search") {
			// Let the search read the tokens, then hold its answer.
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)
			searching <- struct{}{}
			<-gate
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			w.Write(rec.Body.Bytes())
			return
		}
		rp.ServeHTTP(w, req)
	}))
	defer proxy.Close()
	r := newReg(t, proxy.URL, "n1")
	tok, secret, err := r.Create(ctx, "Linux", "", "sam")
	if err != nil {
		t.Fatal(err)
	}
	hold.Store(true)
	done := make(chan error, 1)
	go func() { done <- r.load(ctx) }()
	<-searching
	hold.Store(false)
	if _, _, err := r.Revoke(ctx, tok.ID, "sam"); err != nil {
		t.Fatal(err)
	}
	close(gate)
	if err := <-done; !errors.Is(err, errRaced) {
		t.Fatalf("stale load: %v", err)
	}
	if _, res := r.Check(secret); res != Revoked {
		t.Fatalf("after a stale load: %v", res)
	}
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, res := r.Check(secret); res != Revoked {
		t.Fatalf("after load: %v", res)
	}
}
