package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// newTokenServer is a server whose agent tokens are in a fake OpenSearch,
// with a viewer (vera) and an analyst (andy).
func newTokenServer(t *testing.T) (*httptest.Server, *Server, *fakeOS, *logBuf, *ostest.Server) {
	t.Helper()
	fake := ostest.New(t)
	logs := &logBuf{}
	var srv *Server
	ts, fos := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Log = slog.New(slog.NewTextHandler(logs, nil))
		s.Tokens = &agenttokens.Registry{Client: store.New(store.Config{URL: fake.URL}), Prefix: "tt", Log: s.Log}
		s.Users = users.NewMemory()
		for name, role := range map[string]users.Role{"vera": users.Viewer, "andy": users.Analyst} {
			if _, err := s.Users.Create(users.NewUser{Username: name, Role: role, Password: "role-password"}); err != nil {
				t.Fatal(err)
			}
		}
	})
	return ts, srv, fos, logs, fake
}

func agentSend(t *testing.T, url, path, token, body string, header map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func createToken(t *testing.T, ts *httptest.Server, name string) (string, string) {
	t.Helper()
	code, out, raw := call(t, ts, "POST", "/api/agent-tokens", `{"name":"`+name+`","purpose":"linux"}`, "admin", adminPass, nil)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	tok := out["token"].(map[string]any)
	return tok["id"].(string), out["secret"].(string)
}

func TestAgentTokensEndToEnd(t *testing.T) {
	ts, s, fos, logs, _ := newTokenServer(t)

	// Before the tokens are read, an agent token and a shared one are
	// answered 503 (Fluent Bit keeps the batch): either may have been
	// revoked or refused.
	notYet := "sgl_" + strings.Repeat("a", 52)
	code, body := agentSend(t, ts.URL, "/api/ingest", notYet, `[{"msg":"x"}]`, nil)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, `"code":"tokens_loading"`) {
		t.Fatalf("not loaded: %d %s", code, body)
	}
	if code, body := agentSend(t, ts.URL, "/api/ingest", "tok-0123456789abcdef", `[{"msg":"x"}]`, nil); code != http.StatusServiceUnavailable || !strings.Contains(body, `"code":"tokens_loading"`) {
		t.Fatalf("shared token before loading: %d %s", code, body)
	}
	if err := s.Tokens.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	fos.bulk = nil
	if code, body := agentSend(t, ts.URL, "/api/ingest", "tok-0123456789abcdef", `[{"msg":"x"}]`, nil); code != http.StatusOK {
		t.Fatalf("shared token: %d %s", code, body)
	}
	// Events record the shared token's keyed ID, never one made from the
	// token alone, which could be used to test guesses.
	sharedID := s.Tokens.LegacyID("tok-0123456789abcdef")
	if doc := fos.bulk[len(fos.bulk)-1].Doc; sharedID == "" || sharedID == agenttokens.IDOf("tok-0123456789abcdef") ||
		doc[ingest.TokenIDField] != sharedID || doc[ingest.TokenField] != "Shared token "+sharedID[:6] {
		t.Fatalf("shared token event: %v (id %s)", doc, sharedID)
	}

	// Create returns the token once, with no-store.
	req, _ := http.NewRequest("POST", ts.URL+"/api/agent-tokens", strings.NewReader(`{"name":"Linux servers","purpose":"linux"}`))
	req.SetBasicAuth("admin", adminPass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var created struct {
		Token  agenttokens.Token `json:"token"`
		Secret string            `json:"secret"`
	}
	_ = json.Unmarshal(raw, &created)
	if resp.StatusCode != 201 || resp.Header.Get("Cache-Control") != "no-store" || !agenttokens.IsToken(created.Secret) || created.Token.Name != "Linux servers" {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	secret, id := created.Secret, created.Token.ID

	// Events carry the token's name and ID and the sender, never the
	// token; what the sender claims is dropped.
	fos.bulk = nil
	code, body = agentSend(t, ts.URL, "/api/ingest", secret, `[{"msg":"hello","signalith_sample":"x","signalith_token":"Admins","Signalith_Sender":"1.1.1.1"}]`, nil)
	if code != http.StatusOK {
		t.Fatalf("ingest: %d %s", code, body)
	}
	doc := fos.bulk[len(fos.bulk)-1].Doc
	if doc[ingest.TokenField] != "Linux servers" || doc[ingest.TokenIDField] != id || doc[ingest.SenderField] != "127.0.0.1" ||
		doc[ingest.IntakeField] != "agent" || doc["signalith_sample"] != nil || doc["Signalith_Sender"] != nil || doc["dropped_fields"] != int64(3) {
		t.Errorf("doc = %v", doc)
	}
	rawDoc, _ := json.Marshal(doc)
	if strings.Contains(string(rawDoc), secret) {
		t.Error("the token was stored")
	}

	// OTLP too.
	fos.bulk = nil
	if code, body := agentSend(t, ts.URL, "/api/otlp/v1/logs", secret, `{"resourceLogs":[{"resource":{"attributes":[{"key":"signalith.token","value":{"stringValue":"forged"}}]},"scopeLogs":[{"logRecords":[{"body":{"stringValue":"hi"}}]}]}]}`,
		map[string]string{"Content-Type": "application/json"}); code != 200 {
		t.Fatalf("otlp: %d %s", code, body)
	}
	doc = fos.bulk[len(fos.bulk)-1].Doc
	if doc[ingest.TokenField] != "Linux servers" || doc[ingest.IntakeField] != "otlp" || doc[ingest.SenderField] != "127.0.0.1" {
		t.Errorf("otlp doc = %v", doc)
	}

	// The list, for an analyst too, never holds the token.
	for _, who := range [][2]string{{"admin", adminPass}, {"andy", "role-password"}} {
		code, out, raw := call(t, ts, "GET", "/api/agent-tokens", "", who[0], who[1], nil)
		if code != 200 || strings.Contains(raw, secret) || out["loaded"] != true || len(out["tokens"].([]any)) != 1 || len(out["legacy"].([]any)) != 1 {
			t.Errorf("%s list: %d %s", who[0], code, raw)
		}
	}
	if code, _ := doAs(t, ts, "vera", "role-password", "GET", "/api/agent-tokens", ""); code != 403 {
		t.Errorf("viewer list: %d", code)
	}
	for _, rt := range [][2]string{{"POST", "/api/agent-tokens"}, {"PATCH", "/api/agent-tokens/" + id}, {"POST", "/api/agent-tokens/" + id + "/revoke"},
		{"POST", "/api/agent-tokens/legacy/x/refuse"}, {"POST", "/api/agent-tokens/legacy/x/accept"}} {
		if code, _ := doAs(t, ts, "andy", "role-password", rt[0], rt[1], `{"name":"x"}`); code != 403 {
			t.Errorf("analyst %s %s: %d", rt[0], rt[1], code)
		}
	}

	// Errors carry a code and the field.
	code, out, _ := call(t, ts, "POST", "/api/agent-tokens", `{"name":"linux SERVERS"}`, "admin", adminPass, nil)
	if code != 409 || out["code"] != "name_taken" || out["field"] != "name" {
		t.Errorf("taken: %d %v", code, out)
	}
	code, out, _ = call(t, ts, "POST", "/api/agent-tokens", `{"name":"a\tb"}`, "admin", adminPass, nil)
	if code != 400 || out["code"] != "name_invalid" {
		t.Errorf("invalid: %d %v", code, out)
	}
	code, _, _ = call(t, ts, "POST", "/api/agent-tokens", `{"name":"`+strings.Repeat("a", 5000)+`"}`, "admin", adminPass, nil)
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("large: %d", code)
	}

	// Rename; events record the name at the time.
	code, out, raw2 := call(t, ts, "PATCH", "/api/agent-tokens/"+id, `{"name":"Web servers"}`, "admin", adminPass, nil)
	if code != 200 || strings.Contains(raw2, secret) || out["token"].(map[string]any)["name"] != "Web servers" {
		t.Fatalf("rename: %d %s", code, raw2)
	}

	// Revoke: refused at once with token_revoked on every intake.
	code, out, raw2 = call(t, ts, "POST", "/api/agent-tokens/"+id+"/revoke", `{}`, "admin", adminPass, nil)
	if code != 200 || out["hosts_removed"] != float64(0) || strings.Contains(raw2, secret) {
		t.Fatalf("revoke: %d %s", code, raw2)
	}
	if code, body := agentSend(t, ts.URL, "/api/ingest", secret, `[{"msg":"x"}]`, nil); code != 401 || !strings.Contains(body, `"code":"token_revoked"`) {
		t.Errorf("revoked ingest: %d %s", code, body)
	}
	if code, body := agentSend(t, ts.URL, "/api/otlp/v1/logs", secret, `{}`, map[string]string{"Content-Type": "application/json"}); code != 401 || !strings.Contains(body, "revoked") {
		t.Errorf("revoked otlp: %d %s", code, body)
	}
	if id2, ok := s.EnrollToken(secret); ok || id2 != "" || s.TokenActive(id) {
		t.Error("revoked token enrolls")
	}

	// Shared token: stop accepting, then accept again.
	shared := sharedID
	code, out, _ = call(t, ts, "POST", "/api/agent-tokens/legacy/"+shared+"/refuse", `{}`, "admin", adminPass, nil)
	if code != 200 || out["legacy"].(map[string]any)["status"] != "refused" {
		t.Fatalf("refuse: %d %v", code, out)
	}
	if code, body := agentSend(t, ts.URL, "/api/ingest", "tok-0123456789abcdef", `[{"msg":"x"}]`, nil); code != 401 || !strings.Contains(body, `"code":"token_refused"`) {
		t.Errorf("refused: %d %s", code, body)
	}
	if code, _, _ := call(t, ts, "POST", "/api/agent-tokens/legacy/"+shared+"/accept", `{}`, "admin", adminPass, nil); code != 200 {
		t.Fatal("accept")
	}
	if code, _ := agentSend(t, ts.URL, "/api/ingest", "tok-0123456789abcdef", `[{"msg":"x"}]`, nil); code != 200 {
		t.Errorf("accepted again: %d", code)
	}
	if code, out, _ := call(t, ts, "POST", "/api/agent-tokens/legacy/000000000000/refuse", `{}`, "admin", adminPass, nil); code != 404 || out["code"] != "not_found" {
		t.Errorf("unknown shared: %d %v", code, out)
	}

	// Audit lines, never the token.
	l := logs.String()
	for _, want := range []string{"agent token created", "agent token renamed", "agent token revoked", "shared agent token refused", "shared agent token accepted again"} {
		if !strings.Contains(l, want) {
			t.Errorf("no %q in the log", want)
		}
	}
	if strings.Contains(l, secret) {
		t.Error("the log holds the token")
	}

	// The Health page names agents refused for a revoked token.
	_, h := do(t, ts, "GET", "/api/health", "", true)
	hw, _ := json.Marshal(h["warnings"])
	if !strings.Contains(string(hw), "revoked or no longer accepted token") {
		t.Errorf("warnings: %s", hw)
	}
}

// TestTokensAreNotSessions: an agent token is not a password or session,
// and a session or password is not an agent token.
func TestTokensAreNotSessions(t *testing.T) {
	ts, _, _, _, _ := newTokenServer(t)
	_, secret := createToken(t, ts, "Linux")
	if code, _, _ := call(t, ts, "POST", "/api/search", `{"query":"*"}`, "admin", secret, nil); code != 401 {
		t.Errorf("token as password: %d", code)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/search", strings.NewReader(`{"query":"*"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("token as bearer on search: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", ts.URL+"/api/search", strings.NewReader(`{"query":"*"}`))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: secret})
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("token as session: %d", resp.StatusCode)
	}
	_, _, c := login(t, ts, "admin", adminPass)
	req, _ = http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(`[{"msg":"x"}]`))
	req.AddCookie(c)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("session on ingest: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(`[{"msg":"x"}]`))
	req.SetBasicAuth("admin", adminPass)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("password on ingest: %d", resp.StatusCode)
	}
}

func TestTokenCreateRateLimit(t *testing.T) {
	ts, _, _, _, _ := newTokenServer(t)
	for i := 0; i < 10; i++ {
		createToken(t, ts, "t"+string(rune('a'+i)))
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/agent-tokens", strings.NewReader(`{"name":"one more"}`))
	req.SetBasicAuth("admin", adminPass)
	resp, _ := http.DefaultClient.Do(req)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" || !strings.Contains(string(raw), "rate_limited") {
		t.Errorf("%d %s", resp.StatusCode, raw)
	}
	var r tokenRate
	now := time.Now()
	for i := 0; i < 200; i++ {
		if r.take(string(rune('a'+i%26))+string(rune('a'+i/26)), now) != 0 {
			t.Fatal("refused early")
		}
	}
	if r.take("someone", now) == 0 {
		t.Error("server-wide limit")
	}
}

// TestRevokedTokenOverPlainHTTP: on the plain-HTTP side, a revoked token
// is 401 like a wrong one.
func TestRevokedTokenOverPlainHTTP(t *testing.T) {
	ts, s, _, _, _ := newTokenServer(t)
	id, secret := createToken(t, ts, "Linux")
	plain := httptest.NewServer(s.PlainHandler(s.Handler()))
	defer plain.Close()
	if code, _ := agentSend(t, plain.URL, "/api/ingest", secret, `[{"msg":"x"}]`, nil); code != 503 && code != 200 {
		t.Errorf("valid over plain: %d", code)
	}
	if code, _, _ := call(t, ts, "POST", "/api/agent-tokens/"+id+"/revoke", `{}`, "admin", adminPass, nil); code != 200 {
		t.Fatal("revoke")
	}
	if code, _ := agentSend(t, plain.URL, "/api/ingest", secret, `[{"msg":"x"}]`, nil); code != 401 {
		t.Errorf("revoked over plain: %d", code)
	}
}
