package m365

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// oddAPI answers the sign-in with token and every API call with api.
func oddAPI(t *testing.T, token func(w http.ResponseWriter), api func(w http.ResponseWriter, r *http.Request)) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			token(w)
			return
		}
		api(w, r)
	}))
	t.Cleanup(srv.Close)
	return &Client{S: Settings{TenantID: "t1", ClientID: "app", ClientSecret: "x", TokenURL: srv.URL + "/token", APIURL: srv.URL},
		HTTP: srv.Client()}, srv
}

func goodToken(w http.ResponseWriter) { w.Write([]byte(`{"access_token":"tok","expires_in":"120"}`)) }

func TestAPIErrorText(t *testing.T) {
	long := &APIError{Status: 500, Message: strings.Repeat("m", 400)}
	if got := long.Error(); !strings.HasPrefix(got, "HTTP 500: mmm") || !strings.HasSuffix(got, "...") || len(got) > 320 {
		t.Errorf("long = %q", got)
	}
	// An answer that is not JSON is kept as text.
	c, _ := oddAPI(t, goodToken, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gateway down", http.StatusBadGateway)
	})
	_, err := c.Subscriptions(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 502 || ae.Message != "gateway down" || ae.Code != "" {
		t.Errorf("plain error = %v", err)
	}
}

func TestSignInProblems(t *testing.T) {
	ctx := context.Background()
	// The token's lifetime as text.
	c, _ := oddAPI(t, goodToken, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) })
	now := time.Now()
	c.now = func() time.Time { return now }
	if _, err := c.Subscriptions(ctx); err != nil {
		t.Fatal(err)
	}
	if !c.expires.Equal(now.Add(120 * time.Second)) {
		t.Errorf("expires = %v", c.expires)
	}

	c, _ = oddAPI(t, func(w http.ResponseWriter) { w.Write([]byte(`{"token_type":"Bearer"}`)) }, nil)
	if _, err := c.Subscriptions(ctx); err == nil || !strings.Contains(err.Error(), "no access token") {
		t.Errorf("no token = %v", err)
	}

	c, srv := oddAPI(t, goodToken, nil)
	srv.Close()
	if _, err := c.Subscriptions(ctx); err == nil || !strings.Contains(err.Error(), "sign in to Microsoft") {
		t.Errorf("unreachable = %v", err)
	}

	c = &Client{S: Settings{TokenURL: "http://bad\x7f/", APIURL: "http://api.example"}, HTTP: http.DefaultClient}
	if _, err := c.Subscriptions(ctx); err == nil {
		t.Error("a bad sign-in address worked")
	}
	c = &Client{S: Settings{APIURL: "://no scheme"}, HTTP: http.DefaultClient}
	if _, err := c.Subscriptions(ctx); err == nil {
		t.Error("a bad API address worked")
	}
	c = &Client{S: Settings{APIURL: "http://api.example"}, HTTP: http.DefaultClient}
	if _, err := c.Read(ctx, Blob{ContentURI: "http://api.example/%zz"}); err == nil {
		t.Error("a bad blob address worked")
	}
}

func TestAPICallProblems(t *testing.T) {
	ctx := context.Background()
	answer := func(status int, body string) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte(body))
		}
	}
	// A token the API refuses is not used again.
	c, _ := oddAPI(t, goodToken, answer(401, `{"error":{"code":"AF10001","message":"expired"}}`))
	if _, err := c.Subscriptions(ctx); err == nil || c.token != "" {
		t.Errorf("401 = %v, token %q", err, c.token)
	}

	c, _ = oddAPI(t, goodToken, answer(200, `{"not":"a list"}`))
	if _, err := c.Subscriptions(ctx); err == nil || !strings.Contains(err.Error(), "list subscriptions") {
		t.Errorf("odd subscriptions = %v", err)
	}
	if _, err := c.List(ctx, "Audit.General", time.Now().Add(-time.Hour), time.Now()); err == nil || !strings.Contains(err.Error(), "list content") {
		t.Errorf("odd listing = %v", err)
	}

	c, _ = oddAPI(t, goodToken, answer(403, `{"error":{"code":"AF20023","message":"The subscription was disabled."}}`))
	if err := c.Start(ctx, "Audit.General"); err == nil || !strings.Contains(err.Error(), "AF20023") {
		t.Errorf("start refused = %v", err)
	}
	if _, err := c.Read(ctx, Blob{ContentURI: c.S.APIURL + "/blob/1"}); err == nil {
		t.Error("read a refused blob")
	}

	// A listing that never ends.
	var srvURL string
	c, srv := oddAPI(t, goodToken, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("NextPageUri", srvURL+"/api/v1.0/t1/activity/feed/subscriptions/content?PublisherIdentifier=t1")
		w.Write([]byte(`[]`))
	})
	srvURL = srv.URL
	if _, err := c.List(ctx, "Audit.General", time.Now().Add(-time.Hour), time.Now()); err == nil || !strings.Contains(err.Error(), "1000 pages") {
		t.Errorf("endless listing = %v", err)
	}
}

type fakeSearcher struct {
	docs []store.Doc
	err  error
}

func (f fakeSearcher) SearchDocs(context.Context, string, map[string]any) ([]store.Doc, error) {
	return f.docs, f.err
}

func TestCursorsAndConfig(t *testing.T) {
	ctx := context.Background()
	docs := []store.Doc{
		{Source: []byte(`{"kind":"m365cursor","tenant":"t1","content_type":"Audit.SharePoint"}`)},
		{Source: []byte(`{"kind":"m365cursor","tenant":"t1","content_type":"Audit.Exchange"}`)},
		{Source: []byte(`{"kind":"m365cursor","tenant":"t2","content_type":"Audit.General"}`)},
		{Source: []byte(`{"kind":"m365cursor","tenant":"t1"}`)},
		{Source: []byte(`5`)},
	}
	got, err := Cursors(ctx, fakeSearcher{docs: docs}, "rt", "t1")
	if err != nil || len(got) != 2 || got[0].ContentType != "Audit.Exchange" || got[1].ContentType != "Audit.SharePoint" {
		t.Errorf("cursors = %+v %v", got, err)
	}
	boom := errors.New("down")
	if _, err := Cursors(ctx, fakeSearcher{err: boom}, "rt", "t1"); !errors.Is(err, boom) {
		t.Errorf("cursor failure = %v", err)
	}

	if s := FromConfig(&config.Config{}); s.On() {
		t.Errorf("off = %+v", s)
	}
	cfg := &config.Config{M365: config.M365{TenantID: "t1", ClientID: "app", ClientSecret: "x"}}
	s := FromConfig(cfg)
	if !s.On() || s.APIURL != "https://manage.office.com" || s.TokenURL != "https://login.microsoftonline.com/t1/oauth2/v2.0/token" {
		t.Errorf("on = %+v", s)
	}
	if hc := NewHTTPClient(); hc.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("redirects are followed")
	}
}

func TestRunStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rounds := 0
	p := &Poller{Allowed: func() bool { rounds++; return false }}
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if rounds != 1 {
		t.Errorf("rounds = %d", rounds)
	}
}
