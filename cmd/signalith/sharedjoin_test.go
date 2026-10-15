package main

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

func TestJoinTokenURL(t *testing.T) {
	c := &config.Config{}
	j := &joinAPI{c: c}
	if _, err := j.tokenURL(""); err == nil {
		t.Error("a token without an https address")
	}
	if u, err := j.tokenURL("https://browser:8443"); err != nil || u != "https://browser:8443" {
		t.Errorf("origin: %q %v", u, err)
	}
	c.Server.PublicURL = "http://siem.example.com"
	if u, _ := j.tokenURL("https://browser:8443"); u != "https://browser:8443" {
		t.Errorf("an http public_url was used: %q", u)
	}
	c.Server.PublicURL = "https://siem.example.com"
	if u, _ := j.tokenURL("https://browser:8443"); u != "https://siem.example.com" {
		t.Errorf("public_url: %q", u)
	}
	c.Server.NodeURL = "https://siem-a.example.com:8443"
	if u, _ := j.tokenURL("https://browser:8443"); u != "https://siem-a.example.com:8443" {
		t.Errorf("node_url: %q", u)
	}
}

func TestJoinThroughTheServer(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	a := startRunnerWith(t, runOptions{scheduler: true, name: "siem-a"})
	eventually(t, "A founds the cluster", func() bool {
		m, _ := a.r.shared.Mode()
		return m == shared.ModeMember
	})
	ca := a.ownCA()

	// The public certificate a token pins.
	resp, err := a.client.Get(a.scheme + "://" + a.addr + "/api/cluster/join/ca")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != string(ca) {
		t.Fatalf("join ca = %d %q", resp.StatusCode, body)
	}
	// The fake OpenSearch speaks plain http without sign-in: no token.
	a.signIn()
	code, out, err := a.call("", "POST", "/api/cluster/tokens", `{"platform":"linux"}`)
	if err != nil || code != http.StatusConflict || !strings.Contains(out["error"].(string), "security turned on") {
		t.Fatalf("token with an unsecured OpenSearch: %d %v %v", code, out, err)
	}
	code, out, _ = a.call("", "GET", "/api/cluster", "")
	if _, ok := out["tokens"]; code != 200 || !ok {
		t.Fatalf("cluster = %d %v", code, out)
	}

	// The same server with a secured OpenSearch's settings: a token, and
	// a join with it.
	srv := a.r.srv.Load()
	j := *srv.Join.(*joinAPI)
	c := *j.c
	caFile := filepath.Join(t.TempDir(), "os-ca.pem")
	if err := os.WriteFile(caFile, []byte("-----BEGIN CERTIFICATE-----\nOS\n-----END CERTIFICATE-----\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	c.OpenSearch.URL, c.OpenSearch.Username, c.OpenSearch.Password, c.OpenSearch.CAFile = "https://os.example.com:9200", "signalith", "pw", caFile
	c.Server.NodeURL = "https://" + a.addr
	j.c = &c
	block, _ := pem.Decode(ca)
	ctx := context.Background()
	is, err := j.Issue(ctx, "admin", api.JoinTokenRequest{Platform: "linux", CADER: block.Bytes})
	if err != nil {
		t.Fatal(err)
	}
	tok := is.Token
	if tok.URL != "https://"+a.addr || !tok.MatchesPin(block.Bytes) {
		t.Fatalf("token %v names %s", tok, tok.URL)
	}
	nk, _ := shared.NewNodeKey()
	req, _ := clusterjoin.NewRequest(tok, "n_siem-c", nk.Public())
	req.Name, req.Version, req.LevelMax, req.OS, req.Arch = "siem-c", version, shared.LevelMax, "linux", "amd64"
	sealed, err := j.Answer(ctx, req)
	if err != nil {
		t.Fatal(clusterjoin.Reason(err))
	}
	b, err := clusterjoin.Open(nk, "n_siem-c", tok.ID, tok.Secret, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if b.OpenSearch.URL != "https://os.example.com:9200" || b.OpenSearch.Password != "pw" || b.KID != a.r.shared.Hub().Keys().Active().ID() {
		t.Errorf("bundle %+v", b.OpenSearch)
	}
	kr, _ := a.r.shared.Keyring().Get()
	if kr.Members["n_siem-c"].AddedBy != shared.AddedByJoin {
		t.Errorf("keyring %+v", kr.Members)
	}
	// The token is listed as used, never with its secret.
	raw := mustJSON(t, j.Tokens())
	if !strings.Contains(string(raw), `"used"`) || strings.Contains(string(raw), tok.String()[len(clusterjoin.TokenPrefix):]) {
		t.Errorf("tokens %s", raw)
	}

	// Housekeeping deletes the token once it expired.
	log := slog.New(slog.DiscardHandler)
	joinHousekeep(ctx, a.r.shared, j.tokens, time.Now(), log)
	if len(j.Tokens()) != 1 {
		t.Fatal("a token was deleted before it expired")
	}
	joinHousekeep(ctx, a.r.shared, j.tokens, is.ExpiresAt.Add(time.Second), log)
	eventually(t, "the expired token is gone", func() bool { return len(j.Tokens()) == 0 })
}
