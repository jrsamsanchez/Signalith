// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/clusterpki"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ospki"
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
	// An address only this computer reaches: the new server would reach
	// itself there.
	for _, local := range []string{"https://localhost:8443", "https://127.0.0.1:8443", "https://[::1]:8443", "https://0.0.0.0:8443"} {
		if u, err := j.tokenURL(local); err == nil {
			t.Errorf("a token names %q", u)
		}
	}
	c.Server.NodeURL = "https://127.0.0.1:8443"
	if u, _ := j.tokenURL("https://browser:8443"); u != "https://browser:8443" {
		t.Errorf("a loopback node_url was used: %q", u)
	}
	c.Server.NodeURL = ""
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
	// Founding restarts the components in place, with the shared
	// sessions: a sign-in before that restart is over is lost.
	eventually(t, "A founds the cluster and takes its content from it", func() bool {
		m, _ := a.r.shared.Mode()
		ct := a.r.sharedContent
		return m == shared.ModeMember && ct.on.Load() && ct.users.on.Load() == a.r.shared.SharedUsers() && !a.r.RestartStatus().InProgress
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
	_, port, _ := net.SplitHostPort(a.addr)
	c.Server.NodeURL = "https://siem-a.example.com:" + port
	j.c = &c
	block, _ := pem.Decode(ca)
	ctx := context.Background()
	is, err := j.Issue(ctx, "admin", api.JoinTokenRequest{Platform: "linux", CADER: block.Bytes})
	if err != nil {
		t.Fatal(err)
	}
	tok := is.Token
	if tok.URL != c.Server.NodeURL || !tok.MatchesPin(block.Bytes) {
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

// Without OpenSearch's certificate authority in the cluster (no osca, or
// one without its document), a joining server gets the answering
// server's credential, which the servers then share.
func TestJoinCredentialWithoutOSCAIsShared(t *testing.T) {
	view := func() clusterjoin.View {
		return clusterjoin.View{OpenSearch: config.OpenSearch{Username: "signalith", Password: "pw"}}
	}
	for name, o := range map[string]*clusterpki.OSCA{"no osca": nil, "no osca document": clusterpki.New()} {
		for _, csr := range [][]byte{nil, []byte("-----BEGIN CERTIFICATE REQUEST-----")} {
			cr, err := joinCredential(view, o)(context.Background(), "siem-b", "n2", csr)
			if err != nil || !cr.Shared || cr.Managed || cr.Password != "pw" {
				t.Errorf("%s, csr %t: %+v %v", name, csr != nil, cr, err)
			}
		}
	}
}

// A server removed from the cluster has its OpenSearch certificates
// revoked; it keeps its node id, and joining again with a token (or being
// approved again) gets it a new certificate rather than a refusal.
func TestRejoinAfterRemoveGetsACertificate(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	a := startRunnerWith(t, runOptions{scheduler: true, name: "siem-a"})
	eventually(t, "A founds the cluster", func() bool {
		m, _ := a.r.shared.Mode()
		return m == shared.ModeMember
	})
	srv := a.r.srv.Load()
	j := *srv.Join.(*joinAPI)
	if j.osca == nil {
		t.Fatal("the join API has no osca")
	}
	c := *j.c
	caFile := filepath.Join(t.TempDir(), "os-ca.pem")
	if err := os.WriteFile(caFile, []byte("-----BEGIN CERTIFICATE-----\nOS\n-----END CERTIFICATE-----\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	c.OpenSearch.URL, c.OpenSearch.Username, c.OpenSearch.Password, c.OpenSearch.CAFile = "https://os.example.com:9200", "signalith", "pw", caFile
	_, port, _ := net.SplitHostPort(a.addr)
	c.Server.NodeURL = "https://siem-a.example.com:" + port
	j.c = &c
	ctx := context.Background()
	ca, err := ospki.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := j.osca.Import(ctx, "admin", "siem-a", ca.CertPEM(), ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(a.ownCA())
	nk, _ := shared.NewNodeKey()
	join := func(what string) *clusterjoin.Bundle {
		t.Helper()
		is, err := j.Issue(ctx, "admin", api.JoinTokenRequest{Platform: "linux", CADER: block.Bytes})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := clusterjoin.NewRequest(is.Token, "n_siem-c", nk.Public())
		req.Name, req.Version, req.LevelMax, req.OS, req.Arch = "siem-c", version, shared.LevelMax, "linux", "amd64"
		_, csr, err := ospki.NewClientRequest("siem-c")
		if err != nil {
			t.Fatal(err)
		}
		req.OSCSRPEM = string(csr)
		sealed, err := j.Answer(ctx, req)
		if err != nil {
			t.Fatalf("%s: %s", what, clusterjoin.Reason(err))
		}
		b, err := clusterjoin.Open(nk, "n_siem-c", is.Token.ID, is.Token.Secret, sealed)
		if err != nil {
			t.Fatal(err)
		}
		if !b.OpenSearch.Managed || b.OpenSearch.ClientCertPEM == "" || b.OpenSearch.Shared || b.OpenSearch.Password != "" {
			t.Fatalf("%s: OpenSearch credential %+v", what, b.OpenSearch)
		}
		return b
	}
	join("first join")

	if _, _, err := removeServer(ctx, a.r.shared, removeHooks(a.r.shared, j.osca), "n_siem-c", "siem-c", "admin", false); err != nil {
		t.Fatal(err)
	}
	if b, _ := j.osca.Get(); b.RevokedNodes["n_siem-c"].IsZero() {
		t.Fatal("removing the server revoked nothing")
	}
	eventually(t, "the keyring drops siem-c", func() bool {
		kr, _ := j.rt.Keyring().Get()
		_, there := kr.Members["n_siem-c"]
		return !there
	})

	// Joining again with the same node id: a new certificate.
	join("rejoin")
	if b, _ := j.osca.Get(); !b.RevokedNodes["n_siem-c"].IsZero() {
		t.Error("the rejoined server is still listed as revoked")
	}

	// Approval readmits too.
	if _, _, err := removeServer(ctx, a.r.shared, removeHooks(a.r.shared, j.osca), "n_siem-c", "siem-c", "admin", false); err != nil {
		t.Fatal(err)
	}
	ap := j.approver()
	if ap.Readmit == nil {
		t.Fatal("the approver does not readmit")
	}
	if err := ap.Readmit(ctx, "n_siem-c"); err != nil {
		t.Fatal(err)
	}
	_, csr, _ := ospki.NewClientRequest("siem-c")
	if _, _, err := j.osca.Issue(ctx, "siem-c", "n_siem-c", csr, time.Now()); err != nil {
		t.Errorf("issue after approval: %v", err)
	}
}
