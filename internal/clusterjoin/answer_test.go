package clusterjoin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// member starts a member runtime of name whose hub tracks a token holder.
func (e *env) member(name string) (*shared.Runtime, *Tokens) {
	e.t.Helper()
	tk := &Tokens{Now: e.clock}
	rt, _ := e.runtimeWith(name, true, tk.Track)
	tk.Writable = rt.Writable
	waitMode(e.t, rt, shared.ModeMember)
	return rt, tk
}

// securedView is a view of a secured OpenSearch whose certificate
// authority is in a file.
func securedView(t *testing.T) View {
	ca := filepath.Join(t.TempDir(), "root-ca.pem")
	if err := os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\nOS CA\n-----END CERTIFICATE-----\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	return View{OpenSearch: config.OpenSearch{URL: "https://127.0.0.1:9200", Username: "signalith", Password: "pw-123", CAFile: ca, IndexPrefix: prefix},
		URL: "https://os.example.com:9200", PublicURL: "https://siem.example.com", Listen: ":8443",
		Syslog: SyslogDefaults{UDP: ":514"}}
}

// joiner is a server about to join: its node key and a request for tok.
func joiner(t *testing.T, tok Token, name string) (*shared.NodeKey, *Request) {
	t.Helper()
	nk, err := shared.NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewRequest(tok, "n_"+name, nk.Public())
	if err != nil {
		t.Fatal(err)
	}
	req.Name, req.Version, req.OS, req.Arch, req.LevelMax = name, "1.5.0", "linux", "amd64", shared.LevelMax
	return nk, req
}

func TestAnswer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, tk := e.member("siem-a")
	view := securedView(t)
	var leafNamesSeen []string
	d := Deps{RT: a, Tokens: tk, Version: "1.5.0", View: func() View { return view }, Now: e.clock,
		IssueLeaf: func(csr []byte, names []string) ([]byte, []byte, error) {
			leafNamesSeen = names
			return []byte("CA PEM"), []byte("LEAF PEM"), nil
		}}
	tok := e.issue(tk, nil).Token
	nk, req := joiner(t, tok, "siem-c")
	req.CSRPEM = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
	req.NodeURL = "https://Siem-C.example.com:8443"
	req.CopySyslog = true
	req.Names = []string{"SIEM-C.internal", "10.0.0.7"}

	sealed, err := Answer(ctx, d, req)
	if err != nil {
		t.Fatalf("answer: %v (%s)", err, Reason(err))
	}
	b, err := Open(nk, req.NodeID, tok.ID, tok.Secret, sealed)
	if err != nil {
		t.Fatal(err)
	}
	k := a.Hub().Keys().Active()
	got, err := shared.ClusterKeyFrom(b.ClusterKey)
	if err != nil || got.ID() != k.ID() || b.KID != k.ID() {
		t.Fatalf("the bundle's key is not the cluster's: %v", err)
	}
	cb, _ := a.Cluster().Get()
	if b.ClusterID != cb.ClusterID || b.Level != cb.Level || b.IssuerVersion != "1.5.0" || b.NodeName != "siem-c" || b.IndexPrefix != prefix {
		t.Errorf("bundle %+v", b)
	}
	osb := b.OpenSearch
	if osb.URL != "https://os.example.com:9200" || osb.Username != "signalith" || osb.Password != "pw-123" || !strings.Contains(osb.CAPEM, "OS CA") || !osb.Shared || osb.Managed {
		t.Errorf("opensearch %+v", osb)
	}
	if b.ClusterCAPEM != "CA PEM" || b.LeafPEM != "LEAF PEM" || !slices.Equal(leafNamesSeen, []string{"10.0.0.7", "siem-c", "siem-c.example.com", "siem-c.internal"}) {
		t.Errorf("leaf: %q %q, names %v", b.ClusterCAPEM, b.LeafPEM, leafNamesSeen)
	}
	if b.Syslog == nil || b.Syslog.UDP != ":514" || b.Listen != ":8443" || b.PublicURL != "https://siem.example.com" {
		t.Errorf("copied %+v %+v", b.Syslog, b)
	}
	kr, _ := a.Keyring().Get()
	if m := kr.Members["n_siem-c"]; m.AddedBy != shared.AddedByJoin || m.NodePub != nk.PublicText() || m.Fingerprint != nk.Fingerprint() {
		t.Errorf("keyring member %+v", m)
	}
	if l := tk.List(); len(l) != 1 || l[0].State != "used" || l[0].UsedBy == nil || l[0].UsedBy.NodeID != "n_siem-c" {
		t.Errorf("token after use: %+v", l)
	}

	// A second use, by the same or another server, is refused with the
	// one text.
	_, req2 := joiner(t, tok, "siem-d")
	_, err = Answer(ctx, d, req2)
	var r *RefusedError
	if !errors.As(err, &r) || err.Error() != Refused || !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second use: %v (%s)", err, Reason(err))
	}
}

func TestAnswerRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, tk := e.member("siem-a")
	view := securedView(t)
	d := Deps{RT: a, Tokens: tk, Version: "1.5.0", View: func() View { return view }, Now: e.clock}
	tok := e.issue(tk, nil).Token
	open := func() {
		t.Helper()
		if l := tk.List(); len(l) != 1 || l[0].State != "open" {
			t.Fatalf("the token was used: %+v", l)
		}
	}
	refused := func(err error, reason error) {
		t.Helper()
		var r *RefusedError
		if !errors.As(err, &r) || err.Error() != Refused {
			t.Fatalf("not refused with the one text: %v", err)
		}
		if reason != nil && !errors.Is(err, reason) {
			t.Fatalf("reason %s, want %v", Reason(err), reason)
		}
	}

	// A wrong secret.
	wrong := tok
	wrong.Secret = make([]byte, SecretSize)
	_, req := joiner(t, wrong, "siem-c")
	_, err := Answer(ctx, d, req)
	refused(err, ErrProof)
	open()
	// A proof for another node key.
	_, req = joiner(t, tok, "siem-c")
	other, _ := shared.NewNodeKey()
	req.NodePub = encode(other.Public())
	_, err = Answer(ctx, d, req)
	refused(err, ErrProof)
	open()
	// An unknown token, and a request that is not one.
	_, req = joiner(t, tok, "siem-c")
	req.TokenID = "jt_aaaaaaaaaaaaaaaaaaaa"
	_, err = Answer(ctx, d, req)
	refused(err, ErrTokenUnknown)
	_, req = joiner(t, tok, "siem-c")
	req.Name = "no spaces allowed"
	_, err = Answer(ctx, d, req)
	refused(err, nil)
	_, req = joiner(t, tok, "siem-c")
	req.CSRPEM = "not a CSR"
	_, err = Answer(ctx, d, req)
	refused(err, nil)
	_, req = joiner(t, tok, "siem-c")
	req.Names = make([]string, MaxNames+1)
	for i := range req.Names {
		req.Names[i] = "n.internal"
	}
	_, err = Answer(ctx, d, req)
	refused(err, nil)
	// The answering server's own node id.
	_, req = joiner(t, tok, "siem-a")
	_, err = Answer(ctx, d, req)
	refused(err, nil)
	open()

	// Once the proof matched, the joiner is told what is wrong, and the
	// token stays usable.
	var je *JoinError
	_, req = joiner(t, tok, "siem-c")
	req.Version = "1.4.0"
	if _, err = Answer(ctx, d, req); !errors.As(err, &je) || !strings.Contains(err.Error(), "install Signalith 1.5.0") {
		t.Fatalf("other version: %v", err)
	}
	open()
	_, req = joiner(t, tok, "siem-c")
	req.LevelMax = 1
	if _, err = Answer(ctx, d, req); !errors.As(err, &je) {
		t.Fatalf("level below the cluster's: %v", err)
	}
	open()
	insecure := view
	insecure.URL = "http://os.example.com:9200"
	d2 := d
	d2.View = func() View { return insecure }
	_, req = joiner(t, tok, "siem-c")
	if _, err = Answer(ctx, d2, req); !errors.As(err, &je) || err.Error() != ErrNotSecured.Error() {
		t.Fatalf("not secured: %v", err)
	}
	open()

	// Another version joins when it asks to, at a level it reads.
	nk, req := joiner(t, tok, "siem-c")
	req.Version, req.AllowVersionSkew = "1.5.1", true
	sealed, err := Answer(ctx, d, req)
	if err != nil {
		t.Fatal(Reason(err))
	}
	if _, err := Open(nk, req.NodeID, tok.ID, tok.Secret, sealed); err != nil {
		t.Fatal(err)
	}

	// An expired token.
	tok2 := e.issue(tk, nil).Token
	e.advance(DefaultTTL)
	_, req = joiner(t, tok2, "siem-d")
	_, err = Answer(ctx, d, req)
	refused(err, ErrTokenExpired)
}

func TestAnswerNotMember(t *testing.T) {
	e := newEnv(t)
	a, tk := e.member("siem-a")
	tok := e.issue(tk, nil).Token
	b, _ := e.runtime("siem-b", false)
	waitMode(t, b, shared.ModeLegacyB)
	tb := New(b.Writable)
	view := securedView(t)
	_, req := joiner(t, tok, "siem-c")
	_, err := Answer(context.Background(), Deps{RT: b, Tokens: tb, Version: "1.5.0", View: func() View { return view }}, req)
	if !errors.Is(err, ErrUnavailable) || err.Error() != ErrUnavailable.Error() {
		t.Fatalf("outside the cluster: %v", err)
	}
	_ = a
}

func TestAnswerCredentialHook(t *testing.T) {
	e := newEnv(t)
	a, tk := e.member("siem-a")
	view := securedView(t)
	var asked string
	d := Deps{RT: a, Tokens: tk, Version: "1.5.0", View: func() View { return view },
		Credential: func(_ context.Context, name, _ string, csr []byte) (OSCredential, error) {
			asked = name + ":" + string(csr)
			return OSCredential{CAPEM: "CA", ClientCertPEM: "CERT", Managed: true}, nil
		}}
	tok := e.issue(tk, nil).Token
	nk, req := joiner(t, tok, "siem-c")
	req.OSCSRPEM = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
	sealed, err := Answer(context.Background(), d, req)
	if err != nil {
		t.Fatal(Reason(err))
	}
	b, err := Open(nk, req.NodeID, tok.ID, tok.Secret, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(asked, "siem-c:-----BEGIN CERTIFICATE REQUEST") || !b.OpenSearch.Managed || b.OpenSearch.Password != "" ||
		b.OpenSearch.ClientKeyPEM != "" || b.OpenSearch.ClientCertPEM != "CERT" || b.Syslog != nil {
		t.Errorf("asked %q, bundle %+v", asked, b.OpenSearch)
	}
}

func TestViewOf(t *testing.T) {
	c := &config.Config{}
	c.OpenSearch.URL = "https://127.0.0.1:9200"
	if v := ViewOf(c); v.URL != "https://127.0.0.1:9200" {
		t.Errorf("url %q", v.URL)
	}
	c.Cluster.OpenSearchURL = " https://os.example.com:9200 "
	if v := ViewOf(c); v.URL != "https://os.example.com:9200" {
		t.Errorf("url %q", v.URL)
	}
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestAnswerRefusesToTakeAMembersPlace(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, tk := e.member("siem-a")
	view := securedView(t)
	d := Deps{RT: a, Tokens: tk, Version: "1.5.0", View: func() View { return view }, Now: e.clock}
	tok := e.issue(tk, nil).Token
	cNK, req := joiner(t, tok, "siem-c")
	sealed, err := Answer(ctx, d, req)
	if err != nil {
		t.Fatal(Reason(err))
	}
	b, _ := Open(cNK, req.NodeID, tok.ID, tok.Secret, sealed)
	if b.Servers != 2 {
		t.Errorf("servers %d", b.Servers)
	}

	// siem-c's node id with another node key (a copied state folder, or
	// someone posing as siem-c): refused, and the token is not used.
	tok2 := e.issue(tk, nil).Token
	unused := func() bool {
		for _, l := range tk.List() {
			if l.ID == tok2.ID {
				return l.State == "open"
			}
		}
		return false
	}
	_, pose := joiner(t, tok2, "siem-c")
	var je *JoinError
	if _, err := Answer(ctx, d, pose); !errors.As(err, &je) || !strings.Contains(je.Msg, "another node key") || !unused() {
		t.Fatalf("another key for a member's node id: %v (%s)", err, Reason(err))
	}
	// A member's name under another node id.
	_, same := joiner(t, tok2, "SIEM-C")
	same.NodeID = "n_other"
	if _, err := Answer(ctx, d, same); !errors.As(err, &je) || !strings.Contains(je.Msg, "named siem-c already") || !unused() {
		t.Fatalf("a member's name: %v (%s)", err, Reason(err))
	}
	kr, _ := a.Keyring().Get()
	if kr.Members["n_siem-c"].NodePub != cNK.PublicText() || len(kr.Members) != 2 {
		t.Errorf("the keyring changed: %+v", kr.Members)
	}

	// An OpenSearch address only the answering machine reaches, for a
	// server on another machine.
	_, far := joiner(t, tok2, "siem-d")
	far.RemoteIP = net.ParseIP("203.0.113.9")
	local := view
	local.URL = "https://localhost:9200"
	dl := d
	dl.View = func() View { return local }
	if _, err := Answer(ctx, dl, far); !errors.As(err, &je) || !strings.Contains(je.Msg, "cluster.opensearch_url") || !unused() {
		t.Fatalf("a loopback OpenSearch address: %v (%s)", err, Reason(err))
	}
	// The answering server cannot read its own OpenSearch files.
	broken := view
	broken.OpenSearch.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	db := d
	db.View = func() View { return broken }
	if _, err := Answer(ctx, db, far); !errors.As(err, &je) || !strings.Contains(je.Msg, "token was not used") || !unused() {
		t.Fatalf("unreadable OpenSearch files: %v (%s)", err, Reason(err))
	}
	// A failure once the token is used says so.
	ds := d
	ds.Credential = func(context.Context, string, string, []byte) (OSCredential, error) {
		return OSCredential{}, errors.New("osca is down")
	}
	if _, err := Answer(ctx, ds, far); !errors.Is(err, ErrSpent) || !strings.Contains(Reason(err), "osca is down") || unused() {
		t.Fatalf("a failure after the token was used: %v (%s)", err, Reason(err))
	}
}

func TestMemberClash(t *testing.T) {
	kb := &shared.KeyringBody{Members: map[string]shared.KeyringMember{"n_a": {Name: "siem-a", NodePub: "pa"}}}
	var ce *ClashError
	if err := memberClash(kb, "n_a", "siem-a", "pa"); err != nil {
		t.Errorf("the same server again: %v", err)
	}
	if err := memberClash(kb, "n_a", "siem-a", "pb"); !errors.As(err, &ce) || ce.SameName {
		t.Errorf("another key: %v", err)
	}
	if err := memberClash(kb, "n_b", "Siem-A", "pb"); !errors.As(err, &ce) || !ce.SameName {
		t.Errorf("a member's name: %v", err)
	}
	if err := memberClash(nil, "n_b", "siem-b", "pb"); err != nil {
		t.Errorf("no keyring: %v", err)
	}
}

// While the cluster key is being rotated a server that joined would get
// the key being replaced and no copy of the new one: the join is refused
// and the token stays unused.
func TestAnswerRefusesDuringAKeyRotation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, tk := e.member("siem-a")
	view := securedView(t)
	d := Deps{RT: a, Tokens: tk, Version: "1.5.0", View: func() View { return view }, Now: e.clock}
	if _, err := a.Keyring().Mutate(ctx, "test", func(kb *shared.KeyringBody) error {
		kb.Next = json.RawMessage(`{"kid":"k_next","from":"` + kb.Active + `","phase":"copies"}`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	tok := e.issue(tk, nil).Token
	_, req := joiner(t, tok, "siem-c")
	var je *JoinError
	if _, err := Answer(ctx, d, req); !errors.As(err, &je) || !strings.Contains(je.Msg, "being rotated") {
		t.Fatalf("joined during a rotation: %v (%s)", err, Reason(err))
	}
	for _, l := range tk.List() {
		if l.ID == tok.ID && l.State != "open" {
			t.Errorf("the token is %s", l.State)
		}
	}
	kr, _ := a.Keyring().Get()
	if _, listed := kr.Members[req.NodeID]; listed {
		t.Error("the joining server was listed")
	}
	if err := rotating(&shared.KeyringBody{}); err != nil {
		t.Errorf("no rotation: %v", err)
	}
}
