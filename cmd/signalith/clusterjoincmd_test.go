package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

func TestClusterTokenAndApprove(t *testing.T) {
	fake := ostest.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-test-admin-password")
	t.Setenv(clusterKeyFileEnv, "")
	conf := "opensearch:\n  url: " + fake.URL + "\n  index_prefix: cj\nlookups:\n  dir: " + filepath.ToSlash(filepath.Join(dir, "lookups")) + "\n"
	if err := os.WriteFile(path, []byte(conf), 0o666); err != nil {
		t.Fatal(err)
	}
	old := cliWatch
	cliWatch = 10 * time.Millisecond
	t.Cleanup(func() { cliWatch = old })
	run := func(input string, args ...string) (string, error) {
		t.Helper()
		in, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		w.WriteString(input)
		w.Close()
		var out, errOut bytes.Buffer
		err = runCluster(append(args, "-c", path), in, &out, &errOut)
		return out.String() + errOut.String(), err
	}
	stateA := filepath.Join(dir, "state-a")
	clusterServerDir(t, stateA, "siem-a")

	// Not a member yet.
	allowUnsecured(t)
	if _, err := run("", "token", "-url", "https://siem-a.example.com:8080"); err == nil || !strings.Contains(err.Error(), "shared settings") {
		t.Errorf("token before the cluster exists: %v", err)
	}
	if out, err := run("", "found"); err != nil {
		t.Fatalf("found: %v\n%s", err, out)
	}

	// The fake OpenSearch is not secured.
	joinSecured = func(c *config.Config) error { return clusterjoin.ViewOf(c).Secured() }
	if _, err := run("", "token", "-url", "https://siem-a.example.com:8080"); !errors.Is(err, clusterjoin.ErrNotSecured) {
		t.Errorf("token with an unsecured OpenSearch: %v", err)
	}
	if _, err := run("", "approve", "siem-b"); !errors.Is(err, clusterjoin.ErrNotSecured) && (err == nil || !strings.Contains(err.Error(), "no server waits")) {
		t.Errorf("approve with an unsecured OpenSearch: %v", err)
	}
	allowUnsecured(t)

	// No HTTPS certificate authority made yet: the server never started.
	if _, err := run("", "token", "-url", "https://siem-a.example.com:8080"); err == nil || !strings.Contains(err.Error(), "start it once") {
		t.Errorf("token without a certificate authority: %v", err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := newCertificates(c, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(certs.CAPEM())

	// No https address for the token.
	if _, err := run("", "token"); err == nil || !strings.Contains(err.Error(), "-url") {
		t.Errorf("token without an address: %v", err)
	}
	if _, err := run("", "token", "-url", "http://siem-a.example.com:8080"); err == nil {
		t.Error("a token for an http address")
	}
	if _, err := run("", "token", "-url", "https://siem-a.example.com:8080", "-ttl", "25h"); err == nil {
		t.Error("a token for 25 hours")
	}
	if _, err := run("", "token", "-url", "https://siem-a.example.com:8080", "-platform", "bsd"); err == nil {
		t.Error("a token for bsd")
	}

	out, err := run("", "token", "-url", "https://siem-a.example.com:8080", "-platform", "linux", "-note", "rack 4", "-ttl", "30m")
	if err != nil {
		t.Fatalf("token: %v\n%s", err, out)
	}
	text := regexp.MustCompile(`SJ1\.[A-Za-z0-9_-]+`).FindString(out)
	tok, err := clusterjoin.Parse(text)
	if err != nil {
		t.Fatalf("the printed token %q: %v\n%s", text, err, out)
	}
	if tok.URL != "https://siem-a.example.com:8080" || !tok.MatchesPin(caBlock.Bytes) {
		t.Errorf("token = %v %s, pin of %s", tok.URL, tok.CA, clusterjoin.Pin(caBlock.Bytes))
	}
	for _, want := range []string{"sudo signalith join '" + text + "'", "SIGNALITH_JOIN=" + text, "signalith.exe\" join '" + text + "'", "works once"} {
		if !strings.Contains(out, want) {
			t.Errorf("token output lacks %q:\n%s", want, out)
		}
	}
	// The secret is nowhere in OpenSearch in clear.
	secret := tok.Secret
	for _, ix := range fake.Indices() {
		raw, _ := json.Marshal(fake.Source(ix, "jointoken:"+tok.ID))
		if bytes.Contains(raw, []byte(text)) || strings.Contains(string(raw), string(secret)) {
			t.Errorf("the token is in %s in clear", ix)
		}
	}
	out, err = run("", "token", "-url", "https://siem-a.example.com:8080", "-json")
	var ans tokenAnswer
	if err != nil || json.Unmarshal([]byte(out[:strings.LastIndex(out, "}")+1]), &ans) != nil || ans.ID == "" || ans.ID == tok.ID ||
		!strings.HasPrefix(ans.Token, "SJ1.") || ans.Commands["docker"] != "SIGNALITH_JOIN="+ans.Token || time.Until(ans.ExpiresAt) < 59*time.Minute {
		t.Fatalf("token -json: %v %+v\n%s", err, ans, out)
	}

	// A server waits for approval.
	out, err = run("", "approve")
	if err != nil || !strings.Contains(out, "No server waits") {
		t.Errorf("approve with none waiting: %v\n%s", err, out)
	}
	nk, err := shared.NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pending := func(id, name, pub, fp string) {
		p := shared.PendingDoc{Kind: shared.PendingKind, NodeID: id, Name: name, NodePub: pub, Fingerprint: fp,
			Version: "1.0.0", OS: "linux", Arch: "amd64", Addresses: []string{"10.0.0.7"}, RequestedAt: now, At: now}
		fake.Put("cj_runtime", shared.PendingID(id), asMap(t, p))
	}
	pending("n_b", "siem-b", nk.PublicText(), nk.Fingerprint())
	other0, _ := shared.NewNodeKey()
	out, err = run("", "approve")
	if err != nil || !strings.Contains(out, "siem-b") || !strings.Contains(out, nk.Fingerprint()) {
		t.Errorf("approve lists: %v\n%s", err, out)
	}
	if _, err := run("", "approve", "siem-x"); err == nil || !strings.Contains(err.Error(), "no server waits") {
		t.Errorf("approve an unknown server: %v", err)
	}
	// By name, the admin gives or confirms the fingerprint: away from a
	// terminal, and with -yes, only -fingerprint does that, never the
	// fingerprint the (unsigned) pending document says.
	if _, err := run("y\n", "approve", "siem-b"); err == nil || !strings.Contains(err.Error(), "-fingerprint") {
		t.Errorf("approve by name away from a terminal: %v", err)
	}
	if _, err := run("", "approve", "-yes", "siem-b"); err == nil || !strings.Contains(err.Error(), "-fingerprint") {
		t.Errorf("approve by name with -yes: %v", err)
	}
	if _, err := run("", "approve", "-yes", "-fingerprint", other0.Fingerprint(), "siem-b"); !errors.Is(err, clusterjoin.ErrFingerprint) {
		t.Errorf("approve by name with another fingerprint: %v", err)
	}
	if fake.Source("cj_runtime", shared.ApprovalID("n_b")) != nil {
		t.Fatal("approved without a confirmation")
	}
	// Two waiting servers of one name: only a fingerprint picks one.
	other, _ := shared.NewNodeKey()
	pending("n_b2", "siem-b", other.PublicText(), other.Fingerprint())
	if _, err := run("", "approve", "-yes", "siem-b"); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("approve one of two by name: %v", err)
	}
	fp := strings.ToLower(strings.ReplaceAll(nk.Fingerprint(), "-", ""))
	out, err = run("", "approve", fp)
	if err != nil || !strings.Contains(out, "Approved siem-b") {
		t.Fatalf("approve by fingerprint: %v\n%s", err, out)
	}
	if fake.Source("cj_runtime", shared.ApprovalID("n_b")) == nil || fake.Source("cj_runtime", shared.ApprovalID("n_b2")) != nil {
		t.Error("the approval documents are not as approved")
	}
	out, err = run("", "status", "-json")
	var st clusterStatus
	if err != nil || json.Unmarshal([]byte(out[:strings.LastIndex(out, "}")+1]), &st) != nil {
		t.Fatalf("status -json: %v\n%s", err, out)
	}
	if m := st.Keyring["n_b"]; m.AddedBy != shared.AddedByApproval || m.Fingerprint != nk.Fingerprint() {
		t.Errorf("keyring member = %+v", m)
	}
	// It no longer waits.
	out, _ = run("", "approve")
	if strings.Contains(out, nk.Fingerprint()) {
		t.Errorf("the approved server still waits:\n%s", out)
	}
	// Its approval is lost (housekeeping removed it a day later, or it
	// was never written): the server, which asks again, shows again and
	// is approved again.
	fake.Delete("cj_runtime", shared.ApprovalID("n_b"))
	pending("n_b", "siem-b", nk.PublicText(), nk.Fingerprint())
	if out, _ = run("", "approve"); !strings.Contains(out, nk.Fingerprint()) {
		t.Errorf("a server whose approval is lost does not show:\n%s", out)
	}
	if out, err = run("", "approve", "-fingerprint", nk.Fingerprint(), "n_b"); err != nil || fake.Source("cj_runtime", shared.ApprovalID("n_b")) == nil {
		t.Errorf("approve again: %v\n%s", err, out)
	}
	// A pending document for a member's node id with another key, or a
	// member's name, is not approved: it would take that member's place.
	fake.Delete("cj_runtime", shared.ApprovalID("n_b"))
	pending("n_b", "siem-b", other0.PublicText(), other0.Fingerprint())
	var clash *clusterjoin.ClashError
	if _, err := run("", "approve", other0.Fingerprint()); !errors.As(err, &clash) {
		t.Errorf("approve another key for a member's node id: %v", err)
	}
	pending("n_c", "SIEM-B", other0.PublicText(), other0.Fingerprint())
	if _, err := run("", "approve", "-fingerprint", other0.Fingerprint(), "n_c"); !errors.As(err, &clash) {
		t.Errorf("approve a member's name: %v", err)
	}
	if kr := mustKeyring(t, run); kr["n_b"].NodePub != nk.PublicText() || kr["n_c"].NodePub != "" {
		t.Errorf("the keyring changed: %+v", kr)
	}
}

// mustKeyring is the keyring's members as signalith cluster status -json
// shows them.
func mustKeyring(t *testing.T, run func(string, ...string) (string, error)) map[string]shared.KeyringMember {
	t.Helper()
	out, err := run("", "status", "-json")
	var st clusterStatus
	if err != nil || json.Unmarshal([]byte(out[:strings.LastIndex(out, "}")+1]), &st) != nil {
		t.Fatalf("status -json: %v\n%s", err, out)
	}
	return st.Keyring
}
