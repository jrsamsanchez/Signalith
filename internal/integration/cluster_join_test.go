//go:build integration && linux

package integration

// Adding a server with a join token (signalith cluster token on a member,
// signalith join on the new server) and by approval (a server started
// with the cluster's OpenSearch and no key waits with a fingerprint;
// signalith cluster approve on a member gives it the key). Every server is
// a real `signalith serve` process.
//
// Joins need OpenSearch with security turned on. In CI they run against
// the quick start's secured OpenSearch (the harness's client
// certificate); on a laptop, against the in-memory fake served over
// HTTPS with a password. The binary is the clustertest build, which lets
// signalith join run as the test's own user instead of root.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// joinOS is how the servers of a join test sign in to OpenSearch.
type joinOS struct {
	url, caFile, certFile, keyFile, user, password string
}

const joinOSPassword = "join-test-opensearch-password"

// newJoinHarness is newClusterHarness with a secured OpenSearch: the real
// one of SIGNALITH_TEST_OPENSEARCH, or the fake over HTTPS with a
// password.
func newJoinHarness(t *testing.T) (*clusterHarness, joinOS) {
	t.Helper()
	if os.Getenv("SIGNALITH_TEST_OPENSEARCH") != "" {
		h := newClusterHarness(t)
		c := storeConfig(h.url)
		return h, joinOS{url: h.url, caFile: c.CAFile, certFile: c.CertFile, keyFile: c.KeyFile}
	}
	if os.Getenv("CI") != "" {
		t.Fatal("SIGNALITH_TEST_OPENSEARCH is not set: in CI these tests must run against a real OpenSearch")
	}
	fake, handler := ostest.NewHandler()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	fake.Secure(&ostest.Account{User: "signalith", Password: joinOSPassword, Roles: []string{"signalith_server"}})
	root := t.TempDir()
	ca := filepath.Join(root, "opensearch-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &clusterHarness{t: t, url: srv.URL, prefix: "signalithcl" + config.RandomToken(3), root: root, fake: fake}
	return h, joinOS{url: srv.URL, caFile: ca, user: "signalith", password: joinOSPassword}
}

// addJoinServer makes a server's folder without the cluster key: with
// withOS, it has the cluster's OpenSearch settings; without, only its
// listen address, as a fresh install that joins with a token.
func addJoinServer(h *clusterHarness, o joinOS, name string, withOS bool) *testServer {
	t := h.t
	t.Helper()
	s := &testServer{h: h, name: name, dir: filepath.Join(h.root, name), port: freePort(t), opts: serverOptions{noKey: true}}
	if err := os.MkdirAll(filepath.Join(s.dir, "lookups"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf("server:\n  listen: 127.0.0.1:%d\ncluster:\n  node_name: %s\n", s.port, name)
	if withOS {
		cfg += fmt.Sprintf("opensearch:\n  url: %q\n  index_prefix: %s\n", o.url, h.prefix)
		for _, f := range []struct{ key, v string }{{"ca_file", o.caFile}, {"cert_file", o.certFile}, {"key_file", o.keyFile},
			{"username", o.user}, {"password", o.password}} {
			if f.v != "" {
				cfg += fmt.Sprintf("  %s: %q\n", f.key, f.v)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(s.dir, "signalith.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

// runCode runs a signalith command with the server's environment and config,
// and returns its output and exit code.
func (s *testServer) runCode(args ...string) (string, int) {
	t := s.h.t
	t.Helper()
	cmd := exec.Command(signalithBinary(t), append(args, "-c", filepath.Join(s.dir, "signalith.yaml"))...)
	cmd.Env = s.env()
	cmd.Stdin = strings.NewReader("")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &ee):
		return out.String(), ee.ExitCode()
	}
	t.Fatalf("%s %v: %v", s.name, args, err)
	return "", -1
}

// joinStatus is what signalith cluster status -json says of a server.
type joinStatus struct {
	NodeID string `json:"node_id"`
	Shared struct {
		Mode        string `json:"mode"`
		Fingerprint string `json:"fingerprint"`
	} `json:"shared"`
	Keyring map[string]struct {
		AddedBy string `json:"added_by"`
	} `json:"keyring"`
}

func (s *testServer) clusterStatus() (joinStatus, bool) {
	out, code := s.runCode("cluster", "status", "-json")
	var st joinStatus
	i, j := strings.Index(out, "{"), strings.LastIndex(out, "}")
	if code != 0 || i < 0 || j < i || json.Unmarshal([]byte(out[i:j+1]), &st) != nil {
		return st, false
	}
	return st, true
}

// joinToken makes a token on the member s that names its address.
func (s *testServer) joinToken(args ...string) string {
	t := s.h.t
	t.Helper()
	var out string
	var code int
	// The cluster is founded within seconds of the first start.
	waitUntil(t, 60*time.Second, s.name+" makes a join token", func() bool {
		out, code = s.runCode(append([]string{"cluster", "token", "-url", fmt.Sprintf("https://127.0.0.1:%d", s.port)}, args...)...)
		return code == 0
	})
	tok := regexp.MustCompile(`SJ1\.[A-Za-z0-9_-]+`).FindString(out)
	if tok == "" {
		t.Fatalf("no token in:\n%s", out)
	}
	return tok
}

// ownedByMe checks that join's files belong to the user that runs the
// test (CI runs as an ordinary user, so the service account is that one).
func ownedByMe(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
			t.Errorf("%s belongs to uid %d", p, st.Uid)
		}
		if fi.Mode().Perm()&0o007 != 0 {
			t.Errorf("%s is readable by everyone: %v", p, fi.Mode())
		}
	}
}

func TestClusterJoinWithToken(t *testing.T) {
	h, o := newJoinHarness(t)
	a := addJoinServer(h, o, "siem-a", true)
	a.start()
	tok := a.joinToken("-platform", "linux", "-note", "integration")

	// A token whose pin is not the server's certificate authority: exit 3,
	// nothing written.
	p, err := clusterjoin.Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	wrong := clusterjoin.Token{URL: p.URL, CA: "sha256:" + strings.Repeat("0", 64), ID: p.ID, Secret: p.Secret}
	c := addJoinServer(h, o, "siem-c", false)
	if out, code := c.runCode("join", wrong.String(), "--yes", "--no-start"); code != 3 || !strings.Contains(out, "intercepting") {
		t.Fatalf("join with a wrong pin = %d:\n%s", code, out)
	}
	for _, f := range []string{"keys", "lookups/settings.yaml", "opensearch"} {
		if _, err := os.Stat(filepath.Join(c.dir, f)); err == nil {
			t.Errorf("a join refused by its pin wrote %s", f)
		}
	}
	// A token that was never made: exit 2, the one refusal text.
	forged := clusterjoin.Token{URL: p.URL, CA: p.CA, ID: "jt_" + strings.Repeat("a", 20), Secret: p.Secret}
	if out, code := c.runCode("join", forged.String(), "--yes", "--no-start"); code != 2 || !strings.Contains(out, clusterjoin.Refused) {
		t.Fatalf("join with an unknown token = %d:\n%s", code, out)
	}

	// The real token.
	out, code := c.runCode("join", tok, "--yes", "--no-start", "--listen", fmt.Sprintf("127.0.0.1:%d", c.port))
	if code != 0 || !strings.Contains(out, "siem-c joined") {
		t.Fatalf("join = %d:\n%s", code, out)
	}
	if strings.Contains(out, string(p.Secret)) || strings.Contains(a.logTail(400), tok) {
		t.Error("the token's secret is in the output or the log")
	}
	keys, _ := filepath.Glob(filepath.Join(c.dir, "keys", "cluster-*.key"))
	if len(keys) != 1 {
		t.Fatalf("cluster keys after the join: %v", keys)
	}
	ownedByMe(t, filepath.Join(c.dir, "keys"), keys[0], filepath.Join(c.dir, "opensearch"), filepath.Join(c.dir, "lookups", "settings.yaml"))
	c.start()
	waitUntil(t, 60*time.Second, "siem-c is a member", func() bool {
		st, ok := c.clusterStatus()
		return ok && st.Shared.Mode == "member" && st.Keyring[st.NodeID].AddedBy == "join"
	})
	// It serves with the cluster's certificate authority once the cluster
	// keeps one; at the latest, it takes it within seconds.
	waitUntil(t, 60*time.Second, "siem-c uses siem-a's certificate authority", func() bool {
		return caFingerprint(t, filepath.Join(c.dir, "tls", "ca.pem")) == caFingerprint(t, filepath.Join(a.dir, "tls", "ca.pem"))
	})

	// The token works once.
	d := addJoinServer(h, o, "siem-d", false)
	if out, code := d.runCode("join", tok, "--yes", "--no-start"); code != 2 || !strings.Contains(out, clusterjoin.Refused) {
		t.Fatalf("a second join with one token = %d:\n%s", code, out)
	}
	if keys, _ := filepath.Glob(filepath.Join(d.dir, "keys", "cluster-*.key")); len(keys) > 0 {
		t.Errorf("a refused join kept a cluster key: %v", keys)
	}
}

func TestClusterJoinByApproval(t *testing.T) {
	h, o := newJoinHarness(t)
	a := addJoinServer(h, o, "siem-a", true)
	a.start()
	a.joinToken() // the cluster is founded
	e := addJoinServer(h, o, "siem-e", true)
	e.start()
	var fp string
	waitUntil(t, 60*time.Second, "siem-e waits for approval", func() bool {
		out, code := a.runCode("cluster", "approve")
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); code == 0 && len(f) > 1 && f[0] == "siem-e" {
				fp = f[1]
			}
		}
		return fp != ""
	})
	st, ok := e.clusterStatus()
	if !ok || st.Shared.Fingerprint != fp {
		t.Fatalf("siem-e shows fingerprint %q, siem-a lists %q", st.Shared.Fingerprint, fp)
	}
	// A wrong fingerprint approves nothing.
	if out, code := a.runCode("cluster", "approve", "0000-0000-0000-0000-0000-0000-0000-0000"); code == 0 {
		t.Fatalf("approved a fingerprint nobody shows:\n%s", out)
	}
	if out, code := a.runCode("cluster", "approve", fp); code != 0 || !strings.Contains(out, "Approved siem-e") {
		t.Fatalf("approve = %d:\n%s", code, out)
	}
	waitUntil(t, 90*time.Second, "siem-e is a member", func() bool {
		st, ok := e.clusterStatus()
		return ok && st.Shared.Mode == "member" && st.Keyring[st.NodeID].AddedBy == "approval"
	})
}

// configDoc reads a document of the shared settings and returns its body.
func configDoc(t *testing.T, h *clusterHarness, o joinOS, id string) (string, bool) {
	t.Helper()
	cfg := store.Config{URL: o.url, CAFile: o.caFile, CertFile: o.certFile, KeyFile: o.keyFile, Username: o.user,
		Password: secrets.New("opensearch.password", o.password)}
	cl := store.New(cfg)
	defer cl.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, _, found, err := cl.Get(ctx, shared.ConfigIndex(h.prefix), id)
	if err != nil || !found {
		return "", false
	}
	var e shared.Envelope
	if json.Unmarshal(raw, &e) != nil {
		return "", false
	}
	return e.Body, true
}

// A server that served alone with users and retention policies of its
// own joins with --merge: the cluster gains the user it lacked, keeps its
// own where they differ, holds retention until an admin confirms, and
// keeps the server's migration report.
func TestClusterJoinMerge(t *testing.T) {
	h, o := newJoinHarness(t)
	a := addJoinServer(h, o, "siem-a", true)
	a.start()
	tok := a.joinToken()

	b := addJoinServer(h, o, "siem-b", true)
	us, err := users.Open(filepath.Join(b.dir, "lookups", "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := us.Create(users.WithActor(context.Background(), "sam"), users.NewUser{Username: "newbie", Role: users.Viewer, Password: "a-good-password"}); err != nil {
		t.Fatal(err)
	}
	if err := retention.NewStore(filepath.Join(b.dir, "lookups", "retention.yaml")).Update(func(s *retention.Saved) {
		s.Policies = map[string]retention.Policy{"findings": {KeepDays: 45}}
	}); err != nil {
		t.Fatal(err)
	}
	out, code := b.runCode("join", tok, "--yes", "--no-start", "--merge", "--listen", fmt.Sprintf("127.0.0.1:%d", b.port))
	if code != 0 || !strings.Contains(out, "added user") || !strings.Contains(out, "newbie") || !strings.Contains(out, "siem-b joined") {
		t.Fatalf("join --merge = %d:\n%s", code, out)
	}
	if strings.Contains(out, "a-good-password") || strings.Contains(out, "$2") {
		t.Errorf("the merge printed a secret:\n%s", out)
	}
	st, ok := b.clusterStatus()
	if !ok {
		t.Fatal("no status of siem-b")
	}
	report, ok := configDoc(t, h, o, clustercfg.MigrationKind+":"+st.NodeID)
	if !ok || !strings.Contains(report, `"newbie"`) || !strings.Contains(report, `"siem-b"`) {
		t.Fatalf("migration report %q", report)
	}
	b.start()
	waitUntil(t, 60*time.Second, "siem-b is a member", func() bool {
		st, ok := b.clusterStatus()
		return ok && st.Shared.Mode == "member"
	})
	// Differing policies: none here (the cluster had no findings policy),
	// so it was added, and retention is not held.
	ret, ok := configDoc(t, h, o, "retention")
	if !ok || !strings.Contains(ret, `"findings"`) || strings.Contains(ret, `"reason":"merge"`) {
		t.Errorf("shared retention %q", ret)
	}
}
