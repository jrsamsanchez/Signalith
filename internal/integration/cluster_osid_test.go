//go:build integration && linux

package integration

// Each server's own OpenSearch certificate (internal/clusterpki): the
// Docker quick start's OpenSearch CA, handed to the founder in its import
// folder, is kept by the cluster; the founder then signs in with
// CN=signalith-server-<name> instead of the shared CN=signalith, and so
// does a second server that starts with the shared one.
//
// The CI cluster job runs it against the quick start it started, with
// COMPOSE set to its docker compose command.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

// exportedCA hands the quick start's OpenSearch CA over with
// bootstrap-docker -export-ca-key and returns its certificate and key.
func exportedCA(t *testing.T, compose []string) (certPEM, keyPEM []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	top, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		all := append(slices.Clone(compose[1:]), args...)
		cmd := exec.CommandContext(ctx, compose[0], all...)
		cmd.Dir = top
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v\n%s%s", strings.Join(all, " "), err, out, stderr.String())
		}
		return out
	}
	importDir := "/signalith-data/" + ospki.ImportDir + "/"
	t.Cleanup(func() {
		cmd := exec.Command(compose[0], append(slices.Clone(compose[1:]), "run", "--rm", "-T", "--entrypoint", "rm", "setup", "-f",
			importDir+ospki.ExportCAFile, importDir+ospki.ExportCAKeyFile)...)
		cmd.Dir = top
		cmd.Run()
	})
	run("run", "--rm", "-T", "setup", "bootstrap-docker", "-export-ca-key")
	return run("run", "--rm", "-T", "--entrypoint", "cat", "setup", importDir+ospki.ExportCAFile),
		run("run", "--rm", "-T", "--entrypoint", "cat", "setup", importDir+ospki.ExportCAKeyFile)
}

// ownCertificate waits until the server s signs in with its own
// certificate, and returns its common name.
func ownCertificate(t *testing.T, s *testServer, within time.Duration) *x509.Certificate {
	t.Helper()
	path := filepath.Join(s.dir, "opensearch", "client.pem")
	var c *x509.Certificate
	waitUntil(t, within, s.name+" signs in with its own OpenSearch certificate", func() bool {
		b, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return false
		}
		c, err = x509.ParseCertificate(block.Bytes)
		return err == nil
	})
	return c
}

// signsInAs asks OpenSearch who the pair in dir signs in as.
func signsInAs(t *testing.T, url, caFile, dir string) (string, []string) {
	t.Helper()
	user, roles, err := trySignIn(url, caFile, dir)
	if err != nil {
		t.Fatal(err)
	}
	return user, roles
}

// trySignIn asks OpenSearch who the pair in dir signs in as, and says
// why it could not.
func trySignIn(url, caFile, dir string) (string, []string, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem"))
	if err != nil {
		return "", nil, err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return "", nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	cl := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}}}}
	defer cl.CloseIdleConnections()
	resp, err := cl.Get(strings.TrimSuffix(url, "/") + "/_plugins/_security/authinfo")
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	var info struct {
		User  string   `json:"user_name"`
		Roles []string `json:"roles"`
	}
	json.Unmarshal(body, &info)
	return info.User, info.Roles, nil
}

// putCRL puts the revocation list b where the quick start's OpenSearch
// reads it, and returns what was there.
func putCRL(t *testing.T, compose []string, b []byte) []byte {
	t.Helper()
	top, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	run := func(stdin []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, compose[0], append(slices.Clone(compose[1:]), append([]string{"run", "--rm", "-T"}, args...)...)...)
		cmd.Dir = top
		cmd.Stdin = bytes.NewReader(stdin)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v\n%s%s", err, out, stderr.String())
		}
		return out
	}
	old := run(nil, "--entrypoint", "cat", "setup", "/opensearch-crl/"+ospki.CRLFile)
	run(b, "--entrypoint", "sh", "setup", "-c",
		"cat > /opensearch-crl/.crl && chmod 644 /opensearch-crl/.crl && chown 65532:65532 /opensearch-crl/.crl && mv /opensearch-crl/.crl /opensearch-crl/"+ospki.CRLFile)
	return old
}

func TestClusterOSIdentity(t *testing.T) {
	compose := strings.Fields(os.Getenv("COMPOSE"))
	url := os.Getenv("SIGNALITH_TEST_OPENSEARCH")
	caFile := os.Getenv("SIGNALITH_TEST_OPENSEARCH_CA")
	if len(compose) == 0 || url == "" || caFile == "" {
		t.Skip("COMPOSE, SIGNALITH_TEST_OPENSEARCH and SIGNALITH_TEST_OPENSEARCH_CA are not set")
	}
	certPEM, keyPEM := exportedCA(t, compose)
	h := newClusterHarness(t)

	// The founder finds the CA in its import folder, as the quick start's
	// server would after bootstrap-docker -export-ca-key.
	a := h.add("siem-a", serverOptions{})
	// siem-a keeps a revocation list of its own, here outside OpenSearch.
	cfgFile := filepath.Join(a.dir, "signalith.yaml")
	cfg, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg = []byte(strings.Replace(string(cfg), "opensearch:\n", fmt.Sprintf("opensearch:\n  crl_file: %q\n", filepath.Join(a.dir, "crl.pem")), 1))
	if err := os.WriteFile(cfgFile, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	imp := filepath.Join(a.dir, ospki.ImportDir)
	if err := os.MkdirAll(imp, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(imp, ospki.ExportCAFile), certPEM, 0o600)
	os.WriteFile(filepath.Join(imp, ospki.ExportCAKeyFile), keyPEM, 0o600)
	a.start()
	c := ownCertificate(t, a, 2*time.Minute)
	if c.Subject.CommonName != "signalith-server-siem-a" {
		t.Fatalf("siem-a signs in as %s", c.Subject.CommonName)
	}
	if d := time.Until(c.NotAfter); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("siem-a's certificate lasts %v", d)
	}
	if _, err := os.Stat(filepath.Join(imp, ospki.ExportCAKeyFile)); !os.IsNotExist(err) {
		t.Errorf("the handed-over key file is still there: %v", err)
	}
	if user, roles := signsInAs(t, url, caFile, filepath.Join(a.dir, "opensearch")); user != "signalith-server-siem-a" || !slices.Contains(roles, "signalith_server") {
		t.Errorf("OpenSearch lets siem-a's certificate in as %q with %v", user, roles)
	}
	// It still works with it.
	waitUntil(t, 30*time.Second, "siem-a ready with its own certificate", func() bool { return a.readyz() == http.StatusOK })

	// A second server that starts with the shared certificate gets its
	// own too.
	b := h.start("siem-b", serverOptions{noJobs: true})
	if c := ownCertificate(t, b, 2*time.Minute); c.Subject.CommonName != "signalith-server-siem-b" {
		t.Fatalf("siem-b signs in as %s", c.Subject.CommonName)
	}
	if user, _ := signsInAs(t, url, caFile, filepath.Join(b.dir, "opensearch")); user != "signalith-server-siem-b" {
		t.Errorf("OpenSearch lets siem-b's certificate in as %q", user)
	}

	// Revoking siem-b: the revocation list siem-a keeps names its
	// certificate, and once OpenSearch reads it, siem-b's certificate is
	// refused at once while siem-a's still works.
	crlFile := filepath.Join(a.dir, "crl.pem")
	if out, err := a.cli("", "cluster", "opensearch-ca", "revoke", "-yes", "siem-b"); err != nil {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	bSerial := readCertFile(t, filepath.Join(b.dir, "opensearch", "client.pem")).SerialNumber
	caCert := readCertFile(t, caFile)
	var list []byte
	waitUntil(t, time.Minute, "siem-a's revocation list to name siem-b", func() bool {
		var err error
		if list, err = os.ReadFile(crlFile); err != nil {
			return false
		}
		l, err := ospki.ParseCRL(list, caCert, time.Now())
		return err == nil && slices.ContainsFunc(l.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool { return e.SerialNumber.Cmp(bSerial) == 0 })
	})
	old := putCRL(t, compose, list)
	t.Cleanup(func() { putCRL(t, compose, old) })
	if _, _, err := trySignIn(url, caFile, filepath.Join(b.dir, "opensearch")); err == nil {
		t.Error("OpenSearch still lets siem-b's revoked certificate in")
	}
	if user, _ := signsInAs(t, url, caFile, filepath.Join(a.dir, "opensearch")); user != "signalith-server-siem-a" {
		t.Errorf("after revoking siem-b, siem-a signs in as %q", user)
	}
}

func readCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s holds no PEM", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
