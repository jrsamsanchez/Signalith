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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	cl := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}}}}
	resp, err := cl.Get(strings.TrimSuffix(url, "/") + "/_plugins/_security/authinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info struct {
		User  string   `json:"user_name"`
		Roles []string `json:"roles"`
	}
	json.Unmarshal(body, &info)
	return info.User, info.Roles
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
}
