//go:build integration && linux

package integration

// The Docker quick start's OpenSearch CA, handed to Signalith with
// bootstrap-docker -export-ca-key, issues each server its own client
// certificate (CN=signalith-server-<name>), which OpenSearch maps to the
// signalith_server role; another name from the same CA gets no role.
//
// The CI cluster job runs it against the quick start it started, with
// COMPOSE set to its docker compose command (run from the repository's
// top folder).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

func TestClusterPKIServerCertificate(t *testing.T) {
	compose := strings.Fields(os.Getenv("COMPOSE"))
	url := os.Getenv("SIGNALITH_TEST_OPENSEARCH")
	if len(compose) == 0 || url == "" {
		t.Skip("COMPOSE and SIGNALITH_TEST_OPENSEARCH are not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	top, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
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
		return string(out)
	}
	importDir := "/signalith-data/" + ospki.ImportDir + "/"
	t.Cleanup(func() {
		cmd := exec.Command(compose[0], append(slices.Clone(compose[1:]), "run", "--rm", "-T", "--entrypoint", "rm", "setup", "-f",
			importDir+ospki.ExportCAFile, importDir+ospki.ExportCAKeyFile)...)
		cmd.Dir = top
		cmd.Run()
	})
	out := run("run", "--rm", "-T", "setup", "bootstrap-docker", "-export-ca-key")
	if !strings.Contains(out, "Handed the OpenSearch CA") && !strings.Contains(out, "already waiting") {
		t.Fatalf("bootstrap-docker -export-ca-key said:\n%s", out)
	}
	dir := t.TempDir()
	for _, name := range []string{ospki.ExportCAFile, ospki.ExportCAKeyFile} {
		b := run("run", "--rm", "-T", "--entrypoint", "cat", "setup", importDir+name)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The handed-over files are the CA's certificate and key under
	// LoadCA's names.
	os.Rename(filepath.Join(dir, ospki.ExportCAFile), filepath.Join(dir, ospki.RootCAFile))
	os.Rename(filepath.Join(dir, ospki.ExportCAKeyFile), filepath.Join(dir, ospki.RootCAKeyFile))
	ca, err := ospki.LoadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The same CA OpenSearch and Signalith's own certificate use.
	if b, err := os.ReadFile(os.Getenv("SIGNALITH_TEST_OPENSEARCH_CA")); err == nil && strings.TrimSpace(string(b)) != strings.TrimSpace(string(ca.CertPEM())) {
		t.Fatal("the handed-over CA is not OpenSearch's")
	}

	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = 3072 })
	roles := func(cn string) (int, []string) {
		t.Helper()
		p, err := ospki.IssueClient(ca, cn, time.Now(), 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(p.CertPEM(), p.KeyPEM())
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		cl := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}}}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(url, "/")+"/_plugins/_security/authinfo", nil)
		resp, err := cl.Do(req)
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
		t.Logf("%s: %d %s", cn, resp.StatusCode, body)
		return resp.StatusCode, info.Roles
	}
	name, err := ospki.ServerClientName("pkitest")
	if err != nil {
		t.Fatal(err)
	}
	if code, r := roles(name); code != http.StatusOK || !slices.Contains(r, "signalith_server") {
		t.Errorf("%s: %d, roles %v; want the signalith_server role", name, code, r)
	}
	if code, r := roles("signalith-other"); code == http.StatusOK && slices.Contains(r, "signalith_server") {
		t.Errorf("signalith-other got the signalith_server role")
	}
}
