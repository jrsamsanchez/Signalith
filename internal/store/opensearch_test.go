package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func green(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"status":"green"}`) }

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProxyEnvironmentIsIgnored(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		green(w, r)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	tr, err := Transport(Config{})
	if err != nil || tr.Proxy != nil {
		t.Fatalf("transport proxy set from the environment: %v", err)
	}
	// 192.0.2.1 is a documentation address nobody answers on.
	c := New(Config{URL: "http://192.0.2.1:9200", Username: "signalith", Password: secrets.New("opensearch.password", "OS-SECRET"), Timeout: 300 * time.Millisecond})
	if _, err := c.Health(context.Background()); err == nil || proxied.Load() != 0 {
		t.Fatalf("health went through the proxy: err=%v proxied=%d", err, proxied.Load())
	}

	// An explicit opensearch.proxy is used.
	c = New(Config{URL: "http://192.0.2.1:9200", Proxy: proxy.URL, Timeout: 5 * time.Second})
	if status, err := c.Health(context.Background()); err != nil || status != "green" || proxied.Load() != 1 {
		t.Fatalf("explicit proxy: %q %v proxied=%d", status, err, proxied.Load())
	}
}

func TestPrivateCA(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(green))
	defer ts.Close()
	ca := writePEM(t, t.TempDir(), "ca.pem", "CERTIFICATE", ts.Certificate().Raw)

	if _, err := New(Config{URL: ts.URL}).Health(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("an unknown CA was trusted: %v", err)
	}
	if status, err := New(Config{URL: ts.URL, CAFile: ca}).Health(context.Background()); err != nil || status != "green" {
		t.Fatalf("with ca_file: %q %v", status, err)
	}
	if status, err := New(Config{URL: ts.URL, TLSSkipVerify: true}).Health(context.Background()); err != nil || status != "green" {
		t.Fatalf("with tls_skip_verify: %q %v", status, err)
	}
	// A CA file that cannot be used fails every request with a clear error.
	_, err := New(Config{URL: ts.URL, CAFile: filepath.Join(t.TempDir(), "missing.pem")}).Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "opensearch CA file") {
		t.Fatalf("missing CA file: %v", err)
	}
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(notPEM, []byte("hello"), 0o600)
	if _, err := LoadCAFile(notPEM); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Fatalf("not PEM: %v", err)
	}
}

func TestOldTLSRefused(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(green))
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	ts.StartTLS()
	defer ts.Close()
	if _, err := New(Config{URL: ts.URL, TLSSkipVerify: true}).Health(context.Background()); err == nil {
		t.Fatal("connected with TLS 1.1")
	}
}

func TestClientCertificate(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "signalith"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certFile := writePEM(t, dir, "client.pem", "CERTIFICATE", der)
	keyFile := writePEM(t, dir, "client-key.pem", "PRIVATE KEY", keyDER)

	var user atomic.Value
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user.Store(r.TLS.PeerCertificates[0].Subject.CommonName)
		green(w, r)
	}))
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	ts.StartTLS()
	defer ts.Close()

	if _, err := New(Config{URL: ts.URL, TLSSkipVerify: true}).Health(context.Background()); err == nil {
		t.Fatal("connected without a client certificate")
	}
	status, err := New(Config{URL: ts.URL, TLSSkipVerify: true, CertFile: certFile, KeyFile: keyFile}).Health(context.Background())
	if err != nil || status != "green" || user.Load() != "signalith" {
		t.Fatalf("with a client certificate: %q %v %v", status, err, user.Load())
	}
	if _, err := Transport(Config{CertFile: certFile, KeyFile: filepath.Join(dir, "nope.pem")}); err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("missing key: %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var leaked atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get("Authorization") + "|" + r.URL.Path)
		green(w, r)
	}))
	defer other.Close()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer ts.Close()
	_, err := New(Config{URL: ts.URL, Username: "signalith", Password: secrets.New("opensearch.password", "OS-SECRET")}).Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirect") || leaked.Load() != nil {
		t.Fatalf("err=%v, other host got %v", err, leaked.Load())
	}
}

func TestURLCredentialsAreUsedButNeverShown(t *testing.T) {
	var auth atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		auth.Store(u + ":" + p)
		green(w, r)
	}))
	defer ts.Close()
	withCreds := strings.Replace(ts.URL, "http://", "http://signalith:S3cr3tPass@", 1)
	if _, err := New(Config{URL: withCreds}).Health(context.Background()); err != nil || auth.Load() != "signalith:S3cr3tPass" {
		t.Fatalf("credentials from the URL: %v %v", err, auth.Load())
	}
	// Bulk to a closed port: the error names the address but not the password.
	c := New(Config{URL: "http://signalith:S3cr3tPass@127.0.0.1:1"})
	_, err := c.Bulk(context.Background(), []IndexedDoc{{Index: "x", Doc: map[string]any{"a": 1}}})
	if err == nil || strings.Contains(err.Error(), "S3cr3tPass") || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error: %v", err)
	}
}

// TestQueryInURLIsNotRepeatedInErrors: Go's own error repeats the request
// URL with only the password hidden; the rest is redacted as well.
func TestQueryInURLIsNotRepeatedInErrors(t *testing.T) {
	c := New(Config{URL: "http://admin:OS-PASS@127.0.0.1:1/?apikey=URLKEY"})
	_, err := c.Health(context.Background())
	if err == nil || strings.Contains(err.Error(), "URLKEY") || strings.Contains(err.Error(), "OS-PASS") || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error: %v", err)
	}
}

// clearProxyEnv unsets the proxy variables for one test.
func clearProxyEnv(t *testing.T) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
}

// TestUnusedProxyEnvironmentIsExplained: after an upgrade, an OpenSearch
// only reachable through HTTPS_PROXY fails; the error says why and which
// setting to use.
func TestUnusedProxyEnvironmentIsExplained(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:3128")
	// 192.0.2.1 is a documentation address nobody answers on.
	c := New(Config{URL: "https://192.0.2.1:9200", Timeout: 200 * time.Millisecond})
	_, err := c.Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTPS_PROXY is set") || !strings.Contains(err.Error(), "opensearch.proxy or SIGNALITH_OPENSEARCH_PROXY") {
		t.Errorf("error: %v", err)
	}
	for _, tc := range []struct {
		name string
		cfg  Config
		env  map[string]string
	}{
		{"opensearch.proxy set", Config{URL: "https://os.corp:9200", Proxy: "http://proxy.corp:3128"}, nil},
		{"OpenSearch on this machine", Config{URL: "https://localhost:9200"}, nil},
		{"loopback address", Config{URL: "https://127.0.0.1:9200"}, nil},
		{"only HTTP_PROXY, for an https URL", Config{URL: "https://os.corp:9200"}, map[string]string{"HTTPS_PROXY": "", "HTTP_PROXY": "http://p:1"}},
		{"NO_PROXY names the domain", Config{URL: "https://os.corp:9200"}, map[string]string{"NO_PROXY": "example.com, .corp"}},
		{"NO_PROXY names the network", Config{URL: "https://10.1.2.3:9200"}, map[string]string{"no_proxy": "10.0.0.0/8"}},
		{"NO_PROXY is *", Config{URL: "https://os.corp:9200"}, map[string]string{"NO_PROXY": "*"}},
		{"no proxy at all", Config{URL: "https://os.corp:9200"}, map[string]string{"HTTPS_PROXY": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if h := New(tc.cfg).proxyHint; h != "" {
				t.Errorf("hint: %s", h)
			}
		})
	}
	t.Setenv("HTTP_PROXY", "http://p:1")
	if h := New(Config{URL: "http://os.corp:9200"}).proxyHint; !strings.Contains(h, "HTTP_PROXY is set") {
		t.Errorf("plain http with HTTP_PROXY: %q", h)
	}
}

// TestConfigHidesPassword checks that printing or logging a Config never
// shows the OpenSearch password, including one taken from the URL.
func TestConfigHidesPassword(t *testing.T) {
	c := New(Config{URL: "https://admin:URL-SECRET@os.example.com:9200", Timeout: time.Second})
	for _, s := range []string{fmt.Sprintf("%v", c.cfg), fmt.Sprintf("%+v", c.cfg), fmt.Sprintf("%#v", c.cfg)} {
		if strings.Contains(s, "URL-SECRET") || !strings.Contains(s, "[redacted]") {
			t.Errorf("printed config: %s", s)
		}
	}
	if c.cfg.Password.Reveal() != "URL-SECRET" || c.cfg.Username != "admin" {
		t.Errorf("credentials from the URL: %q", c.cfg.Username)
	}
}

// Replicate leaves a missing index alone and reports other errors.
func TestReplicateMissingIndex(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/gone/") {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":{"type":"index_not_found_exception","reason":"no such index [gone]"},"status":404}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"type":"cluster_block_exception","reason":"blocked"},"status":429}`)
	}))
	defer srv.Close()
	cl := New(Config{URL: srv.URL})
	if err := Replicate(context.Background(), cl, "gone", nil); err != nil {
		t.Errorf("missing index: %v", err)
	}
	if err := Replicate(context.Background(), cl, "full", nil); err == nil {
		t.Error("a blocked index was taken as done")
	}
	if len(paths) == 0 || paths[0] != "GET /gone/_settings" {
		t.Errorf("requests %v", paths)
	}
}
