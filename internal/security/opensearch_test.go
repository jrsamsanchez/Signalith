package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func conn(url string) store.Config {
	return store.Config{URL: url, Username: "signalith", Password: secrets.New("opensearch.password", sentinelOS)}
}

func TestAnonymousProbe(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	if r := probeAnonymous(ctx, conn(fake.URL), "signalith"); r.state != "open" || r.demo {
		t.Errorf("open: %+v", r)
	}
	// It never sends Signalith's own credentials.
	fake.Secure(&ostest.Account{User: "signalith", Password: sentinelOS})
	if r := probeAnonymous(ctx, conn(fake.URL), "signalith"); r.state != "closed" {
		t.Errorf("closed: %+v", r)
	}
	reqs := fake.Requests()
	if last := reqs[len(reqs)-1]; !strings.HasPrefix(last, "GET /signalith-*/_count?allow_no_indices=true&ignore_unavailable=true") {
		t.Errorf("request %q", last)
	}
	fake.Secure(nil)
	fake.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Status: 403, Type: "security_exception"} })
	if r := probeAnonymous(ctx, conn(fake.URL), "signalith"); r.state != "closed" {
		t.Errorf("403: %+v", r)
	}
	fake.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Status: 503, Type: "x"} })
	if r := probeAnonymous(ctx, conn(fake.URL), "signalith"); r.state != "unknown" || r.why != "status 503" || r.notLoaded {
		t.Errorf("503: %+v", r)
	}
	fake.SetFault(func(m, p string) *ostest.Fault { f := ostest.NotInitialized; return &f })
	if r := probeAnonymous(ctx, conn(fake.URL), "signalith"); r.state != "unknown" || r.why != "status 503" || !r.notLoaded {
		t.Errorf("security settings not loaded: %+v", r)
	}
	// Nothing listening.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	if r := probeAnonymous(ctx, conn("http://"+addr), "signalith"); r.state != "unknown" || r.why == "" {
		t.Errorf("down: %+v", r)
	}
}

func TestAnonymousProbeTimeout(t *testing.T) {
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := probeAnonymous(ctx, conn(srv.URL), "signalith")
	if r.state != "unknown" || time.Since(start) > 3*time.Second {
		t.Errorf("%+v after %v", r, time.Since(start))
	}
}

func TestAuthInfo(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	if _, noPlugin, why, _ := probeAuthInfo(ctx, conn(fake.URL)); !noPlugin || why != "" {
		t.Errorf("no plugin: %v %q", noPlugin, why)
	}
	fake.Secure(&ostest.Account{User: "signalith", Password: sentinelOS, Roles: []string{"signalith_server"}, BackendRoles: []string{"siem"}})
	info, noPlugin, why, refused := probeAuthInfo(ctx, conn(fake.URL))
	if noPlugin || why != "" || refused != store.NotRefused || info.User != "signalith" || !slices.Equal(info.Roles, []string{"signalith_server"}) || !slices.Equal(info.BackendRole, []string{"siem"}) {
		t.Errorf("%+v %v %q", info, noPlugin, why)
	}
	wrong := conn(fake.URL)
	wrong.Password = secrets.New("opensearch.password", "wrong")
	if _, _, why, refused := probeAuthInfo(ctx, wrong); why != "status 401" || refused != store.RefusedSignIn {
		t.Errorf("wrong password: %q %q", why, refused)
	}
	// Security settings not loaded: OpenSearch turns everyone away with
	// 503, before it looks at the sign-in.
	fake.Secure(nil)
	fake.SetFault(func(m, p string) *ostest.Fault { f := ostest.NotInitialized; return &f })
	if _, noPlugin, why, refused := probeAuthInfo(ctx, conn(fake.URL)); noPlugin || why != "status 503" || refused != store.RefusedNotInitialized {
		t.Errorf("not loaded: %v %q %q", noPlugin, why, refused)
	}
	fake.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Status: 503, Type: "x"} })
	if _, _, _, refused := probeAuthInfo(ctx, conn(fake.URL)); refused != store.RefusedUnavailable {
		t.Errorf("another 503 is not the security settings: %q", refused)
	}
	fake.SetFault(func(m, p string) *ostest.Fault {
		return &ostest.Fault{Status: 429, Type: "rejected_execution_exception"}
	})
	if _, _, _, refused := probeAuthInfo(ctx, conn(fake.URL)); refused != store.RefusedBusy {
		t.Errorf("busy: %q", refused)
	}
}

func TestDataPaths(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	got, err := probeDataPaths(ctx, conn(fake.URL))
	if err != nil || !slices.Equal(got, []string{"/usr/share/opensearch/data"}) {
		t.Errorf("home: %v %v", got, err)
	}
	fake.SetPaths("/opt/os", "/data/a", "relative")
	got, err = probeDataPaths(ctx, conn(fake.URL))
	if err != nil || !slices.Equal(got, []string{"/data/a", "/opt/os/relative"}) {
		t.Errorf("data: %v %v", got, err)
	}
	fake.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Status: 403, Type: "security_exception"} })
	if _, err := probeDataPaths(ctx, conn(fake.URL)); err == nil || err.Error() != "status 403" {
		t.Errorf("refused: %v", err)
	}
}

// demoServer serves HTTPS with a certificate from a CA named like the
// OpenSearch demo one, and returns its URL and that CA's file.
func demoServer(t *testing.T, cn string) (string, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "node-0.example.com"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL, file
}

func TestDemoCertificate(t *testing.T) {
	for _, tc := range []struct {
		cn   string
		demo bool
	}{{demoRootCN, true}, {"Corp Root CA", false}} {
		url, ca := demoServer(t, tc.cn)
		c := conn(url)
		c.CAFile = ca
		r := probeAnonymous(context.Background(), c, "signalith")
		if r.state != "closed" || r.demo != tc.demo {
			t.Errorf("%s: %+v", tc.cn, r)
		}
	}
}

func TestListensOnNetwork(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	ctx := context.Background()
	// 127.0.0.2 stands in for a network address here; on some systems
	// only 127.0.0.1 answers, so only a positive answer is checked.
	addr := l.Addr().(*net.TCPAddr).AddrPort().Addr()
	if !listensOnNetwork(ctx, []netip.Addr{addr}, port) {
		t.Error("not found listening")
	}
	if listensOnNetwork(ctx, nil, port) {
		t.Error("found with no addresses")
	}
	if urlPort("https://x") != "443" || urlPort("http://x:9200") != "9200" {
		t.Error("urlPort")
	}
}

func TestOpenSearchCollectors(t *testing.T) {
	fake := ostest.New(t)
	fake.Secure(&ostest.Account{User: "signalith", Password: sentinelOS, Roles: []string{"all_access"}})
	c := loadConfig(t, "opensearch:\n  url: "+fake.URL+"\n  username: signalith\n  password: "+sentinelOS+"\n")
	f := &Facts{Now: now, Config: c}
	Gather(context.Background(), f, 5*time.Second, OpenSearchCollectors(c, false, t.TempDir()))
	o := f.OpenSearch
	if o.Anonymous != "closed" || !o.AuthProbed || o.AuthUser != "signalith" || !slices.Contains(o.AuthRoles, "all_access") || o.DemoAdmin {
		t.Errorf("%+v", o)
	}
	// The fake says /usr/share/opensearch/data, a container's folder that
	// isn't on this computer: its disk is not looked for.
	if o.DataErr != "" || len(o.DataPaths) != 0 || !slices.Equal(o.DataMissing, []string{"/usr/share/opensearch/data"}) {
		t.Errorf("data %+v %q %q", o.DataPaths, o.DataMissing, o.DataErr)
	}
	if len(f.TimedOut) != 0 {
		t.Errorf("timed out %v", f.TimedOut)
	}

	// A folder that is here is.
	here := t.TempDir()
	fake.SetPaths("/opt/opensearch", here)
	f = &Facts{Now: now, Config: c}
	Gather(context.Background(), f, 5*time.Second, OpenSearchCollectors(c, false, t.TempDir()))
	if o := f.OpenSearch; len(o.DataPaths) != 1 || o.DataPaths[0].Path != here || len(o.DataMissing) != 0 {
		t.Errorf("data %+v %q", o.DataPaths, o.DataMissing)
	}
}
