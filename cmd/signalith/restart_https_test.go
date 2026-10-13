package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// peerCert returns the certificate the server at addr presents.
func peerCert(t *testing.T, addr string) *x509.Certificate {
	t.Helper()
	// Not checked here: the caller looks at what it is.
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS to %s: %v", addr, err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0]
}

// pemFingerprint is the SHA-256 of the first certificate in b.
func pemFingerprint(t *testing.T, b []byte) string {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("no PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// writePair writes a self-signed certificate for 127.0.0.1 and its key
// into dir, and returns their paths and the certificate in PEM.
func writePair(t *testing.T, dir string) (certFile, keyFile string, certPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "own files"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	os.WriteFile(certFile, certPEM, 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile, certPEM
}

// settled waits for the goroutines left over from requests and restarts
// to end, and returns how many are left.
func settled(rs *running, most int) int {
	rs.client.CloseIdleConnections()
	noFollow.CloseIdleConnections()
	n := runtime.NumGoroutine()
	// Under -race on a busy CI runner, closed connections and stopped
	// listeners can take several seconds to finish their goroutines.
	for deadline := time.Now().Add(20 * time.Second); n > most && time.Now().Before(deadline); n = runtime.NumGoroutine() {
		time.Sleep(50 * time.Millisecond)
	}
	return n
}

// A server with HTTPS on restarts in place: HTTPS and plain HTTP on the
// one port stop and start together, the certificate keeps coming from the
// same certificate authority, and changes to it take effect.
func TestRestartWithHTTPS(t *testing.T) {
	boom := errors.New("cannot start with boom.lan")
	rs := startRunnerWith(t, runOptions{fail: func(c *config.Config) error {
		if slices.Contains(c.Server.TLSNames(), "boom.lan") {
			return boom
		}
		return nil
	}, server: "  tls:\n    mode: auto\n    plaintext_ingest: deny\n"})
	ownCA := rs.ownCA()
	ca := pemFingerprint(t, ownCA)

	// Plain HTTP on the same port sends browsers to HTTPS.
	resp, err := noFollow.Get("http://" + rs.addr + "/search")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://"+rs.addr+"/search" {
		t.Fatalf("plain HTTP: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Agents on plain HTTP are refused, or accepted at once from the page.
	plainIngest := func() int {
		t.Helper()
		req, _ := http.NewRequest("POST", "http://"+rs.addr+"/api/ingest", strings.NewReader(`[{"log":"hello"}]`))
		req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := plainIngest(); code != http.StatusServiceUnavailable {
		t.Errorf("plain-text agent while refused: %d", code)
	}
	rs.save(`{"server.tls.plaintext_ingest":"allow"}`)
	if code := plainIngest(); code != http.StatusOK {
		t.Errorf("plain-text agent while accepted: %d", code)
	}
	rs.save(`{"server.tls.plaintext_ingest":"deny"}`)
	if code := plainIngest(); code != http.StatusServiceUnavailable {
		t.Errorf("plain-text agent refused again: %d", code)
	}

	// Extra names: a restart in place, with a certificate that has them,
	// from the same certificate authority.
	base := settled(rs, 0)
	rs.save(`{"server.tls.names":["siem-alias.lan"]}`)
	out, res := rs.restart()
	if !res.OK || out["listen_changed"] != false || strings.Join(res.Keys, ",") != "server.tls.names" {
		t.Fatalf("names: %+v %v\n%s", res, out, rs.logs.String())
	}
	if err := peerCert(t, rs.addr).VerifyHostname("siem-alias.lan"); err != nil {
		t.Errorf("the certificate leaves out the new name: %v", err)
	}
	if got := pemFingerprint(t, rs.ownCA()); got != ca {
		t.Error("a restart made a new certificate authority")
	}
	if !rs.signedIn("") {
		t.Error("signed out by the restart")
	}
	// Restarts leave nothing running behind them.
	for range 3 {
		if _, res := rs.restart(); !res.OK {
			t.Fatalf("restart %+v", res)
		}
	}
	if n := settled(rs, base+2); n > base+2 {
		buf := make([]byte, 1<<20)
		t.Errorf("goroutines: %d before the restarts, %d after\n%s", base, n, buf[:runtime.Stack(buf, true)])
	}

	// Starting fails after the switch: the previous settings start
	// again, and HTTPS keeps answering with the same certificate.
	rs.save(`{"server.tls.names":["siem-alias.lan","boom.lan"]}`)
	_, res = rs.restart()
	if res.OK || !res.RolledBack || !slices.Contains(res.Refused, "server.tls.names") {
		t.Fatalf("rollback %+v", res)
	}
	if !rs.signedIn("") || peerCert(t, rs.addr).VerifyHostname("siem-alias.lan") != nil {
		t.Error("HTTPS does not answer as before after the rollback")
	}
	if code, _, err := rs.call("", "PUT", "/api/settings", `{"values":{"server.tls.names":["siem-alias.lan"]}}`); err != nil || code != 200 {
		t.Fatalf("names again %d %v", code, err)
	}

	// A public address saved on the page joins the certificate at once.
	rs.save(`{"server.public_url":"https://siem-public.lan:` + port(rs.addr) + `"}`)
	if err := peerCert(t, rs.addr).VerifyHostname("siem-public.lan"); err != nil {
		t.Errorf("the certificate leaves out the public address: %v", err)
	}

	// Your own certificate files, then Signalith's own again: in place.
	cert, key, certPEM := writePair(t, t.TempDir())
	rs.useHTTPS(append(slices.Clone(ownCA), certPEM...))
	files, _ := json.Marshal(map[string]string{"server.tls.mode": "files", "server.tls_cert": cert, "server.tls_key": key})
	rs.save(string(files))
	if out, res := rs.restart(); !res.OK || out["listen_changed"] != false {
		t.Fatalf("files: %+v %v", res, out)
	}
	if got := peerCert(t, rs.addr).Subject.CommonName; got != "own files" {
		t.Errorf("serves %q", got)
	}
	code, put, _ := rs.call("", "PUT", "/api/settings", `{"values":{"server.tls.mode":"auto"},"reset":["server.tls_cert","server.tls_key"]}`)
	if code != 200 {
		t.Fatalf("auto again: %d %v", code, put)
	}
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("auto again: %+v", res)
	}
	if leaf := peerCert(t, rs.addr); leaf.Subject.CommonName == "own files" || pemFingerprint(t, rs.ownCA()) != ca {
		t.Errorf("not back on Signalith's own certificate: %s", leaf.Subject.CommonName)
	}

	// A certificate file that is gone by the restart: the page says so,
	// and Signalith keeps running as it is.
	rs.save(string(files))
	os.Remove(cert)
	code, out, _ = rs.call("", "POST", "/api/settings/restart", "")
	if code != http.StatusConflict || out["code"] != "settings_invalid" {
		t.Fatalf("restart with a missing file: %d %v", code, out)
	}
	_, view, _ := rs.call("", "GET", "/api/settings", "")
	if f := settingsField(t, view, "server.tls_cert"); !strings.Contains(f["problem"].(string), "can't be used") {
		t.Errorf("certificate field %v", f)
	}
	rs.useHTTPS(ownCA)
	if !rs.signedIn("") {
		t.Error("HTTPS stopped answering")
	}
	code, out, _ = rs.call("", "PUT", "/api/settings", `{"reset":["server.tls.mode","server.tls_cert","server.tls_key"]}`)
	if code != 200 || len(out["pending"].([]any)) != 0 {
		t.Fatalf("reset %d %v", code, out["pending"])
	}

	// HTTPS off moves the web page to http:// on the same port, and on
	// again back to https://, with the same certificate authority.
	rs.save(`{"server.tls.mode":"off"}`)
	out, res = rs.restart()
	if !res.OK || out["go_to"] != "http://"+rs.addr+"/" {
		t.Fatalf("off: %+v %v\n%s", res, out, rs.logs.String())
	}
	if _, err := tls.Dial("tcp", rs.addr, &tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Error("still serves HTTPS with HTTPS off")
	}
	rs.scheme, rs.client = "http", &http.Client{Timeout: 10 * time.Second}
	rs.signIn()
	if code, _, _ := rs.call("", "GET", "/api/settings", ""); code != 200 || rs.r.RestartStatus().Awaiting != nil {
		t.Fatalf("confirming over http: %d %+v", code, rs.r.RestartStatus().Awaiting)
	}
	rs.save(`{"server.tls.mode":"auto"}`)
	out, res = rs.restart()
	if !res.OK || out["go_to"] != "https://"+rs.addr+"/" {
		t.Fatalf("on: %+v %v", res, out)
	}
	rs.useHTTPS(rs.ownCA())
	rs.signIn()
	if code, _, _ := rs.call("", "GET", "/api/settings", ""); code != 200 || rs.r.RestartStatus().Awaiting != nil {
		t.Fatalf("confirming over https: %d", code)
	}
	if pemFingerprint(t, rs.ownCA()) != ca {
		t.Error("turning HTTPS on again made a new certificate authority")
	}

	// Stopping frees the port.
	rs.stop()
	ln, err := net.Listen("tcp", rs.addr)
	if err != nil {
		t.Fatalf("the port is still taken: %v", err)
	}
	ln.Close()
}

// A certificate that cannot be made stops the restart before anything
// stops, and the change is set aside.
func TestRestartRefusesACertificateItCannotMake(t *testing.T) {
	rs := startRunner(t, nil, nil)
	// Where Signalith keeps its own certificate authority is taken by a
	// file.
	if err := os.WriteFile(filepath.Join(rs.dir, "tls"), []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	rs.save(`{"server.tls.mode":"auto"}`)
	_, res := rs.restart()
	if res.OK || res.RolledBack || !strings.Contains(res.Error, "kept running with the previous settings") ||
		!slices.Contains(res.ProblemKeys, "server.tls.mode") || !slices.Contains(res.Refused, "server.tls.mode") {
		t.Fatalf("restart %+v", res)
	}
	if got := rs.starts(); got != "signalith" {
		t.Errorf("the components were replaced: %s", got)
	}
	if !rs.signedIn("") {
		t.Error("stopped answering")
	}
	if c, err := config.Load(rs.r.path); err != nil || c.Server.HTTPS() {
		t.Errorf("the next start would use it: %v", err)
	}
}

// A restart refused after its checks prepared a certificate does not
// leave that certificate for a later restart: names Add data gave the
// certificate in use in between stay in the one served after it.
func TestRefusedRestartDoesNotKeepItsCertificate(t *testing.T) {
	rs := startRunnerWith(t, runOptions{server: "  tls:\n    mode: auto\n    plaintext_ingest: deny\n"})
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	rs.save(`{"server.tls.names":["alias1.lan"],"server.listen":"` + taken.Addr().String() + `"}`)
	if _, res := rs.restart(); res.OK || !slices.Contains(res.Refused, "server.listen") {
		t.Fatalf("restart on a taken port %+v", res)
	}
	if code, out, err := rs.call("", "POST", "/api/tls/names", `{"name":"agents.lan"}`); err != nil || code != 200 {
		t.Fatalf("add a name: %d %v %v", code, out, err)
	}
	if err := peerCert(t, rs.addr).VerifyHostname("agents.lan"); err != nil {
		t.Fatalf("the certificate in use leaves out the name added: %v", err)
	}
	if code, out, err := rs.call("", "PUT", "/api/settings", `{"reset":["server.listen"]}`); err != nil || code != 200 {
		t.Fatalf("reset %d %v %v", code, out, err)
	}
	_, res := rs.restart()
	if !res.OK || strings.Join(res.Keys, ",") != "server.tls.names" {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	leaf := peerCert(t, rs.addr)
	for _, name := range []string{"agents.lan", "alias1.lan"} {
		if err := leaf.VerifyHostname(name); err != nil {
			t.Errorf("the certificate after the restart leaves out %s: %v", name, err)
		}
	}
}

// Turning HTTPS on with your own certificate files, when nobody confirms
// it, sets the files aside with the mode: signalith.yaml's mode (off)
// would refuse them, and the next start would then use none of the
// page's settings.
func TestUnconfirmedHTTPSMoveSetsAsideItsFiles(t *testing.T) {
	moveWait = 600 * time.Millisecond
	t.Cleanup(func() { moveWait = api.MoveWait })
	rs := startRunner(t, nil, nil)
	cert, key, _ := writePair(t, t.TempDir())
	files, _ := json.Marshal(map[string]any{"server.tls.mode": "files", "server.tls_cert": cert, "server.tls_key": key, "search.max_events": 777})
	rs.save(string(files))
	out, res := rs.restart()
	if !res.OK || out["confirm_within_s"] == nil {
		t.Fatalf("restart %+v %v", res, out)
	}
	waitFor(t, "the move to be undone", func() bool {
		st := rs.r.RestartStatus()
		return st.Last != nil && st.Last.Reverted && !st.InProgress
	})
	last := rs.r.RestartStatus().Last
	refused := slices.Clone(last.Refused)
	slices.Sort(refused)
	if !last.OK || strings.Join(refused, ",") != "server.tls.mode,server.tls_cert,server.tls_key" {
		t.Errorf("reverted %+v", last)
	}
	c, err := config.Load(rs.r.path)
	if err != nil || c.SettingsProblem() != "" || c.Server.HTTPS() || c.Search.MaxEvents != 777 {
		t.Fatalf("the next start: %v %q https %v max_events %d", err, c.SettingsProblem(), c.Server.HTTPS(), c.Search.MaxEvents)
	}
	// The page still saves, and a restart is not blocked.
	rs.save(`{"search.max_events":800}`)
	if _, res := rs.restart(); !res.OK {
		t.Errorf("restart after going back %+v", res)
	}
}

// port is the port of a host:port address.
func port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// The Security page and a restart in place: switching certificate
// authority needs no restart, and a restart keeps the one switched to,
// the last report and the heartbeat's summary.
func TestSecurityAcrossARestartInPlace(t *testing.T) {
	rs := startRunnerWith(t, runOptions{server: "  tls:\n    mode: auto\n"})
	oldCA := rs.ownCA()
	if code, out, err := rs.call("", "GET", "/api/security", ""); err != nil || code != 200 || out["checks"] == nil {
		t.Fatalf("report: %d %v %v", code, out, err)
	}
	if code, out, _ := rs.call("", "POST", "/api/security/ca", `{"action":"prepare","scope":"strict"}`); code != 200 {
		t.Fatalf("prepare: %d %v", code, out)
	}
	nextPEM, err := os.ReadFile(filepath.Join(rs.dir, "tls", "next", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	// A browser that trusts both, as one given the new one beforehand.
	rs.useHTTPS(append(slices.Clone(oldCA), nextPEM...))
	if code, out, _ := rs.call("", "POST", "/api/security/ca", `{"action":"switch"}`); code != 200 {
		t.Fatalf("switch: %d %v", code, out)
	}
	newFP := pemFingerprint(t, nextPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(nextPEM)
	if _, err := peerCert(t, rs.addr).Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("the new certificate authority is not in use at once: %v", err)
	}
	// A restart in place, with a name the strict one doesn't cover.
	rs.save(`{"server.tls.names":["siem-alias.lan"]}`)
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart: %+v\n%s", res, rs.logs.String())
	}
	if got := pemFingerprint(t, rs.ownCA()); got != newFP {
		t.Error("the restart went back to the old certificate authority")
	}
	if _, err := peerCert(t, rs.addr).Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("after the restart: %v", err)
	}
	code, out, _ := rs.call("", "GET", "/api/security", "")
	ca, _ := out["ca"].(map[string]any)
	if code != 200 || ca == nil || ca["previous"] == nil || ca["current"].(map[string]any)["scope"] != "strict" {
		t.Fatalf("report after the restart: %d %v", code, out["ca"])
	}
	// The heartbeat sums up the last report.
	var sec *cluster.SecuritySummary
	for _, s := range rs.r.node.Status().Servers {
		if s.Self && s.Detail != nil {
			sec = s.Detail.Security
		}
	}
	if sec == nil || sec.CheckedAt == nil || sec.CAScope != "strict" {
		t.Errorf("heartbeat: %+v", sec)
	}
}
