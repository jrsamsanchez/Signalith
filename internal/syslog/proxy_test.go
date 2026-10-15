package syslog

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/proxyproto"
)

var balancer = &proxyproto.Config{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}

// viaBalancer connects to the receiver as a load balancer would, naming
// device as the sender.
func viaBalancer(t *testing.T, to, device string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", to)
	if err != nil {
		t.Fatal(err)
	}
	h := proxyproto.Header{Src: netip.MustParseAddrPort(device + ":40000"), Dst: netip.MustParseAddrPort("192.0.2.1:514")}
	if _, err := c.Write(proxyproto.AppendV2(nil, h)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProxyTCPSeesTheDevice(t *testing.T) {
	bulk := &capture{}
	cfg := Config{TCP: "127.0.0.1:0", Proxy: balancer, MaxConnections: 10, MaxConnectionsPerSender: 2,
		Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.1/32")}}
	r, _, _ := start(t, cfg, bulk)
	to := addr(t, r, "tcp")

	c := viaBalancer(t, to, "10.1.2.3")
	defer c.Close()
	fmt.Fprint(c, "<13>Oct 12 13:00:00 fw1 app: through the balancer\n")
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
	if d := bulk.all()[0].Doc; d["dvc"] != "10.1.2.3" {
		t.Errorf("dvc = %v, want the device", d["dvc"])
	}
	if s := r.Stats(); s.Senders[0].Address != "10.1.2.3" {
		t.Errorf("senders = %+v", s.Senders)
	}

	// syslog.allow is checked against the device.
	out := viaBalancer(t, to, "192.168.7.7")
	defer out.Close()
	if !closedByServer(out) {
		t.Error("a device outside syslog.allow got in through the balancer")
	}

	// The per-sender limit counts the device, not the balancer.
	c2 := viaBalancer(t, to, "10.1.2.3")
	defer c2.Close()
	waitFor(t, "two connections", func() bool { return r.Stats().Connections == 2 })
	c3 := viaBalancer(t, to, "10.1.2.3")
	defer c3.Close()
	if !closedByServer(c3) {
		t.Error("a third connection from one device stayed open")
	}
	other := viaBalancer(t, to, "10.9.9.9")
	defer other.Close()
	fmt.Fprint(other, "<13>Oct 12 13:00:00 sw2 app: another device\n")
	waitFor(t, "the other device's event", func() bool { return bulk.count() == 2 })

	// The balancer itself may connect without a header.
	self, err := net.Dial("tcp", to)
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	fmt.Fprint(self, "<13>Oct 12 13:00:00 lb app: no header\n")
	waitFor(t, "the balancer's own event", func() bool { return bulk.count() == 3 })
	if d := bulk.all()[2].Doc; d["dvc"] != "127.0.0.1" {
		t.Errorf("dvc = %v, want the balancer", d["dvc"])
	}
	s := r.Stats()
	if s.RejectedBy.NotAllowed != 1 || s.RejectedBy.TooManyFromSender != 1 || s.RejectedBy.ProxyUntrusted != 0 {
		t.Errorf("rejections = %+v", s.RejectedBy)
	}
}

func TestProxyHeaderFromUntrustedPeer(t *testing.T) {
	bulk := &capture{}
	cfg := Config{TCP: "127.0.0.1:0", Proxy: &proxyproto.Config{Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}}}
	r, _, _ := start(t, cfg, bulk)
	c := viaBalancer(t, addr(t, r, "tcp"), "10.1.2.3")
	defer c.Close()
	fmt.Fprint(c, "<13>Oct 12 13:00:00 fw1 app: forged\n")
	if !closedByServer(c) {
		t.Fatal("a PROXY header from an untrusted peer was accepted")
	}
	waitFor(t, "the count", func() bool { return r.Stats().RejectedBy.ProxyUntrusted == 1 })
	if s := r.Stats(); s.Rejected != 1 || bulk.count() != 0 {
		t.Errorf("stats = %+v, events %d", s, bulk.count())
	}
	// Plain syslog from the same peer still works.
	p, _ := net.Dial("tcp", addr(t, r, "tcp"))
	defer p.Close()
	fmt.Fprint(p, "<13>Oct 12 13:00:00 h app: plain\n")
	waitFor(t, "the plain event", func() bool { return bulk.count() == 1 })
}

// The header comes before TLS, as a balancer passing TLS through sends it.
func TestProxyBeforeTLS(t *testing.T) {
	certFile, keyFile := writeCert(t)
	bulk := &capture{}
	r, _, _ := start(t, Config{TLS: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile, Proxy: balancer}, bulk)
	pemBytes, _ := os.ReadFile(certFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	raw := viaBalancer(t, addr(t, r, "tls"), "10.4.4.4")
	c := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	defer c.Close()
	fmt.Fprint(c, "<13>Oct 12 13:00:00 fw1 app: over TLS\n")
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
	if d := bulk.all()[0].Doc; d["dvc"] != "10.4.4.4" {
		t.Errorf("dvc = %v", d["dvc"])
	}
}
