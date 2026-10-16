package syslog

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// capture is a Bulker that keeps what it is sent. When block is set,
// Bulk waits for it to close first.
type capture struct {
	mu    sync.Mutex
	docs  []store.IndexedDoc
	block chan struct{}
}

func (c *capture) Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	if c.block != nil {
		select {
		case <-c.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.docs = append(c.docs, docs...)
	return nil, nil
}

func (c *capture) all() []store.IndexedDoc {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]store.IndexedDoc{}, c.docs...)
}

func (c *capture) count() int { return len(c.all()) }

// start runs a receiver writing to a pipeline backed by bulk, and stops it
// when the test ends.
func start(t *testing.T, cfg Config, bulk *capture) (*Receiver, *ingest.Pipeline, context.CancelFunc) {
	t.Helper()
	p := &ingest.Pipeline{Store: bulk, Prefix: "sig"}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 20 * time.Millisecond
	}
	r := New(cfg, p, nil)
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		r.Wait()
	})
	return r, p, cancel
}

// addr returns the address a listener of the receiver is bound to.
func addr(t *testing.T, r *Receiver, proto string) string {
	t.Helper()
	for _, l := range r.Stats().Listeners {
		if l.Protocol == proto {
			return l.Address
		}
	}
	t.Fatalf("no %s listener in %+v", proto, r.Stats().Listeners)
	return ""
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sendUDP(t *testing.T, to string, msgs ...string) {
	t.Helper()
	c, err := net.Dial("udp", to)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, m := range msgs {
		if _, err := c.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUDP(t *testing.T) {
	bulk := &capture{}
	r, p, _ := start(t, Config{UDP: "127.0.0.1:0"}, bulk)
	sendUDP(t, addr(t, r, "udp"), "<38>1 2026-10-12T13:59:00Z web1 sshd 811 - - Failed password for root from 192.0.2.4 port 40122 ssh2\n")
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
	d := bulk.all()[0]
	if d.Index != "sig-authentication-2026.10.12" {
		t.Errorf("index = %s", d.Index)
	}
	check(t, "udp", d.Doc, map[string]any{"user": "root", "action": "failure", "host": "web1", "dvc": "127.0.0.1", "sourcetype": "syslog", "app": "sshd"})
	s := r.Stats()
	if !s.Enabled || s.Received != 1 || s.Dropped != 0 || s.Rejected != 0 || s.LastMessage.IsZero() {
		t.Errorf("stats = %+v", s)
	}
	if len(s.Senders) != 1 || s.Senders[0].Address != "127.0.0.1" || s.Senders[0].Host != "web1" || s.Senders[0].Protocol != "udp" || s.Senders[0].Messages != 1 {
		t.Errorf("senders = %+v", s.Senders)
	}
	if ps := p.Stats(); ps.Received != 1 || ps.Indexed != 1 {
		t.Errorf("pipeline stats = %+v", ps)
	}
}

func TestTCPFramingOnOneConnection(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{TCP: "127.0.0.1:0"}, bulk)
	c, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	octet := "<13>1 2026-10-12T13:00:00Z h app - - - two\nlines"
	stream := "<13>Oct 12 13:00:00 h app: first\n" + fmt.Sprintf("%d %s", len(octet), octet) + "<13>Oct 12 13:00:01 h app: third\n"
	for i := 0; i < len(stream); i += 7 { // partial writes
		end := min(i+7, len(stream))
		if _, err := c.Write([]byte(stream[i:end])); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "three events", func() bool { return bulk.count() == 3 })
	docs := bulk.all()
	for i, want := range []string{"<13>Oct 12 13:00:00 h app: first", octet, "<13>Oct 12 13:00:01 h app: third"} {
		if docs[i].Doc["message"] != want {
			t.Errorf("event %d message = %q, want %q", i, docs[i].Doc["message"], want)
		}
	}
	if s := r.Stats(); s.Connections != 1 || s.Senders[0].Protocol != "tcp" {
		t.Errorf("stats = %+v", s)
	}
}

func writeCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "signalith test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}

func TestTLS(t *testing.T) {
	certFile, keyFile := writeCert(t)
	bulk := &capture{}
	r, _, _ := start(t, Config{TLS: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile}, bulk)
	pemBytes, _ := os.ReadFile(certFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	c, err := tls.Dial("tcp", addr(t, r, "tls"), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	msg := "<86>1 2026-10-12T13:00:00Z web1 useradd 900 - - new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash"
	fmt.Fprintf(c, "%d %s", len(msg), msg)
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
	c.Close()
	d := bulk.all()[0]
	if d.Index != "sig-change-2026.10.12" || d.Doc["object"] != "backdoor" {
		t.Errorf("event = %s %v", d.Index, d.Doc)
	}
	if s := r.Stats(); s.Senders[0].Protocol != "tls" {
		t.Errorf("senders = %+v", s.Senders)
	}

	// Plain text to the TLS port is not syslog.
	plain, err := net.Dial("tcp", addr(t, r, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(plain, "<13>Oct 12 13:00:00 h app: not encrypted\n")
	plain.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.Copy(io.Discard, plain) // the server hangs up
	plain.Close()
	if bulk.count() != 1 {
		t.Errorf("plain text over the TLS port was accepted")
	}
}

// With Signalith's own certificate: senders trust its CA, and a renewed
// certificate is served without a restart.
func TestTLSWithCertificateManager(t *testing.T) {
	m, err := tlsauto.New(tlsauto.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	bulk := &capture{}
	r, _, _ := start(t, Config{TLS: "127.0.0.1:0", GetCertificate: m.GetCertificate}, bulk)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(m.CAPEM())
	send := func() *x509.Certificate {
		c, err := tls.Dial("tcp", addr(t, r, "tls"), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		msg := "<86>1 2026-10-12T13:00:00Z web1 sshd 900 - - Accepted password for bob from 192.0.2.4 port 22 ssh2"
		fmt.Fprintf(c, "%d %s", len(msg), msg)
		return c.ConnectionState().PeerCertificates[0]
	}
	first := send()
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
	if err := m.EnsureName("syslog.corp.lan"); err != nil {
		t.Fatal(err)
	}
	if second := send(); second.SerialNumber.Cmp(first.SerialNumber) == 0 || second.VerifyHostname("syslog.corp.lan") != nil {
		t.Error("the new certificate is not served")
	}
	waitFor(t, "the second event", func() bool { return bulk.count() == 2 })
}

// The name a TLS sender asked for is heard once per connection, and only
// after it sends syslog: a bare handshake doesn't count.
func TestTLSNameAfterFirstMessage(t *testing.T) {
	m, err := tlsauto.New(tlsauto.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureName("syslog.corp.lan"); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var names []string
	bulk := &capture{}
	r, _, _ := start(t, Config{TLS: "127.0.0.1:0", GetCertificate: m.GetCertificate, OnTLSName: func(n string) {
		mu.Lock()
		names = append(names, n)
		mu.Unlock()
	}}, bulk)
	heard := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, names...)
	}
	c, err := tls.Dial("tcp", addr(t, r, "tls"), &tls.Config{InsecureSkipVerify: true, ServerName: "stranger.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(m.CAPEM())
	c, err = tls.Dial("tcp", addr(t, r, "tls"), &tls.Config{RootCAs: pool, ServerName: "syslog.corp.lan"})
	if err != nil {
		t.Fatal(err)
	}
	msg := "<86>1 2026-10-12T13:00:00Z web1 sshd 900 - - Accepted password for bob from 192.0.2.4 port 22 ssh2"
	fmt.Fprintf(c, "%d %s%d %s", len(msg), msg, len(msg), msg)
	waitFor(t, "the events", func() bool { return bulk.count() == 2 })
	c.Close()
	if got := heard(); len(got) != 1 || got[0] != "syslog.corp.lan" {
		t.Errorf("%v", got)
	}
}

func TestTLSNeedsCertificate(t *testing.T) {
	r := New(Config{TLS: "127.0.0.1:0", CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"}, &ingest.Pipeline{Store: &capture{}}, nil)
	err := r.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "server.tls_cert") {
		t.Errorf("err = %v", err)
	}
}

func TestAllowList(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0", Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, bulk)
	sendUDP(t, addr(t, r, "udp"), "<13>Oct 12 13:00:00 h app: from outside")
	waitFor(t, "the UDP rejection", func() bool { return r.Stats().RejectedBy.NotAllowed == 1 })
	c, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection from a sender outside the allow list stayed open")
	}
	c.Close()
	s := r.Stats()
	if s.RejectedBy.NotAllowed != 2 || s.Rejected != 2 || s.Received != 0 || len(s.Senders) != 0 || bulk.count() != 0 {
		t.Errorf("stats = %+v, events %d", s, bulk.count())
	}
	// The health page names the sender to add to syslog.allow.
	if s.LastNotAllowed != "127.0.0.1" {
		t.Errorf("last not allowed = %q", s.LastNotAllowed)
	}

	bulk2 := &capture{}
	r2, _, _ := start(t, Config{UDP: "127.0.0.1:0", Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, bulk2)
	sendUDP(t, addr(t, r2, "udp"), "<13>Oct 12 13:00:00 h app: allowed")
	waitFor(t, "the allowed event", func() bool { return bulk2.count() == 1 })
}

func TestFullQueueDropsUDP(t *testing.T) {
	bulk := &capture{block: make(chan struct{})}
	r, p, _ := start(t, Config{UDP: "127.0.0.1:0", QueueSize: 5, BatchSize: 1, FlushInterval: 5 * time.Millisecond}, bulk)
	var msgs []string
	for i := range 50 {
		msgs = append(msgs, fmt.Sprintf("<13>Oct 12 13:00:00 h app: message %d", i))
	}
	sendUDP(t, addr(t, r, "udp"), msgs...)
	waitFor(t, "all 50 to be read", func() bool { return r.Stats().Received == 50 })
	s := r.Stats()
	// One batch is stuck in OpenSearch and five wait in the queue.
	if s.Dropped < 40 || s.Dropped > 45 {
		t.Errorf("dropped = %d", s.Dropped)
	}
	close(bulk.block)
	waitFor(t, "the rest to be written", func() bool { return p.Stats().Indexed == 50-s.Dropped })
}

func TestTCPWaitsWhenQueueIsFull(t *testing.T) {
	bulk := &capture{block: make(chan struct{})}
	r, p, _ := start(t, Config{TCP: "127.0.0.1:0", QueueSize: 2, BatchSize: 1, FlushInterval: 5 * time.Millisecond}, bulk)
	c, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 20 {
		fmt.Fprintf(c, "<13>Oct 12 13:00:00 h app: message %d\n", i)
	}
	time.Sleep(100 * time.Millisecond)
	if s := r.Stats(); s.Dropped != 0 || s.Received > 5 {
		t.Errorf("while blocked: %+v", s)
	}
	close(bulk.block)
	waitFor(t, "all 20", func() bool { return p.Stats().Indexed == 20 })
	if s := r.Stats(); s.Dropped != 0 {
		t.Errorf("dropped = %d", s.Dropped)
	}
}

func TestWaitsUntilReady(t *testing.T) {
	ready := make(chan struct{})
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", Ready: ready}, bulk)
	sendUDP(t, addr(t, r, "udp"), "<13>Oct 12 13:00:00 h app: early")
	waitFor(t, "the message", func() bool { return r.Stats().Received == 1 })
	time.Sleep(50 * time.Millisecond)
	if bulk.count() != 0 {
		t.Fatal("written before the index template was ready")
	}
	close(ready)
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
}

func TestStopFlushesTheQueue(t *testing.T) {
	bulk := &capture{}
	r, _, cancel := start(t, Config{TCP: "127.0.0.1:0", FlushInterval: time.Hour, BatchSize: 1000}, bulk)
	c, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		fmt.Fprintf(c, "<13>Oct 12 13:00:00 h app: message %d\n", i)
	}
	waitFor(t, "three messages", func() bool { return r.Stats().Received == 3 })
	if bulk.count() != 0 {
		t.Fatal("flushed early")
	}
	cancel()
	r.Wait()
	if bulk.count() != 3 {
		t.Errorf("after stop: %d events written", bulk.count())
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection still open after stop")
	}
	c.Close()
}

func TestLimits(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0", MaxMessageSize: 100, MaxConnections: 1, IdleTimeout: 300 * time.Millisecond}, bulk)
	sendUDP(t, addr(t, r, "udp"), "<13>"+strings.Repeat("x", 200))
	waitFor(t, "the too-large UDP message", func() bool { return r.Stats().RejectedBy.TooLarge == 1 })

	a, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	fmt.Fprintf(a, "<13>%s\n<13>Oct 12 13:00:00 h app: fits\n", strings.Repeat("y", 200))
	waitFor(t, "the fitting message", func() bool { return bulk.count() == 1 })
	if s := r.Stats(); s.RejectedBy.TooLarge != 2 || s.Connections != 1 {
		t.Errorf("stats = %+v", s)
	}

	b, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Error("connection over the limit stayed open")
	}
	b.Close()
	if s := r.Stats(); s.RejectedBy.TooManyConnections != 1 {
		t.Errorf("too many connections = %d", s.RejectedBy.TooManyConnections)
	}

	// The idle connection is closed, which frees its slot.
	a.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Error("idle connection stayed open")
	}
	waitFor(t, "the slot to free", func() bool { return r.Stats().Connections == 0 })

	bad, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	fmt.Fprint(bad, "123456789 <13>x")
	waitFor(t, "the framing error", func() bool { return r.Stats().RejectedBy.BadFraming == 1 })
}

func TestBindErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for _, cfg := range []Config{{TCP: ln.Addr().String()}, {UDP: pc.LocalAddr().String()}, {UDP: "127.0.0.1:0", TCP: ln.Addr().String()}} {
		err := New(cfg, &ingest.Pipeline{Store: &capture{}}, nil).Start(context.Background())
		if err == nil || !strings.Contains(err.Error(), "already in use") || !strings.Contains(err.Error(), "1514") {
			t.Errorf("%+v: err = %v", cfg, err)
		}
	}

	denied := &net.OpError{Op: "listen", Net: "udp", Err: os.NewSyscallError("bind", syscall.EACCES)}
	msg := bindError("syslog.udp", "udp", "0.0.0.0:514", denied).Error()
	for _, want := range []string{"syslog.udp", "0.0.0.0:514", "permission denied", "CAP_NET_BIND_SERVICE", "deploy/systemd", "setcap", "0.0.0.0:1514"} {
		if !strings.Contains(msg, want) {
			t.Errorf("permission error lacks %q: %s", want, msg)
		}
	}
	other := bindError("syslog.tcp", "tcp", "10.9.9.9:514", errors.New("cannot assign requested address")).Error()
	if !strings.Contains(other, "syslog.tcp: cannot listen on 10.9.9.9:514/tcp: cannot assign requested address") {
		t.Errorf("other error = %s", other)
	}
}

func TestNilReceiver(t *testing.T) {
	var r *Receiver
	s := r.Stats()
	if s.Enabled || s.Listeners == nil || s.Allow == nil || s.Senders == nil {
		t.Errorf("stats = %+v", s)
	}
	r.Wait()
}

// TestStatsSayWhereToSend checks what the Add data page builds the setup
// from: the port senders use for each listener, and who may send.
func TestStatsSayWhereToSend(t *testing.T) {
	certFile, keyFile := writeCert(t)
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0", TLS: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile}, &capture{})
	s := r.Stats()
	if len(s.Listeners) != 3 || len(s.Allow) != 0 || s.Allow == nil {
		t.Fatalf("stats = %+v", s)
	}
	for _, l := range s.Listeners {
		if _, port, _ := net.SplitHostPort(l.Address); port != fmt.Sprint(l.Port) || l.Port == 0 {
			t.Errorf("%s listener on %s, port %d: want the port listened on", l.Protocol, l.Address, l.Port)
		}
	}

	// Forwarded (Docker publishes 514 as 5514): UDP and TCP senders use
	// the public port; TLS keeps its own.
	allow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("2001:db8::1/128")}
	r, _, _ = start(t, Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0", TLS: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile, PublicPort: 514, Allow: allow}, &capture{})
	s = r.Stats()
	got := map[string]int{}
	for _, l := range s.Listeners {
		got[l.Protocol] = l.Port
	}
	_, tlsPort, _ := net.SplitHostPort(addr(t, r, "tls"))
	if got["udp"] != 514 || got["tcp"] != 514 || fmt.Sprint(got["tls"]) != tlsPort {
		t.Errorf("ports = %v, TLS listens on %s", got, tlsPort)
	}
	if strings.Join(s.Allow, " ") != "10.0.0.0/8 192.0.2.7 2001:db8::1" {
		t.Errorf("allow = %q", s.Allow)
	}
}

func TestSenderTableKeepsTheMostRecent(t *testing.T) {
	st := senderTable{max: 3, m: map[netip.Addr]*Sender{}}
	for i := range 5 {
		st.seen(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), "", "udp", now.Add(time.Duration(i)*time.Second))
	}
	st.seen(netip.AddrFrom4([4]byte{10, 0, 0, 2}), "h2", "tcp", now.Add(time.Minute))
	got := st.list()
	if len(got) != 3 || got[0].Address != "10.0.0.2" || got[0].Messages != 2 || got[0].Host != "h2" || got[1].Address != "10.0.0.4" || got[2].Address != "10.0.0.3" {
		t.Errorf("senders = %+v", got)
	}
}

// TestLoggerClient sends with the util-linux logger command, the way a
// Linux server without an agent forwards its logs, in every framing it
// supports.
func TestLoggerClient(t *testing.T) {
	logger, err := exec.LookPath("logger")
	if err != nil {
		t.Skip("logger (util-linux) not installed")
	}
	if out, err := exec.Command(logger, "--help").CombinedOutput(); err != nil || !strings.Contains(string(out), "--server") {
		t.Skip("this logger cannot send to a server")
	}
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0"}, bulk)
	modes := [][]string{
		{"--udp", "--rfc3164"},
		{"--udp", "--rfc5424"},
		{"--tcp", "--rfc3164"},
		{"--tcp", "--rfc5424"},
		{"--tcp", "--rfc5424", "--octet-count"},
	}
	for i, mode := range modes {
		proto := strings.TrimPrefix(mode[0], "--")
		_, port, _ := net.SplitHostPort(addr(t, r, proto))
		args := append([]string{"--server", "127.0.0.1", "--port", port, "-t", "sshd", "--id=4242"}, mode[1:]...)
		args = append(args, mode[0], fmt.Sprintf("Failed password for invalid user oracle%d from 192.0.2.4 port 4022 ssh2", i))
		if out, err := exec.Command(logger, args...).CombinedOutput(); err != nil {
			t.Fatalf("logger %v: %v %s", args, err, out)
		}
		waitFor(t, fmt.Sprintf("logger %v", mode), func() bool { return bulk.count() == i+1 })
		d := bulk.all()[i]
		check(t, strings.Join(mode, " "), d.Doc, map[string]any{
			"datamodel": "Authentication", "action": "failure", "user": fmt.Sprintf("oracle%d", i), "src": "192.0.2.4",
			"app": "sshd", "process_id": int64(4242), "dvc": "127.0.0.1", "facility": "user", "severity": "notice",
		})
		if !strings.HasPrefix(d.Index, "sig-authentication-") {
			t.Errorf("%v: index %s", mode, d.Index)
		}
	}
}

// startWith runs a receiver writing to sink after setup has adjusted it,
// and stops it when the test ends.
func startWith(t *testing.T, cfg Config, sink Sink, setup func(*Receiver)) (*Receiver, context.CancelFunc) {
	t.Helper()
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 20 * time.Millisecond
	}
	r := New(cfg, sink, nil)
	if setup != nil {
		setup(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		r.Wait()
	})
	return r, cancel
}

// sink is a Sink that records batch sizes, optionally taking delay per
// call or failing, or hanging until the write is cancelled.
type sink struct {
	mu      sync.Mutex
	batches []int
	delay   time.Duration
	hang    bool
	fail    error
	reject  bool // OpenSearch refuses every event
}

func (s *sink) IngestEvents(ctx context.Context, events []ingest.Event) (*ingest.Result, error) {
	if s.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	time.Sleep(s.delay)
	s.mu.Lock()
	s.batches = append(s.batches, len(events))
	s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	if s.reject {
		// The result lists only the first few errors.
		res := &ingest.Result{Received: len(events), Rejected: len(events)}
		for i := range min(len(events), 10) {
			res.Errors = append(res.Errors, store.BulkItemError{Pos: i, Reason: "mapper_parsing_exception"})
		}
		return res, nil
	}
	return &ingest.Result{Received: len(events), Indexed: len(events)}, nil
}

// TestRejectedEventsAreAllCounted: a result lists only the first few
// rejected events, so the not-written count uses the full count.
func TestRejectedEventsAreAllCounted(t *testing.T) {
	sk := &sink{reject: true}
	r, _ := startWith(t, Config{UDP: "127.0.0.1:0"}, sk, nil)
	var msgs []string
	for i := range 25 {
		msgs = append(msgs, fmt.Sprintf("<13>1 - h app - - - event %d", i))
	}
	sendUDP(t, addr(t, r, "udp"), msgs...)
	waitFor(t, "all 25 counted as not written", func() bool { return r.Stats().WriteFailed == 25 })
}

func (s *sink) sizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int{}, s.batches...)
}

// TestOldTimestampsCannotCreateIndices sends messages naming many distinct
// old days; they all go to today's index, so a sender cannot use up the
// cluster's shards.
func TestOldTimestampsCannotCreateIndices(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0"}, bulk)
	var msgs []string
	for i := range 300 {
		day := time.Date(2001, 1, 1, 12, 0, 0, 0, time.UTC).AddDate(0, 0, 7*i)
		msgs = append(msgs, fmt.Sprintf("<13>1 %s h app - - - old %d", day.Format(time.RFC3339), i))
	}
	msgs = append(msgs, "<134>CEF:0|V|P|1|1|N|3|rt=978307200000 src=10.0.0.1 dst=10.0.0.2")
	sendUDP(t, addr(t, r, "udp"), msgs...)
	waitFor(t, "all messages", func() bool { return bulk.count() == len(msgs) })
	indices := map[string]bool{}
	for _, d := range bulk.all() {
		indices[d.Index] = true
		if d.Doc["device_time"] == nil {
			t.Fatalf("device time not kept: %v", d.Doc)
		}
	}
	// Other and Network_Traffic for today (two if the test spans midnight).
	if len(indices) > 4 {
		t.Errorf("%d indices: %v", len(indices), indices)
	}
}

// TestNoTinyBatchesAfterASlowWrite checks that the flush interval counts
// from the end of a write: a write slower than the interval must not be
// followed by a near-empty one.
func TestNoTinyBatchesAfterASlowWrite(t *testing.T) {
	ready := make(chan struct{})
	sk := &sink{delay: 60 * time.Millisecond}
	r, _ := startWith(t, Config{UDP: "127.0.0.1:0", Ready: ready, BatchSize: 100, FlushInterval: 20 * time.Millisecond}, sk, nil)
	for i := range 1000 {
		r.handle(context.Background(), fmt.Appendf(nil, "<13>Oct 12 13:00:00 h app: message %d", i), sender, "udp", true)
	}
	close(ready)
	waitFor(t, "all batches", func() bool {
		n := 0
		for _, b := range sk.sizes() {
			n += b
		}
		return n == 1000
	})
	if got := sk.sizes(); len(got) != 10 {
		t.Errorf("batches %v, want 10 of 100", got)
	}
}

// TestShutdownDeadline stops a receiver whose OpenSearch hangs: Wait must
// return by the deadline, and what was not written is counted.
func TestShutdownDeadline(t *testing.T) {
	sk := &sink{hang: true}
	r, cancel := startWith(t, Config{UDP: "127.0.0.1:0", BatchSize: 100}, sk, func(r *Receiver) { r.finalFlush = 300 * time.Millisecond })
	for i := range 1200 {
		r.handle(context.Background(), fmt.Appendf(nil, "<13>Oct 12 13:00:00 h app: message %d", i), sender, "udp", true)
	}
	time.Sleep(50 * time.Millisecond) // the first write is in progress
	began := time.Now()
	cancel()
	r.Wait()
	if took := time.Since(began); took > 2*time.Second {
		t.Errorf("shutdown took %v", took)
	}
	s := r.Stats()
	if s.Dropped+s.WriteFailed != 1200 || s.WriteFailed == 0 || s.Dropped == 0 {
		t.Errorf("received %d dropped %d write_failed %d", s.Received, s.Dropped, s.WriteFailed)
	}
}

func TestWriteFailuresAreCounted(t *testing.T) {
	sk := &sink{fail: errors.New("opensearch is down")}
	r, _ := startWith(t, Config{UDP: "127.0.0.1:0"}, sk, nil)
	sendUDP(t, addr(t, r, "udp"), "<13>Oct 12 13:00:00 h app: one", "<13>Oct 12 13:00:00 h app: two")
	waitFor(t, "the failures", func() bool { return r.Stats().WriteFailed == 2 })
	if s := r.Stats(); s.Dropped != 0 {
		t.Errorf("stats = %+v", s)
	}
}

// dialFrom connects from a given loopback address, or skips the test when
// the system cannot (only Linux routes all of 127.0.0.0/8 by default).
func dialFrom(t *testing.T, from, to string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", to)
	if err != nil {
		t.Skipf("cannot connect from %s: %v", from, err)
	}
	return c
}

func closedByServer(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// TestOneSenderCannotTakeAllConnections opens more connections from one
// address than it may have; another address can still connect.
func TestOneSenderCannotTakeAllConnections(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{TCP: "127.0.0.1:0", MaxConnections: 10, MaxConnectionsPerSender: 3}, bulk)
	to := addr(t, r, "tcp")
	var conns []net.Conn
	for range 3 {
		c := dialFrom(t, "127.0.0.1", to)
		defer c.Close()
		conns = append(conns, c)
	}
	waitFor(t, "three connections", func() bool { return r.Stats().Connections == 3 })
	extra := dialFrom(t, "127.0.0.1", to)
	defer extra.Close()
	if !closedByServer(extra) {
		t.Error("connection over the per-sender limit stayed open")
	}
	other := dialFrom(t, "127.0.0.2", to)
	defer other.Close()
	fmt.Fprint(other, "<13>Oct 12 13:00:00 h app: from another sender\n")
	waitFor(t, "the other sender's message", func() bool { return bulk.count() == 1 })
	if s := r.Stats(); s.RejectedBy.TooManyFromSender != 1 || s.RejectedBy.TooManyConnections != 0 || s.Rejected != 1 {
		t.Errorf("stats = %+v", s.RejectedBy)
	}
}

// TestQuietConnectionsMakeRoom fills the connection limit with quiet
// connections; a new one still gets in by closing the quietest.
func TestQuietConnectionsMakeRoom(t *testing.T) {
	bulk := &capture{}
	r, _ := startWith(t, Config{TCP: "127.0.0.1:0", MaxConnections: 2}, &ingest.Pipeline{Store: bulk, Prefix: "sig"}, func(r *Receiver) { r.evictAfter = 100 * time.Millisecond })
	to := addr(t, r, "tcp")
	first := dialFrom(t, "127.0.0.1", to)
	defer first.Close()
	time.Sleep(20 * time.Millisecond)
	second := dialFrom(t, "127.0.0.1", to)
	defer second.Close()
	waitFor(t, "two connections", func() bool { return r.Stats().Connections == 2 })

	// Both are too recent to close: the new one is refused.
	early := dialFrom(t, "127.0.0.1", to)
	defer early.Close()
	if !closedByServer(early) {
		t.Fatal("connection over the limit stayed open")
	}
	time.Sleep(150 * time.Millisecond)
	fmt.Fprint(second, "<13>Oct 12 13:00:00 h app: still here\n") // second is no longer quiet
	waitFor(t, "the message", func() bool { return bulk.count() == 1 })
	late := dialFrom(t, "127.0.0.1", to)
	defer late.Close()
	fmt.Fprint(late, "<13>Oct 12 13:00:00 h app: got in\n")
	waitFor(t, "the new connection's message", func() bool { return bulk.count() == 2 })
	if !closedByServer(first) {
		t.Error("the quietest connection was not closed")
	}
	if s := r.Stats(); s.Connections != 2 || s.RejectedBy.TooManyConnections != 1 {
		t.Errorf("stats = %+v", s)
	}
}

// TestUnfinishedMessagesTimeOut: a message must be finished within the
// message timeout of its first byte, even if bytes keep trickling in.
func TestUnfinishedMessagesTimeOut(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{TCP: "127.0.0.1:0", MessageTimeout: 300 * time.Millisecond}, bulk)
	to := addr(t, r, "tcp")

	trickle := dialFrom(t, "127.0.0.1", to)
	defer trickle.Close()
	began := time.Now()
	go func() {
		for _, b := range []byte("500 <13>trickling one byte at a time") {
			if _, err := trickle.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	if !closedByServer(trickle) {
		t.Fatal("trickling connection stayed open")
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Errorf("closed after %v", took)
	}

	// A last line without a newline is written when the time is up.
	open := dialFrom(t, "127.0.0.1", to)
	defer open.Close()
	fmt.Fprint(open, "<13>Oct 12 13:00:00 h app: complete\n<13>Oct 12 13:00:01 h app: no newline")
	if !closedByServer(open) {
		t.Fatal("connection with an unfinished line stayed open")
	}
	waitFor(t, "both lines", func() bool { return bulk.count() == 2 })

	// Between messages, only the idle timeout applies.
	quiet := dialFrom(t, "127.0.0.1", to)
	defer quiet.Close()
	fmt.Fprint(quiet, "<13>Oct 12 13:00:00 h app: then quiet\n")
	quiet.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	if _, err := quiet.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("quiet connection: %v", err)
	}
}

func TestSenderHostIsCapped(t *testing.T) {
	r := New(Config{}, &sink{}, nil)
	r.handle(context.Background(), []byte("<13>1 - "+strings.Repeat("h", 60000)+" app - - - hi"), sender, "udp", false)
	if s := r.senders.list(); len(s) != 1 || len(s[0].Host) != 255 {
		t.Errorf("sender host is %d bytes", len(s[0].Host))
	}
}

type zonedConn struct{ net.Conn }

func (zonedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 5000, Zone: "eth0"}
}

func TestLinkLocalSenderMatchesAllowList(t *testing.T) {
	r := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("fe80::/10")}}, &sink{}, nil)
	from := remoteAddr(zonedConn{})
	if from.Zone() != "" || !r.allowed(from) {
		t.Errorf("%v not allowed", from)
	}
}

// TestIPv6SendersCountedByNetwork: an IPv6 host can pick any address in
// its /64, so the per-sender connection limit and field-name share count
// the /64, not each address (as for the web server; see dos-2).
func TestIPv6SendersCountedByNetwork(t *testing.T) {
	r := New(Config{MaxConnections: 100, MaxConnectionsPerSender: 3}, &ingest.Pipeline{Store: &capture{}}, nil)
	track := func(from string) trackResult {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		return r.track(a, newConnState(netip.MustParseAddr(from)))
	}
	for i := range 3 {
		if got := track(fmt.Sprintf("2001:db8:5:6::%x", i+1)); got != trackOK {
			t.Fatalf("connection %d: %v", i, got)
		}
	}
	if got := track("2001:db8:5:6:ffff::1"); got != trackSenderFull {
		t.Errorf("a fourth address in the same /64: %v, want refused", got)
	}
	if got := track("2001:db8:5:7::1"); got != trackOK {
		t.Errorf("the next /64: %v", got)
	}

	b := newNameBudget(10, 2)
	now := time.Now()
	for i, from := range []string{"2001:db8:5:6::1", "2001:db8:5:6::2", "2001:db8:5:6::3"} {
		e := ingest.Event{Model: "Other", Time: now, Fields: map[string]any{fmt.Sprintf("cef_n%d", i): 1}}
		b.limit(e, netip.MustParseAddr(from), now, DefaultMaxAge)
		if kept := len(e.Fields); kept != map[bool]int{true: 1, false: 0}[i < 2] {
			t.Errorf("name %d from %s kept: %v", i, from, e.Fields)
		}
	}
}

// A sender that doesn't trust the certificate is heard of, by address.
func TestTLSRefusalIsNoted(t *testing.T) {
	certFile, keyFile := writeCert(t)
	refused := make(chan string, 4)
	r, _, _ := start(t, Config{TLS: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile,
		OnRefusal: func(addr string) { refused <- addr }}, &capture{})
	// No CA given: the client refuses the certificate.
	if c, err := tls.Dial("tcp", addr(t, r, "tls"), &tls.Config{ServerName: "127.0.0.1"}); err == nil {
		c.Close()
		t.Fatal("the certificate was trusted")
	}
	select {
	case a := <-refused:
		if !strings.HasPrefix(a, "127.0.0.1") {
			t.Errorf("address %q", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the refusal was not noted")
	}
	// Plain text is no refusal.
	plain, err := net.Dial("tcp", addr(t, r, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(plain, "<13>Oct 12 13:00:00 h app: not encrypted\n")
	plain.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.Copy(io.Discard, plain)
	plain.Close()
	select {
	case a := <-refused:
		t.Errorf("plain text noted as a refusal from %s", a)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRefusedCertificate(t *testing.T) {
	for msg, want := range map[string]bool{
		"remote error: tls: unknown certificate authority": true,
		"remote error: tls: bad certificate":               true,
		// An OpenSSL client's alert over TLS 1.3, sent before it encrypts.
		"local error: tls: bad record MAC":                     true,
		"remote error: tls: protocol version not supported":    false,
		"tls: first record does not look like a TLS handshake": false,
		"read tcp 127.0.0.1:6514->127.0.0.1:5000: i/o timeout": false,
	} {
		if got := refusedCertificate(errors.New(msg)); got != want {
			t.Errorf("%q: %v", msg, got)
		}
	}
}

// Servers that store events share each day's budget of vendor field names:
// each gets an equal part, at least 100, and a sender never more than the
// server's part.
func TestNameBudgetIsSharedByServers(t *testing.T) {
	for _, c := range []struct{ servers, perIndex, perSender int }{
		{1, 600, 150}, {4, 150, 150}, {10, 100, 100}, {0, 600, 150},
	} {
		b := newNameBudget(maxExtraNamesPerIndex, maxExtraNamesPerSender)
		b.servers = func() int { return c.servers }
		if pi, ps := b.shares(); pi != c.perIndex || ps != c.perSender {
			t.Errorf("%d servers: %d per index, %d per sender; want %d and %d", c.servers, pi, ps, c.perIndex, c.perSender)
		}
		// One sender with many names stops at its share.
		now := time.Now()
		fields := map[string]any{}
		for i := range 1000 {
			fields[fmt.Sprintf("cef_x%04d", i)] = 1
		}
		e := ingest.Event{Model: "Other", Time: now, Fields: fields}
		b.limit(e, netip.MustParseAddr("192.0.2.9"), now, DefaultMaxAge)
		if len(e.Fields) != c.perSender {
			t.Errorf("%d servers: one sender kept %d names", c.servers, len(e.Fields))
		}
	}
	// Without Servers the receiver keeps the whole budget.
	r := New(Config{}, nil, nil)
	if pi, ps := r.names.shares(); pi != maxExtraNamesPerIndex || ps != maxExtraNamesPerSender {
		t.Errorf("alone: %d %d", pi, ps)
	}
	r = New(Config{Servers: func() int { return 4 }}, nil, nil)
	if pi, _ := r.names.shares(); pi != 150 {
		t.Errorf("from Config: %d", pi)
	}
}
