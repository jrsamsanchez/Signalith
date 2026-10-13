package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

func sampleMessage() Message {
	f := &findings.Finding{ID: "f-123", Title: "Brute force from 10.0.0.5 <@here> [click](https://evil.example) *bold*\r\nInjected: header",
		DetectionID: "brute-force", Severity: "medium", Urgency: "high", MITRE: []string{"T1110"},
		Entities: map[string]any{"user": "bob", "host": "web1", "src": "10.0.0.5", "dest": "10.0.0.9", "cmdline": "secret"},
		Result:   map[string]any{"risk_score": 85.0, "password": "hunter2"}, Created: t0}
	return NewMessage(f, "https://siem.example.com/#findings")
}

// receiver is an HTTP receiver that records what it gets.
type receiver struct {
	*httptest.Server
	mu     sync.Mutex
	body   []byte
	header http.Header
	status int
	answer string
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{status: 200, answer: "ok"}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.body, r.header = b, req.Header.Clone()
		status, answer := r.status, r.answer
		r.mu.Unlock()
		w.WriteHeader(status)
		io.WriteString(w, answer)
	}))
	t.Cleanup(r.Close)
	return r
}

func TestWebhookBodyAndSignature(t *testing.T) {
	rc := newReceiver(t)
	c := Channel{ID: "h", Name: "SOAR", Type: TypeWebhook, URL: rc.URL + "/hook?token=abc", AllowLoopback: true,
		Headers: map[string]string{"Authorization": "Bearer tok-123456"}, SigningSecret: "sign-me"}
	s := &Senders{Now: func() time.Time { return t0.Add(time.Minute) }}
	if err := s.Send(context.Background(), c, sampleMessage()); err != nil {
		t.Fatal(err)
	}
	if rc.header.Get("Authorization") != "Bearer tok-123456" || rc.header.Get("Content-Type") != "application/json" {
		t.Errorf("headers %v", rc.header)
	}
	if got := rc.header.Get(SignatureHeader); got != Sign("sign-me", rc.body) || !strings.HasPrefix(got, "sha256=") || len(got) != 71 {
		t.Errorf("signature %q", got)
	}
	var b map[string]any
	if err := json.Unmarshal(rc.body, &b); err != nil {
		t.Fatal(err)
	}
	f := b["finding"].(map[string]any)
	if b["version"] != 1.0 || b["type"] != "finding" || b["sent"] != "2026-10-13T09:01:00Z" || f["id"] != "f-123" || f["urgency"] != "high" ||
		f["severity"] != "medium" || f["detection"] != "brute-force" || f["risk_score"] != 85.0 || f["created"] != "2026-10-13T09:00:00Z" ||
		f["link"] != "https://siem.example.com/#findings" || f["mitre"].([]any)[0] != "T1110" || f["sample"] != false {
		t.Errorf("body %s", rc.body)
	}
	ent := f["entities"].(map[string]any)
	if len(ent) != 4 || ent["user"] != "bob" || ent["dest"] != "10.0.0.9" {
		t.Errorf("entities %v", ent)
	}
	// No raw event data, and no line breaks from the title.
	for _, leak := range []string{"hunter2", "cmdline", "secret", "\\r", "\\n"} {
		if strings.Contains(string(rc.body), leak) {
			t.Errorf("body holds %q: %s", leak, rc.body)
		}
	}
}

func TestSlackPayload(t *testing.T) {
	rc := newReceiver(t)
	c := Channel{ID: "s", Name: "#soc", Type: TypeSlack, URL: rc.URL + "/services/T0/B0/xyz", AllowLoopback: true}
	if err := (&Senders{}).Send(context.Background(), c, sampleMessage()); err != nil {
		t.Fatal(err)
	}
	var b struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal(rc.body, &b); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.Text, "High: Brute force from 10.0.0.5 &lt;@here&gt;") || len(b.Blocks) != 3 {
		t.Fatalf("slack %s", rc.body)
	}
	head := b.Blocks[0]["text"].(map[string]any)
	if b.Blocks[0]["type"] != "header" || head["type"] != "plain_text" {
		t.Errorf("header %v", b.Blocks[0])
	}
	fields := b.Blocks[1]["fields"].([]any)
	first := fields[0].(map[string]any)
	if first["type"] != "plain_text" || first["text"] != "Urgency\nHigh (severity medium)" {
		t.Errorf("fields %v", fields)
	}
	btn := b.Blocks[2]["elements"].([]any)[0].(map[string]any)
	if btn["url"] != "https://siem.example.com/#findings" {
		t.Errorf("button %v", btn)
	}
}

func TestTeamsPayload(t *testing.T) {
	rc := newReceiver(t)
	rc.status, rc.answer = 202, ""
	c := Channel{ID: "t", Name: "SOC", Type: TypeTeams, URL: rc.URL + "/workflows/abc", AllowLoopback: true}
	if err := (&Senders{}).Send(context.Background(), c, sampleMessage()); err != nil {
		t.Fatal(err)
	}
	var b struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string         `json:"contentType"`
			Content     map[string]any `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(rc.body, &b); err != nil {
		t.Fatal(err)
	}
	if b.Type != "message" || len(b.Attachments) != 1 || b.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("teams %s", rc.body)
	}
	card := b.Attachments[0].Content
	title := card["body"].([]any)[0].(map[string]any)["text"].(string)
	if card["type"] != "AdaptiveCard" || !strings.Contains(title, `\[click\](https://evil.example) \*bold\*`) || !strings.Contains(title, "&lt;@here&gt;") {
		t.Errorf("card title %q", title)
	}
	act := card["actions"].([]any)[0].(map[string]any)
	if act["type"] != "Action.OpenUrl" || act["url"] != "https://siem.example.com/#findings" {
		t.Errorf("actions %v", act)
	}
}

func TestSendErrorsHideSecrets(t *testing.T) {
	rc := newReceiver(t)
	rc.status, rc.answer = 403, "invalid token tok-123456 for /services/T0/B0/very-secret-token"
	c := Channel{ID: "s", Name: "#soc", Type: TypeSlack, URL: rc.URL + "/services/T0/B0/very-secret-token", AllowLoopback: true}
	err := (&Senders{}).Send(context.Background(), c, sampleMessage())
	var se *SendError
	if err == nil || !strings.Contains(err.Error(), "403 Forbidden") || strings.Contains(err.Error(), "very-secret-token") {
		t.Fatalf("error %v", err)
	}
	if !asSendError(err, &se) || se.Retry {
		t.Errorf("403 is not retried: %+v", se)
	}
	rc.status = 503
	if err := (&Senders{}).Send(context.Background(), c, sampleMessage()); !asSendError(err, &se) || !se.Retry {
		t.Errorf("503 is retried: %v", err)
	}
	// A dead receiver: the URL is not in the error.
	c.URL = "http://127.0.0.1:1/services/T0/B0/very-secret-token"
	err = (&Senders{}).Send(context.Background(), c, sampleMessage())
	if err == nil || strings.Contains(err.Error(), "very-secret-token") || strings.Contains(err.Error(), "127.0.0.1:1/") {
		t.Errorf("dead receiver: %v", err)
	}
}

func asSendError(err error, se **SendError) bool {
	e, ok := err.(*SendError)
	if ok {
		*se = e
	}
	return ok
}

func TestSendRefusesLoopbackAndRedirects(t *testing.T) {
	rc := newReceiver(t)
	c := Channel{ID: "h", Name: "hook", Type: TypeWebhook, URL: rc.URL + "/hook"}
	err := (&Senders{}).Send(context.Background(), c, sampleMessage())
	if err == nil || !strings.Contains(err.Error(), "does not send notifications to 127.0.0.1") || !strings.Contains(err.Error(), "Allow this server's own addresses") {
		t.Errorf("loopback: %v", err)
	}
	// A name that leads to a loopback address is refused at connect time.
	c.URL = strings.Replace(rc.URL, "127.0.0.1", "localhost", 1) + "/hook"
	if err := (&Senders{}).Send(context.Background(), c, sampleMessage()); err == nil {
		t.Error("localhost by name was reached")
	}
	// Signalith's own OpenSearch is never reached.
	c.URL, c.AllowLoopback = rc.URL+"/x", true
	prot := Protected{strings.TrimPrefix(rc.URL, "http://")}
	if err := (&Senders{Protected: prot}).Send(context.Background(), c, sampleMessage()); err == nil || !strings.Contains(err.Error(), "OpenSearch") {
		t.Errorf("protected: %v", err)
	}
	// Redirects to another server are not followed.
	other := newReceiver(t)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	c.URL = redir.URL + "/hook"
	if err := (&Senders{}).Send(context.Background(), c, sampleMessage()); err == nil || !strings.Contains(err.Error(), "redirected") {
		t.Errorf("redirect: %v", err)
	}
	if other.body != nil {
		t.Error("the redirect was followed")
	}
}

func TestPrivateCertificateAuthority(t *testing.T) {
	rc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer rc.Close()
	c := Channel{ID: "h", Name: "hook", Type: TypeWebhook, URL: rc.URL + "/hook", AllowLoopback: true}
	err := (&Senders{}).Send(context.Background(), c, sampleMessage())
	if err == nil || !strings.Contains(err.Error(), "not from a trusted authority") {
		t.Fatalf("untrusted: %v", err)
	}
	c.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rc.Certificate().Raw}))
	if err := (&Senders{}).Send(context.Background(), c, sampleMessage()); err != nil {
		t.Errorf("with its CA: %v", err)
	}
}

func TestMessageText(t *testing.T) {
	m := sampleMessage()
	if m.Title != "Brute force from 10.0.0.5 <@here> [click](https://evil.example) *bold* Injected: header" {
		t.Errorf("title %q", m.Title)
	}
	text := m.text("SOC email")
	for _, want := range []string{"High: Brute force", "Urgency:      High (severity medium)", "Detection:    brute-force", "MITRE ATT&CK: T1110",
		"User:         bob", "Destination:  10.0.0.9", "Risk score:   85", "Raised:       2026-10-13 09:00:00 UTC", "Open in Signalith: https://siem.example.com/#findings"} {
		if !strings.Contains(text, want) {
			t.Errorf("text has no %q:\n%s", want, text)
		}
	}
	if s := summaryMessage(1, "", t0); s.Title != "And 1 more new finding" {
		t.Errorf("summary %q", s.Title)
	}
}

// ---- email ----

// smtpServer is a small SMTP server for tests: it offers STARTTLS (or
// speaks TLS from the start), AUTH PLAIN and LOGIN, and records the mail.
type smtpServer struct {
	ln       net.Listener
	cert     tls.Certificate
	implicit bool // TLS from the start
	starttls bool // offer STARTTLS
	auth     string

	mu       sync.Mutex
	from     string
	rcpts    []string
	data     string
	authUser string
	authPass string
	authTLS  bool
}

func newSMTPServer(t *testing.T, implicit, starttls bool, auth string) *smtpServer {
	t.Helper()
	cert, _ := selfSigned(t)
	s := &smtpServer{cert: cert, implicit: implicit, starttls: starttls, auth: auth}
	var err error
	if implicit {
		s.ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	} else {
		s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.ln.Close() })
	go func() {
		for {
			conn, err := s.ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *smtpServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpServer) serve(conn net.Conn) {
	defer conn.Close()
	isTLS := s.implicit
	r := bufio.NewReader(conn)
	w := func(line string) { io.WriteString(conn, line+"\r\n") }
	w("220 test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			w("250-test")
			if s.starttls && !isTLS {
				w("250-STARTTLS")
			}
			if s.auth != "" {
				w("250-AUTH " + s.auth)
			}
			w("250 8BITMIME")
		case cmd == "STARTTLS":
			w("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}})
			if tc.Handshake() != nil {
				return
			}
			conn, r, isTLS = tc, bufio.NewReader(tc), true
			w = func(line string) { io.WriteString(conn, line+"\r\n") }
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			parts := strings.Split(string(raw), "\x00")
			s.mu.Lock()
			s.authUser, s.authPass, s.authTLS = parts[1], parts[2], isTLS
			s.mu.Unlock()
			w("235 ok")
		case cmd == "AUTH LOGIN":
			w("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			u, _ := r.ReadString('\n')
			w("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			p, _ := r.ReadString('\n')
			du, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
			dp, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
			s.mu.Lock()
			s.authUser, s.authPass, s.authTLS = string(du), string(dp), isTLS
			s.mu.Unlock()
			w("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			s.mu.Lock()
			s.from = line[len("MAIL FROM:"):]
			s.mu.Unlock()
			w("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			s.mu.Lock()
			s.rcpts = append(s.rcpts, line[len("RCPT TO:"):])
			s.mu.Unlock()
			w("250 ok")
		case cmd == "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			w("250 queued")
		case cmd == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pemCert
}

func mailChannel(s *smtpServer, security string) Channel {
	_, ca := selfSignedFor(s)
	return Channel{ID: "m", Name: "SOC email", Type: TypeEmail, Host: "127.0.0.1", Port: s.port(), Security: security,
		From: "Signalith <signalith@example.com>", To: []string{"soc@example.com", `"Lead" <lead@example.com>`}, AllowLoopback: true, CAPEM: ca}
}

func selfSignedFor(s *smtpServer) (tls.Certificate, string) {
	return s.cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert.Certificate[0]}))
}

func readMail(t *testing.T, s *smtpServer) (*mail.Message, string) {
	t.Helper()
	s.mu.Lock()
	data := s.data
	s.mu.Unlock()
	msg, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatalf("not a mail: %v\n%s", err, data)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	return msg, string(body)
}

func TestEmailSTARTTLSWithPassword(t *testing.T) {
	s := newSMTPServer(t, false, true, "PLAIN LOGIN")
	c := mailChannel(s, SecuritySTARTTLS)
	c.Username, c.Password = "svc", "mail-secret"
	if err := (&Senders{Now: func() time.Time { return t0 }}).Send(context.Background(), c, sampleMessage()); err != nil {
		t.Fatal(err)
	}
	if s.authUser != "svc" || s.authPass != "mail-secret" || !s.authTLS {
		t.Errorf("auth %q %q tls=%v", s.authUser, s.authPass, s.authTLS)
	}
	if !strings.HasPrefix(s.from, "<signalith@example.com>") || len(s.rcpts) != 2 || s.rcpts[1] != "<lead@example.com>" {
		t.Errorf("envelope %q %q", s.from, s.rcpts)
	}
	msg, body := readMail(t, s)
	subj, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if !strings.HasPrefix(subj, "[Signalith] High: Brute force from 10.0.0.5") || strings.Contains(subj, "\n") {
		t.Errorf("subject %q", subj)
	}
	if msg.Header.Get("Injected") != "" || msg.Header.Get("Auto-Submitted") != "auto-generated" || msg.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("headers %v", msg.Header)
	}
	if to, _ := msg.Header.AddressList("To"); len(to) != 2 {
		t.Errorf("to %v", msg.Header.Get("To"))
	}
	if !strings.Contains(body, "Risk score:   85") || strings.Contains(body, "hunter2") {
		t.Errorf("body\n%s", body)
	}
}

func TestEmailImplicitTLSWithLogin(t *testing.T) {
	s := newSMTPServer(t, true, false, "LOGIN")
	c := mailChannel(s, SecurityTLS)
	c.Username, c.Password = "svc", "pw-login"
	if err := (&Senders{}).Send(context.Background(), c, TestMessage("", t0)); err != nil {
		t.Fatal(err)
	}
	if s.authUser != "svc" || s.authPass != "pw-login" || !s.authTLS {
		t.Errorf("auth %q %q", s.authUser, s.authPass)
	}
	_, body := readMail(t, s)
	if !strings.Contains(body, "This is a test message from Signalith") {
		t.Errorf("body %s", body)
	}
}

func TestEmailRefusesPlainText(t *testing.T) {
	// The server offers no STARTTLS: nothing is sent.
	s := newSMTPServer(t, false, false, "PLAIN")
	c := mailChannel(s, SecuritySTARTTLS)
	c.Username, c.Password = "svc", "pw-123456"
	err := (&Senders{}).Send(context.Background(), c, sampleMessage())
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") || s.authPass != "" || s.data != "" {
		t.Errorf("no starttls: %v", err)
	}
	// A plain relay on this machine takes mail without a password.
	c = mailChannel(s, SecurityNone)
	c.AllowLoopback = false
	if err := (&Senders{}).Send(context.Background(), c, sampleMessage()); err != nil {
		t.Errorf("local relay: %v", err)
	}
	// The wrong certificate authority is refused.
	s2 := newSMTPServer(t, false, true, "")
	c = mailChannel(s2, SecuritySTARTTLS)
	_, other := selfSigned(t)
	c.CAPEM = other
	if err := (&Senders{}).Send(context.Background(), c, sampleMessage()); err == nil || !strings.Contains(err.Error(), "trusted authority") {
		t.Errorf("wrong CA: %v", err)
	}
}

func TestEmailRefusedAddressIsFinal(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		io.WriteString(conn, "220 hi\r\n")
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch c := strings.ToUpper(l); {
			case strings.HasPrefix(c, "EHLO"):
				io.WriteString(conn, "250 hi\r\n")
			case strings.HasPrefix(c, "RCPT"):
				io.WriteString(conn, "550 no such user\r\n")
			default:
				io.WriteString(conn, "250 ok\r\n")
			}
		}
	}()
	port, _ := strconv.Atoi(strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:"))
	c := Channel{ID: "m", Name: "relay", Type: TypeEmail, Host: "127.0.0.1", Port: port, Security: SecurityNone, From: "a@example.com", To: []string{"b@example.com"}}
	err := (&Senders{}).Send(context.Background(), c, sampleMessage())
	var se *SendError
	if !asSendError(err, &se) || se.Retry || !strings.Contains(se.Msg, "550 no such user") {
		t.Errorf("%v %+v", err, se)
	}
}
