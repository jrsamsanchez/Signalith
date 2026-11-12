// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// scriptedSMTP is a plain SMTP server that answers each command with the
// reply set for its first word (EHLO, MAIL, RCPT, DATA, ".", AUTH), or
// 250 ok.
func scriptedSMTP(t *testing.T, greeting string, replies map[string]string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				io.WriteString(conn, greeting+"\r\n")
				inData := false
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if inData {
						if l == ".\r\n" {
							inData = false
							reply := replies["."]
							if reply == "" {
								reply = "250 queued"
							}
							io.WriteString(conn, reply+"\r\n")
						}
						continue
					}
					word := strings.ToUpper(strings.Fields(l + " x")[0])
					reply, ok := replies[word]
					switch {
					case ok:
					case word == "EHLO":
						reply = "250 hi"
					case word == "DATA":
						reply = "354 go"
					case word == "QUIT":
						io.WriteString(conn, "221 bye\r\n")
						return
					default:
						reply = "250 ok"
					}
					if word == "DATA" && strings.HasPrefix(reply, "354") {
						inData = true
					}
					io.WriteString(conn, reply+"\r\n")
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func plainMail(port int) Channel {
	return Channel{ID: "m", Name: "relay", Type: TypeEmail, Host: "127.0.0.1", Port: port, Security: SecurityNone,
		From: "a@example.com", To: []string{"b@example.com"}}
}

func TestEmailServerRefusals(t *testing.T) {
	for _, c := range []struct {
		name     string
		greeting string
		replies  map[string]string
		change   func(*Channel)
		want     string
		retry    bool
	}{
		{"bad greeting", "554 go away", nil, nil, "did not greet Signalith", false},
		{"hello refused", "220 hi", map[string]string{"EHLO": "421 busy", "HELO": "421 busy"}, nil, "refused Signalith's greeting: 421 busy", true},
		{"from refused", "220 hi", map[string]string{"MAIL": "553 sender rejected"}, nil, "refused the From address a@example.com: 553", false},
		{"data refused", "220 hi", map[string]string{"DATA": "451 try later"}, nil, "refused the message: 451 try later", true},
		{"message refused", "220 hi", map[string]string{".": "554 spam"}, nil, "refused the message: 554 spam", false},
		{"password in plain text", "220 hi", nil, func(c *Channel) { c.Username, c.Password = "svc", "pw-123456" }, "only sends a password over TLS", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			port := scriptedSMTP(t, c.greeting, c.replies)
			ch := plainMail(port)
			if c.change != nil {
				c.change(&ch)
			}
			err := (&Senders{Hostname: "siem.example.com"}).Send(context.Background(), ch, sampleMessage())
			var se *SendError
			if !asSendError(err, &se) || !strings.Contains(se.Msg, c.want) || se.Retry != c.retry {
				t.Errorf("err %v %+v", err, se)
			}
		})
	}
}

func TestEmailChannelProblems(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*Channel)
		want   string
	}{
		{"bad from", func(c *Channel) { c.From = "not an address" }, "From address is not valid"},
		{"bad to", func(c *Channel) { c.To = []string{"nope"} }, `The address "nope" is not valid`},
		{"no to", func(c *Channel) { c.To = nil }, "no address to send to"},
		{"plain to remote", func(c *Channel) { c.Host = "smtp.example.com" }, "only sent without TLS to a relay on this machine"},
		{"bad ca", func(c *Channel) { c.CAPEM = "not pem" }, "not a PEM certificate"},
	} {
		t.Run(c.name, func(t *testing.T) {
			port := scriptedSMTP(t, "220 hi", nil)
			ch := plainMail(port)
			c.change(&ch)
			err := (&Senders{}).Send(context.Background(), ch, sampleMessage())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err %v", err)
			}
		})
	}
	// A protected relay is refused before connecting.
	port := scriptedSMTP(t, "220 hi", nil)
	ch := plainMail(port)
	err := (&Senders{Protected: Protected{"127.0.0.1:" + strconv.Itoa(port)}}).Send(context.Background(), ch, sampleMessage())
	if err == nil {
		t.Error("protected relay reached")
	}
}

func TestEmailSignInChoices(t *testing.T) {
	// No AUTH offered, or only mechanisms Signalith can't use.
	for _, c := range []struct {
		auth string
		want string
	}{
		{"", "does not ask for a sign-in"},
		{"CRAM-MD5 XOAUTH2", "offers no sign-in Signalith can use (PLAIN or LOGIN); it offers CRAM-MD5 XOAUTH2"},
	} {
		s := newSMTPServer(t, true, false, c.auth)
		ch := mailChannel(s, SecurityTLS)
		ch.Username, ch.Password = "svc", "pw-123456"
		err := (&Senders{}).Send(context.Background(), ch, sampleMessage())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("auth %q: %v", c.auth, err)
		}
	}
}

func TestLoginAuth(t *testing.T) {
	a := &loginAuth{user: "svc", pass: "pw"}
	if _, _, err := a.Start(&smtp.ServerInfo{TLS: false}); err == nil {
		t.Error("LOGIN started without TLS")
	}
	if mech, _, err := a.Start(&smtp.ServerInfo{TLS: true}); err != nil || mech != "LOGIN" {
		t.Errorf("start %q %v", mech, err)
	}
	for q, want := range map[string]string{"Username:": "svc", "User Name": "svc", "password": "pw"} {
		if got, err := a.Next([]byte(q), true); err != nil || string(got) != want {
			t.Errorf("Next(%q) = %q %v", q, got, err)
		}
	}
	if got, err := a.Next(nil, false); got != nil || err != nil {
		t.Errorf("done: %q %v", got, err)
	}
	if _, err := a.Next([]byte("Favourite colour?"), true); err == nil {
		t.Error("an unexpected question was answered")
	}
	if (&mailError{msg: "m"}).Error() != "m" {
		t.Error("mailError")
	}
	if got := (&Senders{Hostname: "bad host!"}).helloName(); got != "localhost" {
		t.Errorf("helloName %q", got)
	}
	if got := (&Senders{Hostname: "siem.example.com"}).helloName(); got != "siem.example.com" {
		t.Errorf("helloName %q", got)
	}
	if err := smtpErr("Something", errors.New("plain")); err == nil || err.Error() != "something: plain" {
		t.Errorf("smtpErr %v", err)
	}
}

func TestNewClientAndCheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer ts.Close()
	if _, err := NewClient(ClientOptions{CAPEM: "garbage"}); err == nil {
		t.Error("a bad CA was accepted")
	}
	c, err := NewClient(ClientOptions{AllowLoopback: true, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(ts.URL + "/moved")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("a redirect was followed: %d", resp.StatusCode)
	}
	// Loopback is refused after DNS when not allowed.
	strict, _ := NewClient(ClientOptions{})
	if _, err := strict.Get(ts.URL); err == nil {
		t.Error("loopback reached")
	}
	// A protected address is refused by the dialer too.
	host := strings.TrimPrefix(ts.URL, "http://")
	guarded, _ := NewClient(ClientOptions{AllowLoopback: true, Protected: Protected{host}})
	if _, err := guarded.Get(ts.URL); err == nil {
		t.Error("protected address reached")
	}
	u, _ := url.Parse(ts.URL)
	if err := (Protected{host}).Check(u, true); err == nil {
		t.Error("Check let a protected address through")
	}
	if err := (Protected{}).Check(u, true); err != nil {
		t.Errorf("Check: %v", err)
	}
	if err := (Protected{}).Check(u, false); err == nil {
		t.Error("Check let loopback through")
	}
}

func TestDialerProtectedByName(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	d := newDialer(true, Protected{"localhost:" + port, "bad-entry"})
	if _, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:"+port); err == nil {
		t.Error("an address protected by name was reached")
	}
	// The proxy's own address is dialled without checks.
	d = newDialer(false, nil)
	d.setProxy(ln.Addr().String())
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("proxy dial: %v", err)
	}
	conn.Close()
}
