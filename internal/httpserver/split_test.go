// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package httpserver

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startBoth serves "tls" over HTTPS and "plain" over HTTP on one port.
func startBoth(t *testing.T) string {
	t.Helper()
	cert := testCertificate(t)
	hs := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "tls "+r.Proto)
	}), Limits{}, nil)
	hs.TLSConfig.Certificates = []tls.Certificate{cert}
	plain := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain")
	}), Limits{}, nil)
	ln, err := Listen("127.0.0.1:0", Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go ServeBoth(hs, plain, ln)
	t.Cleanup(func() { hs.Close(); plain.Close() })
	return ln.Addr().String()
}

func get(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestServeBothOnOnePort(t *testing.T) {
	addr := startBoth(t)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	if got := get(t, &http.Client{Transport: tr}, "https://"+addr+"/"); got != "tls HTTP/2.0" {
		t.Errorf("https = %q", got)
	}
	if got := get(t, http.DefaultClient, "http://"+addr+"/"); got != "plain" {
		t.Errorf("http = %q", got)
	}
	// The TLS side keeps Go's minimum of TLS 1.2.
	if _, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Error("TLS 1.1 accepted")
	}
}

func TestSilentClientIsClosed(t *testing.T) {
	ln, err := Listen("127.0.0.1:0", Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	prev := PeekTimeout
	PeekTimeout = 200 * time.Millisecond
	tlsLn, _ := Split(ln) // takes the timeout now
	PeekTimeout = prev
	defer tlsLn.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !closedWithin(c, 3*time.Second) {
		t.Error("a connection that sends nothing stays open")
	}
}

// Each connection takes one place under the per-client limit, whichever
// side it goes to, and gives it back when it closes.
func TestSplitCountsConnectionsOnce(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 10), done: make(chan struct{})}
	tlsLn, plainLn := Split(Limit(fl, Limits{Max: 10, PerClient: 2}, nil))
	defer tlsLn.Close()
	send := func(b byte) net.Conn {
		c := fl.dial("203.0.113.9")
		go c.Write([]byte{b})
		return c
	}
	accept := func(ln net.Listener) net.Conn {
		t.Helper()
		done := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				t.Error(err)
			}
			done <- c
		}()
		select {
		case c := <-done:
			return c
		case <-time.After(5 * time.Second):
			t.Fatal("no connection")
			return nil
		}
	}
	send(0x16)
	tc := accept(tlsLn)
	send('G')
	pc := accept(plainLn)
	// The byte used to route is read again by the server.
	buf := make([]byte, 1)
	if _, err := io.ReadFull(pc, buf); err != nil || buf[0] != 'G' {
		t.Errorf("first byte %q %v", buf, err)
	}
	// A third from the same client is over its limit of two.
	third := fl.dial("203.0.113.9")
	third.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := third.Read(buf); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("third connection: %v, want it closed", err)
	}
	// Closing the TLS one frees a place.
	tc.Close()
	send('P')
	accept(plainLn).Close()
	pc.Close()
}

func TestClosingOneSideStopsBoth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, plainLn := Split(ln)
	if !strings.Contains(tlsLn.Addr().String(), "127.0.0.1") {
		t.Errorf("addr %v", tlsLn.Addr())
	}
	tlsLn.Close()
	if _, err := plainLn.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept after close: %v", err)
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		t.Error("the port is still open")
	}
}
