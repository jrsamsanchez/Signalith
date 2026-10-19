// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package httpserver

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// PeekTimeout is how long a new connection has to send its first byte,
// which says whether it speaks TLS or plain HTTP. It matches
// ReadHeaderTimeout, the time a client has for its first request anyway.
var PeekTimeout = ReadHeaderTimeout

// tlsHandshake is the first byte of every TLS connection: a handshake
// record (type 22).
const tlsHandshake = 0x16

// ServeBoth serves HTTPS with hs and plain HTTP with plain on the one
// listener ln, so http:// addresses and bookmarks reach the plain server
// (which redirects browsers to HTTPS) on the same port. hs needs
// TLSConfig with a certificate. Each connection is counted once by ln's
// limits, whichever server gets it. It returns when either server stops;
// shut both down to stop.
func ServeBoth(hs, plain *http.Server, ln net.Listener) error {
	tlsLn, plainLn := Split(ln)
	errc := make(chan error, 2)
	go func() { errc <- plain.Serve(plainLn) }()
	go func() { errc <- hs.ServeTLS(tlsLn, "", "") }()
	return <-errc
}

// Split hands each connection ln accepts to one of two listeners by its
// first byte: tlsLn gets TLS connections, plainLn the rest. A client that
// sends nothing within PeekTimeout (as it is when Split is called) is
// closed. Closing either listener closes ln.
func Split(ln net.Listener) (tlsLn, plainLn net.Listener) {
	s := &splitter{ln: ln, peek: PeekTimeout, done: make(chan struct{})}
	s.tls = &splitListener{s: s, ch: make(chan net.Conn)}
	s.plain = &splitListener{s: s, ch: make(chan net.Conn)}
	go s.run()
	return s.tls, s.plain
}

type splitter struct {
	ln         net.Listener
	peek       time.Duration
	tls, plain *splitListener
	done       chan struct{}
	once       sync.Once
	err        error // why accepting stopped; set before done closes
}

func (s *splitter) run() {
	var delay time.Duration
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if isTemporary(err) {
				// Out of file descriptors, say: wait and try again, as
				// http.Server does.
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				select {
				case <-time.After(delay):
					continue
				case <-s.done:
					return
				}
			}
			s.stop(err)
			return
		}
		delay = 0
		go s.route(c)
	}
}

// isTemporary reports errors such as "too many open files" that pass.
func isTemporary(err error) bool {
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

// route reads the first byte and hands the connection on.
func (s *splitter) route(c net.Conn) {
	var b [1]byte
	_ = c.SetReadDeadline(time.Now().Add(s.peek))
	if _, err := c.Read(b[:]); err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	to := s.plain
	if b[0] == tlsHandshake {
		to = s.tls
	}
	select {
	case to.ch <- &peekedConn{Conn: c, first: b[0], pending: true}:
	case <-s.done:
		c.Close()
	}
}

func (s *splitter) stop(err error) {
	s.once.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		s.err = err
		close(s.done)
		s.ln.Close()
	})
}

// splitListener is one side of a split listener.
type splitListener struct {
	s  *splitter
	ch chan net.Conn
}

func (l *splitListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.s.done:
		return nil, l.s.err
	}
}

func (l *splitListener) Close() error {
	l.s.stop(nil)
	return nil
}

func (l *splitListener) Addr() net.Addr { return l.s.ln.Addr() }

// peekedConn gives back the byte read to route it.
type peekedConn struct {
	net.Conn
	first   byte
	pending bool
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if c.pending && len(p) > 0 {
		c.pending = false
		p[0] = c.first
		return 1, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite lets net/http finish a reply cleanly before it closes a
// connection whose request body it did not read (see limitConn).
func (c *peekedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
