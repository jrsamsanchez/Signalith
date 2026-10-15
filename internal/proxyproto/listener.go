package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
)

// DefaultHeaderTimeout is how long a trusted peer has to send its header.
const DefaultHeaderTimeout = 5 * time.Second

// ErrUntrusted is returned by Read on a connection closed because a peer
// that is not trusted sent a PROXY header.
var ErrUntrusted = errors.New("proxyproto: PROXY header from a peer that is not a trusted proxy")

// Config says who may send a PROXY header.
type Config struct {
	// Trusted lists the load balancers and proxies that may send the
	// header (server.trusted_proxies). They may also connect without one,
	// as a health check or an admin on the balancer would.
	Trusted []netip.Prefix
	// TrustedNow, when set, is asked for the trusted list instead of
	// Trusted at each new connection, so a change to the list applies
	// without opening the listener again.
	TrustedNow func() []netip.Prefix
	// HeaderTimeout is how long a trusted peer has to send its header;
	// zero uses DefaultHeaderTimeout.
	HeaderTimeout time.Duration
	// Setting names the setting that lists trusted proxies, for the log.
	Setting string
	// Log hears of headers refused from untrusted peers, once a minute.
	Log *slog.Logger
}

// Trusts reports whether a may send a PROXY header.
func (c Config) Trusts(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	trusted := c.Trusted
	if c.TrustedNow != nil {
		trusted = c.TrustedNow()
	}
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Listener reads PROXY headers on the connections of the listener it
// wraps. Accept returns at once: each connection reads its header on its
// own goroutine, when it is first read from or asked for RemoteAddr, so a
// slow peer never holds up the others.
type Listener struct {
	net.Listener
	cfg       Config
	untrusted atomic.Int64
	lastWarn  atomic.Int64
}

// Wrap returns ln reading PROXY headers by cfg.
func Wrap(ln net.Listener, cfg Config) *Listener {
	if cfg.HeaderTimeout <= 0 {
		cfg.HeaderTimeout = DefaultHeaderTimeout
	}
	if cfg.Setting == "" {
		cfg.Setting = "server.trusted_proxies"
	}
	return &Listener{Listener: ln, cfg: cfg}
}

// Accept returns the next connection as a *Conn.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	peer := clientaddr.Of(c.RemoteAddr())
	return &Conn{Conn: c, l: l, trusted: l.cfg.Trusts(peer)}, nil
}

// Untrusted counts connections closed because a peer that is not trusted
// sent a PROXY header.
func (l *Listener) Untrusted() int64 {
	if l == nil {
		return 0
	}
	return l.untrusted.Load()
}

func (l *Listener) refuse(peer net.Addr) {
	n := l.untrusted.Add(1)
	now := time.Now().UnixNano()
	prev := l.lastWarn.Load()
	if l.cfg.Log == nil || (prev != 0 && now-prev < int64(time.Minute)) || !l.lastWarn.CompareAndSwap(prev, now) {
		return
	}
	l.cfg.Log.Warn("closed a connection that sent a PROXY header from a peer that is not a trusted proxy. "+
		"If it is your load balancer, list its address under "+l.cfg.Setting+" (logged at most once a minute)",
		"peer", clientaddr.Of(peer).String(), "refused_so_far", n)
}

// Conn is a connection from a Listener. RemoteAddr is the client the
// PROXY header names, or the peer when there is none.
type Conn struct {
	net.Conn
	l       *Listener
	trusted bool

	once   sync.Once
	remote net.Addr
	err    error  // why the connection cannot be read
	pend   []byte // bytes read while looking for the header

	dmu          sync.Mutex
	readDeadline time.Time
	inHeader     bool
}

// Peer is the address of the other end of the TCP connection: the load
// balancer when a header named the client.
func (c *Conn) Peer() net.Addr { return c.Conn.RemoteAddr() }

// RemoteAddr returns the client the header names. For a trusted peer it
// waits for the header (up to the header timeout).
func (c *Conn) RemoteAddr() net.Addr {
	if !c.trusted {
		return c.Conn.RemoteAddr()
	}
	c.once.Do(c.readHeader)
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

// Proxied reports whether a header named the client. It reads the header
// first when needed.
func (c *Conn) Proxied() bool {
	if !c.trusted {
		return false
	}
	c.once.Do(c.readHeader)
	return c.remote != nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.trusted {
		c.once.Do(c.readHeader)
	} else {
		c.once.Do(c.checkUntrusted)
	}
	if len(c.pend) > 0 {
		n := copy(p, c.pend)
		c.pend = c.pend[n:]
		if len(c.pend) == 0 {
			c.pend = nil
		}
		return n, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

// readHeader reads the header a trusted peer sends, with its own
// deadline. A peer that sends none keeps its own address; a malformed
// header closes the connection.
func (c *Conn) readHeader() {
	c.dmu.Lock()
	c.inHeader = true
	c.dmu.Unlock()
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.l.cfg.HeaderTimeout))
	br := bufio.NewReaderSize(c.Conn, MaxHeader)
	h, err := Parse(br)
	c.dmu.Lock()
	c.inHeader = false
	_ = c.Conn.SetReadDeadline(c.readDeadline)
	c.dmu.Unlock()
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		c.pend = append([]byte(nil), b...)
	}
	switch {
	case err == nil && !h.Local:
		c.remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(h.Src.Addr().Unmap(), h.Src.Port()))
	case err == nil, errors.Is(err, ErrNoHeader):
	default:
		c.err = err
		c.pend = nil
		c.Conn.Close()
	}
}

// checkUntrusted looks at the first bytes from a peer that is not
// trusted: a PROXY signature closes the connection, anything else passes
// through unchanged. It reads only as far as the bytes still match a
// signature, under the deadline the connection's user set.
func (c *Conn) checkUntrusted() {
	var buf [12]byte
	n := 0
	for {
		m, err := c.Conn.Read(buf[n:])
		n += m
		b := buf[:n]
		if bytes.HasPrefix(b, sigV1) || bytes.HasPrefix(b, sigV2) {
			c.err = ErrUntrusted
			c.l.refuse(c.Conn.RemoteAddr())
			c.Conn.Close()
			return
		}
		if err != nil {
			c.err = err
		}
		if err != nil || !HasSignature(b) {
			break
		}
	}
	c.pend = append([]byte(nil), buf[:n]...)
}

// SetDeadline and SetReadDeadline are remembered, so the read deadline
// the header used is put back as the connection's user set it.
func (c *Conn) SetDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.readDeadline = t
	if c.inHeader {
		return c.Conn.SetWriteDeadline(t)
	}
	return c.Conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.readDeadline = t
	if c.inHeader {
		return nil
	}
	return c.Conn.SetReadDeadline(t)
}

// CloseWrite passes a half-close through (see httpserver.limitConn).
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
