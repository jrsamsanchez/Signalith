// Package httpserver builds the web server Signalith serves its UI, API
// and agent ingest on, with timeouts and connection and request limits so
// slow, idle or numerous clients cannot tie it up before anyone has signed
// in.
package httpserver

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/proxyproto"
)

// Timeouts and limits for every connection. Request bodies have their own
// deadline per request (see the api package), because a server-wide
// ReadTimeout also cancels a request's context when it passes, which would
// stop long searches.
const (
	// ReadHeaderTimeout is how long a client has to send its request line
	// and headers.
	ReadHeaderTimeout = 10 * time.Second
	// IdleTimeout closes a kept-alive connection that sends no new request
	// for this long. Browsers and Fluent Bit open a new one when needed.
	IdleTimeout = 2 * time.Minute
	// WriteTimeout bounds one request from the end of its headers to the
	// last byte of the response. It is well above the slowest API calls
	// (running a detection or downloading a feed by hand may take 5
	// minutes) so they still finish, and it stops a client that never
	// reads its response from holding the connection forever.
	WriteTimeout = 10 * time.Minute
	// MaxHeaderBytes caps the request line and headers.
	MaxHeaderBytes = 64 << 10
	// DefaultMaxConnections caps open connections in total; more clients
	// wait until one closes. Each connection costs a file descriptor and
	// some memory, so this keeps a flood of connections from using up
	// either while leaving room for thousands of agents.
	DefaultMaxConnections = 10000
	// MaxStreamsPerConnection is how many requests one HTTP/2 connection
	// (HTTPS only) may have in progress at once. Go's default is 250, which
	// would let each counted connection carry hundreds of requests; a
	// browser page needs far fewer, and more simply wait their turn.
	MaxStreamsPerConnection = 32
)

// New returns a server for handler with Signalith's timeouts, and with
// lim applied to requests in progress. Use Serve to run it on a listener
// from Listen with the same lim.
func New(handler http.Handler, lim Limits, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           limitRequests(handler, lim, logger),
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		WriteTimeout:      WriteTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: MaxStreamsPerConnection},
		ErrorLog:          errorLog(logger),
	}
}

// Serve runs hs on ln until it is shut down, with TLS when certFile is
// set.
func Serve(hs *http.Server, ln net.Listener, certFile, keyFile string) error {
	if certFile != "" {
		return hs.ServeTLS(ln, certFile, keyFile)
	}
	return hs.Serve(ln)
}

// Limits caps a listener's open connections and a server's requests in
// progress.
type Limits struct {
	// Max is the most connections open at once; zero uses
	// DefaultMaxConnections. Beyond it, new clients wait for a free slot.
	// It also caps requests in progress, which only matters over HTTP/2,
	// where one connection carries many: beyond it, requests get 503.
	Max int
	// PerClient is the most connections, and the most requests in
	// progress, from one client; zero uses a tenth of Max, at least 16.
	// Beyond it, new connections from that client are closed at once (and
	// its extra HTTP/2 requests get 503), so one client cannot take every
	// slot. A client is one IPv4 address or one IPv6 /64 network (see
	// clientaddr.Key). Connections from this machine (loopback) and from
	// Shared networks are not limited per client, so a reverse proxy is
	// not held back.
	PerClient int
	// Shared lists networks whose addresses stand for many clients, such
	// as a reverse proxy, load balancer or NAT gateway on another machine
	// (server.shared_addresses).
	Shared []netip.Prefix
	// Proxy, when set, makes Listen read a PROXY protocol header from the
	// trusted load balancers it lists, so requests carry the client's
	// own address. Those balancers count as Shared.
	Proxy *proxyproto.Config
}

func (l Limits) withDefaults() Limits {
	if l.Max <= 0 {
		l.Max = DefaultMaxConnections
	}
	if l.PerClient <= 0 {
		l.PerClient = max(16, l.Max/10)
	}
	return l
}

// Listen opens a TCP listener on addr with lim applied. With lim.Proxy
// set, connections read the balancer's PROXY header first: the
// connection limits count the balancer, and requests the client.
func Listen(addr string, lim Limits, logger *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if lim.Proxy != nil {
		cfg := *lim.Proxy
		cfg.Log = logger
		return proxyproto.Wrap(Limit(ln, lim, logger), cfg), nil
	}
	return Limit(ln, lim, logger), nil
}

// client returns what a connection or request from addr is counted
// under, and false when it is not limited per client.
func (l Limits) client(addr netip.Addr) (netip.Addr, bool) {
	if clientaddr.Shared(addr, l.Shared) || l.Proxy != nil && l.Proxy.Trusts(addr) {
		return netip.Addr{}, false
	}
	return clientaddr.Key(addr), true
}

// Limit wraps ln so it holds at most lim connections open.
func Limit(ln net.Listener, lim Limits, logger *slog.Logger) net.Listener {
	lim = lim.withDefaults()
	return &limitListener{
		Listener: ln,
		lim:      lim,
		slots:    make(chan struct{}, lim.Max),
		done:     make(chan struct{}),
		open:     map[netip.Addr]int{},
		log:      logger,
	}
}

type limitListener struct {
	net.Listener
	lim       Limits
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	mu   sync.Mutex
	open map[netip.Addr]int

	log                   *slog.Logger
	refused               atomic.Int64
	lastRefused, lastFull atomic.Int64 // unix nanoseconds of the last warning
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		select {
		case l.slots <- struct{}{}:
		default:
			l.warn(&l.lastFull, "every connection slot is in use; new clients wait until one closes (logged at most once a minute)",
				"limit", l.lim.Max)
			select {
			case l.slots <- struct{}{}:
			case <-l.done:
				return nil, net.ErrClosed
			}
		}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.slots
			return nil, err
		}
		from := clientaddr.Of(c.RemoteAddr())
		key, limited := l.lim.client(from)
		if !limited || l.admit(key) {
			return &limitConn{Conn: c, l: l, key: key, limited: limited}, nil
		}
		<-l.slots
		c.Close()
		n := l.refused.Add(1)
		l.warn(&l.lastRefused, "connection refused: this client has too many connections open. If many clients reach Signalith through this address "+
			"(a proxy, load balancer or NAT), list it under server.shared_addresses (logged at most once a minute)",
			"client", from.String(), "counted_as", countedAs(key), "limit", l.lim.PerClient, "refused_so_far", n)
	}
}

// countedAs describes a client key for the log: an IPv4 address, or an
// IPv6 /64 network.
func countedAs(key netip.Addr) string {
	if key.Is6() {
		return netip.PrefixFrom(key, clientaddr.IPv6Prefix).String()
	}
	return key.String()
}

func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// admit counts a new connection from a client, or reports false when
// that client already has PerClient open.
func (l *limitListener) admit(key netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open[key] >= l.lim.PerClient {
		return false
	}
	l.open[key]++
	return true
}

func (l *limitListener) release(key netip.Addr, limited bool) {
	<-l.slots
	if !limited {
		return
	}
	l.mu.Lock()
	if l.open[key] <= 1 {
		delete(l.open, key)
	} else {
		l.open[key]--
	}
	l.mu.Unlock()
}

func (l *limitListener) warn(last *atomic.Int64, msg string, args ...any) {
	warnOnceAMinute(l.log, last, msg, args...)
}

// warnOnceAMinute logs at most once a minute per kind of message (one
// last per kind), so a flood of connections cannot flood the log too.
func warnOnceAMinute(logger *slog.Logger, last *atomic.Int64, msg string, args ...any) {
	now := time.Now().UnixNano()
	prev := last.Load()
	if logger == nil || (prev != 0 && now-prev < int64(time.Minute)) || !last.CompareAndSwap(prev, now) {
		return
	}
	logger.Warn(msg, args...)
}

type limitConn struct {
	net.Conn
	l       *limitListener
	key     netip.Addr
	limited bool
	once    sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.release(c.key, c.limited) })
	return err
}

// CloseWrite passes a half-close through. net/http uses it before closing
// a connection whose request body it did not read, such as a refused
// upload, so the client reads the reply instead of losing it to a reset.
func (c *limitConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// limitRequests answers 503 to a request when its client already has
// PerClient requests in progress, or the server Max. Over HTTP/1.1 a
// connection carries one request at a time, so the connection limits
// already hold and this never triggers; over HTTP/2 one connection can
// carry many, each with its own goroutine and buffers, and this keeps
// those within the same budget.
func limitRequests(next http.Handler, lim Limits, logger *slog.Logger) http.Handler {
	lim = lim.withDefaults()
	rl := &requestLimiter{lim: lim, perClient: map[netip.Addr]int{}, log: logger}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from := clientaddr.Parse(r.RemoteAddr)
		key, limited := lim.client(from)
		if ok, clientFull := rl.begin(key, limited); !ok {
			rl.refuse(w, from, key, clientFull)
			return
		}
		defer rl.end(key, limited)
		next.ServeHTTP(w, r)
	})
}

type requestLimiter struct {
	lim       Limits
	mu        sync.Mutex
	total     int
	perClient map[netip.Addr]int

	log                    *slog.Logger
	lastClient, lastServer atomic.Int64
}

// begin counts a request in, or reports why it cannot be: clientFull
// when its client is at PerClient, otherwise the server is at Max.
func (rl *requestLimiter) begin(key netip.Addr, limited bool) (ok, clientFull bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if limited && rl.perClient[key] >= rl.lim.PerClient {
		return false, true
	}
	if rl.total >= rl.lim.Max {
		return false, false
	}
	rl.total++
	if limited {
		rl.perClient[key]++
	}
	return true, false
}

func (rl *requestLimiter) end(key netip.Addr, limited bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.total--
	if !limited {
		return
	}
	if rl.perClient[key] <= 1 {
		delete(rl.perClient, key)
	} else {
		rl.perClient[key]--
	}
}

func (rl *requestLimiter) refuse(w http.ResponseWriter, from, key netip.Addr, clientFull bool) {
	msg := "Signalith has too many requests in progress; try again in a few seconds"
	if clientFull {
		msg = "this client has too many requests in progress; try again in a few seconds"
		warnOnceAMinute(rl.log, &rl.lastClient, "request refused: this client has too many requests in progress (logged at most once a minute)",
			"client", from.String(), "counted_as", countedAs(key), "limit", rl.lim.PerClient)
	} else {
		warnOnceAMinute(rl.log, &rl.lastServer, "request refused: too many requests in progress (logged at most once a minute)", "limit", rl.lim.Max)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusServiceUnavailable)
	io.WriteString(w, `{"error":"`+msg+`"}`+"\n")
}

// errorLog sends net/http's own messages (such as "TLS handshake error
// from ...", which any client can cause) to logger, at most a few a
// minute, so they cannot flood the log.
func errorLog(logger *slog.Logger) *log.Logger {
	if logger == nil {
		return nil
	}
	return log.New(&throttledWriter{log: logger}, "", 0)
}

type throttledWriter struct {
	log *slog.Logger
	// refused hears of each client that refused the certificate, before
	// any throttling.
	refused    atomic.Pointer[func(addr string)]
	mu         sync.Mutex
	window     time.Time
	n          int
	suppressed int
}

// errorLogBurst is how many net/http messages are logged a minute.
const errorLogBurst = 10

func (w *throttledWriter) Write(p []byte) (int, error) {
	if fn := w.refused.Load(); fn != nil {
		if addr, ok := ParseRefusal(string(p)); ok {
			(*fn)(addr)
		}
	}
	w.mu.Lock()
	now := time.Now()
	if now.Sub(w.window) >= time.Minute {
		if w.suppressed > 0 {
			w.log.Warn("http server: more messages like the ones above were not logged", "count", w.suppressed)
		}
		w.window, w.n, w.suppressed = now, 0, 0
	}
	w.n++
	logIt := w.n <= errorLogBurst
	if !logIt {
		w.suppressed++
	}
	w.mu.Unlock()
	if logIt {
		w.log.Warn("http server", "detail", string(bytes.TrimSpace(p)))
	}
	return len(p), nil
}

// OnRefusal calls fn with the address of each client that refuses hs's
// certificate during the TLS handshake: one that does not trust the
// certificate authority. hs must come from New with a logger. fn must
// be quick; it runs on the connection's own goroutine.
func OnRefusal(hs *http.Server, fn func(addr string)) {
	if hs.ErrorLog == nil {
		return
	}
	if w, ok := hs.ErrorLog.Writer().(*throttledWriter); ok {
		w.refused.Store(&fn)
	}
}

// refusalAlerts are the TLS alerts a client sends when it does not trust
// the certificate it was shown.
var refusalAlerts = []string{"unknown certificate authority", "bad certificate", "certificate unknown"}

// RefusedCertificate reports whether why, the reason a TLS handshake
// failed, says the client refused the certificate it was shown: it sent
// one of refusalAlerts. Over TLS 1.3, OpenSSL clients (curl, Fluent Bit)
// send that alert before they encrypt, which Go reads as "local error:
// tls: bad record MAC"; during a handshake that is what such a refusal
// looks like, so it counts too.
func RefusedCertificate(why string) bool {
	if alert, ok := strings.CutPrefix(why, "remote error: tls: "); ok {
		return slices.Contains(refusalAlerts, alert)
	}
	return why == "local error: tls: bad record MAC"
}

// ParseRefusal reads one of net/http's messages, "http: TLS handshake
// error from {addr}: {why}", and returns the client's address when why
// says it refused the certificate (see RefusedCertificate).
func ParseRefusal(line string) (string, bool) {
	const prefix = "http: TLS handshake error from "
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := line[len(prefix):]
	addr, why, ok := strings.Cut(rest, ": ")
	if !ok {
		return "", false
	}
	if !RefusedCertificate(why) {
		return "", false
	}
	return addr, true
}
