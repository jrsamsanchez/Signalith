package syslog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/httpserver"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/proxyproto"
)

// Defaults for the limits in Config.
const (
	DefaultMaxMessageSize = 64 << 10
	DefaultMaxConnections = 1000
	// DefaultIdleTimeout closes TCP connections that sent nothing for this
	// long. It is long because quiet devices (a switch that logs once a
	// day) keep one connection open, and closing it can lose the next
	// message; TCP keepalives find dead senders much sooner.
	DefaultIdleTimeout = time.Hour
	// DefaultMessageTimeout is how long a sender has to finish a message
	// once its first byte arrived, so a connection cannot hold a partial
	// message (and its buffer) for the whole idle timeout.
	DefaultMessageTimeout = time.Minute
	DefaultBatchSize      = 500
	DefaultFlushInterval  = time.Second
	DefaultQueueSize      = 10000
	DefaultQueueBytes     = 64 << 20
	// maxSenders is how many recent senders the stats keep.
	maxSenders = 50
	// maxExtraNamesPerIndex caps the distinct cef_* and sd_* field names
	// one daily index gets per run, for all servers together, and
	// maxExtraNamesPerSender one sender's share of that, so one device
	// cannot use up the budget of the others. Each server that stored
	// events in the last 10 minutes gets an equal share of the index's
	// budget, at least minExtraNamesPerServer (see Config.Servers).
	// Together with the data model fields this stays well under the 2000
	// fields the index template allows; the ingest pipeline's own budget
	// and mapping guard apply after these.
	maxExtraNamesPerIndex  = 600
	maxExtraNamesPerSender = 150
	minExtraNamesPerServer = 100
	// evictAfter is how long a TCP connection must have been quiet before
	// it is closed to make room for a new one when the limit is reached.
	evictAfter       = 30 * time.Second
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 30 * time.Second
	// finalFlushTimeout is how long the queue has to be written out once
	// the receiver stops; whatever is left then is counted as dropped. It
	// fits in the 10 seconds docker stop waits.
	finalFlushTimeout = 5 * time.Second
)

// Config says where the receiver listens and how it treats senders.
type Config struct {
	// UDP, TCP and TLS are host:port listen addresses; empty turns that
	// listener off.
	UDP, TCP, TLS string
	// GetCertificate gives the TLS certificate (the web UI's, which is
	// renewed and reloaded while the receiver runs). When nil, CertFile
	// and KeyFile are loaded once at Start.
	GetCertificate    func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	CertFile, KeyFile string
	// OnRefusal, when set, hears of each sender that refused the
	// certificate during the TLS handshake, by its address.
	OnRefusal func(addr string)
	// OnTLSName, when set, hears the name a TLS sender asked for in the
	// handshake, once per connection, after its first message: only
	// senders syslog.allow lets in, and that send syslog, count.
	OnTLSName func(name string)
	// Allow lists the senders that may send; empty allows any sender.
	Allow []netip.Prefix
	// Proxy, when set, reads a PROXY protocol header from the trusted
	// load balancers on the TCP and TLS listeners (before TLS), so Allow,
	// the per-sender limits and each event's host see the device. Nil
	// reads none.
	Proxy *proxyproto.Config
	// PublicPort is the port senders use for UDP and TCP when something
	// forwards it to the one listened on (Docker publishing 514 as 5514).
	// It is only reported, as Listener.Port; zero means the listen port.
	PublicPort int
	// Ready, when set, holds back writes until it is closed, so the first
	// syslog indices are created after the index template is in place and
	// get the right field types. Messages wait in the queue meanwhile.
	Ready <-chan struct{}

	// Servers returns how many servers share each day's field-name budget
	// (see cluster.Node.IndexingServers); nil is this server alone.
	Servers func() int

	// MaxAge is how old a message's own timestamp may be and still be the
	// event time (zero: DefaultMaxAge). Older ones use the receive time
	// and are kept in device_time, so senders cannot create an index for
	// every day they name.
	MaxAge time.Duration

	// Limits; zero uses the defaults above.
	MaxMessageSize int
	MaxConnections int
	// MaxConnectionsPerSender limits the TCP and TLS connections from one
	// sender (an IPv4 address, or an IPv6 /64 network); zero uses a tenth
	// of MaxConnections, at least 16.
	MaxConnectionsPerSender int
	IdleTimeout             time.Duration
	MessageTimeout          time.Duration
	BatchSize               int
	FlushInterval           time.Duration
	QueueSize               int
	QueueBytes              int64
}

// Sink receives batches of events; ingest.Pipeline is one.
type Sink interface {
	IngestEvents(ctx context.Context, events []ingest.Event) (*ingest.Result, error)
}

// Receiver listens for syslog and writes it through a Sink. Network
// readers parse messages and put them on a bounded queue; one writer sends
// them on in batches. UDP readers never wait: when the queue is full the
// message is dropped and counted. TCP readers wait for room instead, which
// slows the sender down rather than losing its messages.
type Receiver struct {
	cfg  Config
	sink Sink
	log  *slog.Logger
	now  func() time.Time

	queue       chan queued
	queuedBytes atomic.Int64
	// maxAge is cfg.MaxAge, which SetMaxAge changes while it runs.
	maxAge atomic.Int64

	udp       *net.UDPConn
	lns       []net.Listener
	proxyLns  []*proxyproto.Listener
	listeners []Listener
	tlsConf   *tls.Config

	readers  sync.WaitGroup
	done     chan struct{}
	started  bool
	stopOnce sync.Once
	// drain ends finalFlushTimeout after the receiver starts stopping;
	// writes use it so a slow OpenSearch cannot hold up the shutdown.
	drain       context.Context
	drainCancel context.CancelFunc

	mu         sync.Mutex
	conns      map[net.Conn]*connState
	perSender  map[netip.Addr]int
	closing    bool
	evictAfter time.Duration
	finalFlush time.Duration

	received, dropped, writeFailed            atomic.Int64
	notAllowed, tooLarge, badFraming, tooMany atomic.Int64
	tooManyFromSender                         atomic.Int64
	lastMessage                               atomic.Int64 // unix nanoseconds
	senders                                   senderTable
	names                                     nameBudget

	warnMu sync.Mutex
	warned map[string]time.Time

	// lastNotAllowed is the latest sender outside syslog.allow, so the
	// health page can say whom to add.
	rejMu          sync.Mutex
	lastNotAllowed netip.Addr
}

type queued struct {
	ev   ingest.Event
	size int64
}

// Listener is one address the receiver listens on.
type Listener struct {
	Protocol string `json:"protocol"` // udp, tcp or tls
	Address  string `json:"address"`
	// Port is the port senders use: Config.PublicPort for UDP and TCP
	// when set, else the port listened on.
	Port int `json:"port"`
}

// Sender is a system that sent syslog recently.
type Sender struct {
	Address  string    `json:"address"`
	Host     string    `json:"host,omitempty"` // host name in its last message
	Protocol string    `json:"protocol"`
	Messages int64     `json:"messages"`
	LastSeen time.Time `json:"last_seen"`
}

// Rejections counts messages and connections turned away.
type Rejections struct {
	NotAllowed         int64 `json:"not_allowed"`          // sender outside syslog.allow
	TooLarge           int64 `json:"too_large"`            // message over the size limit
	BadFraming         int64 `json:"bad_framing"`          // TCP stream with an impossible octet count
	TooManyConnections int64 `json:"too_many_connections"` // TCP connection over the limit
	TooManyFromSender  int64 `json:"too_many_from_sender"` // TCP connection over the per-sender limit
	// ProxyUntrusted counts TCP and TLS connections closed because a
	// peer that is not a trusted proxy sent a PROXY header.
	ProxyUntrusted int64 `json:"proxy_untrusted,omitempty"`
}

// Stats is what the receiver has done since start, for the health page.
type Stats struct {
	Enabled   bool       `json:"enabled"`
	Listeners []Listener `json:"listeners"`
	// Allow lists the senders accepted, as addresses or CIDRs; empty
	// means any sender.
	Allow []string `json:"allow"`
	// Received counts messages accepted from allowed senders.
	Received int64 `json:"received"`
	// Dropped counts received messages lost because the queue was full
	// (OpenSearch slower than the senders) or the server was stopping.
	Dropped int64 `json:"dropped"`
	// WriteFailed counts messages OpenSearch did not store: it was down,
	// timed out, or rejected them.
	WriteFailed int64      `json:"write_failed"`
	Rejected    int64      `json:"rejected"`
	RejectedBy  Rejections `json:"rejected_by"`
	Queued      int        `json:"queued"`
	// Connections is the number of open TCP and TLS connections.
	Connections int       `json:"connections"`
	LastMessage time.Time `json:"last_message,omitzero"`
	// Senders are the most recent senders, newest first.
	Senders []Sender `json:"senders"`
	// LastNotAllowed is the latest sender turned away because it is not
	// in syslog.allow.
	LastNotAllowed string `json:"last_not_allowed,omitempty"`
}

// New returns a receiver; Start opens its listeners.
func New(cfg Config, sink Sink, log *slog.Logger) *Receiver {
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = DefaultMaxMessageSize
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = DefaultMaxConnections
	}
	if cfg.MaxConnectionsPerSender <= 0 {
		cfg.MaxConnectionsPerSender = max(16, cfg.MaxConnections/10)
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.MessageTimeout <= 0 {
		cfg.MessageTimeout = DefaultMessageTimeout
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = DefaultQueueBytes
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	drain, drainCancel := context.WithCancel(context.Background())
	r := &Receiver{
		cfg:         cfg,
		sink:        sink,
		log:         log,
		now:         time.Now,
		queue:       make(chan queued, cfg.QueueSize),
		done:        make(chan struct{}),
		drain:       drain,
		drainCancel: drainCancel,
		conns:       map[net.Conn]*connState{},
		perSender:   map[netip.Addr]int{},
		evictAfter:  evictAfter,
		finalFlush:  finalFlushTimeout,
		senders:     senderTable{max: maxSenders, m: map[netip.Addr]*Sender{}},
		names:       newNameBudget(maxExtraNamesPerIndex, maxExtraNamesPerSender),
		warned:      map[string]time.Time{},
	}
	r.names.servers = cfg.Servers
	r.maxAge.Store(int64(cfg.MaxAge))
	return r
}

// Start opens every configured listener and starts receiving. It returns
// an error that says what to do when a port cannot be opened. The receiver
// stops when ctx ends; Wait then returns once the queue is written out.
func (r *Receiver) Start(ctx context.Context) error {
	switch {
	case r.cfg.TLS != "" && r.cfg.GetCertificate != nil:
		r.tlsConf = &tls.Config{GetCertificate: r.cfg.GetCertificate, MinVersion: tls.VersionTLS12}
	case r.cfg.TLS != "":
		cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("syslog.tls: cannot load the certificate in server.tls_cert and server.tls_key: %w", err)
		}
		r.tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	var lc net.ListenConfig
	if r.cfg.UDP != "" {
		pc, err := lc.ListenPacket(ctx, "udp", r.cfg.UDP)
		if err != nil {
			return bindError("syslog.udp", "udp", r.cfg.UDP, err)
		}
		r.udp = pc.(*net.UDPConn)
		// A bigger socket buffer rides out bursts while a reader is busy.
		_ = r.udp.SetReadBuffer(4 << 20)
		r.listeners = append(r.listeners, r.listener("udp", r.cfg.UDP, r.udp.LocalAddr()))
	}
	var protos []string
	for _, l := range []struct{ proto, addr, setting string }{{"tcp", r.cfg.TCP, "syslog.tcp"}, {"tls", r.cfg.TLS, "syslog.tls"}} {
		if l.addr == "" {
			continue
		}
		ln, err := lc.Listen(ctx, "tcp", l.addr)
		if err != nil {
			r.closeListeners()
			return bindError(l.setting, "tcp", l.addr, err)
		}
		if r.cfg.Proxy != nil {
			pl := proxyproto.Wrap(ln, *r.cfg.Proxy)
			r.proxyLns = append(r.proxyLns, pl)
			ln = pl
		}
		r.lns = append(r.lns, ln)
		protos = append(protos, l.proto)
		r.listeners = append(r.listeners, r.listener(l.proto, l.addr, ln.Addr()))
	}
	for i, ln := range r.lns {
		r.readers.Add(1)
		go r.accept(ctx, ln, protos[i])
	}
	if r.udp != nil {
		for range min(runtime.NumCPU(), 4) {
			r.readers.Add(1)
			go r.readUDP(ctx)
		}
	}
	r.started = true
	go r.write(ctx)
	go func() {
		<-ctx.Done()
		r.stop()
	}()
	return nil
}

// Wait blocks until the receiver has stopped and written out its queue.
// It returns at once if Start was not called or failed.
func (r *Receiver) Wait() {
	if r == nil || !r.started {
		return
	}
	<-r.done
}

// stop closes the listeners and connections, waits for the readers, and
// closes the queue so the writer flushes what is left and finishes. The
// writer has finalFlushTimeout from now, including a write in progress;
// what is still queued then is counted as dropped.
func (r *Receiver) stop() {
	r.stopOnce.Do(func() {
		time.AfterFunc(r.finalFlush, r.drainCancel)
		r.mu.Lock()
		r.closing = true
		for c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
		r.closeListeners()
		r.readers.Wait()
		close(r.queue)
	})
}

func (r *Receiver) closeListeners() {
	if r.udp != nil {
		r.udp.Close()
	}
	for _, ln := range r.lns {
		ln.Close()
	}
}

// listener describes a listener that opened: the address it is on, and
// the port senders use.
func (r *Receiver) listener(proto, configured string, actual net.Addr) Listener {
	l := Listener{Protocol: proto, Address: shownAddr(configured, actual)}
	if _, port, err := net.SplitHostPort(l.Address); err == nil {
		l.Port, _ = strconv.Atoi(port)
	}
	if proto != "tls" && r.cfg.PublicPort > 0 {
		l.Port = r.cfg.PublicPort
	}
	return l
}

// shownAddr is the configured address with the port actually bound, so
// "0.0.0.0:514" stays readable and ":0" in tests shows the real port.
func shownAddr(configured string, actual net.Addr) string {
	host, _, err := net.SplitHostPort(configured)
	if err != nil {
		return actual.String()
	}
	_, port, err := net.SplitHostPort(actual.String())
	if err != nil {
		return actual.String()
	}
	return net.JoinHostPort(host, port)
}

// bindError explains why a listener could not open and what to do.
func bindError(setting, network, addr string, err error) error {
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	other := "a free port"
	switch setting {
	case "syslog.udp", "syslog.tcp":
		other = "another port, such as 0.0.0.0:1514"
	case "syslog.tls":
		other = "another port, such as 0.0.0.0:6515"
	}
	var errno syscall.Errno
	isErrno := errors.As(err, &errno)
	switch {
	case errors.Is(err, syscall.EADDRINUSE) || (isErrno && errno == 10048): // WSAEADDRINUSE
		return fmt.Errorf("%s: cannot listen on %s/%s: the port is already in use, probably by another syslog server such as rsyslog or syslog-ng. Stop that service, or set %s to %s", setting, addr, network, setting, other)
	case isErrno && errno == 10013: // WSAEACCES
		return fmt.Errorf("%s: cannot listen on %s/%s: Windows refused the port; another program may hold it, or it is in a reserved range (see: netsh interface ipv4 show excludedportrange protocol=%s). Set %s to %s", setting, addr, network, network, setting, other)
	case errors.Is(err, os.ErrPermission) && p > 0 && p < 1024:
		return fmt.Errorf("%s: cannot listen on %s/%s: permission denied. Ports below 1024 need extra permission on Linux: run Signalith with the systemd unit from deploy/systemd (it grants CAP_NET_BIND_SERVICE), or grant it once with: sudo setcap cap_net_bind_service=+ep $(command -v signalith); or set %s to a port above 1023, such as 0.0.0.0:1514", setting, addr, network, setting)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%s: cannot listen on %s/%s: permission denied. Run Signalith as a user that may open this port, or set %s to %s", setting, addr, network, setting, other)
	}
	return fmt.Errorf("%s: cannot listen on %s/%s: %w", setting, addr, network, err)
}

// ---- reading ----

func (r *Receiver) readUDP(ctx context.Context) {
	defer r.readers.Done()
	// Room for the largest datagram, so the size check below sees how
	// big a message really was on every platform.
	buf := make([]byte, max(r.cfg.MaxMessageSize, 65535)+1)
	for {
		n, ap, err := r.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Such as an ICMP error Windows reports on the socket; keep
			// reading, without spinning if it repeats.
			time.Sleep(time.Millisecond)
			continue
		}
		// Without the zone, fe80::1%eth0 matches fe80::/10 in syslog.allow.
		from := ap.Addr().Unmap().WithZone("")
		if !r.allowed(from) {
			r.rejectSender(from)
			continue
		}
		if n > r.cfg.MaxMessageSize {
			r.tooLarge.Add(1)
			continue
		}
		r.handle(ctx, buf[:n], from, "udp", false)
	}
}

func (r *Receiver) accept(ctx context.Context, ln net.Listener, proto string) {
	defer r.readers.Done()
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Out of file descriptors and the like: back off and retry.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			r.warn("accept", "syslog listener could not accept a connection; retrying", "protocol", proto, "err", err)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			continue
		}
		delay = 0
		if r.cfg.Proxy != nil {
			// The sender is known once the load balancer's header is
			// read, which may take a moment: read it on the
			// connection's own goroutine so others are not held up.
			r.readers.Add(1)
			go func() {
				defer r.readers.Done()
				r.admit(ctx, c, proto)
			}()
			continue
		}
		r.admit(ctx, c, proto)
	}
}

// admit checks a new connection's sender against syslog.allow and the
// connection limits, and serves it or closes it.
func (r *Receiver) admit(ctx context.Context, c net.Conn, proto string) {
	from := remoteAddr(c)
	if !r.allowed(from) {
		r.rejectSender(from)
		c.Close()
		return
	}
	cs := newConnState(from)
	switch r.track(c, cs) {
	case trackOK:
		r.readers.Add(1)
		go r.serveConn(ctx, c, cs, proto)
		return
	case trackSenderFull:
		r.tooManyFromSender.Add(1)
		r.warn("sender-connections", "syslog connection refused: this sender has too many open connections", "limit", r.cfg.MaxConnectionsPerSender, "sender", from.String())
	case trackFull:
		r.tooMany.Add(1)
		r.warn("connections", "syslog connection refused: too many open connections", "limit", r.cfg.MaxConnections, "sender", from.String())
	}
	c.Close()
}

func remoteAddr(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap().WithZone("")
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap.Addr().Unmap().WithZone("")
}

// connState is what the receiver knows about one TCP or TLS connection.
type connState struct {
	from netip.Addr
	// sender is what the per-sender connection limit counts it under: the
	// address, or for IPv6 its /64 network (see clientaddr.Key).
	sender netip.Addr
	// active is when the connection last sent something, and msgStart
	// when the message being read began (zero between messages), both
	// in unix nanoseconds.
	active, msgStart atomic.Int64
}

func newConnState(from netip.Addr) *connState {
	cs := &connState{from: from, sender: clientaddr.Key(from)}
	cs.active.Store(time.Now().UnixNano())
	return cs
}

type trackResult int

const (
	trackOK trackResult = iota
	trackSenderFull
	trackFull
	trackStopping
)

// track registers a new connection. When its sender, or the receiver as a
// whole, is at the connection limit, the connection quiet the longest (of
// that sender, or of all) makes room if it has been quiet for evictAfter,
// so idle connections cannot lock other devices out; otherwise the new
// connection is refused.
func (r *Receiver) track(c net.Conn, cs *connState) trackResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return trackStopping
	}
	if r.perSender[cs.sender] >= r.cfg.MaxConnectionsPerSender && !r.evictLocked(cs.sender, true) {
		return trackSenderFull
	}
	if len(r.conns) >= r.cfg.MaxConnections && !r.evictLocked(netip.Addr{}, false) {
		return trackFull
	}
	r.conns[c] = cs
	r.perSender[cs.sender]++
	return trackOK
}

// evictLocked closes the connection quiet the longest, from sender only
// when sameSender is set, if it has been quiet for evictAfter. r.mu is held.
func (r *Receiver) evictLocked(sender netip.Addr, sameSender bool) bool {
	var victim net.Conn
	var quietSince int64
	for c, cs := range r.conns {
		if sameSender && cs.sender != sender {
			continue
		}
		if a := cs.active.Load(); victim == nil || a < quietSince {
			victim, quietSince = c, a
		}
	}
	if victim == nil || time.Since(time.Unix(0, quietSince)) < r.evictAfter {
		return false
	}
	from := r.conns[victim].from
	r.forgetLocked(victim)
	victim.Close()
	r.warn("evict", "closed the longest-quiet syslog connection to make room for a new one (logged once a minute)", "sender", from.String())
	return true
}

func (r *Receiver) forgetLocked(c net.Conn) {
	cs, ok := r.conns[c]
	if !ok {
		return
	}
	delete(r.conns, c)
	if r.perSender[cs.sender] <= 1 {
		delete(r.perSender, cs.sender)
	} else {
		r.perSender[cs.sender]--
	}
}

func (r *Receiver) untrack(c net.Conn) {
	r.mu.Lock()
	r.forgetLocked(c)
	r.mu.Unlock()
	c.Close()
}

// connReader reads from a connection with two deadlines: the idle timeout
// between messages, and the message timeout once a message has begun, so
// a sender trickling a byte at a time cannot hold a partial message open.
type connReader struct {
	c         net.Conn
	cs        *connState
	idle, msg time.Duration
}

func (cr connReader) Read(p []byte) (int, error) {
	deadline := time.Now().Add(cr.idle)
	if start := cr.cs.msgStart.Load(); start != 0 {
		if d := time.Unix(0, start).Add(cr.msg); d.Before(deadline) {
			deadline = d
		}
	}
	_ = cr.c.SetReadDeadline(deadline)
	n, err := cr.c.Read(p)
	if n > 0 {
		cr.cs.active.Store(time.Now().UnixNano())
	}
	return n, err
}

func (r *Receiver) serveConn(ctx context.Context, c net.Conn, cs *connState, proto string) {
	defer r.readers.Done()
	defer r.untrack(c)
	from := cs.from
	conn := c
	if proto == "tls" {
		tc := tls.Server(c, r.tlsConf)
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			if r.cfg.OnRefusal != nil && refusedCertificate(err) {
				r.cfg.OnRefusal(from.String())
			}
			r.warn("handshake", "syslog TLS handshake failed", "sender", from.String(), "err", err)
			return
		}
		conn = tc
	}
	var tlsName string
	if tc, ok := conn.(*tls.Conn); ok && r.cfg.OnTLSName != nil {
		tlsName = tc.ConnectionState().ServerName
	}
	fr := newFramer(connReader{c: conn, cs: cs, idle: r.cfg.IdleTimeout, msg: r.cfg.MessageTimeout}, r.cfg.MaxMessageSize)
	fr.mark = func(inMessage bool) {
		if inMessage {
			cs.msgStart.Store(time.Now().UnixNano())
		} else {
			cs.msgStart.Store(0)
		}
	}
	for {
		msg, err := fr.Next()
		switch {
		case err == nil:
			r.handle(ctx, msg, from, proto, true)
			if tlsName != "" {
				r.cfg.OnTLSName(tlsName)
				tlsName = ""
			}
		case errors.Is(err, errTooLarge):
			r.tooLarge.Add(1)
		case errors.Is(err, errFraming):
			r.badFraming.Add(1)
			r.warn("framing", "closed a syslog connection that sent an impossible octet count", "sender", from.String())
			return
		default:
			return // closed, idle too long, or stopping
		}
	}
}

func (r *Receiver) allowed(a netip.Addr) bool {
	if len(r.cfg.Allow) == 0 {
		return true
	}
	for _, p := range r.cfg.Allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// rejectSender counts a sender outside the allow list, logging at most
// once a minute rather than per message.
func (r *Receiver) rejectSender(a netip.Addr) {
	r.notAllowed.Add(1)
	r.rejMu.Lock()
	r.lastNotAllowed = a
	r.rejMu.Unlock()
	r.warn("allow", "dropped syslog from a sender outside syslog.allow (logged once a minute)", "sender", a.String(), "dropped_so_far", r.notAllowed.Load())
}

// SetMaxAge changes how old a message's own timestamp may be and still be
// the event time, while the receiver runs, as when the shared retention
// policies change; zero or less is ignored.
func (r *Receiver) SetMaxAge(d time.Duration) {
	if d > 0 {
		r.maxAge.Store(int64(d))
	}
}

// handle parses one message and queues its event. wait says whether to
// wait for room in the queue (TCP) or drop the message when it is full
// (UDP).
func (r *Receiver) handle(ctx context.Context, data []byte, from netip.Addr, proto string, wait bool) {
	now := r.now()
	m := Parse(data, now)
	if m.Raw == "" {
		return
	}
	maxAge := time.Duration(r.maxAge.Load())
	ev := m.Event(from, now, maxAge)
	r.names.limit(ev, from, now, maxAge)
	r.received.Add(1)
	r.lastMessage.Store(now.UnixNano())
	r.senders.seen(from, m.Hostname, proto, now)
	if !r.enqueue(ctx, queued{ev: ev, size: int64(2*len(m.Raw) + 512)}, wait) {
		r.dropped.Add(1)
	}
}

// enqueue puts an event on the queue, which is bounded both in events and
// in (estimated) bytes.
func (r *Receiver) enqueue(ctx context.Context, q queued, wait bool) bool {
	for {
		if r.queuedBytes.Add(q.size) <= r.cfg.QueueBytes {
			if wait {
				select {
				case r.queue <- q:
					return true
				case <-ctx.Done():
					r.queuedBytes.Add(-q.size)
					return false
				}
			}
			select {
			case r.queue <- q:
				return true
			default:
				r.queuedBytes.Add(-q.size)
				return false
			}
		}
		r.queuedBytes.Add(-q.size)
		if !wait {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// ---- writing ----

// write sends queued events in batches: when a batch is full or every
// FlushInterval. When the queue closes it sends the rest and finishes.
func (r *Receiver) write(ctx context.Context) {
	defer close(r.done)
	if r.cfg.Ready != nil {
		select {
		case <-r.cfg.Ready:
		case <-ctx.Done():
		}
	}
	defer r.drainCancel()
	tick := time.NewTicker(r.cfg.FlushInterval)
	defer tick.Stop()
	batch := make([]ingest.Event, 0, r.cfg.BatchSize)
	flush := func() {
		if len(batch) > 0 {
			r.send(batch)
			clear(batch)
			batch = batch[:0]
		}
		// Count the interval from the end of this write, so a slow write
		// is not followed straight away by a tiny batch.
		tick.Reset(r.cfg.FlushInterval)
	}
	for {
		select {
		case q, ok := <-r.queue:
			if !ok {
				flush()
				return
			}
			r.queuedBytes.Add(-q.size)
			if r.drain.Err() != nil {
				// Stopping, and out of time to write: what is left is lost.
				r.dropped.Add(1)
				continue
			}
			batch = append(batch, q.ev)
			if len(batch) >= r.cfg.BatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (r *Receiver) ready() bool {
	if r.cfg.Ready == nil {
		return true
	}
	select {
	case <-r.cfg.Ready:
		return true
	default:
		return false
	}
}

// send writes one batch. Failures are counted (write_failed here, and
// "failed" in the ingest stats) and logged at most once a minute; the batch
// is not retried, so a slow or down OpenSearch cannot back up the receiver.
func (r *Receiver) send(batch []ingest.Event) {
	if !r.ready() || r.drain.Err() != nil {
		// Stopping before OpenSearch was ever ready, or out of time.
		r.dropped.Add(int64(len(batch)))
		return
	}
	ctx, cancel := context.WithTimeout(r.drain, writeTimeout)
	defer cancel()
	res, err := r.sink.IngestEvents(ctx, batch)
	if err != nil {
		r.writeFailed.Add(int64(len(batch)))
		r.warn("write", "could not write syslog events to OpenSearch; they were dropped", "events", len(batch), "err", err)
		return
	}
	// Errors lists only the first few; Rejected counts them all.
	if res.Rejected > 0 && len(res.Errors) > 0 {
		r.writeFailed.Add(int64(res.Rejected))
		r.warn("rejected", "OpenSearch rejected some syslog events", "rejected", res.Rejected, "first", res.Errors[0].Reason)
	}
}

// warn logs a problem at most once a minute per kind.
func (r *Receiver) warn(kind, msg string, args ...any) {
	now := time.Now()
	r.warnMu.Lock()
	last, seen := r.warned[kind]
	if seen && now.Sub(last) < time.Minute {
		r.warnMu.Unlock()
		return
	}
	r.warned[kind] = now
	r.warnMu.Unlock()
	r.log.Warn(msg, args...)
}

// ---- stats ----

// Stats returns the receiver's counters. A nil receiver (syslog off)
// reports enabled false.
func (r *Receiver) Stats() Stats {
	if r == nil {
		return Stats{Listeners: []Listener{}, Allow: []string{}, Senders: []Sender{}}
	}
	s := Stats{
		Enabled:     true,
		Listeners:   append([]Listener{}, r.listeners...),
		Allow:       make([]string, 0, len(r.cfg.Allow)),
		Received:    r.received.Load(),
		Dropped:     r.dropped.Load(),
		WriteFailed: r.writeFailed.Load(),
		RejectedBy: Rejections{
			NotAllowed:         r.notAllowed.Load(),
			TooLarge:           r.tooLarge.Load(),
			BadFraming:         r.badFraming.Load(),
			TooManyConnections: r.tooMany.Load(),
			TooManyFromSender:  r.tooManyFromSender.Load(),
		},
		Queued:  len(r.queue),
		Senders: r.senders.list(),
	}
	for _, p := range r.cfg.Allow {
		if p.IsSingleIP() {
			s.Allow = append(s.Allow, p.Addr().String())
		} else {
			s.Allow = append(s.Allow, p.String())
		}
	}
	r.rejMu.Lock()
	if r.lastNotAllowed.IsValid() {
		s.LastNotAllowed = r.lastNotAllowed.String()
	}
	r.rejMu.Unlock()
	for _, pl := range r.proxyLns {
		s.RejectedBy.ProxyUntrusted += pl.Untrusted()
	}
	s.Rejected = s.RejectedBy.ProxyUntrusted + s.RejectedBy.NotAllowed + s.RejectedBy.TooLarge + s.RejectedBy.BadFraming + s.RejectedBy.TooManyConnections + s.RejectedBy.TooManyFromSender
	if ns := r.lastMessage.Load(); ns > 0 {
		s.LastMessage = time.Unix(0, ns).UTC()
	}
	r.mu.Lock()
	s.Connections = len(r.conns)
	r.mu.Unlock()
	return s
}

// Traffic is how many messages this receiver took in and when the last
// came, read without locks so a heartbeat never waits on the receiver.
func (r *Receiver) Traffic() (received int64, last time.Time) {
	if r == nil {
		return 0, time.Time{}
	}
	if ns := r.lastMessage.Load(); ns > 0 {
		last = time.Unix(0, ns).UTC()
	}
	return r.received.Load(), last
}

// senderTable keeps the most recent senders, evicting the one heard from
// longest ago when full.
type senderTable struct {
	mu  sync.Mutex
	max int
	m   map[netip.Addr]*Sender
}

func (t *senderTable) seen(a netip.Addr, host, proto string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[a]
	if s == nil {
		if len(t.m) >= t.max {
			var oldest netip.Addr
			for k, v := range t.m {
				if !oldest.IsValid() || v.LastSeen.Before(t.m[oldest].LastSeen) {
					oldest = k
				}
			}
			delete(t.m, oldest)
		}
		s = &Sender{Address: a.String()}
		t.m[a] = s
	}
	s.Messages++
	s.LastSeen = at.UTC()
	s.Protocol = proto
	// Capped like the event's host, and copied so the table does not keep
	// the whole message alive.
	if host = truncate(host, maxHostLen); host != "" && host != s.Host {
		s.Host = strings.Clone(host)
	}
}

func (t *senderTable) list() []Sender {
	t.mu.Lock()
	out := make([]Sender, 0, len(t.m))
	for _, s := range t.m {
		out = append(out, *s)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// nameBudget limits the distinct vendor-specific field names (cef_*,
// sd_*) each daily index gets, and each sender's share of them. Events go
// to an index by their own day, which can be up to MaxAge back or a day
// ahead, so the budget is kept per index rather than per receive day; names
// over it are dropped and stay in the raw message.
type nameBudget struct {
	mu        sync.Mutex
	perIndex  int
	perSender int
	// servers is how many servers share the budget; nil is one.
	servers func() int
	indices map[string]*indexNames // by model and day
}

// shares returns this server's share of the per-index budget, and the most
// one sender may take of it: an equal part for each server, at least
// minExtraNamesPerServer, and a sender never more than the index's share.
func (b *nameBudget) shares() (perIndex, perSender int) {
	n := 1
	if b.servers != nil {
		n = b.servers()
	}
	if n <= 1 {
		return b.perIndex, b.perSender
	}
	perIndex = max(minExtraNamesPerServer, b.perIndex/n)
	return perIndex, min(b.perSender, perIndex)
}

type indexNames struct {
	day     string
	names   map[string]struct{}
	senders map[netip.Addr]int // names each sender (clientaddr.Key) added
}

func newNameBudget(perIndex, perSender int) nameBudget {
	return nameBudget{perIndex: perIndex, perSender: perSender, indices: map[string]*indexNames{}}
}

func (b *nameBudget) limit(ev ingest.Event, from netip.Addr, now time.Time, maxAge time.Duration) {
	day := ev.Time.UTC().Format("2006.01.02")
	key := ev.Model + "/" + day
	sender := clientaddr.Key(from)
	perIndex, perSender := b.shares()
	b.mu.Lock()
	defer b.mu.Unlock()
	ix := b.indices[key]
	for k := range ev.Fields {
		if !isExtra(k) {
			continue
		}
		if ix == nil {
			ix = b.add(key, day, now, maxAge)
		}
		if _, ok := ix.names[k]; ok {
			continue
		}
		if len(ix.names) >= perIndex || ix.senders[sender] >= perSender {
			delete(ev.Fields, k)
			continue
		}
		ix.names[k] = struct{}{}
		ix.senders[sender]++
	}
}

// add starts the budget of an index, forgetting indices no event can be
// written to any more.
func (b *nameBudget) add(key, day string, now time.Time, maxAge time.Duration) *indexNames {
	oldest := now.Add(-maxAge - 24*time.Hour).UTC().Format("2006.01.02")
	for k, ix := range b.indices {
		if ix.day < oldest {
			delete(b.indices, k)
		}
	}
	ix := &indexNames{day: day, names: map[string]struct{}{}, senders: map[netip.Addr]int{}}
	b.indices[key] = ix
	return ix
}

// refusedCertificate reports whether a TLS handshake failed because the
// sender does not trust the certificate it was shown (see
// httpserver.RefusedCertificate).
func refusedCertificate(err error) bool {
	msg := err.Error()
	if i := strings.LastIndex(msg, "remote error: tls: "); i >= 0 {
		msg = msg[i:]
	} else if i := strings.LastIndex(msg, "local error: tls: "); i >= 0 {
		msg = msg[i:]
	}
	return httpserver.RefusedCertificate(msg)
}
