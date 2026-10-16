package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/httpserver"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// agentServer is the agent port (server.agent_listen): ingest, OTLP,
// osquery and network sensors send there, apart from the web page. Like
// the web listener it belongs to the runner and stays open across a
// restart in place, which holds its requests back meanwhile (agentFront),
// so an agent never finds the port closed; a restart that changes the
// address or HTTPS listens again.
type agentServer struct {
	hs, plain *http.Server
	addr      string // as set, which says whether a restart moves it
	bound     string // the address listened on
	https     bool
	certs     atomic.Pointer[tlsauto.Manager]
}

// listenAgents makes the agent port match c: it listens on c's agent
// address, keeps the open one when that is the same, and closes it when
// agents send to the web port. certs is the HTTPS certificate of the
// instance that starts.
func (r *runner) listenAgents(c *config.Config, certs *tlsauto.Manager) error {
	addr, https := c.Server.AgentAddr(), c.Server.HTTPS() && certs != nil
	r.agentMu.Lock()
	defer r.agentMu.Unlock()
	if a := r.agentSrv; a != nil {
		if a.addr == addr && a.https == https {
			a.certs.Store(certs)
			return nil
		}
		r.agentSrv = nil
		a.close(drainWait)
	}
	if addr == "" {
		return nil
	}
	lim := webLimits(c)
	ln, err := httpserver.Listen(addr, lim, r.log)
	if err != nil {
		return keyed(fmt.Errorf("cannot listen for agents on %s: %w", addr, opError(err)), "server.agent_listen")
	}
	// Load balancers may check this port as they check the web port.
	probed := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if r.front.probe(w, req) {
				return
			}
			h.ServeHTTP(w, req)
		})
	}
	a := &agentServer{hs: httpserver.New(probed(r.agentFront), lim, r.log), addr: addr, bound: ln.Addr().String(), https: https}
	a.certs.Store(certs)
	if https {
		httpserver.OnRefusal(a.hs, func(addr string) {
			if m := a.certs.Load(); m != nil {
				m.NoteRefusal(addr, "https")
			}
			if v := r.agents.Load(); v != nil {
				v.NoteRefusedCA(addr)
			}
		})
		a.hs.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			m := a.certs.Load()
			if m == nil {
				return nil, errNoCertificate
			}
			return m.GetCertificate(hello)
		}
		a.plain = httpserver.New(probed(r.agentFront.plainSide()), lim, r.log)
		go func() { r.agentServeEnded(a, httpserver.ServeBoth(a.hs, a.plain, ln)) }()
	} else {
		go func() { r.agentServeEnded(a, a.hs.Serve(ln)) }()
	}
	r.agentSrv = a
	r.log.Info("agents send to", "addr", a.bound, "url", c.AgentURL(c.Server.PublicURL))
	if n := c.AgentListenNotice(); n != "" {
		r.log.Warn(n)
	}
	return nil
}

// agentPort returns the agent port open now, or nil.
func (r *runner) agentPort() *agentServer {
	r.agentMu.Lock()
	defer r.agentMu.Unlock()
	return r.agentSrv
}

// closeAgents stops listening for agents, at shutdown.
func (r *runner) closeAgents(wait time.Duration) {
	r.agentMu.Lock()
	a := r.agentSrv
	r.agentSrv = nil
	r.agentMu.Unlock()
	if a != nil {
		a.close(wait)
	}
}

// agentServeEnded logs why the agent port stopped serving, unless it was
// closed.
func (r *runner) agentServeEnded(a *agentServer, err error) {
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		r.log.Error("the agent port stopped", "addr", a.bound, "err", err)
	}
}

// close stops listening, which frees the port at once, and waits up to
// wait for batches in progress.
func (a *agentServer) close(wait time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	var wg sync.WaitGroup
	if a.plain != nil {
		wg.Go(func() { _ = a.plain.Shutdown(ctx) })
	}
	_ = a.hs.Shutdown(ctx)
	wg.Wait()
}
