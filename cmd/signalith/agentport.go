package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/httpserver"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// agentServer is the agent port of one start (server.agent_listen):
// ingest, OTLP, osquery and network sensors send there, apart from the
// web page. Unlike the web listener it belongs to the components, as the
// syslog receiver does: a restart closes it and the next start listens
// again, and agents send their batches again meanwhile.
type agentServer struct {
	hs, plain *http.Server
	addr      string
}

// serveAgents listens on the agent port of c and serves srv's agent
// routes there, over HTTPS when c has it on, with the web page's
// certificate. It returns nil when agents send to the web port.
func (r *runner) serveAgents(c *config.Config, srv *api.Server, certs *tlsauto.Manager) (*agentServer, error) {
	addr := c.Server.AgentAddr()
	if addr == "" {
		return nil, nil
	}
	lim := webLimits(c)
	ln, err := httpserver.Listen(addr, lim, r.log)
	if err != nil {
		return nil, keyed(fmt.Errorf("cannot listen for agents on %s: %w", addr, opError(err)), "server.agent_listen")
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
	h := srv.AgentHandler()
	a := &agentServer{hs: httpserver.New(probed(h), lim, r.log), addr: ln.Addr().String()}
	if c.Server.HTTPS() && certs != nil {
		httpserver.OnRefusal(a.hs, func(addr string) {
			certs.NoteRefusal(addr, "https")
			if v := r.agents.Load(); v != nil {
				v.NoteRefusedCA(addr)
			}
		})
		a.hs.TLSConfig.GetCertificate = certs.GetCertificate
		a.plain = httpserver.New(probed(srv.AgentPlainHandler(h)), lim, r.log)
		go func() { r.agentServeEnded(a, httpserver.ServeBoth(a.hs, a.plain, ln)) }()
	} else {
		go func() { r.agentServeEnded(a, a.hs.Serve(ln)) }()
	}
	r.log.Info("agents send to", "addr", a.addr, "url", c.AgentURL(c.Server.PublicURL))
	if n := c.AgentListenNotice(); n != "" {
		r.log.Warn(n)
	}
	return a, nil
}

// agentServeEnded logs why the agent port stopped serving, unless it was
// closed.
func (r *runner) agentServeEnded(a *agentServer, err error) {
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		r.log.Error("the agent port stopped", "addr", a.addr, "err", err)
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
