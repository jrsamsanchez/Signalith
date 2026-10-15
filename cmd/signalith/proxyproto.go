package main

import (
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/proxyproto"
)

// proxyServer is the API server of the running instance, whose settings
// say which load balancers are trusted now: server.trusted_proxies
// applies at once when changed on the Settings page, while the listeners
// reading PROXY headers stay open.
var proxyServer atomic.Pointer[api.Server]

// followProxyTrust makes the PROXY listeners trust the proxies srv's
// settings list from now on.
func followProxyTrust(srv *api.Server) { proxyServer.Store(srv) }

// proxyFor returns how a listener reads PROXY headers (server.
// proxy_protocol or syslog.proxy_protocol, on) from the trusted proxies
// of c, or nil to read none.
func proxyFor(c *config.Config, on bool, log *slog.Logger) *proxyproto.Config {
	if !on {
		return nil
	}
	static := c.Server.TrustedProxyList()
	return &proxyproto.Config{
		Trusted: static,
		TrustedNow: func() []netip.Prefix {
			if s := proxyServer.Load(); s != nil {
				return s.Running().Server.TrustedProxyList()
			}
			return static
		},
		Setting: "server.trusted_proxies",
		Log:     log,
	}
}
