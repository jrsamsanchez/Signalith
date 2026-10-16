package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Brute tries wrong passwords against accounts made for the run, spread
// over every target, the way a password-guessing attack spreads over the
// servers behind a load balancer. The limits should hold for all servers
// together: each account gets only a few real password checks before
// sign-ins to it are refused (429), whichever server is asked.
type Brute struct {
	load     BruteLoad
	targets  []string
	tls      transportMaker
	accounts []string
	m        *Metrics

	mu      sync.Mutex
	checked map[string]int64
}

// transportMaker makes an HTTP transport that dials with dial.
type transportMaker func(dial func(ctx context.Context, network, addr string) (net.Conn, error)) http.RoundTripper

// Run attacks until ctx ends.
func (b *Brute) Run(ctx context.Context) {
	b.checked = map[string]int64{}
	sources := max(b.load.Sources, 1)
	trs := make([]http.RoundTripper, sources)
	for i := range trs {
		trs[i] = b.tls(b.dialer(i))
	}
	sem := make(chan struct{}, 256)
	var wg sync.WaitGroup
	pace(ctx, b.load.Rate, b.m, func(n int64) {
		select {
		case sem <- struct{}{}:
		default:
			b.m.Add("brute_dropped", 1)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			acct := b.accounts[n%int64(len(b.accounts))]
			src := int(n % int64(sources))
			target := b.targets[n%int64(len(b.targets))]
			b.attempt(ctx, trs[src], target, acct)
		}()
	})
	wg.Wait()
	var most int64
	for _, n := range b.checked {
		most = max(most, n)
	}
	b.m.Set("", "brute_checked_per_account", float64(most))
}

// dialer is how source i connects: from its own loopback address when
// the target is on this machine, or with a PROXY v2 header naming the
// source (or the one proxy address) when the scenario says so.
func (b *Brute) dialer(i int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 10 * time.Second}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostOf(addr)); err == nil && len(ips) > 0 {
				port, _ := strconv.Atoi(portOf(addr))
				ap = netip.AddrPortFrom(ips[0], uint16(port))
			}
		}
		if b.load.ViaProxy == "" && ap.Addr().Is4() && ap.Addr().IsLoopback() && i > 0 {
			// 127.0.0.0/8 is all this machine's, so each source can have
			// its own address.
			d.LocalAddr = &net.TCPAddr{IP: fakeLoopback(i).AsSlice()}
		}
		c, err := d.DialContext(ctx, network, addr)
		if err != nil || b.load.ViaProxy == "" {
			return c, err
		}
		src, err := netip.ParseAddr(b.load.ViaProxy)
		if err != nil {
			c.Close()
			return nil, err
		}
		dst, _ := netip.ParseAddrPort(c.RemoteAddr().String())
		h, err := proxyV2Header(false, netip.AddrPortFrom(src, uint16(30000+i%30000)), dst)
		if err == nil {
			_, err = c.Write(h)
		}
		if err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
}

func hostOf(addr string) string {
	h, _, _ := net.SplitHostPort(addr)
	return h
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// fakeLoopback is the n-th loopback address after 127.0.0.1.
func fakeLoopback(n int) netip.Addr {
	return netip.AddrFrom4([4]byte{127, byte(1 + n>>16), byte(n >> 8), byte(n)})
}

func (b *Brute) attempt(ctx context.Context, tr http.RoundTripper, target, acct string) {
	s := newSession(target, tr, acct, wrongPassword())
	start := time.Now()
	err := s.SignIn(ctx)
	if ctx.Err() != nil {
		return
	}
	b.m.Observe("brute_signin", time.Since(start))
	b.m.Add("brute_attempts", 1)
	switch st := statusOf(err); {
	case err == nil:
		b.m.Add("brute_signed_in", 1)
	case st == http.StatusUnauthorized:
		b.mu.Lock()
		b.checked[acct]++
		b.mu.Unlock()
		b.m.Add("brute_wrong_password", 1)
	case st == http.StatusTooManyRequests:
		b.m.Add("brute_lockouts", 1)
	default:
		b.m.Add("brute_errors", 1)
		b.m.Add("brute_status_"+strconv.Itoa(st), 1)
	}
}

func wrongPassword() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "wrong-" + hex.EncodeToString(b)
}

// randomPassword is a password for an account made for the run.
func randomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CookieFlooder sends requests with made-up session cookies, as a scan
// or a stale browser does. Each should be refused without costing
// OpenSearch anything.
type CookieFlooder struct {
	rate    float64
	targets []string
	tr      http.RoundTripper
	m       *Metrics
}

func (c *CookieFlooder) Run(ctx context.Context) {
	client := &http.Client{Transport: c.tr, Timeout: 30 * time.Second}
	sem := make(chan struct{}, 256)
	var wg sync.WaitGroup
	pace(ctx, c.rate, c.m, func(n int64) {
		select {
		case sem <- struct{}{}:
		default:
			c.m.Add("cookie_dropped", 1)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			target := c.targets[n%int64(len(c.targets))]
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+"/api/health", nil)
			if err != nil {
				return
			}
			tok := randomPassword()
			req.Header.Set("Cookie", "signalith_session="+tok+"; __Host-signalith_session="+tok)
			start := time.Now()
			resp, err := client.Do(req)
			if ctx.Err() != nil {
				return
			}
			c.m.Observe("cookie", time.Since(start))
			c.m.Add("cookie_requests", 1)
			if err != nil {
				c.m.Add("cookie_errors", 1)
				return
			}
			resp.Body.Close()
			c.m.Add("cookie_status_"+strconv.Itoa(resp.StatusCode), 1)
		}()
	})
	wg.Wait()
}
