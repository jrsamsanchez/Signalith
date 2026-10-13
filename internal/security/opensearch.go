package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// userAgent marks the security check's requests in OpenSearch's logs.
const userAgent = "Signalith-security-check"

// demoRootCN is the name of the certificate authority of the demo
// certificates OpenSearch ships with, whose keys anyone can download.
const demoRootCN = "Example Com Inc. Root CA"

// isDemoChain reports whether a certificate chain is OpenSearch's demo
// one.
func isDemoChain(chain []*x509.Certificate) bool {
	for _, c := range chain {
		if c.Subject.CommonName == demoRootCN || c.Issuer.CommonName == demoRootCN {
			return true
		}
	}
	return false
}

// anonymousResult is what the probe without sign-in found.
type anonymousResult struct {
	state  string // open, closed or unknown
	why    string
	demo   bool
	listen bool
	// notLoaded is OpenSearch saying its security settings aren't loaded.
	notLoaded bool
}

// probeAnonymous asks OpenSearch to count events without signing in:
// no user name, password or client certificate, but the same trust,
// certificate check and proxy as Signalith's own connection. It records
// the certificate chain OpenSearch presents, to spot the demo one.
func probeAnonymous(ctx context.Context, conn store.Config, prefix string) anonymousResult {
	base, _, _, _ := redact.Strip(conn.URL)
	anon := conn
	anon.URL, anon.Username, anon.Password, anon.CertFile, anon.KeyFile = base, "", secrets.Secret{}, "", ""
	tr, _ := store.Transport(anon)
	var mu sync.Mutex
	var demo bool
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		mu.Lock()
		demo = demo || isDemoChain(cs.PeerCertificates)
		mu.Unlock()
		return nil
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: OpenSearchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if prefix == "" {
		prefix = "signalith"
	}
	u := strings.TrimRight(base, "/") + "/" + url.PathEscape(prefix) + "-*/_count?allow_no_indices=true&ignore_unavailable=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return anonymousResult{state: "unknown", why: "the OpenSearch address can't be used"}
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	r := anonymousResult{state: "unknown"}
	if err != nil {
		r.why = cleanNetError(err)
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			r.state = "open"
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			r.state = "closed"
		default:
			r.why = "status " + strconv.Itoa(resp.StatusCode)
			r.notLoaded = store.RefusalOf(&store.Error{Status: resp.StatusCode, Body: string(body)}) == store.RefusedNotInitialized
		}
	}
	mu.Lock()
	r.demo = demo
	mu.Unlock()
	return r
}

// cleanNetError says why a request failed without repeating the URL.
func cleanNetError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout") {
		return "no answer in time"
	}
	return short(err.Error())
}

// localAddrs lists this computer's own addresses that aren't loopback.
var localAddrs = func() []netip.Addr {
	list, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range list {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			if ad := p.Addr(); !ad.IsLoopback() && !ad.IsLinkLocalUnicast() {
				out = append(out, ad)
			}
		}
	}
	return out
}

// listensOnNetwork dials port on each of addrs, at once, and reports
// whether any answers.
func listensOnNetwork(ctx context.Context, addrs []netip.Addr, port string) bool {
	if len(addrs) > 16 {
		addrs = addrs[:16]
	}
	found := make(chan bool, len(addrs))
	for _, a := range addrs {
		go func() {
			d := net.Dialer{Timeout: DialTimeout}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
			if err == nil {
				c.Close()
			}
			found <- err == nil
		}()
	}
	yes := false
	for range addrs {
		yes = <-found || yes
	}
	return yes
}

// urlPort is the port of an http(s) address, with the default filled in.
func urlPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// authInfo is what OpenSearch's security plugin says about the account
// Signalith signs in with.
type authInfo struct {
	User        string   `json:"user_name"`
	Roles       []string `json:"roles"`
	BackendRole []string `json:"backend_roles"`
}

// probeAuthInfo asks OpenSearch what Signalith's own account may do.
// refused is how OpenSearch refused to say, when it answered with an
// error.
func probeAuthInfo(ctx context.Context, conn store.Config) (info authInfo, noPlugin bool, why string, refused store.Refusal) {
	conn.Timeout = OpenSearchTimeout
	c := store.New(conn)
	defer c.CloseIdleConnections()
	err := c.Do(ctx, http.MethodGet, "/_plugins/_security/authinfo", nil, &info)
	var se *store.Error
	switch {
	case errors.As(err, &se) && (se.Status == http.StatusNotFound || strings.Contains(se.Body, "no handler found")):
		// OpenSearch without its security plugin.
		return info, true, "", store.NotRefused
	case errors.As(err, &se):
		return info, false, "status " + strconv.Itoa(se.Status), store.RefusalOf(se)
	case err != nil:
		return info, false, cleanNetError(err), store.NotRefused
	}
	return info, false, "", store.NotRefused
}

// probeDataPaths asks the OpenSearch node Signalith talks to where it
// keeps its data: path.data (one folder or a list), else path.home/data.
func probeDataPaths(ctx context.Context, conn store.Config) ([]string, error) {
	conn.Timeout = OpenSearchTimeout
	c := store.New(conn)
	defer c.CloseIdleConnections()
	var out struct {
		Nodes map[string]struct {
			Settings struct {
				Path struct {
					Data json.RawMessage `json:"data"`
					Home string          `json:"home"`
				} `json:"path"`
			} `json:"settings"`
		} `json:"nodes"`
	}
	if err := c.Do(ctx, http.MethodGet, "/_nodes/_local/settings?filter_path=nodes.*.settings.path", nil, &out); err != nil {
		var se *store.Error
		if errors.As(err, &se) {
			return nil, errors.New("status " + strconv.Itoa(se.Status))
		}
		return nil, errors.New(cleanNetError(err))
	}
	for _, n := range out.Nodes {
		p := n.Settings.Path
		var list []string
		var one string
		switch {
		case len(p.Data) == 0:
		case json.Unmarshal(p.Data, &one) == nil && one != "":
			list = []string{one}
		default:
			_ = json.Unmarshal(p.Data, &list)
		}
		if len(list) == 0 && p.Home != "" {
			list = []string{path.Join(p.Home, "data")}
		}
		for i, d := range list {
			if !path.IsAbs(d) && !isWindowsAbs(d) && p.Home != "" {
				list[i] = path.Join(p.Home, d)
			}
		}
		if len(list) > 0 {
			return list, nil
		}
	}
	return nil, errors.New("OpenSearch didn't say")
}

func isWindowsAbs(p string) bool {
	return len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// sameNetwork reports whether host resolves to an address on one of
// this computer's own networks, as a container on the same Docker
// network does.
func sameNetwork(ctx context.Context, host string) bool {
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return false
	}
	list, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range list {
		p, err := netip.ParsePrefix(a.String())
		if err != nil || p.Addr().IsLoopback() {
			continue
		}
		for _, ip := range ips {
			if p.Masked().Contains(ip.Unmap()) {
				return true
			}
		}
	}
	return false
}

// OpenSearchCollectors probe OpenSearch: who can read it without signing
// in, its certificate, what Signalith's account may do, and where it
// keeps events when it runs on this computer.
func OpenSearchCollectors(c *config.Config, inContainer bool, stateDir string) []Collector {
	conn := c.OpenSearchConnection()
	prefix := c.OpenSearch.IndexPrefix
	_, host, _ := urlParts(c.OpenSearch.URL)
	local := isLoopback(host)
	demoAdmin := conn.Username == "admin" && conn.Password.Reveal() == "admin"
	out := []Collector{{
		Name:    "OpenSearch without sign-in",
		Checks:  []string{"rest.opensearch_access", "transit.opensearch", "accounts.opensearch_role"},
		Timeout: OpenSearchTimeout + 2*DialTimeout,
		Run: func(ctx context.Context) func(*Facts) {
			r := probeAnonymous(ctx, conn, prefix)
			if local && r.state == "open" {
				r.listen = listensOnNetwork(ctx, localAddrs(), urlPort(c.OpenSearch.URL))
			}
			same := inContainer && !local && sameNetwork(ctx, host)
			return func(f *Facts) {
				f.OpenSearch.Anonymous, f.OpenSearch.AnonymousErr = r.state, r.why
				f.OpenSearch.DemoCert, f.OpenSearch.Listening = r.demo, r.listen
				f.OpenSearch.SameNetwork = same
				f.OpenSearch.SecurityNotLoaded = f.OpenSearch.SecurityNotLoaded || r.notLoaded
			}
		},
	}, {
		Name:   "OpenSearch account",
		Checks: []string{"accounts.opensearch_role"},
		// Room for the probe's own time limit, so a silent OpenSearch is
		// reported as such rather than as a check that ran out of time.
		Timeout: OpenSearchTimeout + DialTimeout,
		Run: func(ctx context.Context) func(*Facts) {
			info, noPlugin, why, refused := probeAuthInfo(ctx, conn)
			return func(f *Facts) {
				o := &f.OpenSearch
				o.AuthProbed, o.AuthNoPlugin, o.AuthErr, o.AuthRefusal = true, noPlugin, why, refused
				o.AuthUser, o.AuthRoles, o.AuthBackend = info.User, info.Roles, info.BackendRole
				o.DemoAdmin = demoAdmin
				o.SecurityNotLoaded = o.SecurityNotLoaded || refused == store.RefusedNotInitialized
			}
		},
	}}
	if local && !inContainer {
		out = append(out, Collector{
			Name:    "OpenSearch data folder",
			Checks:  []string{"rest.opensearch_disk"},
			Timeout: OpenSearchTimeout + OSTimeout,
			Run: func(ctx context.Context) func(*Facts) {
				paths, err := probeDataPaths(ctx, conn)
				var disks []Disk
				var missing []string
				if err == nil {
					// A folder that isn't here, such as a container's
					// /usr/share/opensearch/data, says nothing about this
					// computer's disks.
					var here []string
					for _, p := range paths {
						if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
							missing = append(missing, p)
						} else {
							here = append(here, p)
						}
					}
					disks = probeDisks(here, false, stateDir)
				}
				return func(f *Facts) {
					if err != nil {
						f.OpenSearch.DataErr = err.Error()
						return
					}
					f.OpenSearch.DataPaths, f.OpenSearch.DataMissing = disks, missing
				}
			},
		})
	}
	return out
}
