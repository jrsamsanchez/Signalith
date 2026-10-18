package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterinstall"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// ClusterInstall hands new servers the install scripts and this server's
// program (Servers > Add a server); nil turns those routes off.
type ClusterInstall struct {
	Files *clusterinstall.Files
	Gate  *clusterinstall.Gate
	// ScriptGate limits downloads of the install scripts (Add a server's
	// and the network sensor's) by address; nil leaves them unlimited.
	// They hold no secrets, but anyone may ask for them.
	ScriptGate *clusterinstall.Gate
	// Deployment is how this server runs: docker, systemd,
	// windows-service, or "" when it was started by hand.
	Deployment string
}

// lines are the one-line installs of a new server that joins with the
// token tok, made on the server at url: install.sh and install.ps1 with
// their SHA-256 checked, and this server's program when the new server is
// the same kind of machine. sums are the SHA-256 of the scripts and the
// program the lines name.
func (ci *ClusterInstall) lines(url, tok, version string) (joinCommands, map[string]string, error) {
	if ci == nil || ci.Files == nil {
		return joinCommands{}, nil, errors.New("this server does not hand out install scripts")
	}
	goos, goarch := ci.Files.Platform()
	// Without its program (a build that cannot read itself) the lines
	// still install from a package.
	bin := ci.Files.BinarySHA256()
	c, err := clusterinstall.Lines(clusterinstall.Line{URL: url, Token: tok, Version: version, GOOS: goos, GOARCH: goarch, BinarySHA256: bin})
	if err != nil {
		return joinCommands{}, nil, err
	}
	sha := clusterinstall.ScriptSHA256()
	sums := map[string]string{clusterinstall.ScriptSH: sha.SH, clusterinstall.ScriptPS1: sha.PS1}
	if bin != "" {
		sums[goos+"/"+goarch] = bin
	}
	return joinCommands{Linux: c.Linux, LinuxNote: c.LinuxNote, Windows: c.Windows, WindowsNote: c.WindowsNote, Docker: c.Docker, DockerRun: c.DockerRun}, sums, nil
}

// installRoutes are public: a new server fetches them before it has
// anything to sign in with. They hand out only the open-source program
// and its scripts, never settings or keys.
var installRoutes = []string{
	"GET /api/cluster/join/install.sh",
	"GET /api/cluster/join/install.ps1",
	"GET /api/cluster/join/binary",
	"GET /api/sensor/install.sh",
	"GET /api/agent/install.sh",
	"GET /api/agent/install.ps1",
}

func (s *Server) routeClusterInstall(mux *http.ServeMux, api *router) {
	mux.HandleFunc("GET /api/cluster/join/install.sh", s.handleInstallScript(clusterinstall.ScriptSH))
	mux.HandleFunc("GET /api/cluster/join/install.ps1", s.handleInstallScript(clusterinstall.ScriptPS1))
	mux.HandleFunc("GET /api/cluster/join/binary", s.handleInstallBinary)
	// What a new server needs from this one's settings (OpenSearch's
	// address, ports), for the Add a server dialog.
	api.admin("GET /api/cluster/join/prepare", s.handleJoinPrepare)
	// Whether this server reaches a new one at its node_url.
	api.admin("GET /api/cluster/servers/{id}/check", s.handleServerCheck)
}

func (s *Server) handleInstallScript(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Install == nil {
			writeError(w, http.StatusNotFound, errors.New("this server does not hand out install scripts"))
			return
		}
		if s.Install.ScriptGate != nil {
			done, ok := s.Install.ScriptGate.Take(s.client(r).Addr.String())
			if !ok {
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, errors.New("too many downloads of the install script from this address; try again later"))
				return
			}
			defer done()
		}
		body, sum, _ := clusterinstall.Script(name)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("X-Signalith-SHA256", sum)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}
}

func (s *Server) handleInstallBinary(w http.ResponseWriter, r *http.Request) {
	if s.Install == nil || s.Install.Files == nil {
		writeError(w, http.StatusNotFound, errors.New("this server does not hand out its program"))
		return
	}
	q := r.URL.Query()
	file, size, sum, err := s.Install.Files.Binary(q.Get("os"), q.Get("arch"))
	if errors.Is(err, clusterinstall.ErrOtherPlatform) {
		goos, goarch := s.Install.Files.Platform()
		writeError(w, http.StatusNotFound, fmt.Errorf("this server runs %s/%s and has only that program", goos, goarch))
		return
	}
	if err != nil {
		s.Log.Warn("cannot hand out this server's program to a new server", "err", err)
		writeError(w, http.StatusInternalServerError, errors.New("this server cannot read its own program"))
		return
	}
	defer file.Close()
	if s.Install.Gate != nil {
		done, ok := s.Install.Gate.Take(s.client(r).Addr.String())
		if !ok {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, errors.New("too many downloads of the program from this address; try again later"))
			return
		}
		defer done()
	}
	name := "signalith"
	if q.Get("os") == "windows" {
		name += ".exe"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Signalith-SHA256", sum)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	io.Copy(w, file)
}

// joinPrepare is GET /api/cluster/join/prepare: what a new server needs
// and whether this server's settings give it, for the Add a server
// dialog's checklist and its Prepare OpenSearch steps.
type joinPrepare struct {
	Version    string `json:"version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Deployment string `json:"deployment,omitempty"`
	// Pinnable is false when this server has no certificate authority a
	// token could name, and PinProblem says why: new servers then join
	// with approval or a key file.
	Pinnable   bool              `json:"pinnable"`
	PinProblem string            `json:"pin_problem,omitempty"`
	PublicURL  string            `json:"public_url,omitempty"`
	NodeURL    string            `json:"node_url,omitempty"`
	ListenPort int               `json:"listen_port,omitempty"`
	OpenSearch prepareOpenSearch `json:"opensearch"`
	// Ports are what a new server must be reachable on, and reach.
	Ports []preparePort `json:"ports"`
	// Scripts are the install scripts' SHA-256.
	Scripts clusterinstall.ScriptSHA `json:"scripts"`
}

type prepareOpenSearch struct {
	// Address is the OpenSearch address new servers are given:
	// cluster.opensearch_url, else this server's own opensearch.url.
	Address string `json:"address"`
	// AddressSet is true when cluster.opensearch_url gives it.
	AddressSet bool `json:"address_set"`
	// Own is this server's opensearch.url, without a user name.
	Own string `json:"own"`
	// Problems are what must change before a server can be added, in
	// order; empty when OpenSearch is ready.
	Problems []prepareProblem `json:"problems"`
	// Auth is how this server signs in to OpenSearch: certificate,
	// password or none.
	Auth string `json:"auth"`
}

type prepareProblem struct {
	// Code is local (OpenSearch's address is this computer only),
	// docker (a name only Docker's own network knows), http (no TLS),
	// no_auth (no password or certificate), skip_verify
	// (opensearch.tls_skip_verify).
	Code string `json:"code"`
	Text string `json:"text"`
}

type preparePort struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	// Where is "new" for a port the new server opens to the others, and
	// "opensearch" for the port the new server reaches OpenSearch on.
	Where string `json:"where"`
	What  string `json:"what"`
}

func (s *Server) handleJoinPrepare(w http.ResponseWriter, r *http.Request) {
	c := s.conf()
	p := joinPrepare{Version: s.Version, Scripts: clusterinstall.ScriptSHA256(), Ports: []preparePort{}}
	if s.Install != nil {
		if s.Install.Files != nil {
			p.OS, p.Arch = s.Install.Files.Platform()
		}
		p.Deployment = s.Install.Deployment
	}
	p.Pinnable = s.TLS != nil && s.TLS.CAPEM() != nil
	switch {
	case p.Pinnable:
	case s.TLS == nil:
		p.PinProblem = "This server doesn't serve HTTPS itself (server.tls.mode is off), so a token has no certificate to name. Turn HTTPS on, or start the new server with this OpenSearch's settings and approve it on this page."
	default:
		p.PinProblem = "This server's HTTPS certificate is from a certificate authority whose root it doesn't have, so a token cannot name it. Start the new server with this OpenSearch's settings and approve it on this page instead."
	}
	p.PublicURL = c.Server.PublicURL
	p.NodeURL = c.Server.NodeURL
	p.ListenPort = portOf(c.Server.Listen)
	p.OpenSearch = prepareOS(c, p.Deployment)
	if p.ListenPort != 0 {
		p.Ports = append(p.Ports, preparePort{Port: p.ListenPort, Proto: "tcp", Where: "new", What: "web page, API and agents"})
	}
	for _, l := range []struct{ addr, proto, what string }{
		{c.Syslog.UDP, "udp", "syslog"},
		{c.Syslog.TCP, "tcp", "syslog"},
		{c.Syslog.TLS, "tcp", "syslog over TLS"},
	} {
		if port := portOf(l.addr); port != 0 {
			if l.what == "syslog" && c.Syslog.PublicPort != 0 {
				port = c.Syslog.PublicPort
			}
			p.Ports = append(p.Ports, preparePort{Port: port, Proto: l.proto, Where: "new", What: l.what})
		}
	}
	if u, err := url.Parse(p.OpenSearch.Address); err == nil && u.Host != "" {
		port := 9200
		if v, err := strconv.Atoi(u.Port()); err == nil {
			port = v
		}
		p.Ports = append(p.Ports, preparePort{Port: port, Proto: "tcp", Where: "opensearch", What: "OpenSearch at " + u.Hostname()})
	}
	writeJSON(w, http.StatusOK, p)
}

// prepareOS works out whether a new server can use OpenSearch as this
// one does.
func prepareOS(c *config.Config, deployment string) prepareOpenSearch {
	o := prepareOpenSearch{Own: redactURL(c.OpenSearch.URL), Address: redactURL(c.OpenSearch.URL), Problems: []prepareProblem{}}
	if c.Cluster.OpenSearchURL != "" {
		o.Address, o.AddressSet = redactURL(c.Cluster.OpenSearchURL), true
	}
	switch {
	case c.OpenSearch.CertFile != "":
		o.Auth = "certificate"
	case c.OpenSearch.Password != "":
		o.Auth = "password"
	default:
		o.Auth = "none"
	}
	add := func(code, text string) { o.Problems = append(o.Problems, prepareProblem{Code: code, Text: text}) }
	u, err := url.Parse(o.Address)
	if err != nil || u.Host == "" {
		add("local", "OpenSearch has no address yet.")
		return o
	}
	host := u.Hostname()
	switch {
	case isLocalHost(host):
		add("local", "OpenSearch's address, "+host+", is this computer only, so another server cannot reach it. Give OpenSearch an address the new server can reach.")
	case deployment == "docker" && !o.AddressSet && !strings.Contains(host, ".") && net.ParseIP(host) == nil:
		add("docker", "OpenSearch's address, "+host+", is a name only Docker's own network knows, and its port is not open to other computers. Publish OpenSearch's port and give its address for new servers.")
	}
	if u.Scheme != "https" {
		add("http", "OpenSearch is reached over plain http, so its password and every event would cross the network readable. Turn on OpenSearch's security plugin (TLS).")
	}
	if o.Auth == "none" {
		add("no_auth", "Signalith signs in to OpenSearch with neither a password nor a certificate, so anyone who reaches OpenSearch could read and change events. Turn on OpenSearch's security plugin and give Signalith a user.")
	}
	if c.OpenSearch.TLSSkipVerify {
		add("skip_verify", "OpenSearch's certificate is not checked (opensearch.tls_skip_verify). Give Signalith OpenSearch's CA file instead.")
	}
	return o
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}

func isLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

func portOf(addr string) int {
	if addr == "" {
		return 0
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// serverCheck is GET /api/cluster/servers/{id}/check.
type serverCheck struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	NodeURL string `json:"node_url,omitempty"`
	// Result is ready, not_ready (it answered, but is not ready yet),
	// no_address (it has no node_url), certificate (its certificate is
	// not from the cluster's certificate authority) or unreachable.
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

func (s *Server) handleServerCheck(w http.ResponseWriter, r *http.Request) {
	if s.Cluster == nil {
		writeError(w, http.StatusServiceUnavailable, errNoCluster)
		return
	}
	id := r.PathValue("id")
	var found bool
	out := serverCheck{}
	for _, srv := range s.Cluster.Status().Servers {
		if srv.NodeID != id {
			continue
		}
		found = true
		out.Name, out.Version = srv.Name, srv.Version
		if srv.Detail != nil {
			out.NodeURL = srv.Detail.NodeURL
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, errors.New("there is no such server"))
		return
	}
	if out.NodeURL == "" {
		out.Result = "no_address"
		out.Detail = "It has no address for the other servers (server.node_url), so they cannot check it or hand it requests."
		writeJSON(w, http.StatusOK, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out.Result, out.Detail = s.dialBack(ctx, out.NodeURL)
	writeJSON(w, http.StatusOK, out)
}

// dialBack asks the server at nodeURL whether it is ready, trusting only
// the cluster's certificate authority (and this server's own).
func (s *Server) dialBack(ctx context.Context, nodeURL string) (result, detail string) {
	u, err := url.Parse(nodeURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "no_address", "Its address for the other servers, " + nodeURL + ", is not a web address."
	}
	pool := x509.NewCertPool()
	if s.TLS != nil {
		pool.AppendCertsFromPEM(s.TLS.AgentCAPEM())
	}
	if s.ClusterTLS != nil {
		if b, ok := s.ClusterTLS.CA(); ok && b != nil {
			pool.AppendCertsFromPEM([]byte(b.CACertPEM))
		}
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			Proxy:           nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	u.Path = strings.TrimSuffix(u.Path, "/") + "/readyz"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := client.Do(req)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if err != nil {
		var cert *tls.CertificateVerificationError
		if errors.As(err, &cert) {
			return "certificate", "It answered, but its certificate is not from the cluster's certificate authority."
		}
		return "unreachable", fmt.Sprintf("This server cannot reach it at %s. Open TCP port %s on it (and on any firewall between) to the other servers.", u.Host, port)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "ready", ""
	}
	return "not_ready", "It answered, but it is not ready yet."
}
