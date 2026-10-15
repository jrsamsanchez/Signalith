package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/opensearchcheck"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// signalith join '<token>' adds this machine to a cluster with a join
// token made on Servers → Add a server (or signalith cluster token): it
// checks the server the token names by its certificate, asks it for what a
// new server needs (sealed to this machine's node key), checks that it can
// use the cluster's OpenSearch from here, writes it all, and starts the
// service. Its exit codes are part of its contract with the install
// scripts.
const (
	joinExitOK        = 0
	joinExitFailed    = 1 // the command cannot run here, or the server did not answer
	joinExitRefused   = 2 // the token was refused
	joinExitPin       = 3 // the server is not the one the token names
	joinExitPreflight = 4 // this machine cannot use the cluster's OpenSearch
	joinExitWrite     = 5 // writing failed and was undone
	joinExitStart     = 6 // the service did not start
)

// joinAnyUser lets signalith join run without root or Administrator: only
// in the clustertest build of the cluster tests (join_clustertest.go),
// which join servers in folders the test's own user owns.
var joinAnyUser = false

// joinTimeout bounds each request to the server the token names.
const joinTimeout = 30 * time.Second

// joinBy is who the settings join writes were changed by.
const joinBy = "signalith join"

// serviceStateDir is where the packages keep the service's files; an
// archive folder outside it needs ReadWritePaths in the unit.
const serviceStateDir = "/var/lib/signalith"

// joinEnv is what join uses of the machine, replaced in tests.
type joinEnv struct {
	out, errOut io.Writer
	in          io.Reader
	// terminal reports whether in is a terminal one can ask questions on.
	terminal bool
	getenv   func(string) string
	goos     string
	// admin is true when running as root or Administrator.
	admin bool
	// serviceEnv applies the service's folders and master key settings.
	serviceEnv func(configPath string)
	// serviceActive reports whether the signalith service runs here.
	serviceActive func() bool
	// startService enables and (re)starts the service.
	startService func() error
	// systemctl runs systemctl.
	systemctl func(args ...string) error
	// dropInDir is where the unit's drop-in files go; "" for none.
	dropInDir string
	// owner is the service account's uid and gid; ok false for none.
	owner func() (uid, gid int, ok bool)
	chown func(path string, uid, gid int) error
	check func(context.Context, store.Config) []opensearchcheck.Finding
	// listenFree reports why addr cannot be listened on, nil when it can.
	listenFree func(addr string) error
	// transport is the base of the HTTP clients, for tests.
	transport func() *http.Transport
	now       func() time.Time
}

func defaultJoinEnv() *joinEnv {
	e := &joinEnv{
		out: os.Stdout, errOut: os.Stderr, in: os.Stdin,
		terminal: term.IsTerminal(int(os.Stdin.Fd())),
		getenv:   os.Getenv, goos: runtime.GOOS, admin: runningAsAdmin() || joinAnyUser,
		serviceEnv: func(path string) { useServiceEnv(path, os.Stdout) },
		check:      opensearchcheck.Check,
		listenFree: func(addr string) error {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			return l.Close()
		},
		transport: func() *http.Transport { return http.DefaultTransport.(*http.Transport).Clone() },
		now:       time.Now,
		owner:     serviceOwner,
		chown:     os.Lchown,
	}
	run := func(name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	e.systemctl = func(args ...string) error { return run("systemctl", args...) }
	switch runtime.GOOS {
	case "linux":
		e.serviceActive = func() bool { return exec.Command("systemctl", "is-active", "--quiet", "signalith").Run() == nil }
		e.startService = func() error {
			if err := e.systemctl("enable", "signalith"); err != nil {
				return err
			}
			return e.systemctl("restart", "signalith")
		}
		// Only where the signalith unit is installed: the packages' or
		// install.sh's.
		for _, unit := range []string{"/usr/lib/systemd/system/signalith.service", "/lib/systemd/system/signalith.service", "/etc/systemd/system/signalith.service"} {
			if _, err := os.Stat(unit); err == nil {
				e.dropInDir = "/etc/systemd/system/signalith.service.d"
				break
			}
		}
	case "windows":
		e.serviceActive = func() bool { return false }
		e.startService = func() error {
			return run("powershell", "-NoProfile", "-NonInteractive", "-Command", "Restart-Service -Name Signalith")
		}
	default:
		e.serviceActive = func() bool { return false }
		e.startService = func() error { return errors.New("start it with: signalith serve") }
	}
	return e
}

// runJoinCommand runs signalith join and returns its exit code.
func runJoinCommand(args []string) int {
	return runJoin(context.Background(), defaultJoinEnv(), args)
}

// joinOptions are signalith join's flags.
type joinOptions struct {
	token, config, name, listen, nodeURL       string
	copySyslog, noStart, merge, yes, allowSkew bool
}

func parseJoinArgs(args []string, errOut io.Writer, getenv func(string) string) (*joinOptions, error) {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	fs.SetOutput(errOut)
	o := &joinOptions{}
	fs.StringVar(&o.config, "c", defaultConfigPath(), "config file")
	fs.StringVar(&o.name, "name", "", "this server's name (default: SIGNALITH_NODE_NAME, else the one it has, else this computer's name)")
	fs.StringVar(&o.listen, "listen", "", "address the web page and API listen on (default: the answering server's)")
	fs.StringVar(&o.nodeURL, "node-url", "", "address the other servers reach this one at (server.node_url)")
	fs.BoolVar(&o.copySyslog, "copy-syslog", false, "receive syslog on the same addresses as the answering server")
	fs.BoolVar(&o.noStart, "no-start", false, "write everything, but do not start the service")
	fs.BoolVar(&o.merge, "merge", false, "keep this server's own users, detections and dashboards, adding those the cluster lacks")
	fs.BoolVar(&o.yes, "yes", false, "do not ask before joining")
	fs.BoolVar(&o.allowSkew, "allow-version-skew", false, "join a cluster whose servers run another version")
	fs.Usage = func() {
		fmt.Fprintln(errOut, "usage: signalith join '<token>' [-c file] [--name name] [--listen addr] [--node-url url] [--copy-syslog] [--no-start] [--merge] [--yes]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, err
	}
	switch {
	case len(pos) == 1:
		o.token = pos[0]
	case len(pos) == 0 && getenv("SIGNALITH_JOIN") != "":
		o.token = getenv("SIGNALITH_JOIN")
	default:
		fs.Usage()
		return nil, errors.New("give one join token")
	}
	return o, nil
}

// joinFail is a failure with its exit code.
type joinFail struct {
	code int
	msg  string
}

func (e *joinFail) Error() string { return e.msg }

func failf(code int, format string, a ...any) *joinFail {
	return &joinFail{code: code, msg: fmt.Sprintf(format, a...)}
}

func runJoin(ctx context.Context, env *joinEnv, args []string) int {
	o, err := parseJoinArgs(args, env.errOut, env.getenv)
	if err != nil {
		return joinExitFailed
	}
	j := &joiner{env: env, o: o}
	if err := j.run(ctx); err != nil {
		var f *joinFail
		if !errors.As(err, &f) {
			f = &joinFail{code: joinExitFailed, msg: err.Error()}
		}
		fmt.Fprintln(env.errOut, f.msg)
		return f.code
	}
	return joinExitOK
}

// joiner is one run of signalith join.
type joiner struct {
	env *joinEnv
	o   *joinOptions
	tok clusterjoin.Token
	// client trusts only the certificate the token pins.
	client *http.Client
	c      *config.Config
	// haveConfig is true when signalith.yaml was there.
	haveConfig bool
	id         cluster.Identity
	nk         *shared.NodeKey
	httpsKey   *ecdsa.PrivateKey
	bundle     *clusterjoin.Bundle
	key        *shared.ClusterKey
	listen     string
	// made are the paths join made or changed, for their owner.
	made []string
	// newMaster is the master key file join made.
	newMaster string
}

func (j *joiner) printf(format string, a ...any) { fmt.Fprintf(j.env.out, format, a...) }

func (j *joiner) run(ctx context.Context) error {
	tok, err := clusterjoin.Parse(strings.TrimSpace(j.o.token))
	if err != nil {
		return failf(joinExitRefused, "%s (%v)", clusterjoin.Refused, err)
	}
	j.tok = tok
	defer j.tok.Clear()
	if j.o.merge {
		return failf(joinExitFailed, "--merge is not in this version of Signalith yet. Join without it: this server then uses the cluster's users, detections and dashboards, and its own files are kept as they are.")
	}
	if !j.env.admin {
		return failf(joinExitFailed, "Run signalith join as root (sudo) or as an Administrator: it writes the service's files and starts it.")
	}

	// 1. The server the token names, checked by its certificate.
	if err := j.pin(ctx); err != nil {
		return err
	}
	// 2-3. This machine: its config, not in a cluster yet, its identity.
	if err := j.local(); err != nil {
		return err
	}
	if !j.o.yes && j.env.terminal {
		j.printf("Join this server, %s, to the cluster of %s? It then uses that cluster's OpenSearch, users and settings. [y/N] ", j.id.Name, j.tok.URL)
		line, _ := bufio.NewReader(j.env.in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return failf(joinExitFailed, "Nothing was done; the token can still be used.")
		}
	}
	// 4. The join.
	if err := j.join(ctx); err != nil {
		return err
	}
	defer j.bundle.Clear()
	// 5. Preflight, before anything is written.
	if err := j.preflight(ctx); err != nil {
		return err
	}
	// 6-8. Write it all, or nothing.
	if err := j.write(); err != nil {
		return err
	}
	// 9. Start.
	return j.start()
}

// pin fetches the certificate the server at the token's address answers
// /api/cluster/join/ca with, without trusting anything, and checks it is
// the one the token names. From then on the client trusts only it.
func (j *joiner) pin(ctx context.Context) error {
	t := j.env.transport()
	t.Proxy = nil
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402: the certificate is checked by its pin below
	insecure := &http.Client{Transport: t, Timeout: joinTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer t.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.tok.URL+"/api/cluster/join/ca", nil)
	if err != nil {
		return err
	}
	resp, err := insecure.Do(req)
	if err != nil {
		return failf(joinExitFailed, "Could not reach the server at %s: %v. Check that this machine reaches it (its firewall, and the address in the token).", j.tok.URL, err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	mismatch := failf(joinExitPin, "The server at %s does not have the certificate this token names. Someone may be intercepting the connection, or the token belongs to another cluster.", j.tok.URL)
	if resp.StatusCode != http.StatusOK {
		return mismatch
	}
	b, _ := pem.Decode(body)
	if b == nil || b.Type != "CERTIFICATE" || !j.tok.MatchesPin(b.Bytes) {
		return mismatch
	}
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return mismatch
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	u, _ := url.Parse(j.tok.URL)
	st := j.env.transport()
	st.Proxy = nil
	st.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	j.client = &http.Client{Transport: st, Timeout: joinTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return nil
}

// local reads this machine's config, refuses one that is in a cluster
// already, and makes or reads its identity, master key and node key.
func (j *joiner) local() error {
	path := j.o.config
	j.env.serviceEnv(path)
	if _, err := os.Stat(path); err == nil {
		j.haveConfig = true
		c, err := config.LoadUnchecked(path)
		if err != nil {
			return failf(joinExitFailed, "Cannot read %s: %v", path, err)
		}
		j.c = c
	} else if errors.Is(err, fs.ErrNotExist) {
		j.c = config.Default()
	} else {
		return err
	}
	state := j.c.StateDir()
	if keys := shared.ClusterKeyFiles(state); len(keys) > 0 {
		return failf(joinExitFailed, "This server belongs to a cluster already (it has %s): run `signalith cluster leave` there first.", keys[0])
	}
	if _, err := os.Stat(shared.CachePath(state)); err == nil {
		return failf(joinExitFailed, "This server belongs to a cluster already (it has %s): run `signalith cluster leave` there first.", shared.CachePath(state))
	}

	name := firstSet(j.o.name, j.env.getenv("SIGNALITH_NODE_NAME"), j.c.Cluster.NodeName)
	if name != "" && !config.ValidNodeName(name) {
		return failf(joinExitFailed, "The name %q cannot be a server's name: use 1 to 63 letters, digits, dots, dashes or underscores, starting with a letter or digit.", name)
	}
	local, err := cluster.OpenLocal(state, cluster.LocalOptions{Name: name, InContainer: cluster.InContainer()})
	if err == nil {
		j.id = local.Identity
		local.Close()
	} else if id, rerr := cluster.ReadIdentity(state); rerr == nil {
		// The service runs and holds the folder: its identity is kept.
		if name != "" && name != id.Name {
			return failf(joinExitFailed, "The signalith service runs as %s. Stop it first (sudo systemctl stop signalith) to join with the name %s.", id.Name, name)
		}
		j.id = id
	} else {
		return err
	}
	if !config.ValidNodeName(j.id.Name) {
		return failf(joinExitFailed, "This computer's name %q cannot be a server's name: give one with --name.", j.id.Name)
	}
	j.made = append(j.made, filepath.Join(state, "cluster"))

	keys := j.c.Keyring()
	keys.OnCreate = func(src secrets.Source) {
		j.newMaster = src.Path
		j.printf("Made a new master key: %s.\nBack it up: without it the stored passwords and keys cannot be read (events are not affected).\n", src)
	}
	secrets.SetDefault(keys)
	if _, err := keys.Seal("init", "make the master key"); err != nil {
		return fmt.Errorf("making the master key: %w", err)
	}
	ks := shared.KeyStore{Dir: state, Master: keys}
	if j.nk, err = ks.NodeKey(); err != nil {
		return fmt.Errorf("this server's node key: %w", err)
	}
	if j.httpsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return err
	}
	return nil
}

func firstSet(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// certNames are the names this server asks its HTTPS certificate for:
// its name, its node_url's host, this computer's name and addresses.
func (j *joiner) certNames() []string {
	names := []string{j.id.Name}
	if u, err := url.Parse(j.o.nodeURL); err == nil && u.Hostname() != "" {
		names = append(names, u.Hostname())
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, strings.ToLower(h))
	}
	names = append(names, localAddresses(8)...)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > clusterjoin.MaxNames {
		names = names[:clusterjoin.MaxNames]
	}
	return names
}

// join asks the server for the bundle, and opens it.
func (j *joiner) join(ctx context.Context) error {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: j.id.Name}}, j.httpsKey)
	if err != nil {
		return err
	}
	req, err := clusterjoin.NewRequest(j.tok, j.id.NodeID, j.nk.Public())
	if err != nil {
		return err
	}
	req.Name, req.Version, req.OS, req.Arch, req.LevelMax = j.id.Name, version, j.env.goos, runtime.GOARCH, shared.LevelMax
	req.CSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	req.NodeURL, req.Names = j.o.nodeURL, j.certNames()
	req.AllowVersionSkew, req.CopySyslog = j.o.allowSkew, j.o.copySyslog
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, j.tok.URL+"/api/cluster/join", bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := j.client.Do(hr)
	if err != nil {
		return failf(joinExitFailed, "Could not reach the server at %s: %v", j.tok.URL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var reply struct {
		clusterjoin.Reply
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &reply)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return failf(joinExitRefused, "%s", firstSet(reply.Error, clusterjoin.Refused))
	case http.StatusTooManyRequests:
		return failf(joinExitRefused, "The server at %s refused more tries for now; wait a few minutes, then make a new token and run signalith join again.", j.tok.URL)
	default:
		return failf(joinExitFailed, "The server at %s cannot answer joins now (%s): %s", j.tok.URL, resp.Status, firstSet(reply.Error, "no reason given"))
	}
	b, err := clusterjoin.Open(j.nk, j.id.NodeID, j.tok.ID, j.tok.Secret, reply.Sealed)
	if err != nil {
		return failf(joinExitFailed, "The answer of the server at %s cannot be opened: %v", j.tok.URL, err)
	}
	j.bundle = b
	if j.key, err = shared.ClusterKeyFrom(b.ClusterKey); err != nil || j.key.ID() != b.KID {
		return failf(joinExitFailed, "The cluster key the server at %s sent is damaged.", j.tok.URL)
	}
	j.listen = firstSet(j.o.listen, b.Listen, j.c.Server.Listen)
	return nil
}

// newToken says what to do once the token is used and the join cannot go
// on.
const newToken = "Nothing was written. The token is used now: make a new one on Servers → Add a server, then run signalith join again."

// preflight checks, from this machine and with the bundle's settings,
// that this server can work as a member: OpenSearch answers, trusts and
// lets it in, the cluster's document checks out with the key received,
// the listen address is free and the clocks agree. It writes nothing
// outside a temporary folder.
func (j *joiner) preflight(ctx context.Context) error {
	tmp, err := os.MkdirTemp("", "signalith-join-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	files := opensearchFiles(tmp)
	if err := writeOpenSearchFiles(files, &j.bundle.OpenSearch, nil); err != nil {
		return err
	}
	cfg := j.storeConfig(files)
	j.printf("Checking, from this machine, what %s needs:\n", j.id.Name)
	findings := j.env.check(ctx, cfg)
	if !opensearchcheck.Failed(findings) {
		findings = append(findings, j.checkClusterDoc(ctx, cfg))
	}
	if j.listen != "" && !j.env.serviceActive() {
		if err := j.env.listenFree(j.listen); err != nil {
			findings = append(findings, opensearchcheck.Finding{What: "The listen address " + j.listen + " is in use", Fix: "Stop what listens there, or give another with --listen."})
		} else {
			findings = append(findings, opensearchcheck.Finding{OK: true, What: "The listen address " + j.listen + " is free"})
		}
	}
	printFindings(j.env.out, findings)
	if opensearchcheck.Failed(findings) {
		return failf(joinExitPreflight, "%s", newToken)
	}
	return nil
}

// checkClusterDoc reads the cluster's document and checks its MAC with
// the key received.
func (j *joiner) checkClusterDoc(ctx context.Context, cfg store.Config) opensearchcheck.Finding {
	cl := store.New(cfg)
	defer cl.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, joinTimeout)
	defer cancel()
	raw, _, found, err := cl.Get(ctx, shared.ConfigIndex(j.bundle.IndexPrefix), shared.ClusterDocID)
	bad := opensearchcheck.Finding{What: "The cluster's settings in OpenSearch do not match the key the server sent",
		Fix: "This machine may reach another OpenSearch than the cluster's: check opensearch.url and cluster.opensearch_url on the cluster's Settings page."}
	switch {
	case err != nil:
		return opensearchcheck.Finding{What: "The cluster's settings could not be read from OpenSearch", Fix: err.Error()}
	case !found:
		return bad
	}
	var e shared.Envelope
	if json.Unmarshal(raw, &e) != nil || shared.Verify(shared.NewKeySet(j.key), shared.ClusterDocID, &e) != nil {
		return bad
	}
	var body struct {
		ClusterID string `json:"cluster_id"`
	}
	if json.Unmarshal([]byte(e.Body), &body) != nil || body.ClusterID != j.bundle.ClusterID {
		return bad
	}
	return opensearchcheck.Finding{OK: true, What: "The cluster's settings in OpenSearch check out with the key received"}
}

func printFindings(w io.Writer, fs []opensearchcheck.Finding) {
	for _, f := range fs {
		if f.OK {
			fmt.Fprintf(w, "  ok    %s\n", f.What)
			continue
		}
		fmt.Fprintf(w, "  FAIL  %s\n", f.What)
		if f.Fix != "" {
			fmt.Fprintf(w, "        %s\n", f.Fix)
		}
	}
}

// osFiles are where the OpenSearch certificate files go.
type osFiles struct{ dir, ca, cert, key string }

func opensearchFiles(dir string) osFiles {
	return osFiles{dir: dir, ca: filepath.Join(dir, "ca.pem"), cert: filepath.Join(dir, "client.pem"), key: filepath.Join(dir, "client-key.pem")}
}

// writeOpenSearchFiles writes the OpenSearch certificate files the bundle
// has, each kept in u first when u is not nil.
func writeOpenSearchFiles(f osFiles, o *clusterjoin.OpenSearch, u *undoList) error {
	if u != nil {
		u.keepDir(f.dir)
	}
	if err := securefile.MkdirPrivate(f.dir); err != nil {
		return err
	}
	for _, w := range []struct{ path, data string }{{f.ca, o.CAPEM}, {f.cert, o.ClientCertPEM}, {f.key, o.ClientKeyPEM}} {
		if w.data == "" || w.path == f.key && o.ClientCertPEM == "" {
			continue
		}
		if u != nil {
			u.keepFile(w.path)
		}
		if err := securefile.Replace(w.path, []byte(w.data)); err != nil {
			return err
		}
	}
	return nil
}

// storeConfig is the OpenSearch connection of the bundle, with its
// certificate files in f.
func (j *joiner) storeConfig(f osFiles) store.Config {
	o := j.bundle.OpenSearch
	cfg := store.Config{URL: o.URL, Username: o.Username, Password: secrets.New("opensearch.password", o.Password)}
	if o.CAPEM != "" {
		cfg.CAFile = f.ca
	}
	if o.ClientCertPEM != "" && o.ClientKeyPEM != "" {
		cfg.CertFile, cfg.KeyFile = f.cert, f.key
	}
	return cfg
}

// write writes everything the server needs, or, when anything fails,
// undoes what it wrote.
func (j *joiner) write() (err error) {
	u := &undoList{}
	defer func() {
		if err != nil {
			if uerr := u.undo(); uerr != nil {
				err = fmt.Errorf("%w; undoing it also failed: %v", err, uerr)
			}
			err = failf(joinExitWrite, "Could not write what this server needs, so nothing was kept: %v. The token is used now: make a new one, then run signalith join again.", err)
		}
	}()
	path := j.o.config
	state := j.c.StateDir()
	now := j.env.now()

	// signalith.yaml, as signalith init makes it, when there is none.
	if !j.haveConfig {
		u.keepDir(filepath.Dir(path))
		u.keepFile(path)
		if err := j.writeConfig(path); err != nil {
			return err
		}
	}
	// The cluster key.
	keys := shared.KeyStore{Dir: state, Master: j.c.Keyring()}
	u.keepDir(filepath.Join(state, "keys"))
	u.keepFile(shared.ClusterKeyPath(state, j.key.ID()))
	if err := keys.SaveClusterKey(j.key); err != nil {
		return fmt.Errorf("the cluster key: %w", err)
	}
	j.made = append(j.made, filepath.Join(state, "keys"))
	// OpenSearch's certificate files.
	files := opensearchFiles(filepath.Join(state, "opensearch"))
	if err := writeOpenSearchFiles(files, &j.bundle.OpenSearch, u); err != nil {
		return fmt.Errorf("OpenSearch's certificate files: %w", err)
	}
	j.made = append(j.made, files.dir)
	// The HTTPS certificate from the cluster's certificate authority.
	if j.bundle.LeafPEM != "" && j.c.Server.TLSMode() == config.TLSAuto {
		u.keepTree(j.c.TLSDir())
		der, err := x509.MarshalPKCS8PrivateKey(j.httpsKey)
		if err != nil {
			return err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := tlsauto.SeedCluster(j.c.TLSDir(), []byte(j.bundle.ClusterCAPEM), []byte(j.bundle.LeafPEM), keyPEM, now); err != nil {
			return fmt.Errorf("the HTTPS certificate: %w", err)
		}
		j.made = append(j.made, j.c.TLSDir())
	}
	// The settings, as Settings page entries.
	file, err := config.SettingsFileFor(path)
	if err != nil {
		return err
	}
	u.keepDir(filepath.Dir(file))
	u.keepFile(file)
	if err := j.writeSettings(path, files, now); err != nil {
		return fmt.Errorf("the settings in %s: %w", file, err)
	}
	j.made = append(j.made, file)
	if _, err := config.Load(path); err != nil {
		return fmt.Errorf("the settings written do not load: %w", err)
	}
	// The service's account owns what it uses.
	if err := j.giveOwners(path, state, file); err != nil {
		return fmt.Errorf("giving the files to the service's account: %w", err)
	}
	// An archive folder outside the service's own.
	return j.archiveDropIn(path, u)
}

// writeConfig makes signalith.yaml as signalith init does, without an
// admin password to show: the cluster's users sign in.
func (j *joiner) writeConfig(path string) error {
	c := config.Default()
	c.Server.Listen = firstSet(j.listen, c.Server.Listen)
	c.Server.TLS = &config.ServerTLS{Mode: config.TLSAuto, PlaintextIngest: "deny"}
	c.Syslog.UDP, c.Syslog.TCP, c.Syslog.TLS = "", "", ""
	h, err := config.HashPassword(config.RandomToken(18))
	if err != nil {
		return err
	}
	c.Auth.AdminPasswordHash = h
	if err := c.Save(path); err != nil {
		return err
	}
	j.printf("Wrote %s.\n", path)
	return nil
}

// writeSettings writes the bundle's settings into the Settings page's
// file: environment variables still win over them, and the Settings page
// shows them.
func (j *joiner) writeSettings(path string, files osFiles, now time.Time) error {
	pf := config.PageFile{Config: path}
	p, err := pf.Read()
	if err != nil {
		return err
	}
	o := j.bundle.OpenSearch
	set := func(key string, v any) error { return p.Set(key, v, joinBy, now) }
	if err := set("opensearch.url", o.URL); err != nil {
		return err
	}
	if err := set("opensearch.index_prefix", j.bundle.IndexPrefix); err != nil {
		return err
	}
	if err := set("opensearch.tls_skip_verify", false); err != nil {
		return err
	}
	for _, k := range []string{"opensearch.username", "opensearch.password", "opensearch.ca_file", "opensearch.cert_file", "opensearch.key_file"} {
		p.Remove(k)
	}
	if o.Username != "" {
		if err := set("opensearch.username", o.Username); err != nil {
			return err
		}
	}
	if o.Password != "" {
		if err := p.SetSecret("opensearch.password", o.Password, config.Origin(o.URL), joinBy, now); err != nil {
			return err
		}
	}
	if o.CAPEM != "" {
		if err := set("opensearch.ca_file", files.ca); err != nil {
			return err
		}
	}
	if o.ClientCertPEM != "" && o.ClientKeyPEM != "" {
		if err := set("opensearch.cert_file", files.cert); err != nil {
			return err
		}
		if err := set("opensearch.key_file", files.key); err != nil {
			return err
		}
	}
	if j.listen != "" {
		if err := set("server.listen", j.listen); err != nil {
			return err
		}
	}
	if j.o.nodeURL != "" {
		if err := set("server.node_url", j.o.nodeURL); err != nil {
			return err
		}
	}
	if s := j.bundle.Syslog; s != nil {
		for k, v := range map[string]string{"syslog.udp": s.UDP, "syslog.tcp": s.TCP, "syslog.tls": s.TLS} {
			if err := set(k, v); err != nil {
				return err
			}
		}
	}
	return pf.Write(p)
}

// giveOwners gives what join made to the service's account on Linux, as
// the packages' postinstall does: the folders join wrote in, and a
// signalith.yaml it made is root's, readable by the service's group.
func (j *joiner) giveOwners(path, state, settings string) error {
	if j.env.goos != "linux" {
		return nil
	}
	uid, gid, ok := j.env.owner()
	if !ok {
		return nil
	}
	if err := j.env.chown(state, uid, gid); err != nil {
		return err
	}
	paths := slices.Clone(j.made)
	if j.newMaster != "" {
		paths = append(paths, j.newMaster)
	}
	paths = append(paths, filepath.Dir(settings))
	for _, p := range paths {
		if err := giveTree(p, uid, gid, j.env.chown); err != nil {
			return err
		}
	}
	if !j.haveConfig {
		if err := j.env.chown(path, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o640); err != nil {
			return err
		}
	}
	return nil
}

// archiveDropIn lets the service write an archive folder outside
// /var/lib/signalith: systemd's unit allows writes there only.
func (j *joiner) archiveDropIn(path string, u *undoList) error {
	if j.env.goos != "linux" || j.env.dropInDir == "" {
		return nil
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	dir := c.ArchiveDir()
	if dir == "" || within(dir, serviceStateDir) {
		return nil
	}
	file := filepath.Join(j.env.dropInDir, "archive.conf")
	u.keepDir(j.env.dropInDir)
	u.keepFile(file)
	text := "# Written by signalith join: the archive folder is outside " + serviceStateDir + ".\n[Service]\nReadWritePaths=" + dir + "\n"
	if err := os.MkdirAll(j.env.dropInDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(file, []byte(text), 0o644); err != nil {
		return err
	}
	if err := j.env.systemctl("daemon-reload"); err != nil {
		return err
	}
	j.printf("Let the service write the archive folder %s (%s).\n", dir, file)
	return nil
}

// within reports whether path is dir or inside it.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// start starts the service, unless --no-start.
func (j *joiner) start() error {
	where := firstSet(j.o.nodeURL)
	if where == "" {
		host := j.id.Name
		_, port, err := net.SplitHostPort(j.listen)
		if err != nil || port == "" {
			port = "8080"
		}
		where = "https://" + net.JoinHostPort(host, port)
	}
	if j.o.noStart {
		j.printf("%s joined %s. Start it with: sudo systemctl enable --now signalith (Windows: Start-Service Signalith). Then add it to your load balancer: %s\n",
			j.id.Name, j.clusterName(), where)
		return nil
	}
	if err := j.env.startService(); err != nil {
		return failf(joinExitStart, "Everything is written, but the service did not start: %v. See its log (journalctl -u signalith), fix what it says, and start it again.", err)
	}
	j.printf("%s joined %s. Add it to your load balancer: %s\n", j.id.Name, j.clusterName(), where)
	return nil
}

func (j *joiner) clusterName() string {
	return firstSet(j.bundle.ClusterName, "Signalith")
}

// undoList puts back what join wrote, last first.
type undoList struct{ steps []func() error }

func (u *undoList) add(f func() error) { u.steps = append(u.steps, f) }

// keepFile records path as it is now: put back, or removed when it was not
// there.
func (u *undoList) keepFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		u.add(func() error {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			return nil
		})
		return
	}
	mode := fs.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	u.add(func() error { return os.WriteFile(path, data, mode) })
}

// keepDir records that dir and the folders above it that are missing are
// to be removed again.
func (u *undoList) keepDir(dir string) {
	top := ""
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		}
		top = d
		if filepath.Dir(d) == d {
			break
		}
	}
	if top != "" {
		u.add(func() error { return os.RemoveAll(top) })
	}
}

// keepTree records the folder dir and everything in it, to be put back as
// it is now.
func (u *undoList) keepTree(dir string) {
	type entry struct {
		rel  string
		dir  bool
		mode fs.FileMode
		data []byte
	}
	var list []entry
	_, statErr := os.Stat(dir)
	if statErr == nil {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			info, err := d.Info()
			if err != nil {
				return nil
			}
			switch {
			case d.IsDir():
				list = append(list, entry{rel: rel, dir: true, mode: info.Mode().Perm()})
			case d.Type().IsRegular():
				data, err := os.ReadFile(p)
				if err == nil {
					list = append(list, entry{rel: rel, mode: info.Mode().Perm(), data: data})
				}
			}
			return nil
		})
	} else {
		u.keepDir(dir)
		return
	}
	u.add(func() error {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		for _, e := range list {
			p := filepath.Join(dir, e.rel)
			var err error
			if e.dir {
				err = os.MkdirAll(p, e.mode)
			} else {
				err = os.WriteFile(p, e.data, e.mode)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// undo runs the steps, last first, and returns the first error.
func (u *undoList) undo() error {
	var first error
	for i := len(u.steps) - 1; i >= 0; i-- {
		if err := u.steps[i](); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// cmdOpenSearchCheck is signalith opensearch-check <url>: the checks join
// makes, on their own.
func cmdOpenSearchCheck(args []string) error {
	return runOpenSearchCheck(context.Background(), args, os.Stdout, os.Getenv, opensearchcheck.Check)
}

// errChecksFailed is a check that failed; the findings say which.
var errChecksFailed = errors.New("OpenSearch is not ready for several servers yet: see above")

func runOpenSearchCheck(ctx context.Context, args []string, out io.Writer, getenv func(string) string, check func(context.Context, store.Config) []opensearchcheck.Finding) error {
	fs := flag.NewFlagSet("opensearch-check", flag.ContinueOnError)
	fs.SetOutput(out)
	ca := fs.String("ca", "", "PEM file of OpenSearch's certificate authority")
	cert := fs.String("cert", "", "client certificate file")
	key := fs.String("key", "", "client key file")
	user := fs.String("user", "", "OpenSearch user name (the password from SIGNALITH_OPENSEARCH_PASSWORD, or asked for)")
	fs.Usage = func() {
		fmt.Fprintln(out, "usage: signalith opensearch-check <url> [--ca file] [--cert file --key file] [--user u]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return errors.New("give OpenSearch's address, such as https://os.example.com:9200")
	}
	if (*cert == "") != (*key == "") {
		return errors.New("give both --cert and --key, or neither")
	}
	cfg := store.Config{URL: pos[0], Username: *user, CAFile: *ca, CertFile: *cert, KeyFile: *key}
	if *user != "" {
		pw := getenv("SIGNALITH_OPENSEARCH_PASSWORD")
		if pw == "" && term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintf(out, "Password of %s: ", *user)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(out)
			if err != nil {
				return err
			}
			pw = string(b)
		}
		cfg.Password = secrets.New("opensearch.password", pw)
	}
	fs2 := check(ctx, cfg)
	printFindings(out, fs2)
	if opensearchcheck.Failed(fs2) {
		return errChecksFailed
	}
	fmt.Fprintln(out, "OpenSearch is ready for several servers.")
	return nil
}
