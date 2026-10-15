package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/jrsamsanchez/signalith/internal/ospki"
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
	// root is true when join may give files to the service's account
	// and write its systemd drop-ins: running as root. A join without it
	// (--no-start, as the Docker image runs it as its own user) writes
	// only files this user can, and changes no owner.
	root bool
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
	// chownFD changes the owner of a file open as fd (see giveTree).
	chownFD func(fd int, path string, uid, gid int) error
	// readSecret reads a line from the terminal without showing it.
	readSecret func() (string, error)
	check      func(context.Context, store.Config) []opensearchcheck.Finding
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
		getenv:   os.Getenv, goos: runtime.GOOS, admin: runningAsAdmin() || joinAnyUser, root: runningAsAdmin(),
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
		chownFD:   chownFD,
		readSecret: func() (string, error) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			return string(b), err
		},
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
		e.serviceActive = func() bool {
			return run("powershell", "-NoProfile", "-NonInteractive", "-Command",
				"if ((Get-Service -Name Signalith -ErrorAction Stop).Status -ne 'Running') { exit 1 }") == nil
		}
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
	fs.StringVar(&o.listen, "listen", "", "address the web page and API listen on (default: SIGNALITH_LISTEN, else the answering server's)")
	fs.StringVar(&o.nodeURL, "node-url", "", "address the other servers reach this one at (server.node_url; default: SIGNALITH_NODE_URL)")
	fs.BoolVar(&o.copySyslog, "copy-syslog", false, "receive syslog on the same addresses as the answering server")
	fs.BoolVar(&o.noStart, "no-start", false, "write everything, but do not start the service")
	fs.BoolVar(&o.merge, "merge", false, "keep this server's own users, detections and dashboards, adding those the cluster lacks")
	fs.BoolVar(&o.yes, "yes", false, "do not ask before joining")
	fs.BoolVar(&o.allowSkew, "allow-version-skew", false, "join a cluster whose servers run another version")
	fs.Usage = func() {
		fmt.Fprintln(errOut, "usage: signalith join '<token>' [-c file] [--name name] [--listen addr] [--node-url url] [--copy-syslog] [--no-start] [--merge] [--yes]")
		fmt.Fprintln(errOut, "The token may be - to read it from the standard input, or left out to be asked for it without showing it.")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, err
	}
	// As the server reads them: the Docker image passes its listen
	// address and the address the other servers reach it at this way.
	if o.listen == "" {
		o.listen = strings.TrimSpace(getenv("SIGNALITH_LISTEN"))
	}
	if o.nodeURL == "" {
		o.nodeURL = strings.TrimSpace(getenv("SIGNALITH_NODE_URL"))
	}
	switch {
	case len(pos) == 1:
		o.token = pos[0]
	case len(pos) == 0:
		// SIGNALITH_JOIN, else asked for on the terminal.
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
	// osKey is this server's own OpenSearch client key, for a client
	// certificate the cluster issues it (OpenSearch.Managed).
	osKey  *rsa.PrivateKey
	bundle *clusterjoin.Bundle
	key    *shared.ClusterKey
	listen string
	// name is the name this server joins with, "" for the one it has or
	// this computer's.
	name string
	// stateExisted is true when the state folder was there before join.
	stateExisted bool
	// in reads the standard input.
	in *bufio.Reader
	// made are the files and folders join made or changed, given to the
	// service's account (giveTree).
	made []string
	// newMaster is the master key file join made.
	newMaster string
	// ownCAPEM is this server's own certificate authority, before the
	// join gave it the cluster's.
	ownCAPEM []byte
}

func (j *joiner) printf(format string, a ...any) { fmt.Fprintf(j.env.out, format, a...) }

func (j *joiner) run(ctx context.Context) error {
	j.in = bufio.NewReader(j.env.in)
	text, err := j.tokenText()
	if err != nil {
		return err
	}
	tok, err := clusterjoin.Parse(strings.TrimSpace(text))
	if err != nil {
		return failf(joinExitRefused, "%s (%v)", clusterjoin.Refused, err)
	}
	j.tok = tok
	defer j.tok.Clear()
	// Starting the service needs root or Administrator; with --no-start
	// (the Docker image, which runs as its own user) join only writes
	// files this user can write.
	if !j.env.admin && !j.o.noStart {
		return failf(joinExitFailed, "Run signalith join as root (sudo) or as an Administrator: it writes the service's files and starts it. "+
			"To only write this user's own files (as in a container), add --no-start.")
	}

	// 2. This machine: its config, and not in a cluster yet. Nothing is
	// written before the admin said yes.
	if err := j.readLocal(); err != nil {
		return err
	}
	if !j.o.yes && j.env.terminal {
		j.printf("Join this server, %s, to the cluster of %s? It then uses that cluster's OpenSearch, users and settings. [y/N] ", j.guessName(), j.tok.URL)
		line, _ := j.in.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return failf(joinExitFailed, "Nothing was done; the token can still be used.")
		}
	}
	// 1. The server the token names, checked by its certificate.
	if err := j.pin(ctx); err != nil {
		return err
	}
	// 3. Its identity and keys. What join makes is the service's account's
	// however join ends, so the service can use it.
	defer j.ownLeftovers()
	if err := j.makeLocal(); err != nil {
		return err
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
	if err := j.write(ctx); err != nil {
		return err
	}
	// --merge: this server's own files into the cluster's, once what
	// joins this server is written and kept.
	merged := j.mergeAfterWrite(ctx)
	// 9. Start.
	if err := j.start(); err != nil {
		return err
	}
	return merged
}

// tokenText is the join token: the argument, SIGNALITH_JOIN, a line of
// the standard input for "-", or asked for on the terminal without
// showing it, so it is not in the process list while join runs.
func (j *joiner) tokenText() (string, error) {
	switch j.o.token {
	case "-":
		line, err := j.in.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			return "", failf(joinExitFailed, "No join token on the standard input (%v).", firstErr(err, io.EOF))
		}
		return line, nil
	case "":
		if !j.env.terminal || j.env.readSecret == nil {
			return "", failf(joinExitFailed, "Give the join token: signalith join '<token>', or signalith join - to read it from the standard input.")
		}
		fmt.Fprint(j.env.out, "Join token (it is not shown): ")
		text, err := j.env.readSecret()
		fmt.Fprintln(j.env.out)
		if err != nil || strings.TrimSpace(text) == "" {
			return "", failf(joinExitFailed, "No join token was given.")
		}
		return text, nil
	}
	return j.o.token, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
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

// alreadyMember is the refusal of a machine that has a cluster's key
// already.
func alreadyMember(what, state string) error {
	return failf(joinExitFailed, "This computer belongs to a cluster already: it has %s. If it should join this cluster instead, stop Signalith, "+
		"run signalith cluster leave (or move the keys folder and cache.enc out of %s), then run signalith join again.", what, state)
}

// readLocal reads this machine's config, refuses one that is in a
// cluster already, and works out its name. It writes nothing.
func (j *joiner) readLocal() error {
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
		// Its folders resolve next to the file join will write.
		j.c = config.DefaultFor(path)
	} else {
		return err
	}
	state := j.c.StateDir()
	if keys := shared.ClusterKeyFiles(state); len(keys) > 0 {
		return alreadyMember(keys[0], state)
	}
	if _, err := os.Stat(shared.CachePath(state)); err == nil {
		return alreadyMember(shared.CachePath(state), state)
	}
	if _, err := os.Lstat(state); err == nil {
		j.stateExisted = true
	}
	// The name: --name, else the one signalith.yaml or the service's
	// environment gives (which the service starts with), else the one it
	// has or this computer's.
	if j.o.name != "" && j.c.Cluster.NodeName != "" && j.o.name != j.c.Cluster.NodeName {
		return failf(joinExitFailed, "This server is named %s in its settings (cluster.node_name in %s, or SIGNALITH_NODE_NAME), and the service starts with that name. "+
			"Change it there to join as %s, or join without --name.", j.c.Cluster.NodeName, path, j.o.name)
	}
	j.name = firstSet(j.o.name, j.env.getenv("SIGNALITH_NODE_NAME"), j.c.Cluster.NodeName)
	if j.name != "" && !config.ValidNodeName(j.name) {
		return failf(joinExitFailed, "The name %q cannot be a server's name: use 1 to 63 letters, digits, dots, dashes or underscores, starting with a letter or digit.", j.name)
	}
	return nil
}

// guessName is the name the question before joining shows: the one join
// will use, as far as it can tell without writing anything.
func (j *joiner) guessName() string {
	if j.name != "" {
		return j.name
	}
	if id, err := cluster.ReadIdentity(j.c.StateDir()); err == nil && id.Name != "" {
		return id.Name
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return strings.ToLower(h)
	}
	return "this server"
}

// makeLocal makes or reads this machine's identity, master key and node
// key, and the keys of its certificate requests.
func (j *joiner) makeLocal() error {
	state := j.c.StateDir()
	if !j.stateExisted {
		j.made = append(j.made, state)
	}
	local, err := cluster.OpenLocal(state, cluster.LocalOptions{Name: j.name, InContainer: cluster.InContainer()})
	j.made = append(j.made, filepath.Join(state, "cluster"))
	if err == nil {
		j.id = local.Identity
		local.Close()
	} else if id, rerr := cluster.ReadIdentity(state); rerr == nil {
		// The service runs and holds the folder: its identity is kept.
		if j.name != "" && j.name != id.Name {
			return failf(joinExitFailed, "The signalith service runs as %s. Stop it first (sudo systemctl stop signalith) to join with the name %s.", id.Name, j.name)
		}
		j.id = id
	} else {
		return err
	}
	if !config.ValidNodeName(j.id.Name) {
		return failf(joinExitFailed, "This computer's name %q cannot be a server's name: give one with --name.", j.id.Name)
	}

	keys := j.c.Keyring()
	keys.OnCreate = func(src secrets.Source) {
		j.newMaster = src.Path
		j.printf("Made a new master key: %s.\nBack it up: without it the stored passwords and keys cannot be read (events are not affected).\n", src)
	}
	secrets.SetDefault(keys)
	if _, err := keys.Seal("init", "make the master key"); err != nil {
		return fmt.Errorf("making the master key: %w", err)
	}
	if j.newMaster != "" {
		j.made = append(j.made, j.newMaster)
	}
	ks := shared.KeyStore{Dir: state, Master: keys}
	j.made = append(j.made, filepath.Join(state, "keys"))
	if j.nk, err = ks.NodeKey(); err != nil {
		return fmt.Errorf("this server's node key: %w", err)
	}
	if j.httpsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return err
	}
	// The key of its own OpenSearch client certificate, which the cluster
	// issues when Signalith keeps OpenSearch's certificate authority; it
	// never leaves this machine.
	if j.osKey, err = rsa.GenerateKey(rand.Reader, ospki.KeyBits); err != nil {
		return err
	}
	return nil
}

// ownLeftovers gives what join made to the service's account when join
// stops early (a refused token, a failed check): its identity and keys
// stay, and the service, which runs as that account, must read them.
func (j *joiner) ownLeftovers() {
	if err := j.giveOwners(); err != nil {
		fmt.Fprintf(j.env.errOut, "Could not give the files join made to the service's account: %v\n", err)
	}
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
	osCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: j.id.Name, Organization: []string{ospki.Org}}}, j.osKey)
	if err != nil {
		return err
	}
	req.OSCSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: osCSR}))
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
		msg := firstSet(reply.Error, clusterjoin.Refused)
		if msg != clusterjoin.Refused && !strings.Contains(msg, "token was not used") {
			// A version or OpenSearch refused after the token checked out:
			// the token was not used.
			msg += " The token was not used: run signalith join again once this is fixed."
		}
		return failf(joinExitRefused, "%s", msg)
	case http.StatusInternalServerError:
		return failf(joinExitFailed, "%s", firstSet(reply.Error, clusterjoin.ErrSpent.Error()))
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
	// The certificate files are checked from a private folder in the
	// state folder, not the shared temporary one: they may hold the
	// cluster's OpenSearch client key, and one left by a join that was
	// killed is removed at the next.
	tmp := filepath.Join(j.c.StateDir(), "opensearch.join-tmp")
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	files := opensearchFiles(tmp)
	if err := j.writeOpenSearchFiles(files, nil); err != nil {
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

// clientKeyPEM is the key of the bundle's OpenSearch client
// certificate: this server's own for one the cluster issued it
// (Managed), else the one the bundle carries; "" for none.
func (j *joiner) clientKeyPEM() string {
	o := j.bundle.OpenSearch
	switch {
	case o.ClientCertPEM == "":
		return ""
	case o.Managed && j.osKey != nil:
		der, err := x509.MarshalPKCS8PrivateKey(j.osKey)
		if err != nil {
			return ""
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	return o.ClientKeyPEM
}

// writeOpenSearchFiles writes the OpenSearch certificate files of the
// bundle in f, each kept in u first when u is not nil.
func (j *joiner) writeOpenSearchFiles(f osFiles, u *undoList) error {
	if u != nil {
		u.keepDir(f.dir)
	}
	if err := securefile.MkdirPrivate(f.dir); err != nil {
		return err
	}
	o := &j.bundle.OpenSearch
	for _, w := range []struct{ path, data string }{{f.ca, o.CAPEM}, {f.cert, o.ClientCertPEM}, {f.key, j.clientKeyPEM()}} {
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
	if o.ClientCertPEM != "" && j.clientKeyPEM() != "" {
		cfg.CertFile, cfg.KeyFile = f.cert, f.key
	}
	return cfg
}

// write writes everything the server needs, or, when anything fails,
// undoes what it wrote.
func (j *joiner) write(ctx context.Context) (err error) {
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
	// OpenSearch's certificate files.
	files := opensearchFiles(filepath.Join(state, "opensearch"))
	if err := j.writeOpenSearchFiles(files, u); err != nil {
		return fmt.Errorf("OpenSearch's certificate files: %w", err)
	}
	j.made = append(j.made, files.dir)
	// The HTTPS certificate from the cluster's certificate authority.
	if j.bundle.LeafPEM != "" && j.c.Server.TLSMode() == config.TLSAuto {
		u.keepTree(j.c.TLSDir())
		// This server's own certificate authority, which agents set up
		// before the join may trust.
		if b, err := os.ReadFile(filepath.Join(j.c.TLSDir(), "ca.pem")); err == nil {
			j.ownCAPEM = b
		}
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
	if _, err := os.Lstat(filepath.Dir(file)); errors.Is(err, fs.ErrNotExist) {
		j.made = append(j.made, filepath.Dir(file))
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
	if err := j.giveOwners(); err != nil {
		return fmt.Errorf("giving the files to the service's account: %w", err)
	}
	// An archive folder outside the service's own.
	return j.archiveDropIn(path, u)
}

// mergeAfterWrite runs --merge once everything that joins this server is
// written: the merge writes to the cluster's shared settings, which an
// undo of this machine's files could not take back, so it comes last,
// and a merge that fails partway keeps the join. It returns a failure
// with exit code joinExitWrite to report after the service started, or
// nil.
func (j *joiner) mergeAfterWrite(ctx context.Context) error {
	if !j.o.merge {
		return nil
	}
	if err := j.merge(ctx, j.o.config); err != nil {
		return failf(joinExitWrite, "%s joined the cluster, but merging its own files into the cluster's failed: %v. "+
			"The join is kept, and nothing the merge added to the cluster is taken back; add what is missing on the cluster's pages.", j.id.Name, err)
	}
	return nil
}

// writeConfig makes signalith.yaml as signalith init does, without an
// admin password to show: the cluster's users sign in.
func (j *joiner) writeConfig(path string) error {
	c := config.Default()
	c.Server.Listen = firstSet(j.listen, c.Server.Listen)
	c.Server.TLS = &config.ServerTLS{Mode: config.TLSAuto, PlaintextIngest: "deny"}
	c.Syslog.UDP, c.Syslog.TCP, c.Syslog.TLS = "", "", ""
	// No built-in admin password: a joined server's users are the
	// cluster's, and signalith passwd -local adds a break-glass one.
	c.Auth.AdminPasswordHash = ""
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
	if o.ClientCertPEM != "" && j.clientKeyPEM() != "" {
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
// the packages' postinstall does: the files and folders join wrote, never
// a folder it only wrote in (giveTree), and a signalith.yaml it made is
// root's, readable by the service's group.
func (j *joiner) giveOwners() error {
	if j.env.goos != "linux" || j.c == nil || !j.env.root {
		return nil
	}
	uid, gid, ok := j.env.owner()
	if !ok {
		return nil
	}
	for _, p := range j.made {
		if err := giveTree(p, uid, gid, j.env.chownFD); err != nil {
			return err
		}
	}
	if !j.haveConfig {
		if _, err := os.Lstat(j.o.config); err == nil {
			if err := giveTree(j.o.config, 0, gid, j.env.chownFD); err != nil {
				return err
			}
			if err := os.Chmod(j.o.config, 0o640); err != nil {
				return err
			}
		}
	}
	return nil
}

// archiveDropIn lets the service write an archive folder outside
// /var/lib/signalith: systemd's unit allows writes there only.
func (j *joiner) archiveDropIn(path string, u *undoList) error {
	if j.env.goos != "linux" || j.env.dropInDir == "" || !j.env.root {
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
	if j.o.noStart && !j.env.root && j.env.goos == "linux" {
		j.printf("%s joined %s. Start Signalith with %s (signalith serve -c %s). Then add it to your load balancer: %s\n",
			j.id.Name, j.clusterName(), j.o.config, j.o.config, where)
		return nil
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

// clusterName is the cluster's name, with how many servers it has when
// the answering server said: "Signalith (3 servers)".
func (j *joiner) clusterName() string {
	name := firstSet(j.bundle.ClusterName, "Signalith")
	if n := j.bundle.Servers; n > 0 {
		name += fmt.Sprintf(" (%d servers)", n)
	}
	return name
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
// it is now: with the same modes and owners, and through securefile, so
// a private file is private again (on Windows, with the service's access).
func (u *undoList) keepTree(dir string) {
	type entry struct {
		rel      string
		dir      bool
		mode     fs.FileMode
		data     []byte
		uid, gid int
		owned    bool
	}
	var list []entry
	if _, err := os.Stat(dir); err != nil {
		u.keepDir(dir)
		return
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		e := entry{rel: rel, mode: info.Mode().Perm()}
		e.uid, e.gid, e.owned = ownerOf(info)
		switch {
		case d.IsDir():
			e.dir = true
		case d.Type().IsRegular():
			if e.data, err = os.ReadFile(p); err != nil {
				return nil
			}
		default:
			return nil
		}
		list = append(list, e)
		return nil
	})
	u.add(func() error {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		for _, e := range list {
			p := filepath.Join(dir, e.rel)
			var err error
			if e.dir {
				err = securefile.MkdirPrivate(p)
			} else {
				err = securefile.Replace(p, e.data)
			}
			if err != nil {
				return err
			}
			if runtime.GOOS != "windows" {
				if err := os.Chmod(p, e.mode); err != nil {
					return err
				}
			}
			if e.owned {
				if err := os.Lchown(p, e.uid, e.gid); err != nil {
					return err
				}
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
