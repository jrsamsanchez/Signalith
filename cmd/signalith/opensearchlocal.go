// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/oslocal"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

const opensearchUsage = `usage:
  signalith opensearch install [-zip FILE] [-proxy HOST:PORT]
                                             install or upgrade the OpenSearch Signalith runs on this computer
  signalith opensearch remove                remove it, keeping its data
  signalith opensearch status                show what is installed
  signalith opensearch adopt -c CONFIG       on an upgrade: install it when CONFIG's OpenSearch was never set up

The Windows installer runs these; on Linux, run them as root after
installing Signalith's package (docs/install-packages.md). install
downloads OpenSearch ` + oslocal.Version + ` for this system and checks its SHA-512;
-zip uses a copy of that file instead, for a computer without internet
access; -proxy downloads through a proxy (by default the computer's own
proxy setting is used). adopt installs it the same way, and points CONFIG at it, only when
CONFIG still has the address older installers wrote (plain http on this
computer, port 9200, no sign-in) and nothing answers there. On Linux,
install also sets Signalith to use it.
`

// localOpenSearch is what installing OpenSearch needs from the system.
type localOpenSearch interface {
	// prepare makes Data private and checks home may be changed only by
	// administrators, before anything there is used.
	prepare(l oslocal.Layout, home string) error
	exists() bool
	stop() error
	remove() error
	// install creates the service for the program in home, running as its
	// own account, which it gives the folders OpenSearch writes to.
	install(l oslocal.Layout, home string) error
	start() error
	securityAdmin(l oslocal.Layout, home string, port int) error
	memoryMB() uint64
}

func cmdOpenSearch(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, opensearchUsage)
		return errors.New("an opensearch command is required")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("opensearch "+cmd, flag.ExitOnError)
	def := oslocal.DefaultLayout()
	var l oslocal.Layout
	fs.StringVar(&l.Home, "home", def.Home, "folder for OpenSearch's program")
	fs.StringVar(&l.Data, "data", def.Data, "folder for OpenSearch's config, data and logs")
	fs.StringVar(&l.Client, "client", def.Client, "folder for Signalith's certificate for OpenSearch")
	zip := fs.String("zip", "", "the OpenSearch "+oslocal.Version+" release file for this system ("+oslocal.File()+") to install, instead of downloading it")
	proxy := fs.String("proxy", "", "the proxy to download through (host:port); by default the computer's own proxy setting")
	path := configFlag(fs)
	fs.Parse(args)
	sys, err := newLocalOpenSearch()
	if err != nil {
		return err
	}
	client, err := oslocal.Client(*proxy)
	if err != nil {
		return err
	}
	switch cmd {
	case "install":
		if err := installOpenSearch(context.Background(), os.Stdout, sys, l, *zip, client); err != nil {
			return err
		}
		return afterOpenSearchInstall(os.Stdout, l)
	case "adopt":
		applyServiceEnv(*path)
		c, err := loadConfig(*path, newLogger(os.Stderr))
		if err != nil {
			return err
		}
		return adoptOpenSearch(context.Background(), os.Stdout, sys, l, *zip, client, *path, c, answers)
	case "remove":
		return removeOpenSearch(os.Stdout, sys, l)
	case "status":
		st, err := oslocal.LoadState(l)
		if err != nil {
			return err
		}
		fmt.Printf("Release installed: %s, SHA-512 %s\n", oslocal.URL(), oslocal.SHA512())
		if st == nil {
			fmt.Println("Signalith has not installed OpenSearch on this computer.")
			return nil
		}
		fmt.Printf("OpenSearch %s at %s, the %s service (there: %v)\n", st.Version, st.URL(), oslocal.ServiceName, sys.exists())
		if oslocal.Newer(oslocal.Version, st.Version) {
			fmt.Printf("This Signalith installs OpenSearch %s; upgrade to it with: signalith opensearch install\n", oslocal.Version)
		}
		return nil
	}
	fmt.Fprint(os.Stderr, opensearchUsage)
	return fmt.Errorf("unknown opensearch command %q", cmd)
}

// installOpenSearch installs OpenSearch, or upgrades the one installed
// before to the pinned version, and waits until it answers with its
// security settings loaded. Its config, data and certificates are kept.
func installOpenSearch(ctx context.Context, out io.Writer, sys localOpenSearch, l oslocal.Layout, zip string, client *http.Client) error {
	return installOpenSearchFrom(ctx, out, sys, l, zip, client, oslocal.FirstPort)
}

// installOpenSearchFrom is installOpenSearch with a new install taking
// the first free port from firstPort.
func installOpenSearchFrom(ctx context.Context, out io.Writer, sys localOpenSearch, l oslocal.Layout, zip string, client *http.Client, firstPort int) error {
	st, err := oslocal.LoadState(l)
	if err != nil {
		return err
	}
	// fresh is a new install: it unpacks the release it checked, never a
	// program someone left in Home.
	fresh := st == nil
	if fresh {
		// A new install starts from an empty folder: files someone left
		// there are not trusted.
		if entries, err := os.ReadDir(l.Data); err == nil && len(entries) > 0 {
			return fmt.Errorf("%s already has files in it, but Signalith did not install OpenSearch there. Check what is in it, "+
				"move it aside (or delete it if you don't need it), and run the installer again", l.Data)
		}
		if err := sys.prepare(l, ""); err != nil {
			return err
		}
		port, err := oslocal.FreePort(firstPort)
		if err != nil {
			return err
		}
		// From here on, this is an OpenSearch Signalith installs: a run
		// again (after a failure, an upgrade or a repair) carries on with
		// it, on the same port.
		st = &oslocal.State{Version: oslocal.Version, Port: port}
		if err := oslocal.SaveState(l, *st); err != nil {
			return err
		}
	} else if err := sys.prepare(l, ""); err != nil {
		return err
	}
	version := oslocal.Version
	if oslocal.Newer(st.Version, version) {
		// Never down: an older OpenSearch cannot read a newer one's data.
		version = st.Version
	}
	home := l.VersionHome(version)
	if !fresh && st.Version == version && sys.exists() {
		if _, err := os.Stat(filepath.Join(home, "bin")); err == nil {
			fmt.Fprintf(out, "OpenSearch %s is installed; checking it runs.\n", version)
			if err := sys.prepare(l, home); err != nil {
				return err
			}
			if err := sys.start(); err != nil {
				return err
			}
			return waitOpenSearch(ctx, out, sys, l, home, st.Port)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "bin")); fresh || err != nil {
		if version != oslocal.Version {
			return fmt.Errorf("OpenSearch %s is not in %s any more; install Signalith with OpenSearch %s or newer", version, home, version)
		}
		if err := unpackRelease(ctx, out, l, zip, client, home); err != nil {
			return err
		}
	}
	if err := sys.prepare(l, home); err != nil {
		return err
	}
	// Stopped before its settings are written, so it changes nothing
	// while they are.
	if sys.exists() {
		fmt.Fprintln(out, "Stopping OpenSearch to set it up again...")
		if err := sys.stop(); err != nil {
			return err
		}
		if err := sys.remove(); err != nil {
			return err
		}
	}
	port := st.Port
	if err := oslocal.MakeCerts(l, time.Now()); err != nil {
		return fmt.Errorf("making OpenSearch's certificates: %w", err)
	}
	if err := oslocal.WriteConfig(l, home, port, oslocal.HeapMB(sys.memoryMB())); err != nil {
		return fmt.Errorf("writing OpenSearch's settings: %w", err)
	}
	if err := sys.install(l, home); err != nil {
		return err
	}
	if err := oslocal.SaveState(l, oslocal.State{Version: version, Port: port}); err != nil {
		return err
	}
	fmt.Fprintf(out, "Starting OpenSearch %s (the %s service)...\n", version, oslocal.ServiceName)
	if err := sys.start(); err != nil {
		return err
	}
	if err := waitOpenSearch(ctx, out, sys, l, home, port); err != nil {
		return err
	}
	// Older versions' programs.
	if entries, err := os.ReadDir(l.Home); err == nil {
		for _, e := range entries {
			if e.Name() != version {
				os.RemoveAll(filepath.Join(l.Home, e.Name()))
			}
		}
	}
	return nil
}

// unpackRelease checks there is room, downloads the release (or copies
// zip), checks it against the pin and unpacks it to home, in place of
// whatever was there. The tests change it.
var unpackRelease = func(ctx context.Context, out io.Writer, l oslocal.Layout, zip string, client *http.Client, home string) error {
	if err := oslocal.CheckRoom(l); err != nil {
		return err
	}
	file, err := oslocal.Fetch(ctx, zip, l.Download(), client, out)
	if err != nil {
		return err
	}
	defer os.Remove(file)
	if err := os.RemoveAll(home); err != nil {
		return err
	}
	fmt.Fprintf(out, "Unpacking OpenSearch %s to %s...\n", filepath.Base(home), home)
	return oslocal.Extract(file, home)
}

// oldDefaultOpenSearch is the address installers before 0.3.1 wrote when
// they were given none: an OpenSearch the user was to install themselves.
const oldDefaultOpenSearch = "127.0.0.1:9200"

// adoptOpenSearch is for an upgrade of an install made before the
// installer set up OpenSearch. When the config still has the old default
// address with no sign-in and nothing answers there, Signalith has never
// reached an OpenSearch, so this installs one as a new install does and
// points the config file at it. Any other config is left as it is.
func adoptOpenSearch(ctx context.Context, out io.Writer, sys localOpenSearch, l oslocal.Layout, zip string, client *http.Client, path string, c *config.Config, answers func(addr string) bool) error {
	if st, err := oslocal.LoadState(l); err != nil || st != nil {
		return err
	}
	if why := openSearchInUse(c, answers); why != "" {
		fmt.Fprintf(out, "Keeping the OpenSearch in %s: %s.\n", path, why)
		return nil
	}
	fmt.Fprintf(out, "Nothing answers at http://%s, the OpenSearch address in %s, so Signalith installs OpenSearch on this computer.\n", oldDefaultOpenSearch, path)
	// From the next port, so an OpenSearch of the user's that is only
	// stopped now can still start on 9200 later.
	if err := installOpenSearchFrom(ctx, out, sys, l, zip, client, oslocal.FirstPort+1); err != nil {
		return err
	}
	st, err := oslocal.LoadState(l)
	if err != nil {
		return err
	}
	// The config as it was, to go back to.
	before := path + ".before-opensearch"
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := securefile.WriteFile(before, data); err != nil {
		return err
	}
	ca, cert, key := l.ClientFiles()
	if err := config.SetOpenSearch(path, st.URL(), ca, cert, key); err != nil {
		return err
	}
	fmt.Fprintf(out, "Signalith now uses OpenSearch at %s. The config as it was, with http://%s, is in %s: "+
		"if you run an OpenSearch of your own there, copy that file back over %s and restart the Signalith service.\n", st.URL(), oldDefaultOpenSearch, before, path)
	return nil
}

// openSearchInUse says why c's OpenSearch may be one the user runs, or ""
// when it is the old default, untouched, and nothing answers there.
func openSearchInUse(c *config.Config, answers func(addr string) bool) string {
	o := c.OpenSearch
	u, err := url.Parse(o.URL)
	if err != nil || u.Scheme != "http" || u.Port() != "9200" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return "it is not the address older installers wrote"
	}
	if len(o.URLs) > 0 || o.Username != "" || o.Password != "" || o.CAFile != "" || o.CertFile != "" || o.KeyFile != "" {
		return "it has more settings than the address"
	}
	for _, k := range c.PageKeys() {
		if strings.HasPrefix(k, "opensearch.") {
			return "it was changed on the Settings page"
		}
	}
	if answers(oldDefaultOpenSearch) {
		return "something answers at http://" + oldDefaultOpenSearch
	}
	return ""
}

// answers is whether something accepts connections at addr.
func answers(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Waits, as variables so the tests take less time.
var (
	osAnswerWait   = 5 * time.Minute
	osSecurityWait = time.Minute
	osPoll         = 3 * time.Second
)

// waitOpenSearch waits until OpenSearch answers with its security
// settings loaded, and Signalith's certificate signs in. OpenSearch loads
// them by itself as it starts the first time, but tries only once, which
// can fail on a slow computer; then they are loaded with its tool.
func waitOpenSearch(ctx context.Context, out io.Writer, sys localOpenSearch, l oslocal.Layout, home string, port int) error {
	url := fmt.Sprintf("https://127.0.0.1:%d", port)
	health, err := openSearchClient(filepath.Join(l.Certs(), ospki.RootCAFile), "", "")
	if err != nil {
		return err
	}
	ca, cert, key := l.ClientFiles()
	signalith, err := openSearchClient(ca, cert, key)
	if err != nil {
		return err
	}
	status := func() int {
		resp, err := health.Get(url + "/_plugins/_security/health")
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	logs := fmt.Sprintf("its log, %s", filepath.Join(l.Logs(), "signalith.log"))
	deadline := time.Now().Add(osAnswerWait)
	code := 0
	for code = status(); code == 0; code = status() {
		if time.Now().After(deadline) {
			return fmt.Errorf("OpenSearch did not answer at %s. Its service may have stopped: see %s, and the service's own logs in %s", url, logs, l.Logs())
		}
		time.Sleep(osPoll)
	}
	tries := 0
	for code != http.StatusOK {
		wait := time.Now().Add(osSecurityWait)
		for code != http.StatusOK && time.Now().Before(wait) {
			time.Sleep(osPoll)
			code = status()
		}
		if code == http.StatusOK {
			break
		}
		if tries == 3 {
			return fmt.Errorf("OpenSearch answers, but its security settings are not loaded (HTTP %d). See %s", code, logs)
		}
		tries++
		fmt.Fprintln(out, "OpenSearch has not loaded its security settings by itself; loading them...")
		if err := sys.securityAdmin(l, home, port); err != nil {
			fmt.Fprintf(out, "  that did not work yet: %v\n", err)
		}
	}
	resp, err := signalith.Get(url + "/_cluster/health")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OpenSearch refused Signalith's certificate (HTTP %d). See %s", resp.StatusCode, logs)
	}
	fmt.Fprintf(out, "OpenSearch is running at %s, on this computer only, and Signalith signs in to it with its certificate.\n", url)
	return nil
}

// openSearchClient returns an HTTPS client that trusts only OpenSearch's
// CA, signing in with a certificate when one is given.
func openSearchClient(caFile, certFile, keyFile string) (*http.Client, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", caFile)
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if certFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil}}, nil
}

// removeOpenSearch removes the service and the program, keeping the
// config, data and certificates in Data, so installing Signalith again
// carries on with them.
func removeOpenSearch(out io.Writer, sys localOpenSearch, l oslocal.Layout) error {
	st, err := oslocal.LoadState(l)
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Fprintln(out, "Signalith has not installed OpenSearch on this computer; nothing to remove.")
		return nil
	}
	if sys.exists() {
		if err := sys.stop(); err != nil {
			return err
		}
		if err := sys.remove(); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(l.Home); err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed OpenSearch's service and program. Its data, settings and certificates are kept in %s.\n", l.Data)
	return nil
}
