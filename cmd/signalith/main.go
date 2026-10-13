// Command signalith is the Signalith SIEM server and admin CLI.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/nlq"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/risk"
	"github.com/jrsamsanchez/signalith/internal/safelog"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/syslog"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
	"github.com/jrsamsanchez/signalith/web"
	"golang.org/x/term"
)

// version is set at build time with -ldflags "-X main.version=..."
var version = "dev"

const usage = `Signalith: an open-source SIEM.

Usage:
  signalith init      [-c file] [flags]   write a starter config file
  signalith serve     [-c file]           run the server
  signalith validate  [-c file]           check the config file
  signalith passwd    [-c file]           set the admin password
  signalith settings  list|reset [-c file] [-file f] [key...]   show or undo changes made on the Settings page
  signalith initial-password [-c file]    print the first admin password the Docker quick start or a package made
  signalith query     [-c file] [-explain] "<query>"   run a query from the shell
  signalith ask       [-c file] [-ai] "<question>"     turn a question into a query
  signalith archive   list|verify|restore [-c file] ...  list, check or restore archived days
  signalith sample-data load|remove|status [-c file] [-size ...]  load or remove a week of sample data to try
  signalith tokens    list|create|rename|revoke|legacy [-c file] ...  the tokens agents send with
  signalith secrets   status|encrypt|set|rotate-master [-c file] ...  the master key and stored passwords
  signalith security  [-c file] [-json]   print the security report (exit 2 when something is at risk)
  signalith service   install|uninstall|start|stop     manage the Windows service
  signalith opensearch-certs -out DIR [-node name] [-san name]   certificates to secure your own OpenSearch
  signalith bootstrap-docker -opensearch-dir DIR -signalith-dir DIR   prepare the Docker quick start (its setup service runs this)
  signalith version

The config file defaults to %s
(override with -c or the SIGNALITH_CONFIG environment variable).
On Linux, validate, settings, secrets and security use the folders, files
and master key the signalith service is given in its unit, when it runs
with the same config file. If the unit cannot be read, give settings and
validate the Settings page's file with -file (the service keeps it in
/var/lib/signalith/lookups/settings.yaml).
`

func defaultConfigPath() string {
	if p := os.Getenv("SIGNALITH_CONFIG"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\Signalith\signalith.yaml`
	}
	return "/etc/signalith/signalith.yaml"
}

func main() {
	runService()
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, defaultConfigPath())
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "serve":
		err = cmdServe(args)
	case "validate":
		err = cmdValidate(args)
	case "passwd":
		err = cmdPasswd(args)
	case "settings":
		err = cmdSettings(args)
	case "initial-password":
		err = cmdInitialPassword(args)
	case "bootstrap-docker":
		err = cmdBootstrapDocker(args)
	case "opensearch-certs":
		err = cmdOpenSearchCerts(args)
	case "query":
		err = cmdQuery(args)
	case "ask":
		err = cmdAsk(args)
	case "service":
		err = cmdService(args)
	case "archive":
		err = cmdArchive(args)
	case "sample-data":
		err = cmdSampleData(args)
	case "tokens":
		err = cmdTokens(args)
	case "secrets":
		err = cmdSecrets(args)
	case "security":
		err = cmdSecurity(args)
	case "version", "-v", "--version":
		fmt.Println("signalith", version)
	case "help", "-h", "--help":
		fmt.Printf(usage, defaultConfigPath())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, defaultConfigPath())
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("c", defaultConfigPath(), "config file")
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	path := configFlag(fs)
	listen := fs.String("listen", "0.0.0.0:8080", "address to listen on")
	publicURL := fs.String("public-url", "", "URL agents use to reach this server (default: derived from -listen)")
	osURL := fs.String("opensearch", "http://127.0.0.1:9200", "OpenSearch URL")
	osUser := fs.String("opensearch-user", "", "OpenSearch username")
	osInsecure := fs.Bool("opensearch-allow-insecure-http", false, "allow the OpenSearch username and password over plain http to another machine (sets opensearch.allow_insecure_http; prefer https)")
	password := fs.String("admin-password", "", "admin password (default: generate one)")
	syslogUDP := fs.String("syslog-udp", "0.0.0.0:514", "address to receive syslog on over UDP (empty: off)")
	syslogTCP := fs.String("syslog-tcp", "0.0.0.0:514", "address to receive syslog on over TCP (empty: off)")
	syslogTLS := fs.String("syslog-tls", "0.0.0.0:6514", "address to receive syslog on over TLS (empty: off)")
	force := fs.Bool("force", false, "overwrite an existing config file")
	savePassword := fs.Bool("save-password", false, "keep a generated admin password in "+initialPasswordFile+" next to the config file, for signalith initial-password, instead of printing it (for installers)")
	fs.Parse(args)

	if _, err := os.Stat(*path); err == nil && !*force {
		return fmt.Errorf("%s already exists; use -force to overwrite it", *path)
	}
	// A service set up already (an install run again) keeps its master
	// key where it has it.
	useServiceEnv(*path, os.Stdout)
	c := config.Default()
	c.Server.Listen = *listen
	c.Server.PublicURL = *publicURL
	// HTTPS with a certificate the server makes for itself, and no
	// agents over plain HTTP.
	c.Server.TLS = &config.ServerTLS{Mode: config.TLSAuto, PlaintextIngest: "deny"}
	c.OpenSearch.URL = *osURL
	c.OpenSearch.Username = *osUser
	c.OpenSearch.AllowInsecureHTTP = *osInsecure
	// New installs receive syslog right away; existing configs without a
	// syslog section keep it off.
	c.Syslog.UDP = *syslogUDP
	c.Syslog.TCP = *syslogTCP
	c.Syslog.TLS = *syslogTLS
	pw := *password
	generated := pw == ""
	if generated {
		pw = config.RandomToken(9)
	}
	h, err := config.HashPassword(pw)
	if err != nil {
		return err
	}
	c.Auth.AdminPasswordHash = h
	// No shared agent token: Add data gives each agent its own (see
	// internal/agenttokens).
	if err := c.Validate(); err != nil {
		return err
	}
	if err := c.Save(*path); err != nil {
		return err
	}
	// An installer shows no output to whoever runs it, so the generated
	// password is kept where only administrators can read it until
	// signalith initial-password shows it.
	saved := generated && *savePassword
	if saved {
		if err := securefile.Replace(filepath.Join(filepath.Dir(*path), initialPasswordFile), []byte(pw+"\n")); err != nil {
			return fmt.Errorf("cannot keep the admin password: %w", err)
		}
	}
	fmt.Printf("Wrote %s\n\n", *path)
	fmt.Printf("  Web UI:      %s\n", c.Server.PublicURL)
	fmt.Printf("  HTTPS:       the server makes its own certificate when it starts; browsers warn\n")
	fmt.Printf("               until you trust it (see docs/https.md)\n")
	fmt.Printf("  User:        %s\n", c.Auth.AdminUser)
	switch {
	case saved:
		fmt.Printf("  Password:    show it with: signalith initial-password   (change it with: signalith passwd)\n")
	case generated:
		fmt.Printf("  Password:    %s   (shown once; change it with: signalith passwd)\n", pw)
	}
	if s := syslogSummary(c); s != "" {
		fmt.Printf("  Syslog:      %s\n", s)
	}
	// Make the master key now (sealing a value makes one when there is
	// none), so init can say where it is and to back it up.
	if _, err := c.Keyring().Seal("init", "make the master key"); err != nil {
		return fmt.Errorf("making the master key: %w", err)
	}
	if src, err := c.Keyring().Source(); err == nil {
		fmt.Printf("  Master key:  %s\n", src)
		if src.Created {
			fmt.Println("               It encrypts the passwords and keys Signalith stores. Back it up; see docs/encryption.md.")
		}
	}
	fmt.Printf("\nNext: start OpenSearch, then run: signalith serve -c %s\n", *path)
	return nil
}

// httpsSummary says how the web UI and agents are protected in transit.
func httpsSummary(c *config.Config) string {
	var s string
	switch c.Server.TLSMode() {
	case config.TLSOff:
		s = "HTTPS is off (server.tls.mode: off), so a reverse proxy in front must add it."
	case config.TLSFiles:
		cert, _ := c.TLSFiles()
		s = "HTTPS is on with the certificate in " + cert + "."
	default:
		s = "HTTPS is on with Signalith's own certificate, kept in " + c.TLSDir() + "."
	}
	if c.Server.HTTPS() {
		if c.Server.PlaintextIngest() {
			s += " Agents may still send over plain HTTP (server.tls.plaintext_ingest: allow); the Health page lists any that do."
		} else {
			s += " Agents must send over HTTPS."
		}
	}
	return s
}

// syslogSummary describes the syslog listeners, or "" when syslog is off.
func syslogSummary(c *config.Config) string {
	var parts []string
	for _, l := range []struct{ name, addr string }{{"UDP", c.Syslog.UDP}, {"TCP", c.Syslog.TCP}, {"TLS", c.Syslog.TLS}} {
		if l.addr != "" {
			parts = append(parts, l.name+" "+l.addr)
		}
	}
	s := strings.Join(parts, ", ")
	// public_port applies to UDP and TCP, whichever are on.
	var fwd []string
	for _, l := range []struct{ name, addr string }{{"UDP", c.Syslog.UDP}, {"TCP", c.Syslog.TCP}} {
		if l.addr != "" {
			fwd = append(fwd, l.name)
		}
	}
	if c.Syslog.PublicPort > 0 && len(fwd) > 0 {
		s += fmt.Sprintf(" (devices send %s to port %d)", strings.Join(fwd, " and "), c.Syslog.PublicPort)
	}
	return s
}

// printSyslogPorts prints the syslog listeners for install scripts, such
// as "udp 514 10.0.0.0/8,192.0.2.10/32" or "tcp 514 any".
func printSyslogPorts(c *config.Config) {
	allow := "any"
	if list := c.Syslog.AllowList(); len(list) > 0 {
		var parts []string
		for _, p := range list {
			parts = append(parts, p.String())
		}
		allow = strings.Join(parts, ",")
	}
	for _, l := range []struct{ proto, addr string }{{"udp", c.Syslog.UDP}, {"tcp", c.Syslog.TCP}, {"tls", c.Syslog.TLS}} {
		if _, port, err := net.SplitHostPort(l.addr); err == nil {
			fmt.Println(l.proto, port, allow)
		}
	}
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := configFlag(fs)
	ports := fs.Bool("syslog-ports", false, "only print the syslog listeners, one per line: protocol, port, and the allowed senders (any, or a comma-separated list); for installers")
	fileFlag := settingsFileFlag(fs)
	fs.Parse(args)
	// -file first: the service's settings below do not replace it.
	if err := useSettingsFile(*fileFlag); err != nil {
		return err
	}
	// The service's folders and master key, so this checks what it uses.
	// Installers read the -syslog-ports output, so nothing else is
	// printed then.
	if *ports {
		applyServiceEnv(*path)
	} else {
		useServiceEnv(*path, os.Stdout)
	}
	c, err := loadConfig(*path, newLogger(os.Stderr))
	if err != nil {
		return err
	}
	if *ports {
		printSyslogPorts(c)
		return nil
	}
	fmt.Printf("%s is valid.\n", *path)
	fmt.Println(httpsSummary(c))
	if n := len(c.Unreadable()); n > 0 {
		fmt.Printf("Warning: %d %s in it cannot be decrypted, so Signalith runs without %s (see the warnings below).\n",
			n, plural(n, "password or key", "passwords or keys"), plural(n, "it", "them"))
	}
	if n := len(c.PageUnreadable()); n > 0 {
		fmt.Printf("Warning: %d %s saved on the Settings page cannot be decrypted, so Signalith runs without %s (see the warnings below).\n",
			n, plural(n, "password or key", "passwords or keys"), plural(n, "it", "them"))
	}
	switch src, err := c.Keyring().Source(); {
	case err == nil:
		fmt.Printf("Master key for stored passwords and keys: %s, key id %s.\n", src, src.KeyID)
	case !errors.Is(err, secrets.ErrNoKey):
		fmt.Println("Warning:", err)
	}
	if p := c.SettingsProblem(); p != "" {
		fmt.Println("Warning:", p)
	} else if keys := c.PageKeys(); len(keys) > 0 {
		fmt.Printf("Changed on the Settings page (%s): %s.\n", c.SettingsFile(), strings.Join(keys, ", "))
	}
	for _, r := range c.Refused() {
		fmt.Printf("Set aside on the Settings page, not used: %s (%s)\n", r.Key, strings.TrimSuffix(r.Reason, "."))
	}
	if *fileFlag == "" {
		if note := serviceNote(c.SettingsFile(), *path, "validate", nil); strings.HasPrefix(note, "The Signalith service") {
			fmt.Println("Note:", note)
		}
	}
	for _, w := range c.SettingsWarnings() {
		fmt.Println("Warning:", w+".")
	}
	// The state folder holds the master key, the HTTPS certificate and
	// this server's identity and its lock.
	state, why := c.StateDirChoice()
	if why != "" {
		fmt.Println("Note:", strings.ToUpper(why[:1])+why[1:]+".")
	}
	warnings, err := cluster.CheckFolder(state)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Println("Warning:", w)
	}
	lib, problems, err := detect.NewLibrary(c.DetectionsDir())
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("Detection error:", p)
		}
		return fmt.Errorf("%d detection file(s) in %s need fixing", len(problems), c.DetectionsDir())
	}
	enabled := 0
	for _, d := range lib.List() {
		if d.Enabled {
			enabled++
		}
	}
	fmt.Printf("%d detections loaded, %d enabled (custom ones in %s).\n", len(lib.List()), enabled, c.DetectionsDir())
	lists, err := assets.NewStore(c.LookupsDir())
	if err != nil {
		return err
	}
	fmt.Printf("%d assets and %d identities loaded from %s.\n", len(lists.Assets()), len(lists.Identities()), c.LookupsDir())
	people, dir, err := openUsers(c)
	if err != nil {
		return err
	}
	n := people.Count()
	fmt.Printf("%d local users and %d directory users in %s, plus the built-in admin %q.\n", n[users.SourceLocal], n[users.SourceDirectory], c.UsersFile(), c.Auth.AdminUser)
	if s := dir.Settings(); s.IsEnabled() {
		from := "the Users page"
		if dir.FromConfig() {
			from = "auth.ldap in this file"
		}
		fmt.Printf("Directory sign-in is on (%s), set up in %s. Test it on the Users page.\n", s.URL, from)
	}
	if p := dir.Problem(); p != "" {
		fmt.Println("Warning:", p)
	}
	feeds := newFeeds(c, nil, nil)
	if err := feeds.Load(); err != nil {
		fmt.Println("Warning:", err)
	}
	if list := feeds.Status(); len(list) > 0 {
		on, page := 0, 0
		for _, f := range list {
			if f.Enabled && f.Problem == "" {
				on++
			}
			if f.Source == intel.SourceUI {
				page++
			}
			// Problems of feeds in signalith.yaml are among the warnings
			// below.
			if f.Problem != "" && f.Source == intel.SourceUI {
				fmt.Printf("Warning: threat intel feed %s (added on the Threat intel page): %s\n", f.Name, f.Problem)
			}
		}
		fmt.Printf("%d threat intel feeds (%d in signalith.yaml, %d added on the Threat intel page), %d enabled.\n", len(list), len(list)-page, page, on)
	}
	notes := &notify.Manager{File: c.NotifyFile(), Log: slog.New(slog.DiscardHandler)}
	if s, err := notes.Settings(); err != nil {
		fmt.Println("Warning:", err)
	} else if len(s.Channels) > 0 {
		on := 0
		for _, r := range s.Rules {
			if r.Enabled {
				on++
			}
		}
		fmt.Printf("%d notification channels and %d rules (%d on), set on the Notifications page.\n", len(s.Channels), len(s.Rules), on)
	}
	if list, err := (&playbooks.Manager{File: c.PlaybooksFile()}).List(); err != nil {
		fmt.Println("Warning:", err)
	} else if len(list) > 0 {
		on := 0
		for _, p := range list {
			if p.Enabled {
				on++
			}
		}
		fmt.Printf("%d playbooks (%d on), set on the Playbooks page.\n", len(list), on)
	}
	if s := syslogSummary(c); s != "" {
		allow := "any sender"
		if len(c.Syslog.Allow) > 0 {
			allow = strings.Join(c.Syslog.Allow, ", ")
		}
		fmt.Printf("Syslog receiver on %s, accepting %s.\n", s, allow)
		if c.Syslog.UDP != "" && len(c.Syslog.Allow) > 0 {
			fmt.Println("Note: over UDP a sender's address can be forged, so syslog.allow cannot fully protect syslog.udp. Use TCP or TLS for trusted senders, and limit the port with a firewall.")
		}
	} else {
		fmt.Println("Syslog receiver is off (set syslog.udp or syslog.tcp to turn it on).")
	}
	if boards, err := dashboards.NewStore(c.DashboardsDir()); err != nil {
		fmt.Printf("Warning: dashboards folder %s: %v\n", c.DashboardsDir(), err)
	} else if list, problems, err := boards.List(); err == nil {
		for _, p := range problems {
			fmt.Printf("Dashboard error: %s: %s\n", p.File, p.Error)
		}
		if len(problems) > 0 {
			return fmt.Errorf("%d dashboard file(s) in %s need fixing", len(problems), c.DashboardsDir())
		}
		fmt.Printf("%d custom dashboards loaded from %s.\n", len(list), c.DashboardsDir())
	}
	for _, w := range c.Warnings() {
		fmt.Println("Warning:", w)
	}
	cl := newStore(c)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if status, err := cl.Health(ctx); err != nil && store.Problem(err) == "" {
		fmt.Printf("Warning: OpenSearch is not reachable yet: %v\n", err)
	} else if err != nil {
		fmt.Println("Warning:", store.Unusable(err))
	} else {
		fmt.Printf("OpenSearch at %s is %s.\n", redact.URL(c.OpenSearch.URL), status)
	}
	return nil
}

func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	if _, err := os.Stat(*path); err != nil {
		return fmt.Errorf("config file %s: %w", *path, err)
	}
	// The service's state folder, and whether the service is given the
	// admin password, which replaces the one in signalith.yaml: a shell
	// has neither.
	useServiceEnv(*path, os.Stdout)
	svcPassword := serviceGives(*path, "SIGNALITH_ADMIN_PASSWORD_FILE", "SIGNALITH_ADMIN_PASSWORD")
	pw := os.Getenv("SIGNALITH_NEW_PASSWORD")
	if pw == "" {
		var err error
		if pw, err = readNewPassword(os.Stdin, os.Stderr); err != nil {
			return err
		}
	}
	h, err := config.HashPassword(pw)
	if err != nil {
		return err
	}
	// Where the first password was generated and passed in a file (the
	// Docker quick start, whose signalith.yaml is read-only), the new one
	// is kept in the state folder and replaces it. So is every later one,
	// and one for a service given the password in its environment.
	stateDir := config.StateDirFor(*path)
	hashFile := config.AdminHashFileIn(stateDir)
	_, statErr := os.Stat(hashFile)
	if os.Getenv("SIGNALITH_ADMIN_PASSWORD_FILE") != "" || svcPassword != "" || statErr == nil {
		if err := config.RecordStateDir(stateDir); err != nil {
			return err
		}
		if err := writeAdminHash(hashFile, h); err != nil {
			return err
		}
		if svcPassword != "" {
			fmt.Printf("Password updated. It is kept in %s, since the signalith service is given %s; it replaces that password.\n", hashFile, svcPassword)
			fmt.Println("Restart the service to apply it.")
			return nil
		}
		fmt.Printf("Password updated. It is kept in %s and replaces the first password.\n", hashFile)
		fmt.Println("Restart the server to apply it. With the Docker quick start, from the Signalith folder: docker compose -f deploy/docker/docker-compose.yml restart signalith")
		return nil
	}
	// Only the hash changes in the file; settings from the environment
	// (such as SIGNALITH_OPENSEARCH_PASSWORD) are not written into it.
	if err := config.SetAdminPasswordHash(*path, h); err != nil {
		return err
	}
	fmt.Println("Password updated. Restart the server to apply it.")
	if os.Getenv("SIGNALITH_ADMIN_PASSWORD") != "" {
		fmt.Println("Note: SIGNALITH_ADMIN_PASSWORD is set in this environment, and wherever it is set for the server it replaces the password in the file.")
	}
	return nil
}

// readNewPassword asks for the new password twice without showing it.
// When input is not a terminal (a script piping it in), it reads one line.
func readNewPassword(in *os.File, prompt io.Writer) (string, error) {
	return readSecret(in, prompt, "New admin password: ", false)
}

// readSecret asks for a password or key with label, twice, without
// showing it. When input is not a terminal (a script piping it in), it
// reads one line. When orEmpty is set, pressing Enter at the first
// question returns "" (so the caller can make a value); otherwise nothing
// entered is an error.
func readSecret(in *os.File, prompt io.Writer, label string, orEmpty bool) (string, error) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(in).ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			return "", errors.New("nothing entered; nothing was changed")
		}
		return line, nil
	}
	read := func(label string) (string, error) {
		fmt.Fprint(prompt, label)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(prompt)
		return string(b), err
	}
	v, err := read(label)
	if err != nil {
		return "", err
	}
	if v == "" {
		if orEmpty {
			return "", nil
		}
		return "", errors.New("nothing entered; nothing was changed")
	}
	again, err := read("Type it again: ")
	if err != nil {
		return "", err
	}
	if again != v {
		return "", errors.New("the two entries do not match; nothing was changed")
	}
	return v, nil
}

// openUsers opens the users file and the directory sign-in settings.
func openUsers(c *config.Config) (*users.Store, *users.Directory, error) {
	people, err := users.Open(c.UsersFile())
	if err != nil {
		return nil, nil, err
	}
	people.BuiltinAdmin = c.Auth.AdminUser
	fromFile, err := c.LDAP()
	if err != nil {
		return nil, nil, err
	}
	dir, err := users.OpenDirectory(c.DirectoryFile(), fromFile)
	if err != nil {
		return nil, nil, err
	}
	return people, dir, nil
}

func newStore(c *config.Config) *store.Client {
	return store.New(c.OpenSearchConnection())
}

func newEngine(c *config.Config, s store.Searcher) *search.Engine {
	return &search.Engine{Store: s, Opt: search.Options{
		IndexPrefix:     c.OpenSearch.IndexPrefix,
		DefaultEarliest: c.Search.DefaultEarliest,
		MaxEvents:       c.Search.MaxEvents,
	}}
}

func cmdQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	path := configFlag(fs)
	explain := fs.Bool("explain", false, "print the OpenSearch request instead of running it")
	fs.Parse(args)
	src := strings.Join(fs.Args(), " ")
	if src == "" {
		return errors.New(`usage: signalith query "datamodel=Authentication | stats count by action"`)
	}
	q, err := query.Parse(src)
	if err != nil {
		return err
	}
	var c *config.Config
	if *explain {
		c, err = config.Load(*path)
		if err != nil {
			c = config.Default() // explaining needs no server
		}
	} else if c, err = config.Load(*path); err != nil {
		return err
	}
	if q.Earliest == "" {
		q.Earliest = c.Search.DefaultEarliest
	}
	eng := newEngine(c, newStore(c))
	if lists, err := assets.NewStore(c.LookupsDir()); err == nil {
		eng.Assets = lists
	}
	if strings.Contains(src, "intel") || strings.Contains(src, "threatmatch") {
		eng.Intel = intel.NewStore(intel.NewOpenSearch(newStore(c), c.OpenSearch.IndexPrefix))
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err := eng.Intel.Load(ctx)
		cancel()
		if err != nil && !*explain {
			return fmt.Errorf("could not read threat intel indicators: %w", err)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if *explain {
		for i, s := range api.Explain(q) {
			fmt.Printf("%d. %s\n", i+1, s)
		}
		plan, err := eng.Compile(q)
		if err != nil {
			return err
		}
		fmt.Printf("\nPOST /%s/_search\n", plan.Index)
		return enc.Encode(plan.Body)
	}
	res, err := eng.Execute(context.Background(), q)
	if err != nil {
		return err
	}
	return enc.Encode(res)
}

func newAssistant(c *config.Config) *assistant.Client {
	a := c.Assistant
	return assistant.New(a.Provider, a.URL, a.Model, a.APIKey)
}

// cmdAsk prints the query for a plain-English question, with how each
// part was understood.
func cmdAsk(args []string) error {
	fs := flag.NewFlagSet("ask", flag.ExitOnError)
	path := configFlag(fs)
	useAI := fs.Bool("ai", false, "ask the configured AI model instead of the built-in translator")
	fs.Parse(args)
	question := strings.Join(fs.Args(), " ")
	if question == "" {
		return errors.New(`usage: signalith ask "failed logins from 203.0.113.9 in the last 24 hours"`)
	}
	c, err := config.Load(*path)
	if err != nil {
		if *useAI {
			return err
		}
		c = config.Default() // the built-in translator needs no server
	}
	var hints nlq.Hints
	if lists, err := assets.NewStore(c.LookupsDir()); err == nil {
		hints = api.AssetHints{A: lists}
	}
	res, err := nlq.Translate(question, hints)
	if err != nil {
		return err
	}
	if *useAI {
		ai := newAssistant(c)
		if ai == nil {
			return errors.New("no AI model is configured; set assistant.provider in the config file")
		}
		q, err := ai.Translate(context.Background(), question, res.Query)
		if err != nil {
			return err
		}
		fmt.Println(q)
		return nil
	}
	fmt.Println(res.Query)
	fmt.Println()
	for _, s := range res.Steps {
		if s.Phrase != "" {
			fmt.Printf("  %-28s %s\n", "\""+s.Phrase+"\"", s.Meaning)
		} else {
			fmt.Printf("  %-28s %s\n", "", s.Meaning)
		}
	}
	if len(res.Unknown) > 0 {
		fmt.Printf("\nNot understood: %s\n", strings.Join(res.Unknown, ", "))
	}
	return nil
}

// cmdServe runs until interrupted (or until the Windows service stops).
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, *path, newLogger(os.Stderr))
}

// newLogger returns the server log. Values in it are cut to a sensible
// length, since some come from whoever connects (such as the user name of
// a failed sign-in).
func newLogger(w io.Writer) *slog.Logger {
	return slog.New(safelog.New(slog.NewTextHandler(w, nil)))
}

// loadConfig loads the config file and makes its master key the one the
// files the server writes are encrypted with; a new master key made later
// is logged.
func loadConfig(path string, log *slog.Logger) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	useKeys(c, log)
	return c, nil
}

// logMasterKey says where the master key comes from.
func logMasterKey(c *config.Config, log *slog.Logger) {
	keys := c.Keyring()
	src, err := keys.Source()
	switch {
	case errors.Is(err, secrets.ErrNoKey):
		log.Info("no master key yet; one is made the first time a password or key is stored", "file", keys.DefaultPath())
		return
	case err != nil:
		log.Error("the master key cannot be read, so stored passwords and keys cannot be decrypted or saved", "err", err)
		return
	}
	log.Info("master key for stored passwords and keys", "key", src.String(), "key_id", src.KeyID)
	if src.OldPath != "" {
		log.Info("the previous master key is still kept after a rotation; remove it once nothing needs it: signalith secrets rotate-master -prune", "file", src.OldPath)
	}
	for _, p := range keys.Unused() {
		log.Warn("another master key file is not used; values encrypted with it cannot be read", "file", p)
	}
}

// useKeys makes c's master key the one the files the server writes are
// encrypted with, says where it comes from when that is new (at the first
// start, or after a restart in place that changed it), and encrypts the
// plain values in those files. Each start of the components, a restart in
// place included, goes through here, so a config loaded again brings its
// own master key.
func (r *runner) useKeys(c *config.Config) {
	useKeys(c, r.log)
	if state := keyState(c); state != r.keysLogged {
		r.keysLogged = state
		logMasterKey(c, r.log)
	}
	encryptStores(c, r.log)
}

// keyState sums up where c's master key comes from, to log it only when
// it changes.
func keyState(c *config.Config) string {
	keys := c.Keyring()
	src, err := keys.Source()
	if err != nil {
		return "error: " + err.Error()
	}
	return fmt.Sprint(src.String(), "|", src.KeyID, "|", src.OldPath, "|", src.OldKeyID, "|", keys.Unused())
}

func serve(ctx context.Context, path string, log *slog.Logger) error {
	hardenProcess(log)
	// A crash prints only the goroutine that failed, not every one with
	// the values on its stack. This is Go's default; it cannot lower a
	// GOTRACEBACK set in the environment, and on Linux hardenProcess
	// keeps even GOTRACEBACK=crash from writing a core file.
	debug.SetTraceback("single")
	c, err := loadConfig(path, log)
	if err != nil {
		return err
	}
	// The identity, its lock, the heartbeat and the job lease belong to
	// the process: an in-process restart keeps them.
	node, log, err := openNode(c, log)
	if err != nil {
		return err
	}
	defer node.Close()
	defer node.Stop()
	// The first start of the Docker quick start with this version decides
	// whether it was upgraded from one whose agents send the example
	// ingest token (see config.Config.OldToken).
	if c.OldToken() == config.OldTokenUndecided {
		cl := newStore(c)
		decided := decideDockerUpgradeAtStart(ctx, c, cl, log)
		cl.CloseIdleConnections()
		if decided {
			if c, err = loadConfig(path, log); err != nil {
				return err
			}
		}
	}
	r := newRunner(path, log)
	r.node = node
	r.browsers = loadBrowserKey(c, log)
	// The node outlives ctx: stopping gives the job lease up first, which
	// needs it.
	node.Start(context.WithoutCancel(ctx))
	return r.run(ctx, c)
}

// instance is every component built from one config: what a restart from
// the Settings page stops and builds again. The web listener, sign-in
// sessions and the user store belong to the runner and carry over.
type instance struct {
	cfg     *config.Config
	srv     *api.Server
	handler http.Handler
	// plain answers plain HTTP on the port that serves HTTPS; handler
	// itself when HTTPS is off.
	plain http.Handler
	// certs is the HTTPS certificate, which syslog over TLS uses too; nil
	// when neither needs one. certKey names the settings it is for.
	certs    *tlsauto.Manager
	certKey  string
	receiver *syslog.Receiver
	// retention is the retention manager.
	retention *retention.Manager
	// jobsList are the background jobs, which run only while this server
	// holds the job lease, and node the cluster node that runs them.
	jobsList []cluster.Job
	node     *cluster.Node
	// store is the OpenSearch client, whose idle connections stop says
	// goodbye to.
	store  *store.Client
	cancel context.CancelFunc
	jobs   sync.WaitGroup // what runs on every server, such as index creation
	log    *slog.Logger
}

// stop ends the background jobs, retention and the syslog receiver, and
// waits for them, so the next instance does not run them twice. The job
// lease is kept: the next instance runs its jobs under the same epoch.
func (in *instance) stop() {
	if in.node != nil {
		in.node.SetJobs(nil)
	}
	in.cancel()
	in.jobs.Wait()
	if in.retention != nil {
		in.retention.Wait()
	}
	if in.receiver != nil {
		// Stop receiving and write out what is queued.
		in.receiver.Wait()
		s := in.receiver.Stats()
		in.log.Info("syslog receiver stopped", "received", s.Received, "dropped", s.Dropped, "write_failed", s.WriteFailed, "rejected", s.Rejected)
	}
	if in.store != nil {
		in.store.CloseIdleConnections()
	}
}

// start builds every component from c and starts the background jobs.
// On an error, what had started is stopped again.
func (r *runner) start(parent context.Context, c *config.Config) (*instance, error) {
	log := r.log
	ctx, cancel := context.WithCancel(parent)
	in := &instance{cfg: c, cancel: cancel, log: log}
	started := false
	defer func() {
		if !started {
			in.stop()
		}
	}()
	if r.failStart != nil {
		if err := r.failStart(c); err != nil {
			return nil, err
		}
	}
	if p := c.SettingsProblem(); p != "" {
		log.Error("settings from the Settings page are not in use", "file", c.SettingsFile(), "problem", p)
	}
	for _, w := range c.SettingsWarnings() {
		log.Warn("Settings page: " + w)
	}
	if keys := c.PageKeys(); len(keys) > 0 {
		log.Info("settings changed on the Settings page are in use", "settings", strings.Join(keys, ","), "file", c.SettingsFile())
	}
	for _, w := range c.Warnings() {
		log.Warn(w)
	}
	if f := c.AdminPasswordChanged(); f != "" {
		log.Info("the built-in admin's password was set with signalith passwd and is kept in a file of its own", "file", f)
	}
	// The HTTPS certificate, which syslog over TLS uses too. A restart
	// keeps the one in use when its settings did not change, and its own
	// certificate authority in any case.
	certs, certKey, err := r.certificates(c)
	if err != nil {
		return nil, err
	}
	if certs != nil {
		in.certs, in.certKey = certs, certKey
		in.jobs.Go(func() { certs.Run(ctx) })
	}
	// The master key, again after a restart: the files saved from now on
	// are encrypted with this config's, and their plain values with it.
	r.useKeys(c)
	cl := newStore(c)
	in.store = cl
	ret := newRetention(c, cl, log)
	maxAge := c.MaxEventAge(retentionKeepDays(ret))
	pipeline := &ingest.Pipeline{Store: cl, Prefix: c.OpenSearch.IndexPrefix, MaxEventAge: maxAge, Log: log}
	// Closed once the index template is in place, so syslog does not
	// create the day's first indices with the wrong field types.
	templateReady := make(chan struct{})
	var receiver *syslog.Receiver
	if c.Syslog.Enabled() {
		sc := syslog.Config{
			UDP: c.Syslog.UDP, TCP: c.Syslog.TCP, TLS: c.Syslog.TLS,
			Allow: c.Syslog.AllowList(), Ready: templateReady,
			MaxAge: maxAge, PublicPort: c.Syslog.PublicPort,
		}
		if certs != nil {
			sc.GetCertificate = certs.GetCertificate
			sc.OnRefusal = func(addr string) { certs.NoteRefusal(addr, "syslog") }
			// The names senders use, for the Security page's strict
			// certificate authority.
			sc.OnTLSName = certs.NoteName
		}
		receiver = syslog.New(sc, pipeline, log)
		if err := receiver.Start(ctx); err != nil {
			return nil, keyed(err, "syslog.udp", "syslog.tcp", "syslog.tls")
		}
		in.receiver = receiver
		var addrs []any
		for _, l := range receiver.Stats().Listeners {
			addrs = append(addrs, l.Protocol, l.Address)
		}
		allow := "any sender"
		if len(c.Syslog.Allow) > 0 {
			allow = strings.Join(c.Syslog.Allow, ", ")
		}
		log.Info("syslog receiver listening", append(addrs, "allow", allow)...)
	}
	eng := newEngine(c, cl)
	// A damaged list must not keep Signalith from starting: it starts with
	// empty lists, and picks the file up once it is fixed.
	lists, err := assets.OpenStore(c.LookupsDir())
	if err != nil {
		log.Error("asset or identity list has errors; using empty lists until it is fixed", "err", err)
	}
	log.Info("asset and identity lists loaded", "assets", len(lists.Assets()), "identities", len(lists.Identities()), "dir", c.LookupsDir())
	eng.Assets = lists
	in.jobs.Go(func() { reloadLookups(ctx, lists, log) })
	ibackend := intel.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	indicators := intel.NewStore(ibackend)
	eng.Intel = indicators
	feeds := newFeeds(c, indicators, log)
	if err := feeds.Load(); err != nil {
		log.Error("threat intel feeds added on the Threat intel page cannot be used until the file is fixed", "err", err)
	}
	lib, problems, err := detect.NewLibrary(c.DetectionsDir())
	if err != nil {
		return nil, err
	}
	for _, p := range problems {
		// One bad file should not stop the SIEM; it is skipped and reported.
		log.Error("detection skipped", "err", p)
	}
	boards, err := dashboards.NewStore(c.DashboardsDir())
	if err != nil {
		return nil, fmt.Errorf("dashboards.dir: %w", err)
	}
	if _, problems, err := boards.List(); err == nil {
		for _, p := range problems {
			log.Error("dashboard file has errors; fix it to show the dashboard", "file", p.File, "err", p.Error)
		}
	}
	people, dir, err := r.openUsers(c)
	if err != nil {
		return nil, err
	}
	if _, clash := people.Get(c.Auth.AdminUser); clash {
		log.Warn("a user on the Users page has the built-in admin's name; that name signs in as the built-in admin", "user", c.Auth.AdminUser)
	}
	n := people.Count()
	log.Info("users loaded", "local", n[users.SourceLocal], "directory", n[users.SourceDirectory], "file", c.UsersFile())
	if (os.Getenv("SIGNALITH_LDAP_BIND_PASSWORD") != "" || os.Getenv("SIGNALITH_LDAP_BIND_PASSWORD_FILE") != "") && c.Auth.LDAP == nil {
		log.Warn("SIGNALITH_LDAP_BIND_PASSWORD is set but signalith.yaml has no auth.ldap, so it is not used; directory sign-in set up on the Users page keeps its own bind password")
	}
	if s := dir.Settings(); s.IsEnabled() {
		log.Info("directory sign-in is on", "server", s.URL, "from_config_file", dir.FromConfig())
		for _, w := range s.Warnings() {
			log.Warn("directory sign-in: " + w)
		}
	}
	fstore := findings.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	cstore := cases.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	// Hosts running osquery, managed from the Endpoints page. Each server
	// notes the hosts that reach it and writes their last contact in bulk.
	estore := endpoint.NewStore(cl, c.OpenSearch.IndexPrefix)
	in.jobs.Go(func() { estore.Run(ctx, 30*time.Second) })
	in.jobs.Go(func() { feedEndpointAssets(ctx, estore, lists, log) })
	// Notifications: the channels and rules set on the Notifications
	// page, and the deliveries index that makes each message go out once.
	notes, deliveries, senders := newNotify(c, cl, log)
	if err := notes.Load(); err != nil {
		log.Error("notifications are not sent until the notifications file is fixed", "err", err)
	}
	sched := &detect.Scheduler{
		Library: lib, Engine: eng, Findings: fstore, Log: log,
		Risk: &risk.Store{Client: cl, Prefix: c.OpenSearch.IndexPrefix}, Assets: lists,
		MaxFindingsPerRun: c.Detections.MaxFindingsPerRun,
	}
	if saved, err := ret.Store.Get(); err != nil {
		log.Error("retention settings file has errors; retention is paused until it is fixed", "err", err)
	} else if saved.Default != nil && c.Retention.Default == nil && saved.Default.KeepDays != c.Retention.Days {
		log.Info("the default retention policy saved on the Data retention page replaces retention.days",
			"retention.days", c.Retention.Days, "keep_days", saved.Default.KeepDays)
	}
	// The one-click sample data loads a week of made-up activity through
	// the same parsers and its own ingest pipeline, and removes it exactly.
	// An admin may load or remove it on any server: it is not a background
	// job, and its detection backfill reads and marks only its own data, so
	// it does not wait for the job lease. What it wrote is recorded in the
	// runtime index, which every server that shares this OpenSearch reads,
	// so they all show the same sample and only one load happens at a time.
	sampleServer, sampleNode := "", ""
	if r.node != nil {
		sampleServer, sampleNode = r.node.Name(), r.node.ID()
	}
	if sampleServer == "" {
		sampleServer, _ = os.Hostname()
	}
	sampleLoader := &sample.Loader{
		Prefix:   c.OpenSearch.IndexPrefix,
		Bulk:     cl,
		OS:       cl,
		Docs:     cl,
		Intel:    indicators,
		Assets:   lists,
		Library:  lib,
		Engine:   eng,
		Findings: fstore,
		Cases:    cstore,
		Risk:     &risk.Store{Client: cl, Prefix: c.OpenSearch.IndexPrefix},
		Server:   sampleServer,
		NodeID:   sampleNode,
		Log:      log,
	}
	dispatcher := &notify.Dispatcher{
		Settings: notes, Findings: fstore, Deliveries: deliveries, Sender: senders, Server: sampleServer, Log: log,
		PublicURL: func() string { return c.Server.PublicURL },
	}
	// Each server keeps the sample's asset and identity context in its own
	// lookups folder, and its threat intel in memory: follow a load or
	// removal made on another server.
	in.jobs.Go(func() { sampleLoader.WatchLists(ctx, time.Minute) })
	// Response actions: analysts run them by hand from a finding or a
	// case, on whichever server they use, so every server can; each run
	// is recorded in the <prefix>_actions index.
	astore := respond.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	responder := &respond.Runner{
		Actions:    &respond.Actions{File: c.ResponseFile(), Log: log},
		Directory:  dir.Settings,
		ScriptsDir: c.ResponseScriptsDir(),
		Store:      astore,
		Server:     sampleServer,
		Log:        log,
	}
	if p := intel.ProtectedAddr(c.OpenSearch.URL); p != "" {
		responder.Protected = []string{p}
	}
	ensureScriptsDir(c.ResponseScriptsDir(), log)
	// Playbooks: set on the Playbooks page, run by the server that runs
	// the background jobs; each run is claimed in <prefix>_playbook_runs.
	pbooks := &playbooks.Manager{File: c.PlaybooksFile()}
	if err := pbooks.Load(); err != nil {
		log.Error("playbooks do not start until the playbooks file is fixed", "err", err)
	}
	pruns := playbooks.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	// Sessions and the failed sign-in limits carry over a restart.
	r.sessions.SetIdle(c.SessionIdle())
	// Agent tokens: one per agent or group, kept in the runtime index so
	// every server that shares this OpenSearch accepts the same ones and
	// refuses a revoked one within seconds. Revoking one removes the
	// osquery hosts enrolled with it.
	tokens := &agenttokens.Registry{Client: cl, Prefix: c.OpenSearch.IndexPrefix, Log: log, Node: func() string { return sampleNode }}
	tokens.OnRevoke(estore.RevokeToken)
	// The shared tokens come from the configuration in use, which the
	// server holds once it exists; set before the first load so that load
	// and the server never race to set it.
	var tokenSrv atomic.Pointer[api.Server]
	tokens.Legacy = func() []agenttokens.Legacy {
		if s := tokenSrv.Load(); s != nil {
			return api.LegacyTokens(s.Running())
		}
		return api.LegacyTokens(c)
	}
	{
		lctx, lcancel := context.WithTimeout(ctx, 5*time.Second)
		if err := tokens.Load(lctx); err != nil {
			log.Warn("agent tokens could not be read from OpenSearch yet; agents that send with one are asked to send again until they are", "err", err)
		}
		lcancel()
	}
	in.jobs.Go(func() { tokens.Run(ctx) })
	srv := &api.Server{
		Config:     c,
		Tokens:     tokens,
		Engine:     eng,
		Pipeline:   pipeline,
		Syslog:     receiver,
		Backend:    cl,
		Detections: lib,
		Scheduler:  sched,
		Findings:   fstore,
		Assets:     lists,
		Intel:      indicators,
		Feeds:      feeds,
		Notify:     &api.Notify{Settings: notes, Deliveries: deliveries, Sender: senders, Server: sampleServer},
		Dashboards: boards,
		Cases:      cstore,
		Respond:    responder,
		Playbooks:  &api.Playbooks{Manager: pbooks, Runs: pruns},
		Retention:  ret,
		Sample:     sampleLoader,
		Endpoints:  estore,
		Background: r.backgroundContext(parent),
		Assistant:  newAssistant(c),
		Users:      people,
		Directory:  dir,
		TLS:        certs,
		Sessions:   r.sessions,
		Limiter:    r.limiter,
		Restarter:  r,
		Security:   r.security,
		Started:    r.started,
		UI:         web.FS(),
		Log:        log,
		Version:    version,
	}
	srv.KnownBrowsers = r.browsers
	pbRunner := &playbooks.Runner{
		Playbooks: pbooks, Findings: fstore, Runs: pruns, Desk: srv.PlaybookDesk(), Respond: responder,
		Notify: notes, Sender: senders, Server: sampleServer, Log: log,
		PublicURL: func() string { return c.Server.PublicURL },
	}
	// Every server makes the indices it uses when they are missing; the
	// indicesReady channel is closed once it has tried, and the flags say
	// which ones are there. Changes to existing indices and the background
	// jobs are for the one server that runs those.
	indicesReady := make(chan struct{})
	var intelOK, casesOK, findingsOK, notifyOK, playbooksOK bool
	in.jobs.Go(func() {
		if !ensureTemplate(ctx, cl, c, log) {
			return
		}
		close(templateReady)
		if err := ibackend.EnsureIndex(ctx); err != nil {
			log.Error("could not create the threat intel index; threat intel will not work", "index", ibackend.Index, "err", err)
		} else {
			intelOK = true
			in.jobs.Go(func() { indicators.Watch(ctx, time.Minute, log) })
		}
		if err := cstore.EnsureIndex(ctx); err != nil {
			log.Error("could not create the cases index; investigations will not work", "index", cstore.Index, "err", err)
		} else {
			casesOK = true
		}
		if err := fstore.EnsureIndex(ctx); err != nil {
			log.Error("could not create the findings index; detections will not run", "index", fstore.Index, "err", err)
		} else {
			findingsOK = true
		}
		if err := estore.EnsureIndex(ctx); err != nil {
			log.Error("could not create the endpoints index; osquery hosts cannot enroll", "index", estore.Index, "err", err)
		}
		if err := deliveries.EnsureIndex(ctx); err != nil {
			log.Error("could not create the notifications index; notifications will not be sent", "index", deliveries.Index, "err", err)
		} else {
			notifyOK = true
		}
		if err := astore.EnsureIndex(ctx); err != nil {
			log.Error("could not create the response actions index; response actions will not run", "index", astore.Index, "err", err)
		}
		if err := pruns.EnsureIndex(ctx); err != nil {
			log.Error("could not create the playbook runs index; playbooks will not run", "index", pruns.Index, "err", err)
		} else {
			playbooksOK = true
		}
		close(indicesReady)
	})
	ready := func(ctx context.Context) bool {
		select {
		case <-indicesReady:
			return true
		case <-ctx.Done():
			return false
		}
	}
	// The background jobs run only while this server holds the job lease:
	// of the servers that share one OpenSearch, one runs them.
	in.jobsList = []cluster.Job{
		{Name: "index upgrades", Run: func(ctx context.Context) {
			if !ready(ctx) {
				return
			}
			upgradeIndices(ctx, log, func() bool { return r.node == nil || r.node.RunsJobs() }, []indexUpgrade{
				{intelOK, ibackend.Index, ibackend.Upgrade}, {casesOK, cstore.Index, cstore.Upgrade}, {findingsOK, fstore.Index, fstore.Upgrade},
			})
		}},
		{Name: "detections", Run: func(ctx context.Context) {
			if !ready(ctx) || !findingsOK {
				return
			}
			log.Info("detection scheduler started", "detections", len(lib.List()))
			sched.Start(ctx)
			log.Info("detection scheduler stopped")
		}},
		{Name: "threat intel feeds", Run: func(ctx context.Context) {
			if !ready(ctx) || !intelOK {
				return
			}
			// Feeds can be added on the page at any time, so the
			// downloader runs even with none yet.
			log.Info("threat intel feeds will download on their schedules", "feeds", feeds.Len(), "file", c.IntelFeedsFile())
			feeds.Start(ctx)
		}},
		{Name: "notifications", Run: func(ctx context.Context) {
			if !ready(ctx) || !notifyOK || !findingsOK {
				return
			}
			// Channels and rules can be added on the page at any time, so
			// the dispatcher runs even with none yet.
			log.Info("notifications will be sent for new findings that match a rule", "file", c.NotifyFile())
			dispatcher.Run(ctx)
		}},
		{Name: "playbooks", Run: func(ctx context.Context) {
			if !ready(ctx) || !playbooksOK || !findingsOK {
				return
			}
			// Playbooks can be added on the page at any time, so the
			// runner runs even with none yet.
			log.Info("playbooks will run for new findings that match them", "file", c.PlaybooksFile())
			pbRunner.Run(ctx)
		}},
		// Retention keeps running while OpenSearch refuses writes (its
		// disk is full): its disk guard is what frees space.
		{Name: "retention", Emergency: true, Run: func(ctx context.Context) {
			ret.Start(ctx)
			ret.Wait()
		}},
	}
	in.retention = ret
	if hook := jobStarting; hook != nil {
		in.jobsList = watchJobs(in.jobsList, c, hook)
	}
	if !c.Detections.Scheduler {
		log.Warn("detections.scheduler is off, so this server never runs detections, threat intel downloads, notifications, playbooks or retention; " +
			"another server that shares its OpenSearch does. The Data retention and feed settings are read-only here")
	}
	if r.node != nil {
		ret.Leader = func() (bool, string) { return r.node.RunsJobs(), r.node.JobHolder() }
		ret.Fence = r.node.Check
		// The scheduler, the feeds and the notifications ask before each
		// run, download or message, so a server that lost the job lease
		// stops at once, even before its jobs' context ends.
		sched.Allowed, feeds.Allowed, dispatcher.Allowed, pbRunner.Allowed = r.node.RunsJobs, r.node.RunsJobs, r.node.RunsJobs, r.node.RunsJobs
		srv.Cluster = r.node
		in.node = r.node
	}
	tokenSrv.Store(srv)
	in.srv, in.handler = srv, srv.Handler()
	// The example ingest token of an older Docker quick start: decide
	// whether this one was upgraded if that is still open, and end it for
	// good once agents on plain HTTP are refused.
	in.jobs.Go(func() { settleDockerUpgrade(ctx, c, cl, srv, log) })
	// The security checks: 30 seconds after the process started, a moment
	// after a restart in place, then hourly.
	in.jobs.Go(func() { srv.RunSecurityChecks(ctx, api.SecurityDelay(r.started)) })
	in.plain = in.handler
	if c.Server.HTTPS() {
		in.plain = srv.PlainHandler(in.handler)
	}
	if r.node != nil {
		// Last, once everything started: the node points at this
		// OpenSearch, and runs these jobs while it holds the job lease.
		r.node.Use(cl, c.OpenSearch.IndexPrefix, cluster.Settings{
			Eligible: c.Detections.Scheduler, NodeURL: nodeURL(c), Listen: c.Server.Listen,
			Syslog:       cluster.Syslog{UDP: c.Syslog.UDP, TCP: c.Syslog.TCP, TLS: c.Syslog.TLS},
			Fingerprints: func() cluster.Fingerprints { return filesFingerprints(c, ret, feeds, notes, pbooks) },
		})
		// A server with detections.scheduler off never runs the jobs. It
		// may still hold the lease from before a restart in place, which
		// Use gives up in the background: until then it must not start
		// them with settings that say it never runs them.
		if c.Detections.Scheduler {
			r.node.SetJobs(in.jobsList)
		} else {
			r.node.SetJobs(nil)
		}
	}
	started = true
	return in, nil
}

// jobStarting, set by tests, hears of each background job as it starts,
// with the settings it starts with.
var jobStarting func(name string, c *config.Config)

// watchJobs tells hook when each job starts.
func watchJobs(jobs []cluster.Job, c *config.Config, hook func(string, *config.Config)) []cluster.Job {
	out := make([]cluster.Job, len(jobs))
	for i, j := range jobs {
		run := j.Run
		j.Run = func(ctx context.Context) {
			hook(j.Name, c)
			run(ctx)
		}
		out[i] = j
	}
	return out
}

// indexUpgrade is an index whose fields the job holder brings up to date.
type indexUpgrade struct {
	ok      bool // the index is there
	name    string
	upgrade func(context.Context) error
}

// upgradeIndices adds fields introduced since the indices were made. Only
// the server that runs the background jobs does, when it starts running
// them, rather than every server at every start.
func upgradeIndices(ctx context.Context, log *slog.Logger, allowed func() bool, list []indexUpgrade) {
	for _, u := range list {
		if !u.ok || ctx.Err() != nil || !allowed() {
			continue
		}
		if err := u.upgrade(ctx); err != nil && ctx.Err() == nil {
			log.Warn("could not bring an index up to date; it is tried again when this server next starts running the background jobs", "index", u.name, "err", err)
		}
	}
}

// filesFingerprints hashes this server's own files that the background
// jobs use: retention policies, feeds, custom detections, notification
// channels and rules, playbooks and, while a policy archives, the
// archives. A server whose files differ from those of the server that
// runs the jobs does not take them over by itself.
func filesFingerprints(c *config.Config, ret *retention.Manager, feeds *intel.Feeds, notes *notify.Manager, pbooks *playbooks.Manager) cluster.Fingerprints {
	fp := cluster.Fingerprints{Feeds: feeds.Fingerprint(), Detections: detectionsFingerprint(c.DetectionsDir()), Notify: notes.Fingerprint(),
		Playbooks: pbooks.Fingerprint()}
	fp.Retention, fp.Archives = ret.Fingerprint()
	return fp
}

// detectionsFingerprint hashes the names and contents of the custom
// detection files in dir.
func detectionsFingerprint(dir string) string {
	if dir == "" {
		return ""
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return cluster.Hash([]byte(err.Error()))
	}
	// The on and off choices for built-in and pack rules count too.
	states, err := filepath.Glob(filepath.Join(dir, detect.StateDir, "*.yaml"))
	if err != nil {
		return cluster.Hash([]byte(err.Error()))
	}
	sort.Strings(files)
	sort.Strings(states)
	var parts [][]byte
	for _, f := range append(files, states...) {
		b, err := os.ReadFile(f)
		if err != nil {
			b = []byte("unreadable: " + err.Error())
		}
		// The same rules copied to Windows (by Git, WinSCP or Notepad) get
		// CRLF line ends and sometimes a byte order mark: neither changes
		// them.
		b = bytes.TrimPrefix(b, []byte("\ufeff"))
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		name := filepath.Base(f)
		if filepath.Base(filepath.Dir(f)) == detect.StateDir {
			name = detect.StateDir + "/" + name
		}
		parts = append(parts, []byte(name), b)
	}
	return cluster.Hash(parts...)
}

// nodeURL is the address other Signalith servers reach this one at, shown
// on the Servers page: server.node_url, else the web address with this
// computer's name when it listens on every address. A container cannot
// know it.
func nodeURL(c *config.Config) string {
	if c.Server.NodeURL != "" {
		return c.Server.NodeURL
	}
	if cluster.InContainer() {
		return ""
	}
	host, port, err := net.SplitHostPort(c.Server.Listen)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		if host, err = os.Hostname(); err != nil || host == "" {
			return ""
		}
	}
	scheme := "http"
	if c.Server.HTTPS() {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// asService is true when Windows runs Signalith as a service.
var asService bool

// deployment says how this server runs, for the Servers page.
func deployment() string {
	switch {
	case cluster.InContainer():
		return "docker"
	case asService:
		return "windows-service"
	case os.Getenv("INVOCATION_ID") != "":
		return "systemd"
	}
	return ""
}

// openNode opens this server's state folder (its identity and lock, next
// to its master key and HTTPS certificate: config.Config.StateDir) and
// returns the cluster node and the log, which names this server on every
// record from then on.
func openNode(c *config.Config, log *slog.Logger) (*cluster.Node, *slog.Logger, error) {
	inContainer := cluster.InContainer()
	dir, why := c.StateDirChoice()
	// A fallback folder is noted as this install's before anything is
	// kept in it.
	if err := config.RecordStateDir(dir); err != nil {
		return nil, nil, err
	}
	local, err := cluster.OpenLocal(dir, cluster.LocalOptions{Name: c.Cluster.NodeName, InContainer: inContainer})
	if err != nil {
		if why != "" {
			log.Warn(why)
		}
		return nil, nil, err
	}
	log = log.With("node", local.Identity.Name)
	if why != "" {
		log.Warn(why)
	}
	for _, w := range local.Warnings {
		log.Warn(w)
	}
	log.Info("this server's identity", "node_id", local.Identity.NodeID, "state_dir", local.Dir)
	node := cluster.New(cluster.Options{Local: local, Version: version, Deployment: deployment(), Log: log})
	return node, log, nil
}

// loadBrowserKey reads the key that signs the known-browser cookie from
// the state folder, making it on first start (see auth.Limiter). Without
// it the server uses a key kept in memory: browsers are then recognized
// only until the process stops.
func loadBrowserKey(c *config.Config, log *slog.Logger) *auth.BrowserKey {
	path := c.SignInKeyFile()
	key, created, err := auth.LoadBrowserKey(path)
	if err != nil {
		log.Warn("could not use the sign-in key, so browsers that signed in before are recognized only until Signalith stops", "path", path, "err", err)
		return auth.NewBrowserKey()
	}
	if created {
		log.Info("made the sign-in key", "path", path)
	}
	return key
}

// openUsers opens the user store once and keeps it across restarts, so
// sign-in sessions stay valid; the directory sign-in settings are read
// again each time.
func (r *runner) openUsers(c *config.Config) (*users.Store, *users.Directory, error) {
	if r.people == nil || r.people.Path() != c.UsersFile() {
		people, err := users.Open(c.UsersFile())
		if err != nil {
			return nil, nil, err
		}
		r.people = people
	}
	if r.people.BuiltinAdmin != c.Auth.AdminUser {
		r.people.BuiltinAdmin = c.Auth.AdminUser
	}
	fromFile, err := c.LDAP()
	if err != nil {
		return nil, nil, err
	}
	dir, err := users.OpenDirectory(c.DirectoryFile(), fromFile)
	if err != nil {
		return nil, nil, err
	}
	return r.people, dir, nil
}

// certOptions are the settings of c's HTTPS certificate, which syslog
// over TLS uses too: server.tls_cert and tls_key in mode files, else one
// from Signalith's own CA covering this machine, public_url's host and
// server.tls.names. ok is false when c needs none.
func certOptions(c *config.Config) (o tlsauto.Options, ok bool) {
	if !c.Server.HTTPS() && c.Syslog.TLS == "" {
		return o, false
	}
	if c.Server.TLSMode() == config.TLSFiles {
		o.CertFile, o.KeyFile = c.TLSFiles()
		return o, true
	}
	o.Dir = c.TLSDir()
	// Only for a certificate authority made on first start; certKey leaves
	// it out, since it never changes the one in use (the Security page
	// does that).
	o.Scope = c.Server.CAScope()
	if u, err := url.Parse(c.Server.PublicURL); err == nil && u.Hostname() != "" {
		o.Names = append(o.Names, u.Hostname())
	}
	o.Names = append(o.Names, c.Server.TLSNames()...)
	return o, true
}

// newCertificates loads or makes the HTTPS certificate (see certOptions).
// It logs the CA's fingerprint, so admins can check the CA they install
// elsewhere.
func newCertificates(c *config.Config, log *slog.Logger) (*tlsauto.Manager, error) {
	o, _ := certOptions(c)
	o.Log = log
	m, err := tlsauto.New(o)
	if err != nil {
		return nil, err
	}
	leaf, names := m.Leaf(), m.Names()
	if out := m.Outside(); len(out) > 0 {
		log.Warn("the HTTPS certificate leaves out names that Signalith's own certificate authority may not sign; "+
			"see \"Names the certificate can cover\" in docs/https.md", "names", strings.Join(out, ","))
	}
	if m.LocalCA() {
		log.Info("HTTPS certificate from Signalith's own certificate authority; browsers warn until this CA is trusted (see docs/https.md)",
			"ca_file", m.CAPath(), "ca_sha256", m.Fingerprint(), "names", strings.Join(names, ","), "expires", leaf.NotAfter.Format(time.DateOnly))
	} else {
		log.Info("HTTPS certificate from server.tls_cert; reloaded when the file changes",
			"file", o.CertFile, "names", strings.Join(names, ","), "expires", leaf.NotAfter.Format(time.DateOnly), "ca_sha256", m.Fingerprint())
	}
	return m, nil
}

// newRetention returns the retention manager. Policies saved on the Data
// retention page and the run history live next to the asset and identity
// lists, which every install can write.
func newRetention(c *config.Config, cl *store.Client, log *slog.Logger) *retention.Manager {
	return &retention.Manager{
		Cluster:     retention.NewOpenSearch(cl),
		Prefix:      c.OpenSearch.IndexPrefix,
		Config:      c.RetentionPolicies(),
		Store:       retention.NewStore(filepath.Join(c.LookupsDir(), "retention.yaml")),
		Archive:     &retention.Archive{Dir: c.ArchiveDir()},
		HistoryFile: filepath.Join(c.LookupsDir(), "retention_history.json"),
		Interval:    c.RetentionInterval(),
		Log:         log,
		// Retention runs on one of the servers that share an OpenSearch,
		// never on one with detections.scheduler off.
		ReadOnly: !c.Detections.Scheduler,
	}
}

// retentionKeepDays is the shortest time any event category is kept, in
// days (0: forever), as the settings stand when the server starts.
func retentionKeepDays(ret *retention.Manager) int {
	s, _ := ret.Settings()
	return s.ShortestKeepDays()
}

// intelFeeds converts the feeds in signalith.yaml; the config is already
// validated, so durations parse.
func intelFeeds(c *config.Config) []intel.Feed {
	var out []intel.Feed
	for _, f := range c.Intel.Feeds {
		fd := f.Feed(intel.SourceConfig)
		// A feed whose key cannot be decrypted is not downloaded.
		fd.Problem = c.FeedProblem(f.Name)
		out = append(out, fd)
	}
	return out
}

// newFeeds returns the feed downloader: the feeds in signalith.yaml and
// those added on the Threat intel page.
func newFeeds(c *config.Config, indicators *intel.Store, log *slog.Logger) *intel.Feeds {
	f := &intel.Feeds{Store: indicators, List: intelFeeds(c), Log: log,
		File:          c.IntelFeedsFile(),
		StatusFile:    filepath.Join(c.LookupsDir(), "intel_feeds.json"),
		AllowLoopback: c.Intel.AllowLoopbackFeeds}
	// Feed downloads never reach Signalith's own OpenSearch, which may
	// accept requests without a password on the local network.
	if p := intel.ProtectedAddr(c.OpenSearch.URL); p != "" {
		f.Protected = []string{p}
	}
	return f
}

// newNotify returns the notification settings, the deliveries index and
// what sends the messages. Channels may never reach Signalith's own
// OpenSearch.
func newNotify(c *config.Config, cl *store.Client, log *slog.Logger) (*notify.Manager, *notify.OpenSearch, *notify.Senders) {
	senders := &notify.Senders{}
	if p := intel.ProtectedAddr(c.OpenSearch.URL); p != "" {
		senders.Protected = notify.Protected{p}
	}
	senders.Hostname, _ = os.Hostname()
	return &notify.Manager{File: c.NotifyFile(), Log: log}, notify.NewOpenSearch(cl, c.OpenSearch.IndexPrefix), senders
}

// ensureScriptsDir makes the response scripts folder, private to the
// server's account, when it does not exist yet, so admins know where
// scripts go. A folder that exists is left as it is.
func ensureScriptsDir(dir string, log *slog.Logger) {
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err := securefile.MkdirPrivate(dir); err != nil {
		log.Warn("could not make the response scripts folder; script actions cannot run until it exists", "dir", dir, "err", err)
	}
}

// reloadLookups picks up edits to the CSV files made outside the UI.
func reloadLookups(ctx context.Context, lists *assets.Store, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if changed, err := lists.Reload(); err != nil {
			log.Error("asset or identity list has errors; keeping the previous version", "err", err)
		} else if changed {
			log.Info("asset and identity lists reloaded", "assets", len(lists.Assets()), "identities", len(lists.Identities()))
		}
	}
}

// feedEndpointAssets puts the osquery hosts on the Endpoints page in the
// asset list's found hosts every minute, so their names and addresses get
// asset context (category endpoint and their platform) until the user's
// own list describes them.
func feedEndpointAssets(ctx context.Context, es *endpoint.Store, lists *assets.Store, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	failed := false
	for {
		nodes, err := es.Nodes(ctx)
		if err == nil {
			as := make([]assets.Asset, 0, len(nodes))
			for _, n := range nodes {
				a := assets.Asset{Host: []string{n.Hostname}, IP: n.IPs, Category: []string{"endpoint", n.Platform}}
				if short, _, ok := strings.Cut(n.Hostname, "."); ok && short != "" {
					a.Host = append(a.Host, short)
				}
				as = append(as, a)
			}
			lists.SetFound(as)
			failed = false
		} else if !failed && ctx.Err() == nil {
			log.Warn("could not read the osquery hosts for the asset list; trying again every minute", "err", err)
			failed = true
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ensureTemplate installs the index template, retrying until OpenSearch is up.
// It reports false if ctx ended first.
func ensureTemplate(ctx context.Context, cl *store.Client, c *config.Config, log *slog.Logger) bool {
	for {
		err := ingest.PutIndexTemplate(ctx, cl, c.OpenSearch.IndexPrefix, c.OpenSearch.Replicas)
		if err == nil {
			log.Info("opensearch index template ready", "url", redact.URL(c.OpenSearch.URL))
			return true
		}
		if hint := store.Hint(err); hint != "" {
			log.Warn("waiting for opensearch", "url", redact.URL(c.OpenSearch.URL), "err", err, "fix", hint)
		} else {
			log.Warn("waiting for opensearch", "url", redact.URL(c.OpenSearch.URL), "err", err)
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(15 * time.Second):
		}
	}
}
