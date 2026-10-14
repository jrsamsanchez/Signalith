package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Secrets the Docker quick start makes once and then keeps, in Signalith's
// secrets folder next to its OpenSearch certificate.
const (
	initialPasswordFile = "initial-admin-password"
	ingestTokenFile     = "ingest-token"
)

// renewWithin is how close to expiry the OpenSearch certificates may get
// before bootstrap-docker makes new ones.
const renewWithin = 30 * 24 * time.Hour

// cmdBootstrapDocker prepares the Docker quick start's volumes. The setup
// service runs it as root before the other containers start, every time.
func cmdBootstrapDocker(args []string) error {
	fs := flag.NewFlagSet("bootstrap-docker", flag.ExitOnError)
	osDir := fs.String("opensearch-dir", "", "folder for OpenSearch's certificates (mounted as its config/certs)")
	sigDir := fs.String("signalith-dir", "", "folder for Signalith's secrets: OpenSearch's CA, Signalith's client certificate, the first admin password and the ingest token")
	osUID := fs.Int("opensearch-uid", 1000, "user ID OpenSearch runs as; its files are given to it when this runs as root")
	sigUID := fs.Int("signalith-uid", 65532, "user ID Signalith runs as; its files are given to it when this runs as root")
	snapDir := fs.String("snapshots-dir", "", "folder OpenSearch writes snapshots to (path.repo); it is given to OpenSearch")
	fs.Parse(args)
	if *osDir == "" || *sigDir == "" {
		return errors.New("usage: signalith bootstrap-docker -opensearch-dir DIR -signalith-dir DIR [-snapshots-dir DIR]")
	}
	if err := bootstrapDocker(os.Stdout, *osDir, *sigDir, *osUID, *sigUID, time.Now()); err != nil {
		return err
	}
	if *snapDir != "" {
		return snapshotsDir(*snapDir, *osUID)
	}
	return nil
}

// snapshotsDir makes the folder OpenSearch writes snapshots to and gives
// it to OpenSearch's user: Docker makes a new volume's folder for root.
// What OpenSearch wrote in it already stays as it is.
func snapshotsDir(dir string, uid int) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, uid, uid); err != nil {
			return err
		}
	}
	return os.Chmod(dir, 0o750)
}

// bootstrapDocker makes what the Docker quick start needs and nothing a
// person has to choose: OpenSearch's certificates and Signalith's client
// certificate (from a CA of their own), a first admin password and an
// ingest token. Files already there are kept, so it can run on every
// start; it only makes new certificates when some are missing, do not
// belong together or are about to expire. Each file is then given to the
// user that reads it, readable by that user only (keys and secrets).
func bootstrapDocker(out io.Writer, osDir, sigDir string, osUID, sigUID int, now time.Time) error {
	for _, d := range []string{osDir, sigDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	osFiles := []string{ospki.RootCAFile, ospki.NodeCertFile, ospki.NodeKeyFile, ospki.AdminCertFile, ospki.AdminKeyFile}
	sigFiles := []string{ospki.ClientCAFile, ospki.ClientCertFile, ospki.ClientKeyFile}
	if err := ospki.Check(osDir, sigDir, "", now, renewWithin); err == nil {
		fmt.Fprintln(out, "OpenSearch certificates: kept.")
	} else {
		existed := anyExist(osDir, osFiles) || anyExist(sigDir, sigFiles)
		set, err2 := ospki.New(ospki.Options{Now: now})
		if err2 != nil {
			return err2
		}
		if err := writeFiles(osDir, set.OpenSearchFiles()); err != nil {
			return err
		}
		if err := writeFiles(sigDir, set.SignalithFiles()); err != nil {
			return err
		}
		if existed {
			fmt.Fprintf(out, "OpenSearch certificates: made new ones, since %v. If OpenSearch and Signalith are running, restart them to use them, from the Signalith folder: "+
				"docker compose -f deploy/docker/docker-compose.yml restart opensearch signalith\n", err)
		} else {
			fmt.Fprintf(out, "OpenSearch certificates: made, valid until %s.\n", set.CA.Cert.NotAfter.Format(time.DateOnly))
		}
	}
	made := map[string]func() string{
		initialPasswordFile: users.GeneratePassword,
		ingestTokenFile:     func() string { return config.RandomToken(24) },
	}
	for _, name := range []string{initialPasswordFile, ingestTokenFile} {
		p := filepath.Join(sigDir, name)
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
			continue
		}
		if err := writeFile(p, []byte(made[name]()+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(out, "Made %s.\n", name)
	}
	sigFiles = append(sigFiles, initialPasswordFile, ingestTokenFile)

	// Owners and permissions, set every time in case they were changed.
	chown := os.Geteuid() == 0
	if !chown && (osUID != os.Getuid() || sigUID != os.Getuid()) {
		fmt.Fprintln(out, "Not running as root, so the files keep their owner.")
	}
	set := func(path string, uid int, mode fs.FileMode) error {
		if chown {
			if err := os.Chown(path, uid, uid); err != nil {
				return err
			}
		}
		return os.Chmod(path, mode)
	}
	// OpenSearch reads them as uid 1000. Its security plugin warns about
	// any of its files that others can read, certificates too.
	for _, name := range osFiles {
		if err := set(filepath.Join(osDir, name), osUID, 0o600); err != nil {
			return err
		}
	}
	if err := set(osDir, osUID, 0o700); err != nil {
		return err
	}
	// Signalith runs as uid 65532 and only ever reads its secrets.
	for _, name := range sigFiles {
		if err := set(filepath.Join(sigDir, name), sigUID, 0o400); err != nil {
			return err
		}
	}
	if err := set(sigDir, sigUID, 0o700); err != nil {
		return err
	}
	fmt.Fprintln(out, "Ready. Show the first admin password, from the Signalith folder, with: docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password")
	return nil
}

func anyExist(dir string, names []string) bool {
	return slices.ContainsFunc(names, func(n string) bool {
		_, err := os.Stat(filepath.Join(dir, n))
		return err == nil
	})
}

// writeFiles writes each file, keys readable by their owner only.
func writeFiles(dir string, files map[string][]byte) error {
	for name, b := range files {
		mode := fs.FileMode(0o644)
		if ospki.IsKey(name) {
			mode = 0o600
		}
		if err := writeFile(filepath.Join(dir, name), b, mode); err != nil {
			return err
		}
	}
	return nil
}

// writeFile replaces path in one step, so a reader never sees half a
// file, and works even where the old file is read-only.
func writeFile(path string, data []byte, perm fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	return nil
}

// cmdInitialPassword prints the first admin password bootstrap-docker or
// signalith init -save-password made, until the admin changes it.
func cmdInitialPassword(args []string) error {
	fs := flag.NewFlagSet("initial-password", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	return printInitialPassword(os.Stdout, *path)
}

func printInitialPassword(out io.Writer, path string) error {
	file := os.Getenv("SIGNALITH_ADMIN_PASSWORD_FILE")
	if file == "" {
		// The .deb, .rpm and .msi packages run signalith init
		// -save-password, which keeps it next to the config file.
		file = filepath.Join(filepath.Dir(path), initialPasswordFile)
		if _, err := os.Stat(file); err != nil {
			return errors.New("this server has no generated first password (the Docker quick start and the packages keep one; " +
				"other installs got theirs from signalith init or install.ps1). To set a new one, run: signalith passwd")
		}
	}
	if fi, err := os.Stat(config.AdminHashFileIn(config.StateDirFor(path))); err == nil {
		return fmt.Errorf("the first admin password no longer works: it was changed with signalith passwd on %s. "+
			"To set a new one, run signalith passwd and restart Signalith. With the Docker quick start, from the Signalith folder: "+
			"docker compose -f deploy/docker/docker-compose.yml exec signalith signalith passwd, then docker compose -f deploy/docker/docker-compose.yml restart signalith",
			fi.ModTime().Format("2006-01-02 15:04"))
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("cannot read the first admin password: %w", err)
	}
	pw := strings.TrimSpace(string(b))
	if pw == "" {
		return fmt.Errorf("%s is empty", file)
	}
	fmt.Fprintln(out, pw)
	return nil
}

// writeAdminHash keeps the built-in admin's new password hash in the
// state folder (config.AdminHashFile), where the server reads it. It is
// private: mode 0600, or on Windows an access list of its own (SYSTEM,
// Administrators and the service), whatever the folder passes down. Run
// as root, a new file is given the folder's owner, so the server's own
// account can still read it, and a link there is replaced, not followed.
func writeAdminHash(path, hash string) error {
	return securefile.Replace(path, []byte(hash+"\n"))
}

// cmdOpenSearchCerts writes certificates and security settings for an
// OpenSearch installed without Docker, the same as the Docker quick start
// uses. docs/opensearch-security.md says where each file goes.
func cmdOpenSearchCerts(args []string) error {
	fs := flag.NewFlagSet("opensearch-certs", flag.ExitOnError)
	out := fs.String("out", "", "new folder to write the files to")
	node := fs.String("node", ospki.NodeName, "the OpenSearch node's name, used in its certificate")
	var names listFlag
	fs.Var(&names, "san", "another host name or IP address Signalith reaches OpenSearch at (repeat it, or separate names with commas); localhost and 127.0.0.1 are always included")
	fs.Parse(args)
	if *out == "" {
		return errors.New("usage: signalith opensearch-certs -out DIR [-node NAME] [-san NAME]")
	}
	return writeOpenSearchCerts(os.Stdout, *out, *node, names, time.Now())
}

func writeOpenSearchCerts(w io.Writer, out, node string, names []string, now time.Time) error {
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s already has files in it; give a new folder (these files hold keys, so nothing is ever overwritten)", out)
	}
	set, err := ospki.New(ospki.Options{Node: node, Names: names, Now: now})
	if err != nil {
		return err
	}
	osDir := filepath.Join(out, "opensearch")
	sigDir := filepath.Join(out, "signalith")
	certs := filepath.Join(osDir, "certs")
	security := filepath.Join(osDir, "opensearch-security")
	for _, d := range []string{out, osDir, certs, security, sigDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := writeFiles(certs, set.OpenSearchFiles()); err != nil {
		return err
	}
	if err := writeFiles(security, ospki.SecurityFiles()); err != nil {
		return err
	}
	if err := writeFiles(sigDir, set.SignalithFiles()); err != nil {
		return err
	}
	osSettings := "# Add these to opensearch.yml, in place of the \"OpenSearch Security Demo\n" +
		"# Configuration\" block if it has one, and copy the certs folder next to\n" +
		"# opensearch.yml. See docs/opensearch-security.md in Signalith.\n\n" + ospki.Settings(node)
	if err := writeFile(filepath.Join(osDir, "add-to-opensearch.yml"), []byte(osSettings), 0o644); err != nil {
		return err
	}
	covered := append(slices.Clone(set.Node.Cert.DNSNames), ipStrings(set.Node)...)
	// OpenSearch on this machine unless a node name was given.
	host := "127.0.0.1"
	if node != ospki.NodeName {
		host = node
	}
	sigSettings := "# Set these under opensearch: in signalith.yaml, in place of username and\n" +
		"# password, and copy the three files in this folder next to signalith.yaml.\n" +
		"# The url's host must be one OpenSearch's certificate covers: " + strings.Join(covered, ", ") + ".\n" +
		"# See docs/opensearch-security.md in Signalith.\n" +
		"opensearch:\n" +
		"  url: https://" + net.JoinHostPort(host, "9200") + "\n" +
		"  ca_file: " + ospki.ClientCAFile + "\n" +
		"  cert_file: " + ospki.ClientCertFile + "\n" +
		"  key_file: " + ospki.ClientKeyFile + "\n"
	if err := writeFile(filepath.Join(sigDir, "add-to-signalith.yaml"), []byte(sigSettings), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "Wrote OpenSearch certificates and security settings to %s:\n\n", out)
	fmt.Fprintf(w, "  %s  for OpenSearch: certs/, opensearch-security/ and add-to-opensearch.yml\n", osDir)
	fmt.Fprintf(w, "  %s  for Signalith: its CA file, client certificate and key, and add-to-signalith.yaml\n\n", sigDir)
	fmt.Fprintf(w, "The node certificate covers %s and lasts until %s.\n", strings.Join(covered, ", "), set.CA.Cert.NotAfter.Format(time.DateOnly))
	fmt.Fprintln(w, "The *-key.pem files are private keys: keep them readable only by the program that uses them.")
	fmt.Fprintln(w, "Next: follow docs/opensearch-security.md to put them in place and load the security settings.")
	return nil
}

func ipStrings(p *ospki.Pair) []string {
	var out []string
	for _, ip := range p.Cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// listFlag is a flag that may be repeated, each value a comma-separated
// list.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}
