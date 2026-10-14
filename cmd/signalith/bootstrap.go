package main

import (
	"bytes"
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

// loadedFingerprint is the file in the opensearch-security-loaded volume
// where deploy/docker/opensearch/load-security.sh notes which security
// files it loaded last.
const loadedFingerprint = "loaded-files.sha256"

// legacyCANote is printed while the OpenSearch CA has no kept key.
const legacyCANote = "This OpenSearch CA's key was not kept by older versions. To add servers later, run bootstrap-docker -new-ca " +
	"(docs/opensearch-security.md, Replacing the CA)."

// bootstrapOptions are bootstrap-docker's flags.
type bootstrapOptions struct {
	OSDir, SigDir string // OpenSearch's certs, Signalith's secrets
	// CADir keeps the CA's certificate and key; only setup mounts it.
	// Without it (a compose file from before) the CA's key is not kept and
	// a whole new set replaces a broken one, as before.
	CADir     string
	StateDir  string // Signalith's state folder, for ExportCAKey
	LoadedDir string // opensearch-security-loaded, for ApplySecurity
	OSUID     int
	SigUID    int
	// Names are more host names or IP addresses for every node
	// certificate; Nodes is how many node certificates to keep.
	Names         []string
	Nodes         int
	ExportCAKey   bool
	ApplySecurity bool
	NewCA         bool
	Now           time.Time
}

// cmdBootstrapDocker prepares the Docker quick start's volumes. The setup
// service runs it as root before the other containers start, every time.
// Each folder flag defaults to an environment variable the setup service
// sets, so one-off runs only name what they want done:
//
//	docker compose -f deploy/docker/docker-compose.yml run --rm setup bootstrap-docker -export-ca-key
func cmdBootstrapDocker(args []string) error {
	fs := flag.NewFlagSet("bootstrap-docker", flag.ExitOnError)
	var o bootstrapOptions
	fs.StringVar(&o.OSDir, "opensearch-dir", os.Getenv("SIGNALITH_SETUP_OPENSEARCH_DIR"), "folder for OpenSearch's certificates (mounted as its config/certs)")
	fs.StringVar(&o.SigDir, "signalith-dir", os.Getenv("SIGNALITH_SETUP_SIGNALITH_DIR"), "folder for Signalith's secrets: OpenSearch's CA, Signalith's client certificate, the first admin password and the ingest token")
	fs.StringVar(&o.CADir, "ca-dir", os.Getenv("SIGNALITH_SETUP_CA_DIR"), "folder that keeps the OpenSearch CA's certificate and key, which only this command reads")
	fs.StringVar(&o.StateDir, "state-dir", os.Getenv("SIGNALITH_SETUP_STATE_DIR"), "Signalith's state folder, where -export-ca-key hands the CA over")
	fs.StringVar(&o.LoadedDir, "loaded-dir", os.Getenv("SIGNALITH_SETUP_LOADED_DIR"), "the folder where OpenSearch's security settings loader notes what it loaded, for -apply-security")
	fs.IntVar(&o.OSUID, "opensearch-uid", 1000, "user ID OpenSearch runs as; its files are given to it when this runs as root")
	fs.IntVar(&o.SigUID, "signalith-uid", 65532, "user ID Signalith runs as; its files are given to it when this runs as root")
	var names listFlag
	fs.Var(&names, "opensearch-name", "another host name or IP address OpenSearch's node certificates cover (repeat it, or separate names with commas); kept from then on")
	fs.IntVar(&o.Nodes, "nodes", 1, "how many OpenSearch node certificates to keep: node.pem, then node-2.pem and so on")
	fs.BoolVar(&o.ExportCAKey, "export-ca-key", false, "hand the OpenSearch CA's certificate and key to Signalith, in the state folder's import folder, so it can add servers")
	fs.BoolVar(&o.ApplySecurity, "apply-security", false, "make the next \"up\" load OpenSearch's security settings again")
	fs.BoolVar(&o.NewCA, "new-ca", false, "replace the OpenSearch CA and every certificate it issued")
	fs.Parse(args)
	o.Names = names
	if o.OSDir == "" || o.SigDir == "" {
		return errors.New("usage: signalith bootstrap-docker -opensearch-dir DIR -signalith-dir DIR [-ca-dir DIR] [-opensearch-name NAME] [-nodes N] [-export-ca-key] [-apply-security] [-new-ca]")
	}
	o.Now = time.Now()
	return bootstrapDocker(os.Stdout, o)
}

// bootstrapDocker makes what the Docker quick start needs and nothing a
// person has to choose: OpenSearch's certificates and Signalith's client
// certificate (from a CA of their own), a first admin password and an
// ingest token. Files already there are kept, so it can run on every
// start. The CA is made once and its key kept in CADir; certificates that
// are missing, do not belong to it or are about to expire are made again
// under it, and a new CA is only ever made with NewCA. Each file is then
// given to the user that reads it, readable by that user only.
func bootstrapDocker(out io.Writer, o bootstrapOptions) error {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Nodes < 1 {
		o.Nodes = 1
	}
	if o.CADir == "" && (o.NewCA || o.ExportCAKey || o.Nodes > 1 || len(o.Names) > 0) {
		return errors.New("-new-ca, -export-ca-key, -nodes and -opensearch-name need -ca-dir, the folder that keeps the OpenSearch CA's key. " +
			"Update the Signalith folder (git pull) to get a docker-compose.yml that has it")
	}
	if o.ExportCAKey && o.StateDir == "" {
		return errors.New("-export-ca-key needs -state-dir, Signalith's state folder")
	}
	if o.ApplySecurity && o.LoadedDir == "" {
		return errors.New("-apply-security needs -loaded-dir, the opensearch-security-loaded folder")
	}
	if err := ospki.CheckNames(o.Names); err != nil {
		return err
	}
	for _, d := range []string{o.OSDir, o.SigDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if o.CADir == "" {
		if err := bootstrapCertsWithoutCA(out, o); err != nil {
			return err
		}
	} else if err := bootstrapCerts(out, o); err != nil {
		return err
	}
	made := map[string]func() string{
		initialPasswordFile: users.GeneratePassword,
		ingestTokenFile:     func() string { return config.RandomToken(24) },
	}
	for _, name := range []string{initialPasswordFile, ingestTokenFile} {
		p := filepath.Join(o.SigDir, name)
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
			continue
		}
		if err := writeFile(p, []byte(made[name]()+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(out, "Made %s.\n", name)
	}

	// Owners and permissions, set every time in case they were changed.
	chown := os.Geteuid() == 0
	if !chown && (o.OSUID != os.Getuid() || o.SigUID != os.Getuid()) {
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
	for _, name := range pemFiles(o.OSDir) {
		if err := set(filepath.Join(o.OSDir, name), o.OSUID, 0o600); err != nil {
			return err
		}
	}
	if err := set(o.OSDir, o.OSUID, 0o700); err != nil {
		return err
	}
	// Signalith runs as uid 65532 and only ever reads its secrets.
	sigFiles := []string{ospki.ClientCAFile, ospki.ClientCertFile, ospki.ClientKeyFile, initialPasswordFile, ingestTokenFile}
	for _, name := range sigFiles {
		if err := set(filepath.Join(o.SigDir, name), o.SigUID, 0o400); err != nil {
			return err
		}
	}
	if err := set(o.SigDir, o.SigUID, 0o700); err != nil {
		return err
	}
	// The CA's key is for this command only: root's, and nobody else's.
	if o.CADir != "" {
		for _, name := range pemFiles(o.CADir) {
			if err := set(filepath.Join(o.CADir, name), 0, 0o600); err != nil {
				return err
			}
		}
		if err := set(o.CADir, 0, 0o700); err != nil {
			return err
		}
	}
	if o.ExportCAKey {
		if err := exportCAKey(out, o, chown); err != nil {
			return err
		}
	}
	if o.ApplySecurity {
		err := os.Remove(filepath.Join(o.LoadedDir, loadedFingerprint))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		fmt.Fprintln(out, "OpenSearch's security settings will load again. Now run: docker compose -f deploy/docker/docker-compose.yml up -d")
		return nil
	}
	if o.ExportCAKey {
		return nil
	}
	fmt.Fprintln(out, "Ready. Show the first admin password, from the Signalith folder, with: docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password")
	return nil
}

// bootstrapCertsWithoutCA is bootstrap-docker for a compose file without
// the CA's volume: the set is kept while it is good and replaced whole
// when it is not, since there is no CA key to issue under.
func bootstrapCertsWithoutCA(out io.Writer, o bootstrapOptions) error {
	osFiles := []string{ospki.RootCAFile, ospki.NodeCertFile, ospki.NodeKeyFile, ospki.AdminCertFile, ospki.AdminKeyFile}
	sigFiles := []string{ospki.ClientCAFile, ospki.ClientCertFile, ospki.ClientKeyFile}
	err := ospki.Check(o.OSDir, o.SigDir, "", o.Now, renewWithin)
	if err == nil {
		fmt.Fprintln(out, "OpenSearch certificates: kept.")
		return nil
	}
	existed := anyExist(o.OSDir, osFiles) || anyExist(o.SigDir, sigFiles)
	set, err2 := ospki.New(ospki.Options{Now: o.Now})
	if err2 != nil {
		return err2
	}
	if err := writeFiles(o.OSDir, set.OpenSearchFiles()); err != nil {
		return err
	}
	if err := writeFiles(o.SigDir, set.SignalithFiles()); err != nil {
		return err
	}
	if existed {
		fmt.Fprintf(out, "OpenSearch certificates: made new ones, since %v. If OpenSearch and Signalith are running, restart them to use them, from the Signalith folder: "+
			"docker compose -f deploy/docker/docker-compose.yml restart opensearch signalith\n", err)
	} else {
		fmt.Fprintf(out, "OpenSearch certificates: made, valid until %s.\n", set.CA.Cert.NotAfter.Format(time.DateOnly))
	}
	return nil
}

// bootstrapCerts keeps the OpenSearch CA in CADir and the certificates
// it issued in OSDir and SigDir: made the first time, renewed one by one
// under the same CA after that, and never a new CA unless NewCA asks.
func bootstrapCerts(out io.Writer, o bootstrapOptions) error {
	if err := os.MkdirAll(o.CADir, 0o700); err != nil {
		return err
	}
	ca, err := ospki.LoadCA(o.CADir)
	legacy := false
	switch {
	case o.NewCA:
		if ca, err = ospki.NewCA(o.Now); err != nil {
			return err
		}
		if err := writeFiles(o.CADir, map[string][]byte{ospki.RootCAFile: ca.CertPEM(), ospki.RootCAKeyFile: ca.KeyPEM()}); err != nil {
			return err
		}
		fmt.Fprintf(out, "OpenSearch CA: made a new one, valid until %s. Every certificate the old CA issued is replaced now; "+
			"the certificates Signalith made for its servers and its copy of the CA stop working, so run bootstrap-docker -export-ca-key again before adding servers.\n",
			ca.Cert.NotAfter.Format(time.DateOnly))
	case err == nil:
	case errors.Is(err, ospki.ErrNoCAKey):
		return fmt.Errorf("%s has the OpenSearch CA's certificate but not its key. To start again with a new CA, run bootstrap-docker -new-ca "+
			"(docs/opensearch-security.md, Replacing the CA)", o.CADir)
	case errors.Is(err, fs.ErrNotExist):
		if _, err := os.Stat(filepath.Join(o.OSDir, ospki.RootCAFile)); err == nil {
			// Made by a version that did not keep the CA's key.
			b, err := os.ReadFile(filepath.Join(o.OSDir, ospki.RootCAFile))
			if err != nil {
				return err
			}
			c, err := ospki.ParseCA(b, o.Now, 0)
			if err != nil {
				return fmt.Errorf("OpenSearch's CA certificate cannot be used: %v. To start again with a new CA, run bootstrap-docker -new-ca "+
					"(docs/opensearch-security.md, Replacing the CA)", err)
			}
			ca, legacy = &ospki.Pair{Cert: c}, true
		} else {
			// A new install: the first CA.
			if ca, err = ospki.NewCA(o.Now); err != nil {
				return err
			}
			if err := writeFiles(o.CADir, map[string][]byte{ospki.RootCAFile: ca.CertPEM(), ospki.RootCAKeyFile: ca.KeyPEM()}); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("cannot use the OpenSearch CA in %s: %v. To start again with a new CA, run bootstrap-docker -new-ca "+
			"(docs/opensearch-security.md, Replacing the CA)", o.CADir, err)
	}
	if !o.Now.Add(renewWithin).Before(ca.Cert.NotAfter) {
		return fmt.Errorf("the OpenSearch CA expires on %s, and certificates are never made with a new CA by themselves. "+
			"Run bootstrap-docker -new-ca to replace it and every certificate it issued (docs/opensearch-security.md, Replacing the CA)",
			ca.Cert.NotAfter.Format(time.DateOnly))
	}

	// What to write: the CA's certificate wherever it is missing or
	// another, and each certificate that does not check out.
	type leaf struct {
		dir, cert, key, cn string
		node               bool
	}
	leaves := []leaf{}
	for i := 1; i <= o.Nodes; i++ {
		c, k := ospki.NodeFileNames(i)
		leaves = append(leaves, leaf{o.OSDir, c, k, ospki.NodeCN(i), true})
	}
	// Node certificates made earlier for more nodes are kept and renewed
	// too, even when -nodes asks for fewer.
	for i := o.Nodes + 1; ; i++ {
		c, k := ospki.NodeFileNames(i)
		if _, err := os.Stat(filepath.Join(o.OSDir, c)); err != nil {
			break
		}
		leaves = append(leaves, leaf{o.OSDir, c, k, ospki.NodeCN(i), true})
	}
	leaves = append(leaves,
		leaf{o.OSDir, ospki.AdminCertFile, ospki.AdminKeyFile, ospki.AdminName, false},
		leaf{o.SigDir, ospki.ClientCertFile, ospki.ClientKeyFile, ospki.ClientName, false})

	fresh := !anyExist(o.OSDir, []string{ospki.RootCAFile, ospki.NodeCertFile, ospki.AdminCertFile}) &&
		!anyExist(o.SigDir, []string{ospki.ClientCAFile, ospki.ClientCertFile})
	var notes []string
	writes := map[string]map[string][]byte{}
	put := func(dir, name string, b []byte) {
		if writes[dir] == nil {
			writes[dir] = map[string][]byte{}
		}
		writes[dir][name] = b
	}
	for _, f := range []struct{ dir, name string }{{o.OSDir, ospki.RootCAFile}, {o.SigDir, ospki.ClientCAFile}} {
		b, err := os.ReadFile(filepath.Join(f.dir, f.name))
		if err != nil || !bytes.Equal(bytes.TrimSpace(b), bytes.TrimSpace(ca.CertPEM())) {
			put(f.dir, f.name, ca.CertPEM())
			why := "it was missing"
			if err == nil {
				why = "it was another CA"
			}
			notes = append(notes, fmt.Sprintf("wrote the CA certificate to %s, since %s", f.name, why))
		}
	}
	for _, l := range leaves {
		err := ospki.CheckPair(l.dir, l.cert, l.key, l.cn, ca.Cert, o.Now, renewWithin)
		var names []string
		if l.node {
			old, _ := ospki.ReadPair(l.dir, l.cert, "")
			if old != nil && old.Cert.Subject.CommonName == l.cn {
				names = ospki.NamesOf(old)
			}
			if err == nil {
				if missing := missingNames(old, o.Names); len(missing) > 0 {
					err = fmt.Errorf("it does not cover %s yet", strings.Join(missing, ", "))
				}
			}
			names = append(names, o.Names...)
		}
		if err == nil {
			continue
		}
		if legacy {
			return fmt.Errorf("OpenSearch certificate %s needs renewing (%v), but %s", l.cert, err, strings.TrimSuffix(legacyCANote, "."))
		}
		var p *ospki.Pair
		var err2 error
		if l.node {
			p, err2 = ospki.IssueNode(ca, l.cn, names, o.Now)
		} else {
			p, err2 = ospki.IssueClient(ca, l.cn, o.Now, ospki.Validity)
		}
		if err2 != nil {
			return err2
		}
		put(l.dir, l.cert, p.CertPEM())
		put(l.dir, l.key, p.KeyPEM())
		notes = append(notes, fmt.Sprintf("made a new %s, since %v", l.cert, err))
	}
	for dir, files := range writes {
		if err := writeFiles(dir, files); err != nil {
			return err
		}
	}
	switch {
	case len(notes) == 0:
		fmt.Fprintln(out, "OpenSearch certificates: kept.")
	case fresh:
		fmt.Fprintf(out, "OpenSearch certificates: made, valid until %s.\n", ca.Cert.NotAfter.Format(time.DateOnly))
	default:
		for _, n := range notes {
			fmt.Fprintf(out, "OpenSearch certificates: %s.\n", n)
		}
		fmt.Fprintln(out, "If OpenSearch and Signalith are running, restart them to use the new certificates, from the Signalith folder: "+
			"docker compose -f deploy/docker/docker-compose.yml restart opensearch signalith")
	}
	if legacy {
		fmt.Fprintln(out, legacyCANote)
	}
	return nil
}

// missingNames returns the names a node certificate does not cover yet.
func missingNames(p *ospki.Pair, names []string) []string {
	if p == nil {
		return nil
	}
	var missing []string
	for _, n := range names {
		if p.Cert.VerifyHostname(strings.Trim(n, "[]")) != nil {
			missing = append(missing, n)
		}
	}
	return missing
}

// exportCAKey hands the CA's certificate and key to Signalith in its
// state folder's import folder, which only Signalith reads; Signalith
// takes them in once and deletes the key.
func exportCAKey(out io.Writer, o bootstrapOptions, chown bool) error {
	ca, err := ospki.LoadCA(o.CADir)
	if err != nil {
		if errors.Is(err, ospki.ErrNoCAKey) || errors.Is(err, fs.ErrNotExist) {
			return errors.New("there is no OpenSearch CA key to hand over: " + legacyCANote)
		}
		return err
	}
	// A state volume nothing has used yet must stay empty, so Docker
	// still fills it from Signalith's image (and gives it Signalith's
	// owner) when Signalith first starts.
	if entries, err := os.ReadDir(o.StateDir); err != nil || len(entries) == 0 {
		return errors.New("Signalith has not started yet. Start it first (docker compose -f deploy/docker/docker-compose.yml up -d), then run this again")
	}
	dir := filepath.Join(o.StateDir, ospki.ImportDir)
	if anyExist(dir, []string{ospki.ExportCAFile}) && anyExist(dir, []string{ospki.ExportCAKeyFile}) {
		fmt.Fprintf(out, "The OpenSearch CA is already waiting for Signalith in %s; left as it is.\n", dir)
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, b := range map[string][]byte{ospki.ExportCAFile: ca.CertPEM(), ospki.ExportCAKeyFile: ca.KeyPEM()} {
		p := filepath.Join(dir, name)
		if err := writeFile(p, b, 0o600); err != nil {
			return err
		}
		if chown {
			if err := os.Chown(p, o.SigUID, o.SigUID); err != nil {
				return err
			}
		}
	}
	if chown {
		if err := os.Chown(dir, o.SigUID, o.SigUID); err != nil {
			return err
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	fmt.Fprintf(out, "Handed the OpenSearch CA's certificate and key to Signalith, in %s. Signalith takes them in once, when it adds a server, and then deletes the key.\n", dir)
	return nil
}

// pemFiles lists the .pem files in dir.
func pemFiles(dir string) []string {
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".pem") {
			out = append(out, e.Name())
		}
	}
	return out
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
	var o osCertsOptions
	fs.StringVar(&o.Out, "out", "", "new folder to write the files to")
	fs.StringVar(&o.Node, "node", ospki.NodeName, "the OpenSearch node's name, used in its certificate")
	fs.StringVar(&o.CADir, "ca-dir", "", "the ca folder of an earlier run (or that run's -out folder): make this node's certificates under the same CA")
	var names, peers listFlag
	fs.Var(&names, "san", "another host name or IP address Signalith reaches OpenSearch at (repeat it, or separate names with commas); localhost and 127.0.0.1 are always included")
	fs.Var(&peers, "peer", "the -node name of another node in the same OpenSearch cluster (repeat it, or separate names with commas)")
	fs.Parse(args)
	if o.Out == "" {
		return errors.New("usage: signalith opensearch-certs [-ca-dir DIR] -node NAME [-san NAME] [-peer NAME] -out DIR")
	}
	o.Names, o.Peers, o.Now = names, peers, time.Now()
	return writeOpenSearchCerts(os.Stdout, o)
}

// osCertsOptions are opensearch-certs' flags.
type osCertsOptions struct {
	Out, Node, CADir string
	Names, Peers     []string
	Now              time.Time
}

// caFolder is the folder in opensearch-certs' output that keeps the CA.
const caFolder = "ca"

func writeOpenSearchCerts(w io.Writer, o osCertsOptions) error {
	if o.Node == "" {
		o.Node = ospki.NodeName
	}
	if entries, err := os.ReadDir(o.Out); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s already has files in it; give a new folder (these files hold keys, so nothing is ever overwritten)", o.Out)
	}
	for _, n := range append([]string{o.Node}, o.Peers...) {
		if err := ospki.CheckNodeName(n); err != nil {
			return err
		}
	}
	var ca *ospki.Pair
	var osFiles, sigFiles, caFiles map[string][]byte
	var node *ospki.Pair
	if o.CADir != "" {
		var err error
		if ca, err = loadCAFolder(o.CADir); err != nil {
			return err
		}
		if node, err = ospki.IssueNode(ca, o.Node, o.Names, o.Now); err != nil {
			return err
		}
		client, err := ospki.IssueClient(ca, ospki.ClientName, o.Now, ospki.Validity)
		if err != nil {
			return err
		}
		osFiles = map[string][]byte{ospki.RootCAFile: ca.CertPEM(), ospki.NodeCertFile: node.CertPEM(), ospki.NodeKeyFile: node.KeyPEM()}
		sigFiles = map[string][]byte{ospki.ClientCAFile: ca.CertPEM(), ospki.ClientCertFile: client.CertPEM(), ospki.ClientKeyFile: client.KeyPEM()}
	} else {
		set, err := ospki.New(ospki.Options{Node: o.Node, Names: o.Names, Now: o.Now})
		if err != nil {
			return err
		}
		ca, node = set.CA, set.Node
		osFiles, sigFiles, caFiles = set.OpenSearchFiles(), set.SignalithFiles(), set.CAFiles()
	}
	osDir := filepath.Join(o.Out, "opensearch")
	sigDir := filepath.Join(o.Out, "signalith")
	certs := filepath.Join(osDir, "certs")
	security := filepath.Join(osDir, "opensearch-security")
	for _, d := range []string{o.Out, osDir, certs, security, sigDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := writeFiles(certs, osFiles); err != nil {
		return err
	}
	if err := writeFiles(security, ospki.SecurityFiles()); err != nil {
		return err
	}
	if err := writeFiles(sigDir, sigFiles); err != nil {
		return err
	}
	caDir := filepath.Join(o.Out, caFolder)
	if caFiles != nil {
		if err := os.MkdirAll(caDir, 0o700); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(caDir, ospki.RootCAFile), caFiles[ospki.RootCAFile], 0o644); err != nil {
			return err
		}
		// Private on Windows too: an access list of its own.
		if err := securefile.Replace(filepath.Join(caDir, ospki.RootCAKeyFile), caFiles[ospki.RootCAKeyFile]); err != nil {
			return err
		}
	}
	osSettings := "# Add these to opensearch.yml, in place of the \"OpenSearch Security Demo\n" +
		"# Configuration\" block if it has one, and copy the certs folder next to\n" +
		"# opensearch.yml. See docs/opensearch-security.md in Signalith.\n\n" + ospki.SettingsFor(o.Node, o.Peers)
	if err := writeFile(filepath.Join(osDir, "add-to-opensearch.yml"), []byte(osSettings), 0o644); err != nil {
		return err
	}
	covered := append(slices.Clone(node.Cert.DNSNames), ipStrings(node)...)
	// OpenSearch on this machine unless a node name was given.
	host := "127.0.0.1"
	if o.Node != ospki.NodeName {
		host = o.Node
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
	fmt.Fprintf(w, "Wrote OpenSearch certificates and security settings to %s:\n\n", o.Out)
	fmt.Fprintf(w, "  %s  for OpenSearch: certs/, opensearch-security/ and add-to-opensearch.yml\n", osDir)
	fmt.Fprintf(w, "  %s  for Signalith: its CA file, client certificate and key, and add-to-signalith.yaml\n", sigDir)
	if caFiles != nil {
		fmt.Fprintf(w, "  %s  the CA's certificate and key: never copy this folder to OpenSearch\n", caDir)
	}
	fmt.Fprintf(w, "\nThe node certificate covers %s and lasts until %s.\n", strings.Join(covered, ", "), node.Cert.NotAfter.Format(time.DateOnly))
	fmt.Fprintln(w, "The *-key.pem files are private keys: keep them readable only by the program that uses them.")
	if caFiles != nil {
		fmt.Fprintf(w, "Keep the %s folder with the admin, somewhere safe, like a password: it makes certificates for more nodes "+
			"or servers under the same CA (opensearch-certs -ca-dir %s).\n", caDir, caDir)
	} else {
		fmt.Fprintln(w, "No admin certificate was made: use the one from the first run.")
	}
	fmt.Fprintln(w, "Next: follow docs/opensearch-security.md to put them in place and load the security settings.")
	return nil
}

// loadCAFolder loads the CA from dir, or from the ca folder in it when
// dir is an earlier opensearch-certs -out folder.
func loadCAFolder(dir string) (*ospki.Pair, error) {
	ca, err := ospki.LoadCA(dir)
	if errors.Is(err, fs.ErrNotExist) {
		ca, err = ospki.LoadCA(filepath.Join(dir, caFolder))
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s holds no OpenSearch CA (%s and %s): give the ca folder an earlier opensearch-certs run wrote", dir, ospki.RootCAFile, ospki.RootCAKeyFile)
	case errors.Is(err, ospki.ErrNoCAKey):
		return nil, fmt.Errorf("%s has the CA's certificate but not its key (%s), so it cannot make more certificates", dir, ospki.RootCAKeyFile)
	}
	return ca, err
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
