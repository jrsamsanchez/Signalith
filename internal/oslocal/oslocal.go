// Package oslocal installs OpenSearch on the same computer as Signalith,
// for the Windows installer: the official OpenSearch release for Windows,
// at the version pinned here and checked against the SHA-512 pinned here,
// set up the way the Docker quick start sets up its OpenSearch. It listens
// on this computer only (127.0.0.1), over HTTPS with certificates from a
// CA of its own, and accepts only certificates from that CA: Signalith's
// and an admin certificate for its security tools. No password is ever
// made for it.
//
// OpenSearch is downloaded when it is installed, not shipped inside the
// installer: the release for Windows is far larger than Signalith, and
// an upgrade of Signalith then downloads it only when the pinned version
// changes. A computer without internet access is given the same .zip
// file (Fetch's local).
//
// This file holds the parts that are the same on every system, which the
// tests run everywhere; cmd/signalith installs and runs the service.
package oslocal

import (
	"archive/zip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// The OpenSearch release installed, and the SHA-512 of its Windows .zip
// as OpenSearch publishes it next to the file (URL + ".sha512"). A new
// version changes both, and an upgrade of Signalith then upgrades
// OpenSearch too.
const (
	Version = "3.9.0"
	SHA512  = "8d6d1420a93de227b20c4bd4de4987279349841e291b936cf87b40a3522bfd0e" +
		"f8c1753a92bf35bfd82713a609b55682de2e450633ca964d2bc0631c3a64b01e"
)

// pinned is SHA512; the tests change it.
var pinned = SHA512

// URL is where the release's .zip for Windows is downloaded from.
func URL() string {
	return "https://artifacts.opensearch.org/releases/bundle/opensearch/" + Version +
		"/opensearch-" + Version + "-windows-x64.zip"
}

// ServiceName is OpenSearch's Windows service; it runs as its own virtual
// account, NT SERVICE\SignalithOpenSearch.
const ServiceName = "SignalithOpenSearch"

// FirstPort is the port OpenSearch takes when it is free; otherwise the
// next free one up to FirstPort+9 (another OpenSearch may be there).
const FirstPort = 9200

// Layout is where OpenSearch's program and files go.
type Layout struct {
	// Home holds the program, a folder per version (3.9.0\bin, ...), in
	// Program Files, where only administrators may change it.
	Home string
	// Data holds its config, data and logs, and the CA (Data\ca), which
	// only administrators may read.
	Data string
	// Client is the folder Signalith's certificate for OpenSearch goes to,
	// in Signalith's config folder.
	Client string
}

// DefaultLayout is the layout the Windows installer uses.
func DefaultLayout() Layout {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return Layout{
		Home:   filepath.Join(pf, "Signalith", "OpenSearch"),
		Data:   filepath.Join(pd, "SignalithOpenSearch"),
		Client: filepath.Join(pd, "Signalith", "opensearch"),
	}
}

// VersionHome is the program folder of one version.
func (l Layout) VersionHome(v string) string { return filepath.Join(l.Home, v) }

// Config is OpenSearch's config folder (OPENSEARCH_PATH_CONF).
func (l Layout) Config() string { return filepath.Join(l.Data, "config") }

// Folders OpenSearch writes to.
func (l Layout) DataDir() string { return filepath.Join(l.Data, "data") }
func (l Layout) Logs() string    { return filepath.Join(l.Data, "logs") }
func (l Layout) Tmp() string     { return filepath.Join(l.Data, "tmp") }

// CA keeps the CA's certificate and key, which neither OpenSearch nor
// Signalith reads.
func (l Layout) CA() string { return filepath.Join(l.Data, "ca") }

// Certs is the certs folder next to opensearch.yml.
func (l Layout) Certs() string { return filepath.Join(l.Config(), "certs") }

// Security is the security plugin's settings folder.
func (l Layout) Security() string { return filepath.Join(l.Config(), "opensearch-security") }

func (l Layout) stateFile() string { return filepath.Join(l.Data, "installed.json") }

// State is what was installed, kept in Data. Its presence is what makes an
// OpenSearch one Signalith installed (and so upgrades and removes).
type State struct {
	Version string `json:"version"`
	Port    int    `json:"port"`
}

// URL is the address Signalith reaches it at.
func (s State) URL() string { return "https://127.0.0.1:" + strconv.Itoa(s.Port) }

// LoadState returns the state, or nil when OpenSearch was not installed
// by Signalith.
func LoadState(l Layout) (*State, error) {
	b, err := os.ReadFile(l.stateFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", l.stateFile(), err)
	}
	if s.Port <= 0 || s.Port > 65535 || !versionRE.MatchString(s.Version) {
		return nil, fmt.Errorf("%s does not hold a version and port", l.stateFile())
	}
	return &s, nil
}

// SaveState writes the state.
func SaveState(l Layout, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(l.stateFile(), append(b, '\n'))
}

var versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// Newer reports whether version a is newer than b (both x.y.z).
func Newer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// Fetch returns the path of a .zip of the pinned release that has the
// pinned SHA-512: local when it is given (a file copied to a computer
// without internet access), else downloaded from URL into dir. remove
// says whether the caller should delete the file when done.
func Fetch(ctx context.Context, local, dir string, out io.Writer) (file string, remove bool, err error) {
	if local != "" {
		f, err := os.Open(local)
		if err != nil {
			return "", false, err
		}
		defer f.Close()
		h := sha512.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", false, err
		}
		if err := checkSum(hex.EncodeToString(h.Sum(nil)), local); err != nil {
			return "", false, err
		}
		return local, false, nil
	}
	return download(ctx, URL(), dir, out, http.DefaultClient)
}

func download(ctx context.Context, url, dir string, out io.Writer, client *http.Client) (string, bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false, err
	}
	f, err := os.CreateTemp(dir, "opensearch-*.zip")
	if err != nil {
		return "", false, err
	}
	name := f.Name()
	fail := func(err error) (string, bool, error) {
		f.Close()
		os.Remove(name)
		return "", false, err
	}
	fmt.Fprintf(out, "Downloading OpenSearch %s from %s...\n", Version, url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fail(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(fmt.Errorf("could not download OpenSearch (%w). Check that this computer can reach %s, "+
			"or download that file on another computer and install with OPENSEARCHZIP=<the file> (docs/install-packages.md)", err, url))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("could not download OpenSearch: %s answered %s", url, resp.Status))
	}
	h := sha512.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		return fail(fmt.Errorf("the OpenSearch download stopped (%w); run the installer again", err))
	}
	if err := f.Close(); err != nil {
		return fail(err)
	}
	if err := checkSum(hex.EncodeToString(h.Sum(nil)), url); err != nil {
		os.Remove(name)
		return "", false, err
	}
	fmt.Fprintln(out, "  - its SHA-512 is the one Signalith expects")
	return name, true, nil
}

// checkSum refuses a file whose SHA-512 is not the pinned one.
func checkSum(got, what string) error {
	if strings.EqualFold(got, pinned) {
		return nil
	}
	return fmt.Errorf("%s is not the OpenSearch %s release Signalith expects: its SHA-512 is %s, not %s. "+
		"Nothing was installed. Use the file from %s", what, Version, got, pinned, URL())
}

// Extract unpacks the release's .zip into dest (which must not exist
// yet), dropping the opensearch-x.y.z folder every file is in. Nothing is
// written outside dest: names that would leave it, and links, are refused.
func Extract(zipFile, dest string) error {
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("%s already exists", dest)
	}
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()
	partial := dest + ".partial"
	if err := os.RemoveAll(partial); err != nil {
		return err
	}
	if err := os.MkdirAll(partial, 0o755); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(partial)
		}
	}()
	top := ""
	for _, f := range r.File {
		name := strings.ReplaceAll(f.Name, `\`, "/")
		first, rest, _ := strings.Cut(name, "/")
		if top == "" {
			top = first
		}
		if first != top || !strings.HasPrefix(top, "opensearch-") {
			return fmt.Errorf("%s is not an OpenSearch release: %q is outside its opensearch-<version> folder", zipFile, f.Name)
		}
		if rest == "" {
			continue
		}
		clean := path.Clean(rest)
		if !filepath.IsLocal(filepath.FromSlash(clean)) || strings.Contains(clean, ":") {
			return fmt.Errorf("%s has a file outside its folder: %q", zipFile, f.Name)
		}
		target := filepath.Join(partial, filepath.FromSlash(clean))
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case mode.IsRegular():
			if err := extractFile(f, target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s has %q, which is not a file or a folder", zipFile, f.Name)
		}
	}
	if err := os.Rename(partial, dest); err != nil {
		return err
	}
	ok = true
	return nil
}

func extractFile(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	w, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644|f.Mode().Perm()&0o111)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, rc); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

// FreePort returns the first port from FirstPort that nothing listens on
// at 127.0.0.1.
func FreePort() (int, error) {
	for p := FirstPort; p < FirstPort+10; p++ {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err == nil {
			l.Close()
			return p, nil
		}
	}
	return 0, fmt.Errorf("ports %d to %d are all in use on this computer, so OpenSearch has none to listen on", FirstPort, FirstPort+9)
}

// HeapMB is OpenSearch's Java heap for a computer with total MB of memory:
// a quarter, which leaves room for Signalith, for the files OpenSearch
// keeps in the system's cache, and for other programs; at least 1 GB and
// at most 8 GB.
func HeapMB(total uint64) int {
	h := int(total / 4)
	return max(1024, min(h, 8192))
}

// MakeCerts makes the CA, OpenSearch's node and admin certificates and
// Signalith's client certificate, when there are none yet: on the first
// install. They are kept on upgrades.
func MakeCerts(l Layout, now time.Time) error {
	if _, err := os.Stat(filepath.Join(l.Certs(), ospki.NodeCertFile)); err == nil {
		return nil
	}
	set, err := ospki.New(ospki.Options{Now: now})
	if err != nil {
		return err
	}
	// Each folder takes the access list of the private folder it is in:
	// Data (with the service given its config folder) or Signalith's
	// config folder.
	for dir, files := range map[string]map[string][]byte{
		l.Certs(): set.OpenSearchFiles(),
		l.Client:  set.SignalithFiles(),
		l.CA():    set.CAFiles(),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		for name, b := range files {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// ClientFiles are the files Signalith signs in to OpenSearch with:
// opensearch.ca_file, cert_file and key_file.
func (l Layout) ClientFiles() (ca, cert, key string) {
	return filepath.Join(l.Client, ospki.ClientCAFile), filepath.Join(l.Client, ospki.ClientCertFile), filepath.Join(l.Client, ospki.ClientKeyFile)
}

// WriteConfig writes OpenSearch's config folder for the version installed
// in home: the release's own jvm.options and log4j2.properties, its
// security plugin's settings files with Signalith's in place of the demo
// ones (as in the Docker quick start), the heap, and opensearch.yml.
// Signalith's files replace the release's on every run, so an upgrade
// brings the new release's defaults.
func WriteConfig(l Layout, home string, port, heapMB int) error {
	for _, d := range []string{l.Config(), l.Security(), filepath.Join(l.Config(), "jvm.options.d")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	src := filepath.Join(home, "config")
	if err := copyFile(filepath.Join(src, "log4j2.properties"), filepath.Join(l.Config(), "log4j2.properties")); err != nil {
		return err
	}
	jvm, err := os.ReadFile(filepath.Join(src, "jvm.options"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(l.Config(), "jvm.options"), []byte(JVMOptions(l, string(jvm))), 0o600); err != nil {
		return err
	}
	// The release's other security files (action groups, tenants, ...),
	// then Signalith's.
	entries, err := os.ReadDir(filepath.Join(src, "opensearch-security"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".yml") {
			if err := copyFile(filepath.Join(src, "opensearch-security", e.Name()), filepath.Join(l.Security(), e.Name())); err != nil {
				return err
			}
		}
	}
	for name, b := range ospki.SecurityFiles() {
		if err := os.WriteFile(filepath.Join(l.Security(), name), b, 0o600); err != nil {
			return err
		}
	}
	heap := fmt.Sprintf("# Written by Signalith: a quarter of this computer's memory, 1 to 8 GB.\n-Xms%dm\n-Xmx%dm\n", heapMB, heapMB)
	if err := os.WriteFile(filepath.Join(l.Config(), "jvm.options.d", "heap.options"), []byte(heap), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(l.Config(), "opensearch.yml"), []byte(Settings(l, port)), 0o600)
}

// JVMOptions is the release's jvm.options with its paths, which are
// relative to the folder Java starts in, moved to Data: heap dumps and
// crash logs go there, not to the program's folder, which the service
// cannot write to. The garbage collector's log is left out, as Java cannot
// take a Windows path (C:...) in its -Xlog option.
func JVMOptions(l Layout, release string) string {
	var b strings.Builder
	b.WriteString("# The release's jvm.options, with paths in " + l.Data + " (written by Signalith).\n")
	for _, line := range strings.Split(strings.ReplaceAll(release, "\r\n", "\n"), "\n") {
		switch {
		case strings.Contains(line, "-Xlog:gc") || strings.Contains(line, "-Xloggc:"):
			continue
		case strings.HasSuffix(line, "-XX:HeapDumpPath=data"):
			line = strings.TrimSuffix(line, "data") + l.DataDir()
		case strings.Contains(line, "-XX:ErrorFile=logs/"):
			line = strings.Replace(line, "-XX:ErrorFile=logs/", "-XX:ErrorFile="+l.Logs()+string(filepath.Separator), 1)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// Settings is opensearch.yml.
func Settings(l Layout, port int) string {
	return `# OpenSearch for Signalith, on this computer only. Signalith's installer
# writes this file on every install and upgrade; changes here are lost.
cluster.name: signalith
node.name: ` + ospki.NodeName + `
discovery.type: single-node
path.data: ` + yamlPath(l.DataDir()) + `
path.logs: ` + yamlPath(l.Logs()) + `
# Reached only from this computer: Signalith runs here too.
network.host: 127.0.0.1
http.port: ` + strconv.Itoa(port) + `

` + ospki.Settings(ospki.NodeName)
}

// yamlPath quotes a Windows path for YAML (backslashes are kept as they
// are inside single quotes).
func yamlPath(p string) string { return "'" + strings.ReplaceAll(p, "'", "''") + "'" }

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o600)
}
