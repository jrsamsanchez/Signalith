// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package oslocal installs OpenSearch on the same computer as Signalith,
// for the Windows installer and "signalith opensearch install" on Linux:
// the official OpenSearch release for the system,
// at the version pinned here and checked against the SHA-512 pinned here,
// set up the way the Docker quick start sets up its OpenSearch. It listens
// on this computer only (127.0.0.1), over HTTPS with certificates from a
// CA of its own, and accepts only certificates from that CA: Signalith's
// and an admin certificate for its security tools. No password is ever
// made for it.
//
// OpenSearch is downloaded when it is installed, not shipped inside the
// installer: the release is far larger than Signalith, and an upgrade of
// Signalith then downloads it only when the pinned version changes. A
// computer without internet access is given the same file (Fetch's
// local).
//
// This file holds the parts that are the same on every system, which the
// tests run everywhere; cmd/signalith installs and runs the service.
package oslocal

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// The OpenSearch release installed. A new version changes it and every
// pin in Releases, and an upgrade of Signalith then upgrades OpenSearch
// too.
const Version = "3.9.0"

// Release is the release's file for one system, and its SHA-512 as
// OpenSearch publishes it next to the file (its URL + ".sha512").
type Release struct {
	File   string
	SHA512 string
}

// Releases are the files Signalith installs, by GOOS/GOARCH.
var Releases = map[string]Release{
	"windows/amd64": {
		File: "opensearch-" + Version + "-windows-x64.zip",
		SHA512: "8d6d1420a93de227b20c4bd4de4987279349841e291b936cf87b40a3522bfd0e" +
			"f8c1753a92bf35bfd82713a609b55682de2e450633ca964d2bc0631c3a64b01e",
	},
	"linux/amd64": {
		File: "opensearch-" + Version + "-linux-x64.tar.gz",
		SHA512: "a70e52a93ad66d9497dd734f5cc48eb4a8a8c4a92c47491a7ad0f1a898383d11" +
			"c2948d4ba4159b2361d961bf221efa0fd02084e6389532df960b1ebe0c0a2099",
	},
	"linux/arm64": {
		File: "opensearch-" + Version + "-linux-arm64.tar.gz",
		SHA512: "629b6a97104d6f925becd2372d902ea253a6209827435841c2cea9866c83567a" +
			"f776942b488110807370f9f504451bb4512f3bb1afb3c956386914c9474423fc",
	},
}

// release is this system's; File is empty where there is none.
var release = Releases[runtime.GOOS+"/"+runtime.GOARCH]

// maxRelease is the most a release file may be; the tests change it.
var maxRelease int64 = 1500 << 20

// pinned is release's SHA-512; the tests change it.
var pinned = release.SHA512

// File is the name of this system's release file, or "" when Signalith
// has none for it.
func File() string { return release.File }

// SHA512 is the pinned SHA-512 of File.
func SHA512() string { return pinned }

// URL is where this system's release file is downloaded from.
func URL() string { return ReleaseURL(release.File) }

// ReleaseURL is where a release file is downloaded from.
func ReleaseURL(file string) string {
	return "https://artifacts.opensearch.org/releases/bundle/opensearch/" + Version + "/" + file
}

// ServiceName is OpenSearch's service: on Windows SignalithOpenSearch,
// which runs as its own virtual account, NT SERVICE\SignalithOpenSearch;
// on Linux the systemd unit signalith-opensearch, which runs as the
// signalith-opensearch account.
var ServiceName = serviceName()

func serviceName() string {
	if runtime.GOOS == "linux" {
		return "signalith-opensearch"
	}
	return "SignalithOpenSearch"
}

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

// DefaultLayout is the layout the Windows installer uses, or on Linux
// the one "signalith opensearch install" uses.
func DefaultLayout() Layout {
	if runtime.GOOS == "linux" {
		return Layout{
			Home:   "/opt/signalith-opensearch",
			Data:   "/var/lib/signalith-opensearch",
			Client: "/etc/signalith/opensearch",
		}
	}
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

// ServiceFolders are the folders OpenSearch's service account may change.
func (l Layout) ServiceFolders() []string {
	return []string{l.Config(), l.DataDir(), l.Logs(), l.Tmp()}
}

// Download is where the release's .zip is downloaded, or a -zip copied, to
// be checked and unpacked: only administrators may change it, so the file
// unpacked is the one checked.
func (l Layout) Download() string { return filepath.Join(l.Data, "download") }

// CA keeps the CA's certificate and key, and the admin certificate the
// security settings are loaded with, which neither OpenSearch nor
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

// Fetch puts a .zip of the pinned release, with the pinned SHA-512, in dir
// and returns its path: a copy of local when it is given (a file copied to
// a computer without internet access), else downloaded from URL. The file
// is checked as it is written to dir, which only administrators may
// change, so the file a caller unpacks is the one checked, not one someone
// changed after. The caller deletes it when done. client is what it is
// downloaded with (see Client).
func Fetch(ctx context.Context, local, dir string, client *http.Client, out io.Writer) (string, error) {
	if release.File == "" || pinned == "" {
		return "", fmt.Errorf("Signalith has no OpenSearch release pinned for %s/%s; install OpenSearch from its own packages "+
			"and give Signalith its address on the Settings page (docs/install-packages.md)", runtime.GOOS, runtime.GOARCH)
	}
	if local != "" {
		f, err := os.Open(local)
		if err != nil {
			return "", err
		}
		defer f.Close()
		return save(f, dir, local)
	}
	return download(ctx, URL(), dir, out, client)
}

// save writes r to a new file in dir, removing it unless its SHA-512 is
// the pinned one.
func save(r io.Reader, dir, what string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "opensearch-*.download")
	if err != nil {
		return "", err
	}
	name := f.Name()
	h := sha512.New()
	// The release is about 1.1 GB; nothing much larger is read.
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, maxRelease+1))
	if err == nil && n > maxRelease {
		err = fmt.Errorf("%s is larger than any OpenSearch release (%d MB); nothing was installed", what, maxRelease>>20)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = checkSum(hex.EncodeToString(h.Sum(nil)), what)
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func download(ctx context.Context, url, dir string, out io.Writer, client *http.Client) (string, error) {
	fmt.Fprintf(out, "Downloading OpenSearch %s from %s...\n", Version, url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not download OpenSearch (%w). Check that this computer can reach %s; "+
			"behind a proxy, install with OPENSEARCHPROXY=<host:port>; or download that file on another computer "+
			"and install with OPENSEARCHZIP=<the file> (docs/install-packages.md)", err, url)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("could not download OpenSearch: %s answered %s", url, resp.Status)
	}
	name, err := save(resp.Body, dir, url)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(out, "  - its SHA-512 is the one Signalith expects")
	return name, nil
}

// checkSum refuses a file whose SHA-512 is not the pinned one.
func checkSum(got, what string) error {
	if strings.EqualFold(got, pinned) {
		return nil
	}
	return fmt.Errorf("%s is not the OpenSearch %s release Signalith expects: its SHA-512 is %s, not %s. "+
		"Nothing was installed. Use the file from %s", what, Version, got, pinned, URL())
}

// Extract unpacks the release's .zip or .tar.gz into dest (which must
// not exist yet), dropping the opensearch-x.y.z folder everything is in.
// Nothing is written outside dest: names that would leave it are refused,
// and so are links, except (in a .tar.gz) relative ones to somewhere else
// in the release, which its Java has; everything is written through
// os.Root, which never follows a link out of dest.
func Extract(file, dest string) error {
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("%s already exists", dest)
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("%s is not an OpenSearch release: %w", file, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
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
	root, err := os.OpenRoot(partial)
	if err != nil {
		return err
	}
	u := &unpacker{root: root, file: file}
	if magic == [2]byte{0x1f, 0x8b} {
		err = u.tarGz(f)
	} else {
		err = u.zip()
	}
	if err == nil {
		err = u.finish()
	}
	if cerr := root.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(partial, dest); err != nil {
		return err
	}
	ok = true
	return nil
}

// unpacker writes a release's files into root.
type unpacker struct {
	root  *os.Root
	file  string
	top   string      // the opensearch-x.y.z folder
	links [][2]string // name, target
}

// name is where the entry n goes in root, or "" for the top folder.
func (u *unpacker) name(n string) (string, error) {
	n = strings.ReplaceAll(n, `\`, "/")
	first, rest, _ := strings.Cut(strings.TrimPrefix(n, "./"), "/")
	if u.top == "" {
		u.top = first
	}
	if first != u.top || !strings.HasPrefix(u.top, "opensearch-") {
		return "", fmt.Errorf("%s is not an OpenSearch release: %q is outside its opensearch-<version> folder", u.file, n)
	}
	if rest == "" || rest == "." {
		return "", nil
	}
	clean := path.Clean(rest)
	if !filepath.IsLocal(filepath.FromSlash(clean)) || strings.Contains(clean, ":") {
		return "", fmt.Errorf("%s has a file outside its folder: %q", u.file, n)
	}
	return filepath.FromSlash(clean), nil
}

func (u *unpacker) zip() error {
	r, err := zip.OpenReader(u.file)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		name, err := u.name(f.Name)
		if err != nil {
			return err
		}
		if name == "" {
			continue
		}
		mode := f.Mode()
		switch {
		case mode.IsDir():
			err = u.root.MkdirAll(name, 0o755)
		case mode.IsRegular():
			var rc io.ReadCloser
			if rc, err = f.Open(); err == nil {
				err = u.write(name, rc, mode)
				rc.Close()
			}
		default:
			err = fmt.Errorf("%s has %q, which is not a file or a folder", u.file, f.Name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (u *unpacker) tarGz(f io.Reader) error {
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s is not an OpenSearch release: %w", u.file, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			for _, l := range u.links {
				if err := u.link(l[0], l[1]); err != nil {
					return err
				}
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", u.file, err)
		}
		name, err := u.name(h.Name)
		if err != nil {
			return err
		}
		if name == "" {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			err = u.root.MkdirAll(name, 0o755)
		case tar.TypeReg:
			err = u.write(name, tr, h.FileInfo().Mode())
		case tar.TypeSymlink:
			// Made last, so nothing is written through one.
			u.links = append(u.links, [2]string{name, h.Linkname})
		default:
			err = fmt.Errorf("%s has %q, which is not a file, a folder or a link", u.file, h.Name)
		}
		if err != nil {
			return err
		}
	}
}

// finish checks every link ends up inside the release, now all of them
// are made (a link may lead through another), and gives every folder
// mode 0755 whatever the umask, so the service may read the program.
func (u *unpacker) finish() error {
	for _, l := range u.links {
		if _, err := u.root.Stat(l[0]); err != nil {
			return fmt.Errorf("%s has a link that leads outside its folder, or nowhere: %q to %q", u.file, l[0], l[1])
		}
	}
	return fs.WalkDir(u.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		return u.root.Chmod(p, 0o755)
	})
}

// write writes a file, executable if it was in the release.
func (u *unpacker) write(name string, r io.Reader, mode os.FileMode) error {
	if err := u.root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	w, err := u.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644|mode.Perm()&0o111)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		w.Close()
		return err
	}
	// Whatever the umask: readable by all, as in the release.
	if err := w.Chmod(0o644 | mode.Perm()&0o111); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

// link makes a link to target, which must be relative and somewhere in
// the release, through folders only: a ".." after another link could
// leave it.
func (u *unpacker) link(name, target string) error {
	t := filepath.FromSlash(target)
	refuse := fmt.Errorf("%s has a link outside its folder: %q to %q", u.file, name, target)
	if filepath.IsAbs(t) || strings.Contains(target, ":") {
		return refuse
	}
	var at []string
	parts := append(strings.Split(filepath.Dir(name), string(filepath.Separator)), strings.Split(t, string(filepath.Separator))...)
	for i, p := range parts {
		switch {
		case p == "." || p == "":
		case p == "..":
			if len(at) == 0 {
				return refuse
			}
			at = at[:len(at)-1]
		default:
			at = append(at, p)
			if i == len(parts)-1 {
				break
			}
			if fi, err := u.root.Lstat(filepath.Join(at...)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return refuse
			}
		}
	}
	if len(at) == 0 {
		return refuse
	}
	if err := u.root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	// The folders it goes in are folders, not other links.
	for d := filepath.Dir(name); d != "."; d = filepath.Dir(d) {
		if fi, err := u.root.Lstat(d); err != nil || !fi.IsDir() {
			return refuse
		}
	}
	return u.root.Symlink(t, name)
}

// FreePort returns the first port from first that nothing listens on at
// 127.0.0.1.
func FreePort(first int) (int, error) {
	for p := first; p < first+10; p++ {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err == nil {
			l.Close()
			return p, nil
		}
	}
	return 0, fmt.Errorf("ports %d to %d are all in use on this computer, so OpenSearch has none to listen on", first, first+9)
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
// install. They are kept on upgrades. When only Signalith's are missing,
// because its config folder was deleted before installing again, it gets
// a new client certificate from the kept CA.
func MakeCerts(l Layout, now time.Time) error {
	// Whether this is the first install is the CA's to say, in a folder
	// only administrators can change: never the config folder's, which
	// the service may have been able to change.
	if _, err := os.Stat(filepath.Join(l.CA(), ospki.RootCAFile)); err == nil {
		if _, err := os.Lstat(filepath.Join(l.Certs(), ospki.NodeCertFile)); err != nil {
			return fmt.Errorf("OpenSearch's certificates are missing from %s, but its CA is kept in %s: "+
				"restore them from a backup, or move %s aside to install OpenSearch anew", l.Certs(), l.CA(), l.Data)
		}
		ca, cert, key := l.ClientFiles()
		if haveAll(ca, cert, key) {
			return nil
		}
		return remakeClient(l, now)
	}
	set, err := ospki.New(ospki.Options{Now: now})
	if err != nil {
		return err
	}
	// Each folder takes the access list of the private folder it is in:
	// Data (with the service given its config folder) or Signalith's
	// config folder.
	// The admin certificate goes with the CA: only the security settings
	// tool, run by the installer, uses it, never OpenSearch itself.
	osFiles, caFiles := set.OpenSearchFiles(), set.CAFiles()
	for _, name := range []string{ospki.AdminCertFile, ospki.AdminKeyFile} {
		caFiles[name] = osFiles[name]
		delete(osFiles, name)
	}
	for dir, files := range map[string]map[string][]byte{
		l.Certs(): osFiles,
		l.Client:  set.SignalithFiles(),
		l.CA():    caFiles,
	} {
		if err := writeFiles(dir, files); err != nil {
			return err
		}
	}
	return nil
}

// writeFiles writes files to dir, making it if it is missing, through
// os.Root and only over plain files.
func writeFiles(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s is not a folder", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for name, b := range files {
		if err := putIn(root, dir, name, b); err != nil {
			return err
		}
	}
	return nil
}

// putIn writes the file name in root (at dir) anew: what was there must
// be a plain file, and is removed first, so nothing linked to it changes.
func putIn(root *os.Root, dir, name string, b []byte) error {
	if fi, err := root.Lstat(name); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a file", filepath.Join(dir, name))
		}
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func haveAll(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// remakeClient issues Signalith a new client certificate from the CA
// kept in l.CA().
func remakeClient(l Layout, now time.Time) error {
	ca, err := ospki.LoadCA(l.CA())
	if err != nil {
		return fmt.Errorf("Signalith's certificate for OpenSearch is missing from %s, and a new one cannot be made: %w", l.Client, err)
	}
	client, err := ospki.IssueClient(ca, ospki.ClientName, now, ospki.Validity)
	if err != nil {
		return err
	}
	set := ospki.Set{CA: ca, Client: client}
	return writeFiles(l.Client, set.SignalithFiles())
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
	// Everything is written through os.Root, never following a link out
	// of the config folder, and only over plain files: the service may
	// have been able to change this folder.
	if err := writeFiles(l.Config(), nil); err != nil {
		return err
	}
	root, err := os.OpenRoot(l.Config())
	if err != nil {
		return err
	}
	defer root.Close()
	for _, d := range []string{"opensearch-security", "jvm.options.d"} {
		if err := root.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if fi, err := root.Lstat(d); err != nil || !fi.IsDir() {
			return fmt.Errorf("%s is not a folder", filepath.Join(l.Config(), d))
		}
	}
	put := func(name string, b []byte) error {
		return putIn(root, l.Config(), name, b)
	}
	// The release's files are read inside it, never through a link out.
	rel, err := os.OpenRoot(filepath.Join(home, "config"))
	if err != nil {
		return fmt.Errorf("the release's config folder (log4j2.properties, jvm.options, opensearch-security) is missing: %w", err)
	}
	defer rel.Close()
	log4j, err := rel.ReadFile("log4j2.properties")
	if err != nil {
		return err
	}
	if err := put("log4j2.properties", log4j); err != nil {
		return err
	}
	// Only Signalith's own options.
	if entries, err := os.ReadDir(filepath.Join(l.Config(), "jvm.options.d")); err == nil {
		for _, e := range entries {
			if e.Name() != "heap.options" {
				if err := root.RemoveAll(filepath.Join("jvm.options.d", e.Name())); err != nil {
					return err
				}
			}
		}
	}
	jvm, err := rel.ReadFile("jvm.options")
	if err != nil {
		return err
	}
	if err := put("jvm.options", []byte(JVMOptions(l, string(jvm)))); err != nil {
		return err
	}
	// The release's other security files (action groups, tenants, ...),
	// then Signalith's.
	entries, err := fs.ReadDir(rel.FS(), "opensearch-security")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".yml") {
			b, err := rel.ReadFile(filepath.Join("opensearch-security", e.Name()))
			if err != nil {
				return err
			}
			if err := put(filepath.Join("opensearch-security", e.Name()), b); err != nil {
				return err
			}
		}
	}
	for name, b := range ospki.SecurityFiles() {
		if err := put(filepath.Join("opensearch-security", name), b); err != nil {
			return err
		}
	}
	heap := fmt.Sprintf("# Written by Signalith: a quarter of this computer's memory, 1 to 8 GB.\n-Xms%dm\n-Xmx%dm\n", heapMB, heapMB)
	if err := put(filepath.Join("jvm.options.d", "heap.options"), []byte(heap)); err != nil {
		return err
	}
	return put("opensearch.yml", []byte(Settings(l, port)))
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
