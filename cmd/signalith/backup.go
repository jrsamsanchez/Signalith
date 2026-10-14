package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"golang.org/x/term"
)

const backupUsage = `Usage:
  signalith backup  [-c file] [-o file.zip] [-archive] [-no-master-key]
  signalith restore [-c file] [-yes] file.zip

backup copies this server's own files into one zip file: signalith.yaml,
the state folder (master key, cluster key, HTTPS certificate and
authority, identity), the settings saved on the Settings page, users,
detections, lists, dashboards, notifications, response actions,
playbooks and the certificate files signalith.yaml names. It can run
while the server runs. Events, findings and cases are in OpenSearch: back
them up with an OpenSearch snapshot (see docs/backup.md).

  -o              the zip file to write (default: signalith-backup-<server>-<time>.zip
                  in the current folder)
  -archive        also copy the archived days (retention's archive folder),
                  which can be large
  -no-master-key  leave the master key out, to keep it apart from the backup;
                  restore then needs that key put back by hand

The zip holds the master key with the passwords and keys it decrypts,
unless -no-master-key: keep it as private as the key itself.

restore puts the files of such a zip back where this install keeps them,
replacing files with the same name. Stop the server first. It shows what
it will write and asks first (-yes skips the question).`

// backupFormat is the version of the zip's layout.
const backupFormat = 1

// manifestName is the zip entry that describes the backup.
const manifestName = "signalith-backup.json"

// backupRoot is one folder or file a backup copies, under its role: the
// name of its folder in the zip, and how restore finds where the same
// thing goes on another install.
type backupRoot struct {
	Role string `json:"role"`
	Path string `json:"path"`
	Dir  bool   `json:"dir"`
}

// backupManifest is signalith-backup.json in the zip.
type backupManifest struct {
	Format  int          `json:"format"`
	Made    time.Time    `json:"made"`
	Version string       `json:"signalith_version"`
	Host    string       `json:"host"`
	Config  string       `json:"config"`
	Roots   []backupRoot `json:"roots"`
	Files   int          `json:"files"`
	Skipped []string     `json:"skipped,omitempty"`
	// NoMasterKey is set when the master key was left out.
	NoMasterKey bool `json:"no_master_key,omitempty"`
	Archive     bool `json:"archive,omitempty"`
}

// backupConfig loads the config at path the way the server sees it: with
// the service's folders on Linux and Windows, and the Settings page's
// changes when they can be read. Nothing is decrypted.
func backupConfig(path string, out io.Writer) (*config.Config, error) {
	useServiceEnv(path, out)
	if s, err := config.LoadSaved(path); err == nil && s.Config != nil {
		return s.Config, nil
	}
	return config.LoadUnchecked(path)
}

// backupRoots lists what a backup of c copies. A file belongs to the most
// specific root it is in, so each is copied once, and restore puts it
// where the same root is on the other install.
func backupRoots(c *config.Config, archive bool) []backupRoot {
	abs := func(p string) string {
		if p == "" {
			return ""
		}
		if a, err := filepath.Abs(p); err == nil {
			return a
		}
		return p
	}
	ca, cert, key := c.OpenSearchTLSFiles()
	tlsCert, tlsKey := c.TLSFiles()
	roots := []backupRoot{
		{Role: "config", Path: c.Path()},
		{Role: "state", Path: c.StateDir(), Dir: true},
		{Role: "lookups", Path: c.LookupsDir(), Dir: true},
		{Role: "detections", Path: c.DetectionsDir(), Dir: true},
		{Role: "dashboards", Path: c.DashboardsDir(), Dir: true},
		{Role: "scripts", Path: c.ResponseScriptsDir(), Dir: true},
		{Role: "archive", Path: c.ArchiveDir(), Dir: true},
		{Role: "settings", Path: c.SettingsFile()},
		{Role: "users", Path: c.UsersFile()},
		{Role: "directory", Path: c.DirectoryFile()},
		{Role: "intel-feeds", Path: c.IntelFeedsFile()},
		{Role: "notifications", Path: c.NotifyFile()},
		{Role: "response", Path: c.ResponseFile()},
		{Role: "playbooks", Path: c.PlaybooksFile()},
		{Role: "server-tls-cert", Path: tlsCert},
		{Role: "server-tls-key", Path: tlsKey},
		{Role: "opensearch-ca", Path: ca},
		{Role: "opensearch-cert", Path: cert},
		{Role: "opensearch-key", Path: key},
	}
	if c.Auth.LDAP != nil {
		roots = append(roots, backupRoot{Role: "ldap-ca", Path: c.Auth.LDAP.CACertFile})
	}
	var out []backupRoot
	for _, r := range roots {
		r.Path = abs(r.Path)
		if r.Path == "" || (r.Role == "archive" && !archive) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// samePath compares paths as the file system does: without case on Windows.
func samePath(a, b string) bool {
	if filepath.Separator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// skipInBackup reports files a backup leaves out: the state folder's lock
// (held by the running server) and, with noKey, the master key.
func skipInBackup(role, rel string, noKey bool) bool {
	rel = filepath.ToSlash(rel)
	if role != "state" {
		return false
	}
	if rel == "cluster/lock" {
		return true
	}
	return noKey && strings.HasPrefix(rel, "keys/master.key")
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, backupUsage) }
	cfg := configFlag(fs)
	outFile := fs.String("o", "", "zip file to write")
	archive := fs.Bool("archive", false, "also copy the archived days")
	noKey := fs.Bool("no-master-key", false, "leave the master key out")
	fs.Parse(args)
	if fs.NArg() > 0 {
		return errors.New(backupUsage)
	}
	c, err := backupConfig(*cfg, os.Stderr)
	if err != nil {
		return err
	}
	name := *outFile
	if name == "" {
		host, _ := os.Hostname()
		if id, err := cluster.ReadIdentity(c.StateDir()); err == nil && id.Name != "" {
			host = id.Name
		}
		name = fmt.Sprintf("signalith-backup-%s-%s.zip", safeName(host), time.Now().Format("20060102-150405"))
	}
	m, err := writeBackup(name, c, *archive, *noKey)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s: %d files from:\n", name, m.Files)
	for _, r := range m.Roots {
		fmt.Printf("  %-16s %s\n", r.Role, r.Path)
	}
	for _, s := range m.Skipped {
		fmt.Println("Not copied:", s)
	}
	if *noKey {
		fmt.Println("\nThe master key was left out. Keep a copy of it apart: without it the passwords and keys in this backup cannot be read.")
	} else {
		fmt.Println("\nThis file holds the master key and the passwords and keys it decrypts, and the HTTPS keys: keep it as private as the key.")
	}
	fmt.Println("Events, findings and cases are in OpenSearch: back them up with an OpenSearch snapshot (see https://signalith.io/docs/backup/).")
	return nil
}

// isBackupFile reports a backup left in a folder it copies, such as one
// made in the Docker volume to copy it out: backups never hold backups.
func isBackupFile(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "signalith-backup") && strings.HasSuffix(name, ".zip")
}

func safeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, s)
	if s == "" {
		return "server"
	}
	return s
}

// writeBackup writes the zip file name with the files of c.
func writeBackup(name string, c *config.Config, archive, noKey bool) (*backupManifest, error) {
	outAbs, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	// O_EXCL: never write through a file or link someone put there.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%s already exists; give another name with -o", name)
		}
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(name)
		}
	}()
	m := &backupManifest{Format: backupFormat, Made: time.Now().UTC(), Version: version, Config: c.Path(), NoMasterKey: noKey, Archive: archive}
	m.Host, _ = os.Hostname()
	all := backupRoots(c, archive)
	// Roots the archived days are in are left out of their parents too,
	// unless -archive.
	skipDirs := []string{}
	if !archive {
		skipDirs = append(skipDirs, c.ArchiveDir())
	}
	zw := zip.NewWriter(f)
	used := map[string]bool{}
	for _, r := range all {
		if used[r.Path] {
			continue
		}
		if !r.Dir {
			// Copied once, under the first role that names it.
			st, err := os.Stat(r.Path)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				m.Skipped = append(m.Skipped, fmt.Sprintf("%s: %v", r.Path, err))
				continue
			}
			if !st.Mode().IsRegular() || samePath(r.Path, outAbs) {
				continue
			}
			used[r.Path] = true
			if err := addFile(zw, r.Role+"/"+filepath.Base(r.Path), r.Path, st); err != nil {
				return nil, err
			}
			m.Roots = append(m.Roots, r)
			m.Files++
			continue
		}
		st, err := os.Stat(r.Path)
		if err != nil || !st.IsDir() {
			continue
		}
		used[r.Path] = true
		n := 0
		err = ownFiles(r, all, skipDirs, noKey, func(p, rel string, d fs.DirEntry) error {
			if samePath(p, outAbs) {
				return nil
			}
			if !d.Type().IsRegular() {
				m.Skipped = append(m.Skipped, p+": not a regular file")
				return nil
			}
			info, err := d.Info()
			if err != nil {
				m.Skipped = append(m.Skipped, fmt.Sprintf("%s: %v", p, err))
				return nil
			}
			if err := addFile(zw, r.Role+"/"+filepath.ToSlash(rel), p, info); err != nil {
				return err
			}
			n++
			return nil
		}, func(p string, err error) { m.Skipped = append(m.Skipped, fmt.Sprintf("%s: %v", p, err)) })
		if err != nil {
			return nil, err
		}
		m.Roots = append(m.Roots, r)
		m.Files += n
	}
	mf, err := zw.Create(manifestName)
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(mf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	ok = true
	return m, nil
}

// setAsidePrefix starts the name of the folder restore moves files to
// that the backup does not have.
const setAsidePrefix = "before-restore-"

// ownFiles calls fn for each file in the folder root r that belongs to it:
// not in a folder or file that is a root of its own (all), nor in
// skipDirs, nor the state folder's lock or, with noKey, its master key,
// nor an earlier backup or files an earlier restore set aside. onErr hears
// of what cannot be read.
func ownFiles(r backupRoot, all []backupRoot, skipDirs []string, noKey bool, fn func(p, rel string, d fs.DirEntry) error, onErr func(p string, err error)) error {
	return filepath.WalkDir(r.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			onErr(p, err)
			if d != nil && d.IsDir() && p != r.Path {
				return fs.SkipDir
			}
			return nil
		}
		if p == r.Path {
			return nil
		}
		if d.IsDir() {
			for _, o := range all {
				if o.Dir && samePath(o.Path, p) && !samePath(o.Path, r.Path) {
					return fs.SkipDir
				}
			}
			if slices.ContainsFunc(skipDirs, func(s string) bool { return samePath(s, p) }) || strings.HasPrefix(d.Name(), setAsidePrefix) {
				return fs.SkipDir
			}
			return nil
		}
		if isBackupFile(d.Name()) {
			return nil
		}
		for _, o := range all {
			if !o.Dir && samePath(o.Path, p) {
				return nil // under its own role
			}
		}
		rel, err := filepath.Rel(r.Path, p)
		if err != nil || skipInBackup(r.Role, rel, noKey) {
			return nil
		}
		return fn(p, rel, d)
	})
}

func addFile(zw *zip.Writer, name, p string, info fs.FileInfo) error {
	src, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", p, err)
	}
	defer src.Close()
	h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: info.ModTime()}
	h.SetMode(info.Mode().Perm())
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("could not read %s: %w", p, err)
	}
	return nil
}

// restoreFile is one file restore writes.
type restoreFile struct {
	entry *zip.File
	dest  string
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, backupUsage) }
	cfg := configFlag(fs)
	yes := fs.Bool("yes", false, "do not ask before writing")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New(backupUsage)
	}
	c, err := backupConfig(*cfg, os.Stderr)
	if err != nil {
		return err
	}
	return restoreBackup(rest[0], c, *yes, os.Stdin, os.Stdout)
}

func restoreBackup(name string, c *config.Config, yes bool, in *os.File, out io.Writer) error {
	zr, err := zip.OpenReader(name)
	if err != nil {
		return fmt.Errorf("could not open %s: %w", name, err)
	}
	defer zr.Close()
	m, err := readManifest(&zr.Reader)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if busy, err := cluster.InUse(c.StateDir()); err != nil {
		return err
	} else if busy {
		return fmt.Errorf("Signalith is running with the state folder %s. Stop it first (sudo systemctl stop signalith, Stop-Service Signalith, or docker compose stop signalith), then run restore again", c.StateDir())
	}
	here := map[string]backupRoot{}
	for _, r := range backupRoots(c, true) {
		here[r.Role] = r
	}
	backed := map[string]backupRoot{}
	for _, r := range m.Roots {
		backed[r.Role] = r
	}
	var files []restoreFile
	perRole := map[string]int{}
	var unknown []string
	for _, e := range zr.File {
		if e.Name == manifestName || strings.HasSuffix(e.Name, "/") {
			continue
		}
		role, rel, ok := strings.Cut(e.Name, "/")
		if !ok || !filepath.IsLocal(filepath.FromSlash(rel)) || strings.Contains(rel, "\\") {
			return fmt.Errorf("%s: %q is not a file a backup holds", name, e.Name)
		}
		dst, ok := here[role]
		if _, inBackup := backed[role]; !ok || !inBackup {
			unknown = append(unknown, e.Name)
			continue
		}
		dest := dst.Path
		if dst.Dir {
			dest = filepath.Join(dst.Path, filepath.FromSlash(rel))
		}
		files = append(files, restoreFile{entry: e, dest: dest})
		perRole[role]++
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].dest < files[j].dest })
	extra, err := extraFiles(c, m, files)
	if err != nil {
		return err
	}
	aside := filepath.Join(c.StateDir(), setAsidePrefix+time.Now().Format("20060102-150405"))
	fmt.Fprintf(out, "Backup of %s made %s (Signalith %s), %d files.\n", m.Host, m.Made.Local().Format("2006-01-02 15:04"), m.Version, len(files))
	fmt.Fprintln(out, "Restore writes them here, replacing files with the same name:")
	var roles []string
	for r := range perRole {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	for _, r := range roles {
		fmt.Fprintf(out, "  %-16s %4d  -> %s\n", r, perRole[r], here[r].Path)
	}
	for _, u := range unknown {
		fmt.Fprintln(out, "  not restored (this install has no place for it):", u)
	}
	if len(extra) > 0 {
		fmt.Fprintf(out, "%d files here that the backup does not have (such as keys and certificates made since) are moved to %s.\n", len(extra), aside)
	}
	if m.NoMasterKey {
		fmt.Fprintln(out, "The backup has no master key: put the key it was made with back in place too (see docs/encryption.md), or the stored passwords and keys must be entered again.")
	}
	if !yes {
		if !term.IsTerminal(int(in.Fd())) {
			return errors.New("add -yes to restore when not at a terminal")
		}
		fmt.Fprint(out, "Restore these files? [y/N] ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("nothing was changed")
		}
	}
	for _, e := range extra {
		to := filepath.Join(aside, e.role, e.rel)
		if err := mkdirOwned(filepath.Dir(to)); err != nil {
			return fmt.Errorf("could not set %s aside: %w", e.path, err)
		}
		if err := os.Rename(e.path, to); err != nil {
			return fmt.Errorf("could not set %s aside: %w", e.path, err)
		}
	}
	var failed []string
	written := 0
	var readOnly []string
	for _, f := range files {
		if err := restoreOne(f); err != nil {
			if isReadOnly(err) {
				readOnly = append(readOnly, f.dest)
				continue
			}
			failed = append(failed, fmt.Sprintf("%s: %v", f.dest, err))
			continue
		}
		written++
	}
	fmt.Fprintf(out, "Restored %d files.\n", written)
	if len(readOnly) > 0 {
		// The Docker quick start mounts signalith.yaml and the setup
		// step's certificates read-only: those stay as they are.
		fmt.Fprintln(out, "Left as they are, on a read-only file system:")
		for _, f := range readOnly {
			fmt.Fprintln(out, " ", f)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintln(out, "Not restored:")
		for _, f := range failed {
			fmt.Fprintln(out, " ", f)
		}
		return fmt.Errorf("%d files could not be written", len(failed))
	}
	fmt.Fprintln(out, "Start Signalith again. If you also restored OpenSearch from a snapshot, then run: signalith cluster accept-restore")
	return nil
}

// extraFile is a file of this install a restore sets aside.
type extraFile struct{ role, rel, path string }

// extraFiles lists the files in the folders a restore writes that the
// backup does not have: a server would otherwise find a mix of both, such
// as a cluster key made here, encrypted with a master key the backup
// replaces. Archived days are never set aside, nor the master key when
// the backup has none.
func extraFiles(c *config.Config, m *backupManifest, files []restoreFile) ([]extraFile, error) {
	writes := map[string]bool{}
	for _, f := range files {
		writes[filepath.Clean(f.dest)] = true
	}
	backed := map[string]bool{}
	for _, r := range m.Roots {
		backed[r.Role] = true
	}
	all := backupRoots(c, true)
	var out []extraFile
	for _, r := range all {
		if !r.Dir || !backed[r.Role] || r.Role == "archive" {
			continue
		}
		if st, err := os.Stat(r.Path); err != nil || !st.IsDir() {
			continue
		}
		err := ownFiles(r, all, []string{c.ArchiveDir()}, m.NoMasterKey, func(p, rel string, d fs.DirEntry) error {
			if !writes[filepath.Clean(p)] {
				out = append(out, extraFile{role: r.Role, rel: rel, path: p})
			}
			return nil
		}, func(string, error) {})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readManifest(zr *zip.Reader) (*backupManifest, error) {
	for _, e := range zr.File {
		if e.Name != manifestName {
			continue
		}
		r, err := e.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		var m backupManifest
		if err := json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(&m); err != nil {
			return nil, fmt.Errorf("its %s cannot be read: %w", manifestName, err)
		}
		if m.Format != backupFormat {
			return nil, fmt.Errorf("it was made by a newer Signalith (backup format %d); restore it with that version", m.Format)
		}
		return &m, nil
	}
	return nil, errors.New("this is not a Signalith backup (it has no " + manifestName + ")")
}

// restoreOne writes one file through a temporary file renamed into place,
// so a file is never left half written. It is private to the account
// that owns the folder it goes in, which is the server's.
func restoreOne(f restoreFile) error {
	r, err := f.entry.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	dir := filepath.Dir(f.dest)
	if err := mkdirOwned(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(f.dest)+".restore-*")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err := io.Copy(tmp, r); err != nil {
		return err
	}
	// Owner only, keeping whether it may be run (response scripts).
	if err := tmp.Chmod(f.entry.Mode().Perm()&0o700 | 0o600); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	giveToOwnerOf(tmp.Name(), dir)
	if err := os.Rename(tmp.Name(), f.dest); err != nil {
		return err
	}
	done = true
	return nil
}

// mkdirOwned makes dir and the folders above it that are missing, each
// private and owned by the owner of the folder above it.
func mkdirOwned(dir string) error {
	if st, err := os.Stat(dir); err == nil {
		if !st.IsDir() {
			return fmt.Errorf("%s is not a folder", dir)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return fmt.Errorf("%s does not exist", dir)
	}
	if err := mkdirOwned(parent); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	giveToOwnerOf(dir, parent)
	return nil
}
