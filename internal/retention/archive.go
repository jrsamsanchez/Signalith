package retention

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ArchiveFormat names the archive file format in manifests.
const ArchiveFormat = "signalith-archive/1"

// Archive files are <index>.ndjson.gz with a <index>.json manifest beside
// them. When an index was archived before (events that arrived late
// recreated it), the next file is <index>.2.ndjson.gz, and so on.
const (
	dataExt     = ".ndjson.gz"
	manifestExt = ".json"
)

// Archive writes deleted days to a folder and reads them back. Each line
// of an archive file is one document, {"_id":...,"_source":{...}}, so
// plain files (and encrypted ones, once decrypted) can also be read with
// zcat and jq.
type Archive struct {
	Dir string
	// Seal, when set, wraps the file as it is written, for example to
	// encrypt it, and returns the ids of the keys it used, which the
	// manifest records; Unseal reverses it when reading, and Encryption
	// names the scheme in manifests. When nil, files are plain gzip.
	// Unseal is used for every file whose manifest names an encryption,
	// so archives written before Seal was set still read without it.
	Seal       func(io.Writer) (io.WriteCloser, []string, error)
	Unseal     func(io.Reader) (io.Reader, error)
	Encryption string
	// Server names this server in the manifests it writes, when servers
	// share one archive folder.
	Server string
	// Manifests, when set, keeps the manifests (servers that share one
	// OpenSearch and one archive folder keep them in OpenSearch, so two
	// servers never write the same archive): IDs are reserved there
	// before a file is written, and listings read from there. A manifest
	// file is still written next to each archive. When nil, the manifest
	// files are the list.
	Manifests ManifestStore
}

// Manifest states, for a ManifestStore: an archive is pending from when
// its ID is reserved until its file is written and checked.
const (
	ManifestPending  = "pending"
	ManifestComplete = "complete"
)

// ManifestStore keeps archive manifests outside the archive folder.
type ManifestStore interface {
	// Reserve reserves the first free archive ID for m.Index (the index
	// name, then <index>.2, <index>.3 and so on), with m pending, and
	// returns it. An ID is reserved once: two servers never get the same.
	// skip reports IDs to pass over, such as ones whose file exists.
	Reserve(ctx context.Context, m Manifest, skip func(id string) bool) (string, error)
	// Complete records the finished manifest of a reserved ID.
	Complete(ctx context.Context, m Manifest) error
	// Abandon gives up a reserved ID whose archive was not written.
	Abandon(ctx context.Context, id string) error
	// List returns the complete manifests, and problems with others.
	List(ctx context.Context) ([]Manifest, []string, error)
	// Get returns one complete manifest, or ErrArchiveNotFound.
	Get(ctx context.Context, id string) (Manifest, error)
}

// storeTimeout bounds a call to the ManifestStore.
const storeTimeout = 30 * time.Second

// Manifest describes one archive file.
type Manifest struct {
	Format string `json:"format"`
	// ID is the file name without extension; restores name archives by it.
	ID    string `json:"id"`
	Index string `json:"index"`
	// IndexUUID is the UUID of the index the archive was made from. An
	// index of the same name created later, by events that arrived after
	// the day was deleted, has another UUID and is archived again.
	IndexUUID string `json:"index_uuid,omitempty"`
	Category  string `json:"category"`
	Day       string `json:"day"` // YYYY-MM-DD
	Docs      int64  `json:"docs"`
	File      string `json:"file"`
	// Bytes is the archive file's size and IndexBytes the size the index
	// had in OpenSearch.
	Bytes      int64     `json:"bytes"`
	IndexBytes int64     `json:"index_bytes"`
	SHA256     string    `json:"sha256"`
	Created    time.Time `json:"created"`
	Encryption string    `json:"encryption,omitempty"`
	// KID names the keys the file's key is encrypted with, comma-separated.
	KID string `json:"kid,omitempty"`
	// State is pending or complete in a ManifestStore; empty in files.
	State string `json:"state,omitempty"`
	// Server is the server that wrote the archive, when servers share one
	// archive folder.
	Server string `json:"server,omitempty"`
}

var archiveID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,250}$`)

// ErrArchiveNotFound is returned for unknown archive IDs.
var ErrArchiveNotFound = errors.New("archive not found")

func (a *Archive) path(name string) string { return filepath.Join(a.Dir, name) }

// ensureDir creates the archive folder, readable by its owner only.
func (a *Archive) ensureDir() error {
	if a.Dir == "" {
		return errors.New("no archive folder is set (retention.archive_dir)")
	}
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return fmt.Errorf("cannot create the archive folder %s: %w", a.Dir, err)
	}
	// A folder made by an installer or an admin may be more open; tighten
	// it if this server owns it. On Windows this sets an access list for
	// SYSTEM, Administrators and the server's account only.
	_ = restrictDir(a.Dir)
	return nil
}

// freeID returns the first archive ID for an index whose files do not
// exist yet.
func (a *Archive) freeID(index string) string {
	id := index
	for n := 2; ; n++ {
		if !a.taken(id) {
			return id
		}
		id = ArchiveID(index, n)
	}
}

// ArchiveID is the nth archive ID of an index: the index name, then
// <index>.2, <index>.3 and so on.
func ArchiveID(index string, n int) string {
	if n <= 1 {
		return index
	}
	return index + "." + strconv.Itoa(n)
}

// countingWriter counts bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Exporter reads every document of an index.
type Exporter interface {
	Export(ctx context.Context, index string, fn func(Doc) error) error
}

// Source describes the index an archive is written from.
type Source struct {
	Index    string
	UUID     string
	Category string
	Day      string // YYYY-MM-DD
	// Bytes is the index's size in OpenSearch, for the manifest.
	Bytes int64
	// Estimate is about the most the archive file can take, used to check
	// for free space before writing; 0 skips the check.
	Estimate int64
}

// ErrArchiveSpace means the archive folder has too little free space.
var ErrArchiveSpace = errors.New("not enough free space in the archive folder")

// Write exports an index into a new archive file and returns its
// manifest. The file is written to a temporary name, synced to disk,
// checked against the expected document count, renamed into place and
// then read back in full before Write returns, so an index is only
// deleted once its archive is known to be complete and readable. On any
// error no archive files are left behind.
func (a *Archive) Write(ctx context.Context, ex Exporter, src Source, expectDocs int64) (*Manifest, error) {
	index := src.Index
	if !archiveID.MatchString(index) {
		return nil, fmt.Errorf("%q is not an index name that can be archived", index)
	}
	if err := a.ensureDir(); err != nil {
		return nil, err
	}
	// Check for room first rather than fill the disk and fail: the archive
	// folder often shares a disk with OpenSearch.
	if src.Estimate > 0 {
		if free, _, err := diskSpace(a.Dir); err == nil && free < src.Estimate {
			return nil, fmt.Errorf("%w: %s has %s free, and archiving %s may take up to %s; free space there or move the archive folder (retention.archive_dir)",
				ErrArchiveSpace, a.Dir, sizeString(free), index, sizeString(src.Estimate))
		}
	}
	tmp, err := os.CreateTemp(a.Dir, ".tmp-"+index+"-*")
	if err != nil {
		return nil, fmt.Errorf("cannot write to the archive folder %s: %w", a.Dir, err)
	}
	keep := false
	defer func() {
		if !keep {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	sum := sha256.New()
	counted := &countingWriter{w: io.MultiWriter(tmp, sum)}
	var sealed io.WriteCloser
	var kids []string
	var under io.Writer = counted
	if a.Seal != nil {
		if sealed, kids, err = a.Seal(counted); err != nil {
			return nil, err
		}
		under = sealed
	}
	zw := gzip.NewWriter(under)
	bw := bufio.NewWriterSize(zw, 256<<10)
	var docs int64
	var line bytes.Buffer
	err = ex.Export(ctx, index, func(d Doc) error {
		line.Reset()
		id, _ := json.Marshal(d.ID)
		line.WriteString(`{"_id":`)
		line.Write(id)
		line.WriteString(`,"_source":`)
		if err := json.Compact(&line, d.Source); err != nil {
			return fmt.Errorf("document %s is not valid JSON: %w", d.ID, err)
		}
		line.WriteString("}\n")
		docs++
		_, err := bw.Write(line.Bytes())
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("exporting %s: %w", index, err)
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if sealed != nil {
		if err := sealed.Close(); err != nil {
			return nil, err
		}
	}
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("syncing the archive file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if docs != expectDocs {
		return nil, fmt.Errorf("the archive of %s has %d events but the index has %d", index, docs, expectDocs)
	}
	enc := ""
	if a.Seal != nil {
		enc = a.Encryption
		if enc == "" {
			enc = "sealed"
		}
	}
	m := &Manifest{
		Format: ArchiveFormat, Index: index, IndexUUID: src.UUID, Category: src.Category, Day: src.Day,
		Docs: docs, Bytes: counted.n, IndexBytes: src.Bytes,
		SHA256: hex.EncodeToString(sum.Sum(nil)), Created: time.Now().UTC(), Encryption: enc,
	}
	if a.Seal != nil {
		m.KID = strings.Join(kids, ",")
	}
	m.Server = a.Server
	var id string
	if a.Manifests != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
		defer cancel()
		pend := *m
		pend.State = ManifestPending
		if id, err = a.Manifests.Reserve(ctx, pend, a.taken); err != nil {
			return nil, fmt.Errorf("could not reserve an archive name for %s: %w", index, err)
		}
	} else {
		id = a.freeID(index)
	}
	m.ID, m.File = id, id+dataExt
	abandon := func() {
		if a.Manifests != nil {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
			defer cancel()
			_ = a.Manifests.Abandon(ctx, id)
		}
	}
	// A reserved name is this server's alone, but a file of that name
	// must never be written over.
	if a.taken(id) {
		abandon()
		return nil, fmt.Errorf("the archive file %s exists already", m.File)
	}
	if err := os.Rename(tmp.Name(), a.path(m.File)); err != nil {
		abandon()
		return nil, err
	}
	keep = true
	fail := func(err error) (*Manifest, error) {
		os.Remove(a.path(m.File))
		os.Remove(a.path(id + manifestExt))
		abandon()
		return nil, err
	}
	if err := writeFileSynced(a.path(id+manifestExt), m); err != nil {
		return fail(err)
	}
	syncDir(a.Dir)
	if err := a.Verify(*m); err != nil {
		return fail(fmt.Errorf("the archive of %s could not be read back: %w", index, err))
	}
	if a.Manifests != nil {
		done := *m
		done.State = ManifestComplete
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
		defer cancel()
		if err := a.Manifests.Complete(ctx, done); err != nil {
			return fail(fmt.Errorf("could not record the archive of %s: %w", index, err))
		}
		*m = done
	}
	return m, nil
}

// taken reports whether an archive's files exist.
func (a *Archive) taken(id string) bool {
	_, err1 := os.Lstat(a.path(id + dataExt))
	_, err2 := os.Lstat(a.path(id + manifestExt))
	return !errors.Is(err1, os.ErrNotExist) || !errors.Is(err2, os.ErrNotExist)
}

// writeFileSynced writes JSON to a file atomically and syncs it to disk.
func writeFileSynced(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-"+filepath.Base(name)+"-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), name)
}

// syncDir makes a rename durable. Windows cannot sync folders, and does
// not need to.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// List returns every archive, newest day first, and a problem for each
// manifest that cannot be read.
func (a *Archive) List() ([]Manifest, []string, error) {
	if a.Manifests != nil {
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
		return a.Manifests.List(ctx)
	}
	return a.ListFiles()
}

// ListFiles is List from the manifest files in the archive folder,
// whatever keeps the manifests.
func (a *Archive) ListFiles() ([]Manifest, []string, error) {
	if a.Dir == "" {
		return nil, nil, nil
	}
	entries, err := os.ReadDir(a.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var out []Manifest
	var problems []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, manifestExt) {
			continue
		}
		m, err := a.readManifest(strings.TrimSuffix(name, manifestExt))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day > out[j].Day
		}
		return out[i].ID < out[j].ID
	})
	return out, problems, nil
}

// storeIDFile names the archive folder: servers that share one folder
// read the same name.
const storeIDFile = ".signalith-archive-id"

// StoreID returns the archive folder's name, written into it the first
// time any server asks. Servers that share one OpenSearch compare it, to
// tell whether they keep their archives in one shared folder; unlike the
// list of archives, it does not change as days are archived.
func (a *Archive) StoreID() (string, error) {
	if a.Dir == "" {
		return "", nil
	}
	path := a.path(storeIDFile)
	for try := 0; ; try++ {
		b, err := os.ReadFile(path)
		if err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id, nil
			}
			// Another server is writing it just now.
			if try < 20 {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return "", fmt.Errorf("%s in the archive folder is empty", storeIDFile)
		}
		if !errors.Is(err, os.ErrNotExist) || try > 0 {
			return "", err
		}
		if err := a.ensureDir(); err != nil {
			return "", err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue // another server made it first
		}
		if err != nil {
			return "", fmt.Errorf("cannot name the archive folder: %w", err)
		}
		r := make([]byte, 12)
		_, _ = rand.Read(r)
		id := "as_" + hex.EncodeToString(r)
		_, werr := f.WriteString(id + "\n")
		if err := f.Close(); werr == nil {
			werr = err
		}
		if werr != nil {
			return "", fmt.Errorf("cannot name the archive folder: %w", werr)
		}
		return id, nil
	}
}

// Get returns one archive's manifest.
func (a *Archive) Get(id string) (Manifest, error) {
	if !archiveID.MatchString(id) {
		return Manifest{}, ErrArchiveNotFound
	}
	if a.Manifests != nil {
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
		return a.Manifests.Get(ctx, id)
	}
	m, err := a.readManifest(id)
	if errors.Is(err, os.ErrNotExist) {
		return Manifest{}, ErrArchiveNotFound
	}
	return m, err
}

// ReadManifestFile reads the manifest file of archive id.
func (a *Archive) ReadManifestFile(id string) (Manifest, error) { return a.readManifest(id) }

func (a *Archive) readManifest(id string) (Manifest, error) {
	data, err := os.ReadFile(a.path(id + manifestExt))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("not a valid manifest: %w", err)
	}
	if m.Format != ArchiveFormat {
		return Manifest{}, fmt.Errorf("unknown archive format %q", m.Format)
	}
	if m.ID != id || m.File != id+dataExt || !archiveID.MatchString(m.Index) {
		return Manifest{}, errors.New("the manifest does not match its file name")
	}
	st, err := os.Stat(a.path(m.File))
	if err != nil {
		return Manifest{}, fmt.Errorf("its data file is missing: %w", err)
	}
	if st.Size() != m.Bytes {
		return Manifest{}, fmt.Errorf("its data file is %d bytes, not %d", st.Size(), m.Bytes)
	}
	return m, nil
}

// Read calls fn with every document in an archive file, then checks the
// file's checksum and document count against its manifest. Callers that
// must not act on a damaged file call Verify first.
func (a *Archive) Read(m Manifest, fn func(Doc) error) error {
	f, err := os.Open(a.path(m.File))
	if err != nil {
		return err
	}
	defer f.Close()
	sum := sha256.New()
	var r io.Reader = io.TeeReader(f, sum)
	if m.Encryption != "" {
		if a.Unseal == nil {
			return fmt.Errorf("the archive is encrypted (%s) and this server cannot decrypt it", m.Encryption)
		}
		if r, err = a.Unseal(r); err != nil {
			return err
		}
	}
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("not a gzip file: %w", err)
	}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 1<<20), 256<<20)
	var n int64
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var d Doc
		if err := json.Unmarshal(line, &d); err != nil {
			return fmt.Errorf("line %d is not valid JSON: %w", n+1, err)
		}
		if len(d.Source) == 0 {
			return fmt.Errorf("line %d has no _source", n+1)
		}
		n++
		if fn != nil {
			if err := fn(d); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	// Read to the end so the checksum covers the whole file.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != m.SHA256 {
		return fmt.Errorf("checksum mismatch: the file is damaged or was changed (sha256 %s, expected %s)", got, m.SHA256)
	}
	if n != m.Docs {
		return fmt.Errorf("the file holds %d events, not %d", n, m.Docs)
	}
	return nil
}

// Verify reads an archive file in full and checks its checksum and
// document count.
func (a *Archive) Verify(m Manifest) error { return a.Read(m, nil) }

// archivesByIndex groups archives by the index they were made from.
func archivesByIndex(list []Manifest) map[string][]Manifest {
	out := map[string][]Manifest{}
	for _, m := range list {
		out[m.Index] = append(out[m.Index], m)
	}
	return out
}

// sizeString prints bytes the way the page does (1 GB = 1024³ bytes).
func sizeString(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}

// existing returns dir, or its nearest parent that exists.
func existing(dir string) string {
	for {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}
