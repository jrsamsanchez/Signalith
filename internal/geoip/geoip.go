// Package geoip finds where an IP address is, for the search command
// iplocation, from a GeoIP database in the MaxMind DB format (.mmdb) that
// an admin puts in the geoip folder next to the lookup tables: a free
// DB-IP Lite or MaxMind GeoLite2 City or Country database, or a paid one.
package geoip

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// MaxFileBytes is the largest database read. The whole file is kept in
// memory, so it is never held open: on Windows a newer file can replace
// it, and no one changing it in place can change what a search reads.
const MaxFileBytes = 512 << 20

// recheck is how often the folder is looked at again for a newer file.
const recheck = 30 * time.Second

// Location is what a database knows about one address. Fields it has no
// value for are empty, or HasCoords is false.
type Location struct {
	City, Region, Country, Continent, Timezone string
	MetroCode                                  int
	Lat, Lon                                   float64
	HasCoords                                  bool
}

// Store reads the newest .mmdb file in its folder, again when a newer one
// arrives. The zero value is not usable; use Open.
type Store struct {
	dir string
	now func() time.Time
	// fixed is a store of one database held in memory (FromBytes), which
	// never looks at a folder.
	fixed bool

	loadMu  sync.Mutex // one load at a time; guards checked and tried
	checked time.Time
	tried   fileID // the newest file last seen, loaded or not

	mu   sync.RWMutex
	db   *maxminddb.Reader
	file string // where db came from
	err  error
}

type fileID struct {
	path string
	mod  time.Time
	size int64
}

// Open returns a store for the .mmdb files in dir, read the first time an
// address is looked up.
func Open(dir string) *Store {
	return &Store{dir: dir, now: time.Now}
}

// FromBytes returns a store of the one City or Country database in buf,
// which never looks at a folder: for tests, and for checking rules that
// run iplocation against a known database.
func FromBytes(buf []byte) (*Store, error) {
	db, err := openBytes(buf)
	if err != nil {
		return nil, err
	}
	return &Store{now: time.Now, fixed: true, db: db, file: "(in memory)"}, nil
}

// Loading returns a store whose first database is always still loading:
// for tests of what a search does meanwhile.
func Loading() *Store {
	s := &Store{now: time.Now}
	s.loadMu.Lock()
	return s
}

// Dir is the folder the store reads.
func (s *Store) Dir() string { return s.dir }

// ErrNoDatabase means the folder has no .mmdb file.
var ErrNoDatabase = errors.New("no GeoIP database")

// ErrLoading means the first database is still being read.
var ErrLoading = errors.New("the GeoIP database is still loading")

// Lookup returns where ip is, with names in lang (such as en, de or
// zh-CN) where the database has them and in English otherwise. found is
// false for an address the database does not list, such as a private one.
func (s *Store) Lookup(ip netip.Addr, lang string) (loc Location, found bool, err error) {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return Location{}, false, s.errNoDB()
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	if ip.Is6() && s.db.Metadata.IPVersion == 4 {
		return Location{}, false, nil
	}
	var rec record
	res := s.db.Lookup(ip)
	if !res.Found() {
		return Location{}, false, res.Err()
	}
	if err := res.Decode(&rec); err != nil {
		return Location{}, false, fmt.Errorf("reading the GeoIP database: %w", err)
	}
	loc = Location{
		City:      name(rec.City.Names, lang),
		Country:   name(rec.Country.Names, lang),
		Continent: name(rec.Continent.Names, lang),
		Timezone:  rec.Location.TimeZone,
		MetroCode: int(rec.Location.MetroCode),
	}
	if loc.Country == "" {
		loc.Country = name(rec.RegisteredCountry.Names, lang)
	}
	if len(rec.Subdivisions) > 0 {
		loc.Region = name(rec.Subdivisions[0].Names, lang)
	}
	if rec.Location.Latitude != nil && rec.Location.Longitude != nil {
		loc.Lat, loc.Lon, loc.HasCoords = *rec.Location.Latitude, *rec.Location.Longitude, true
	}
	return loc, true, nil
}

// Status returns the file in use, empty when there is none, and why the
// folder's newest file could not be used.
func (s *Store) Status() (file string, err error) {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return "", s.errNoDB()
	}
	return s.file, s.err
}

// errNoDB is why there is no database, with s.mu held.
func (s *Store) errNoDB() error {
	if s.err == nil {
		return ErrLoading
	}
	return s.err
}

type names map[string]string

type record struct {
	City struct {
		Names names `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		Names names `maxminddb:"names"`
	} `maxminddb:"continent"`
	Country struct {
		Names names `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		Names names `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	Subdivisions []struct {
		Names names `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Longitude *float64 `maxminddb:"longitude"`
		MetroCode uint     `maxminddb:"metro_code"`
		TimeZone  string   `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

func name(n names, lang string) string {
	if v := n[lang]; v != "" {
		return v
	}
	return n["en"]
}

// refresh loads the folder's newest .mmdb file when it changed, looking at
// the folder at most every 30 seconds. A file that cannot be used leaves
// the one in use, if any, and sets the error Status returns.
func (s *Store) refresh() {
	if s.fixed {
		return
	}
	// A search does not wait while another loads a file, which can take
	// seconds; it uses the file in use until the load is done.
	if !s.loadMu.TryLock() {
		return
	}
	defer s.loadMu.Unlock()
	now := s.now()
	if !s.checked.IsZero() && now.Sub(s.checked) < recheck {
		return
	}
	s.checked = now
	id, err := newest(s.dir)
	if err != nil {
		s.tried = fileID{}
		s.set(nil, "", err)
		return
	}
	if id == s.tried {
		return
	}
	// A file that fails is tried again once it changes, not on every
	// search.
	s.tried = id
	db, err := load(id)
	if err != nil {
		slog.Warn("GeoIP database not used", "file", id.path, "err", err)
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		return
	}
	slog.Info("GeoIP database loaded", "file", id.path, "type", db.Metadata.DatabaseType, "built", db.Metadata.BuildTime().UTC().Format(time.DateOnly))
	s.set(db, id.path, nil)
}

func (s *Store) set(db *maxminddb.Reader, file string, err error) {
	s.mu.Lock()
	old := s.db
	s.db, s.file, s.err = db, file, err
	s.mu.Unlock()
	if old != nil && old != db {
		old.Close() //nolint:errcheck // an in-memory reader cannot fail to close
	}
}

func newest(dir string) (fileID, error) {
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fileID{}, fmt.Errorf("reading %s: %w", dir, err)
	}
	var best fileID
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.EqualFold(filepath.Ext(e.Name()), ".mmdb") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		id := fileID{path: filepath.Join(dir, e.Name()), mod: info.ModTime(), size: info.Size()}
		if best.path == "" || id.mod.After(best.mod) || id.mod.Equal(best.mod) && id.path > best.path {
			best = id
		}
	}
	if best.path == "" {
		return fileID{}, fmt.Errorf("%w: put a GeoIP City or Country database (.mmdb) in %s", ErrNoDatabase, dir)
	}
	return best, nil
}

func load(id fileID) (*maxminddb.Reader, error) {
	if id.size > MaxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d MB", id.path, MaxFileBytes>>20)
	}
	f, err := os.Open(id.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read in one allocation of the listed size, so memory peaks at the
	// file's size, and refuse a file that changed size since.
	buf := make([]byte, id.size)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, fmt.Errorf("%s changed while it was read: %w", id.path, err)
	}
	if n, _ := f.Read(make([]byte, 1)); n > 0 {
		return nil, fmt.Errorf("%s changed while it was read", id.path)
	}
	db, err := openBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("%s %w", id.path, err)
	}
	return db, nil
}

// openBytes checks that buf is a City or Country database and opens it.
func openBytes(buf []byte) (*maxminddb.Reader, error) {
	db, err := maxminddb.OpenBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("is not a GeoIP database: %w", err)
	}
	if err := db.Verify(); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("is damaged: %w", err)
	}
	t := db.Metadata.DatabaseType
	if !strings.Contains(strings.ToLower(t), "city") && !strings.Contains(strings.ToLower(t), "country") {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("is a %q database; iplocation needs a City or Country database", t)
	}
	return db, nil
}
