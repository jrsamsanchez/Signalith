package geoip

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/geoip/geoiptest"
)

func TestLoadingAndDir(t *testing.T) {
	s := Loading()
	if _, _, err := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); !errors.Is(err, ErrLoading) {
		t.Errorf("lookup while loading = %v", err)
	}
	if f, err := s.Status(); f != "" || !errors.Is(err, ErrLoading) {
		t.Errorf("status while loading = %q %v", f, err)
	}
	dir := t.TempDir()
	if got := Open(dir).Dir(); got != dir {
		t.Errorf("Dir = %s", got)
	}
	if f, err := Open(filepath.Join(dir, "missing")).Status(); f != "" || !errors.Is(err, ErrNoDatabase) {
		t.Errorf("status without a file = %q %v", f, err)
	}
}

func TestIPv6OnAnIPv4Database(t *testing.T) {
	b, err := geoiptest.Build("GeoLite2-Country", testNets)
	if err != nil {
		t.Fatal(err)
	}
	s, err := FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	s.db.Metadata.IPVersion = 4
	if _, found, err := s.Lookup(netip.MustParseAddr("2001:db8::1"), "en"); found || err != nil {
		t.Errorf("IPv6 on IPv4 = %v %v", found, err)
	}
	if loc, found, err := s.Lookup(netip.MustParseAddr("::ffff:81.2.69.1"), "en"); !found || err != nil || loc.Country != "United Kingdom" {
		t.Errorf("mapped IPv4 = %+v %v %v", loc, found, err)
	}
}

func TestFolderContents(t *testing.T) {
	dir := t.TempDir()
	// Other files and folders are left alone.
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0o600)
	os.Mkdir(filepath.Join(dir, "old.mmdb"), 0o755)
	if _, err := newest(dir); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("no database = %v", err)
	}
	writeDB(t, dir, "CITY.MMDB", "GeoLite2-City", testNets)
	if id, err := newest(dir); err != nil || filepath.Base(id.path) != "CITY.MMDB" {
		t.Errorf("newest = %+v %v", id, err)
	}
	// The folder is a file.
	file := filepath.Join(dir, "readme.txt")
	// Windows may report it as a missing folder: then there is no
	// database, which is an error too.
	if _, err := newest(file); err == nil || runtime.GOOS != "windows" && (errors.Is(err, ErrNoDatabase) || !strings.Contains(err.Error(), "reading")) {
		t.Errorf("a file as the folder = %v", err)
	}
}

func TestLoadRefusals(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, dir, "a.mmdb", "GeoLite2-City", testNets)
	path := filepath.Join(dir, "a.mmdb")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := load(fileID{path: path, size: MaxFileBytes + 1}); err == nil || !strings.Contains(err.Error(), "larger than 512 MB") {
		t.Errorf("too big = %v", err)
	}
	if _, err := load(fileID{path: filepath.Join(dir, "gone.mmdb")}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("gone = %v", err)
	}
	if _, err := load(fileID{path: path, size: fi.Size() + 10}); err == nil || !strings.Contains(err.Error(), "changed while it was read") {
		t.Errorf("shrunk = %v", err)
	}
	if _, err := load(fileID{path: path, size: fi.Size() - 10}); err == nil || !strings.Contains(err.Error(), "changed while it was read") {
		t.Errorf("grew = %v", err)
	}
	if db, err := load(fileID{path: path, size: fi.Size()}); err != nil {
		t.Errorf("load = %v", err)
	} else {
		db.Close()
	}
}

// A broken file is not read again until it changes.
func TestBrokenFileTriedOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.mmdb")
	os.WriteFile(path, []byte("junk"), 0o600)
	s := Open(dir)
	now := time.Now()
	s.now = func() time.Time { return now }
	_, _, first := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en")
	if first == nil {
		t.Fatal("no error")
	}
	now = now.Add(31 * time.Second)
	if _, _, err := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); err == nil || err.Error() != first.Error() {
		t.Errorf("second = %v, first %v", err, first)
	}
	// Once fixed, it is used.
	writeDB(t, dir, "x.mmdb", "GeoLite2-City", testNets)
	os.Chtimes(path, now.Add(time.Minute), now.Add(time.Minute))
	now = now.Add(31 * time.Second)
	if loc, found, err := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); err != nil || !found || loc.City != "London" {
		t.Errorf("fixed = %+v %v %v", loc, found, err)
	}
}
