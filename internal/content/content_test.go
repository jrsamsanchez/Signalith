package content

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

const packsDir = "../detect/packs"

func testKey(t *testing.T) (ed25519.PrivateKey, []ed25519.PublicKey) {
	t.Helper()
	priv, pub, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeys("# a comment\n" + pub + " # the test key\n")
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	return k, keys
}

// bundle makes a signed bundle of the real packs, made at now.
func bundle(t *testing.T, priv ed25519.PrivateKey, now time.Time) ([]byte, []byte) {
	t.Helper()
	data, m, err := Build(packsDir, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != Format || len(m.Packs) < 2 || m.Packs[0].Rules < 100 {
		t.Fatalf("manifest = %+v", m)
	}
	return data, Sign(priv, data)
}

func TestTrustedKeysParse(t *testing.T) {
	_ = TrustedKeys() // panics on a bad line
	if _, err := ParseKeys("not a key"); err == nil {
		t.Error("bad key accepted")
	}
}

func TestBuildSignRead(t *testing.T) {
	priv, keys := testKey(t)
	data, sig := bundle(t, priv, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	b, err := Read(keys, data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.Version != "20300102030405" {
		t.Errorf("version %s", b.Manifest.Version)
	}
	// Licences ship; test events and reports do not.
	for _, want := range []string{"packs/sigmahq/pack.yaml", "packs/splunk/LICENSE", "packs/splunk/macros"} {
		if _, err := fs.Stat(b.FS, want); err != nil {
			t.Errorf("%s: %v", want, err)
		}
	}
	for _, not := range []string{"packs/sigmahq/tests", "packs/sigmahq/REPORT.md"} {
		if _, err := fs.Stat(b.FS, not); err == nil {
			t.Errorf("%s is in the bundle", not)
		}
	}
	ps, ds, skipped, err := detect.LoadPacks(b.FS)
	if err != nil || len(ps) != 2 || len(skipped) != 0 || len(ds) < 1500 {
		t.Fatalf("LoadPacks = %d packs, %d detections, %v, %v", len(ps), len(ds), skipped, err)
	}

	// A changed byte, another key, or no key at all is refused.
	bad := bytes.Clone(data)
	bad[len(bad)/2] ^= 1
	if _, err := Read(keys, bad, sig); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("changed bundle: %v", err)
	}
	_, other := testKey(t)
	if _, err := Read(other, data, sig); err == nil {
		t.Error("another key accepted")
	}
	if _, err := Read(nil, data, sig); !errors.Is(err, ErrNoKeys) {
		t.Errorf("no keys: %v", err)
	}
	if _, err := Read(keys, data, []byte("junk")); err == nil {
		t.Error("junk signature accepted")
	}
}

// raw makes a signed tar.gz of the given entries.
func raw(t *testing.T, priv ed25519.PrivateKey, entries map[string]string) ([]byte, []byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes(), Sign(priv, buf.Bytes())
}

func TestReadRefuses(t *testing.T) {
	priv, keys := testKey(t)
	head := func(format int, version string) string {
		b, _ := json.Marshal(Manifest{Format: format, Version: version})
		return string(b)
	}
	for name, entries := range map[string]map[string]string{
		"newer format":  {"content.json": head(Format+1, "20300101000000")},
		"bad version":   {"content.json": head(Format, "soon")},
		"no manifest":   {"packs/x/pack.yaml": "name: x"},
		"outside packs": {"content.json": head(Format, "20300101000000"), "etc/passwd": "x"},
		"climbs out":    {"content.json": head(Format, "20300101000000"), "packs/../../x": "x"},
	} {
		data, sig := raw(t, priv, entries)
		if _, err := Read(keys, data, sig); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestUpdater(t *testing.T) {
	t.Cleanup(func() { detect.UsePacks(nil, nil, "") })
	priv, keys := testKey(t)
	dir := filepath.Join(t.TempDir(), "content")
	lib, _, err := detect.NewLibrary("")
	if err != nil {
		t.Fatal(err)
	}
	u := &Updater{Dir: dir, Keys: keys, Library: lib}
	u.Start()
	if st := u.Status(); st.Updated || !st.Ready || st.Version != st.Builtin {
		t.Fatalf("start = %+v", st)
	}

	// An update older than the built-in rules is refused.
	old, oldSig := bundle(t, priv, time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC))
	if _, err := u.Install(old, oldSig); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("old update: %v", err)
	}

	// A newer one, served over HTTP, is downloaded, kept and used.
	data, sig := bundle(t, priv, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/c.tar.gz":
			w.Write(data)
		case "/c.tar.gz.sig":
			w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	st, err := u.Check(t.Context(), srv.URL+"/c.tar.gz")
	if err != nil || !st.Updated || st.Version != "20990101000000" || st.LastResult != "installed" || len(st.Packs) != 2 {
		t.Fatalf("check = %+v %v", st, err)
	}
	if v, updated := detect.ContentVersion(); !updated || v != "20990101000000" {
		t.Errorf("in use %s %v", v, updated)
	}
	// Checking again finds nothing newer, which is not an error.
	if st, err := u.Check(t.Context(), srv.URL+"/c.tar.gz"); err != nil || st.LastResult != "up to date" {
		t.Errorf("second check = %+v %v", st, err)
	}
	// A missing file is.
	if _, err := u.Check(t.Context(), srv.URL+"/missing.tar.gz"); err == nil || !strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "missing") {
		t.Errorf("missing = %v", err)
	}

	// The next start uses the kept update.
	detect.UsePacks(nil, nil, "")
	u2 := &Updater{Dir: dir, Keys: keys}
	u2.Start()
	if v, updated := detect.ContentVersion(); !updated || v != "20990101000000" {
		t.Errorf("after restart %s %v", v, updated)
	}
	// A kept bundle that was changed is not used.
	if err := os.WriteFile(filepath.Join(dir, bundleFile), old, 0o640); err != nil {
		t.Fatal(err)
	}
	detect.UsePacks(nil, nil, "")
	u3 := &Updater{Dir: dir, Keys: keys}
	u3.Start()
	if _, updated := detect.ContentVersion(); updated || u3.Status().LastError == "" {
		t.Errorf("changed bundle used: %+v", u3.Status())
	}

	// Removing goes back to the built-in rules.
	if st, err := u.Remove(); err != nil || st.Updated {
		t.Errorf("remove = %+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, bundleFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("bundle still there: %v", err)
	}
}

func TestLoadPacksSkipsRulesItCannotRead(t *testing.T) {
	priv, keys := testKey(t)
	head, _ := json.Marshal(Manifest{Format: Format, Version: "20990101000000"})
	pack := "name: demo\ntitle: Demo\nlicense: DRL-1.1\nrules:\n  - id: sigma-demo-ok\n    rule_id: 11111111-1111-1111-1111-111111111111\n    file: ok.yml\n  - id: sigma-demo-bad\n    rule_id: 22222222-2222-2222-2222-222222222222\n    file: bad.yml\n"
	ok, err := os.ReadFile(filepath.Join(packsDir, "sigmahq", "rules", "proc_creation_win_renamed_whoami.yml"))
	if err != nil {
		t.Fatal(err)
	}
	data, sig := raw(t, priv, map[string]string{
		"content.json":             string(head),
		"packs/demo/pack.yaml":     pack,
		"packs/demo/rules/ok.yml":  string(ok),
		"packs/demo/rules/bad.yml": "title: x\nlogsource:\n  category: something_new\ndetection:\n  sel:\n    Foo: bar\n  condition: sel\n",
	})
	b, err := Read(keys, data, sig)
	if err != nil {
		t.Fatal(err)
	}
	_, ds, skipped, err := detect.LoadPacks(b.FS)
	if err != nil || len(ds) != 1 || len(skipped) != 1 || !strings.Contains(skipped[0].Error(), "bad.yml") {
		t.Fatalf("LoadPacks = %d, %v, %v", len(ds), skipped, err)
	}
}
