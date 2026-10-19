package oslocal

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

func TestPin(t *testing.T) {
	if !regexp.MustCompile(`^[0-9a-f]{128}$`).MatchString(SHA512) || SHA512 == strings.Repeat("0", 128) {
		t.Fatalf("SHA512 must be 128 lower-case hex digits, got %q", SHA512)
	}
	if !versionRE.MatchString(Version) || !strings.Contains(URL(), "/"+Version+"/opensearch-"+Version+"-windows-x64.zip") {
		t.Fatalf("Version %q, URL %q", Version, URL())
	}
}

func makeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		if strings.HasSuffix(name, "/") {
			if _, err := w.Create(name); err != nil {
				t.Fatal(err)
			}
			continue
		}
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(f, body)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "os.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtract(t *testing.T) {
	z := makeZip(t, map[string]string{
		"opensearch-3.9.0/":                        "",
		"opensearch-3.9.0/bin/opensearch.bat":      "@echo off",
		"opensearch-3.9.0/config/jvm.options":      "-Xms1g",
		"opensearch-3.9.0/jdk/bin/java.exe":        "java",
		"opensearch-3.9.0/plugins/sec/plugin.prop": "x",
	})
	dest := filepath.Join(t.TempDir(), "3.9.0")
	if err := Extract(z, dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "config", "jvm.options"))
	if err != nil || string(b) != "-Xms1g" {
		t.Fatalf("got %q, %v", b, err)
	}
	if err := Extract(z, dest); err == nil {
		t.Fatal("extracting over an existing folder worked")
	}
}

func TestExtractRefusesEscapes(t *testing.T) {
	for _, name := range []string{
		"opensearch-3.9.0/../evil.txt",
		"opensearch-3.9.0/bin/../../evil.txt",
		"opensearch-3.9.0/C:/evil.txt",
		"other/file.txt",
	} {
		z := makeZip(t, map[string]string{"opensearch-3.9.0/bin/ok": "ok", name: "x"})
		parent := t.TempDir()
		dest := filepath.Join(parent, "3.9.0")
		if err := Extract(z, dest); err == nil {
			t.Errorf("%s: extracted", name)
		}
		if _, err := os.Stat(filepath.Join(parent, "evil.txt")); err == nil {
			t.Errorf("%s: wrote outside the folder", name)
		}
		if _, err := os.Stat(dest); err == nil {
			t.Errorf("%s: left %s", name, dest)
		}
	}
}

// The release is checked and unpacked in a folder OpenSearch's service
// cannot change, so it cannot swap the file between the two.
func TestDownloadIsNotTheServices(t *testing.T) {
	l := DefaultLayout()
	for _, d := range l.ServiceFolders() {
		if rel, err := filepath.Rel(d, l.Download()); err == nil && filepath.IsLocal(rel) {
			t.Errorf("the download folder %s is in %s, which the service may change", l.Download(), d)
		}
	}
	if filepath.Dir(l.Download()) != l.Data {
		t.Errorf("the download folder %s is not in %s", l.Download(), l.Data)
	}
}

func setPin(t *testing.T, sum string) {
	old := pinned
	pinned = sum
	t.Cleanup(func() { pinned = old })
}

func TestFetchLocal(t *testing.T) {
	z := makeZip(t, map[string]string{"opensearch-3.9.0/bin/x": "x"})
	b, _ := os.ReadFile(z)
	sum := sha512.Sum512(b)
	setPin(t, hex.EncodeToString(sum[:]))
	dir := filepath.Join(t.TempDir(), "download")
	got, err := Fetch(context.Background(), z, dir, io.Discard)
	if err != nil || filepath.Dir(got) != dir {
		t.Fatalf("Fetch = %q, %v: want a copy in %s", got, err, dir)
	}
	if c, _ := os.ReadFile(got); !bytes.Equal(c, b) {
		t.Fatal("the copy differs from the file")
	}
	os.Remove(got)
	setPin(t, strings.Repeat("0", 128))
	if _, err := Fetch(context.Background(), z, dir, io.Discard); err == nil || !strings.Contains(err.Error(), hex.EncodeToString(sum[:])) {
		t.Fatalf("a file with another SHA-512 was taken, or the error does not name its SHA-512: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("the refused copy was left in %s", dir)
	}
}

func TestDownload(t *testing.T) {
	body := []byte("the release")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	sum := sha512.Sum512(body)
	dir := t.TempDir()

	setPin(t, hex.EncodeToString(sum[:]))
	got, err := download(context.Background(), srv.URL, dir, io.Discard, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(got); !bytes.Equal(b, body) {
		t.Fatalf("downloaded %q", b)
	}
	os.Remove(got)

	setPin(t, strings.Repeat("0", 128))
	if _, err := download(context.Background(), srv.URL, dir, io.Discard, srv.Client()); err == nil {
		t.Fatal("a download with another SHA-512 was taken")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("the refused download was left in %s", dir)
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"3.9.0", "3.8.1", true}, {"3.10.0", "3.9.0", true}, {"3.9.0", "3.9.0", false}, {"2.17.1", "3.9.0", false}} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestHeapMB(t *testing.T) {
	for total, want := range map[uint64]int{2048: 1024, 8192: 2048, 16384: 4096, 65536: 8192} {
		if got := HeapMB(total); got != want {
			t.Errorf("HeapMB(%d) = %d, want %d", total, got, want)
		}
	}
}

func TestFreePort(t *testing.T) {
	p, err := FreePort()
	if err != nil {
		t.Skip(err)
	}
	if p < FirstPort || p >= FirstPort+10 {
		t.Fatalf("port %d", p)
	}
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
	if err != nil {
		t.Fatalf("FreePort gave %d, which is taken: %v", p, err)
	}
	l.Close()
}

func testLayout(t *testing.T) Layout {
	d := t.TempDir()
	return Layout{Home: filepath.Join(d, "home"), Data: filepath.Join(d, "data"), Client: filepath.Join(d, "signalith", "opensearch")}
}

// releaseJVM is the part of OpenSearch's jvm.options with paths in it.
const releaseJVM = "-XX:+HeapDumpOnOutOfMemoryError\r\n-XX:HeapDumpPath=data\r\n-XX:ErrorFile=logs/hs_err_pid%p.log\r\n" +
	"8:-Xloggc:logs/gc.log\r\n9-:-Xlog:gc*,gc+age=trace,safepoint:file=logs/gc.log:utctime,pid,tags:filecount=32,filesize=64m\r\n" +
	"-Djava.io.tmpdir=${OPENSEARCH_TMPDIR}\r\n"

func TestStateAndConfig(t *testing.T) {
	l := testLayout(t)
	if st, err := LoadState(l); st != nil || err != nil {
		t.Fatalf("LoadState with none = %v, %v", st, err)
	}
	os.MkdirAll(l.Data, 0o700)
	if err := SaveState(l, State{Version: "3.9.0", Port: 9201}); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(l)
	if err != nil || st.Version != "3.9.0" || st.URL() != "https://127.0.0.1:9201" {
		t.Fatalf("LoadState = %+v, %v", st, err)
	}

	home := l.VersionHome("3.9.0")
	for name, body := range map[string]string{
		"config/jvm.options":                            releaseJVM,
		"config/log4j2.properties":                      "status = error\n",
		"config/opensearch-security/action_groups.yml":  "_meta: {}\n",
		"config/opensearch-security/internal_users.yml": "admin: demo\n",
	} {
		p := filepath.Join(home, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	bits := ospki.KeyBits
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = bits })
	if err := MakeCerts(l, time.Now()); err != nil {
		t.Fatal(err)
	}
	node, _ := os.ReadFile(filepath.Join(l.Certs(), ospki.NodeCertFile))
	if err := MakeCerts(l, time.Now()); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(l.Certs(), ospki.NodeCertFile)); !bytes.Equal(node, again) {
		t.Fatal("a second run made new certificates")
	}
	for _, f := range []string{filepath.Join(l.CA(), ospki.RootCAKeyFile), filepath.Join(l.CA(), ospki.AdminCertFile), filepath.Join(l.CA(), ospki.AdminKeyFile)} {
		if _, err := os.Stat(f); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(l.Certs(), ospki.AdminKeyFile)); err == nil {
		t.Fatal("the admin key is in OpenSearch's folder")
	}
	if _, err := os.Stat(filepath.Join(l.Certs(), ospki.RootCAKeyFile)); err == nil {
		t.Fatal("the CA's key is in OpenSearch's folder")
	}
	ca, cert, key := l.ClientFiles()
	for _, f := range []string{ca, cert, key} {
		if _, err := os.Stat(f); err != nil {
			t.Fatal(err)
		}
	}

	planted := filepath.Join(l.Config(), "jvm.options.d", "planted.options")
	os.MkdirAll(filepath.Dir(planted), 0o700)
	os.WriteFile(planted, []byte("-javaagent:x.jar\n"), 0o600)
	if err := WriteConfig(l, home, 9201, 2048); err != nil {
		t.Fatal(err)
	}
	yml, _ := os.ReadFile(filepath.Join(l.Config(), "opensearch.yml"))
	for _, want := range []string{"network.host: 127.0.0.1", "http.port: 9201", "discovery.type: single-node",
		"plugins.security.allow_unsafe_democertificates: false", "plugins.security.ssl.http.enabled: true", "path.data: '" + l.DataDir() + "'"} {
		if !strings.Contains(string(yml), want) {
			t.Errorf("opensearch.yml lacks %q:\n%s", want, yml)
		}
	}
	if strings.Contains(string(yml), "compliance") {
		t.Error("compliance settings belong in audit.yml, not opensearch.yml")
	}
	users, _ := os.ReadFile(filepath.Join(l.Security(), "internal_users.yml"))
	if strings.Contains(string(users), "admin: demo") {
		t.Errorf("the release's demo users were kept: %s", users)
	}
	if _, err := os.Stat(filepath.Join(l.Security(), "action_groups.yml")); err != nil {
		t.Error("the release's other security files were not copied")
	}
	jvm, _ := os.ReadFile(filepath.Join(l.Config(), "jvm.options"))
	for _, want := range []string{"-XX:+HeapDumpOnOutOfMemoryError\n", "-XX:HeapDumpPath=" + l.DataDir() + "\n",
		"-XX:ErrorFile=" + filepath.Join(l.Logs(), "hs_err_pid%p.log") + "\n", "-Djava.io.tmpdir=${OPENSEARCH_TMPDIR}\n"} {
		if !strings.Contains(string(jvm), want) {
			t.Errorf("jvm.options lacks %q:\n%s", want, jvm)
		}
	}
	if strings.Contains(string(jvm), "=logs/") || strings.Contains(string(jvm), "gc.log") || strings.Contains(string(jvm), "\r") {
		t.Errorf("jvm.options has a relative path or a CR:\n%s", jvm)
	}
	if _, err := os.Stat(planted); err == nil {
		t.Error("an options file Signalith did not write was kept")
	}
	heap, _ := os.ReadFile(filepath.Join(l.Config(), "jvm.options.d", "heap.options"))
	if !strings.Contains(string(heap), "-Xmx2048m") {
		t.Errorf("heap.options: %s", heap)
	}
}
