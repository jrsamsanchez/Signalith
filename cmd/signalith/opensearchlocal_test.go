// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/oslocal"
	"github.com/jrsamsanchez/signalith/internal/ospki"
)

// fakeOpenSearch stands in for the Windows service: start serves
// OpenSearch's security health check and cluster health over HTTPS with
// the node certificate, on the installed port.
type fakeOpenSearch struct {
	t         *testing.T
	l         oslocal.Layout
	installed string // the home the service runs
	srv       *http.Server
	// loaded is whether the security settings are loaded.
	loaded    atomic.Bool
	adminRuns int
	// stoppedYML is opensearch.yml as it was when the service was last
	// stopped.
	stoppedYML string
	// failHome is a program the service does not start with.
	failHome string
	// slow is how long the service takes to answer once started.
	slow time.Duration
}

func (f *fakeOpenSearch) prepare(l oslocal.Layout, home string) error {
	return os.MkdirAll(l.Data, 0o700)
}
func (f *fakeOpenSearch) exists() bool { return f.installed != "" }
func (f *fakeOpenSearch) stop() error {
	b, _ := os.ReadFile(filepath.Join(f.l.Config(), "opensearch.yml"))
	f.stoppedYML = string(b)
	if f.srv != nil {
		f.srv.Close()
		f.srv = nil
	}
	return nil
}
func (f *fakeOpenSearch) remove() error { f.installed = ""; return nil }
func (f *fakeOpenSearch) install(l oslocal.Layout, home string) error {
	f.installed = home
	return nil
}
func (f *fakeOpenSearch) memoryMB() uint64 { return 8192 }
func (f *fakeOpenSearch) securityAdmin(oslocal.Layout, string, int) error {
	f.adminRuns++
	f.loaded.Store(true)
	return nil
}

func (f *fakeOpenSearch) start() error {
	if f.srv != nil {
		return nil
	}
	if f.installed == f.failHome {
		return errors.New("the service stopped at once")
	}
	st, err := oslocal.LoadState(f.l)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(f.l.Certs(), ospki.NodeCertFile), filepath.Join(f.l.Certs(), ospki.NodeKeyFile))
	if err != nil {
		return err
	}
	caPEM, _ := os.ReadFile(filepath.Join(f.l.Certs(), ospki.RootCAFile))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	addr := "127.0.0.1:" + strconv.Itoa(st.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if f.slow > 0 {
		// Nothing answers until it has started.
		ln.Close()
	}
	f.srv = &http.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/_plugins/_security/health":
				if !f.loaded.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			case "/_cluster/health":
				if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != ospki.ClientName {
					w.WriteHeader(http.StatusUnauthorized)
				}
			}
		}),
	}
	srv := f.srv
	go func() {
		if f.slow > 0 {
			time.Sleep(f.slow)
			if ln, err = net.Listen("tcp", addr); err != nil {
				return
			}
		}
		srv.ServeTLS(ln, "", "")
	}()
	f.t.Cleanup(func() { f.stop() })
	return nil
}

// fakeRelease puts a release's files in the version's folder, as if it
// had been downloaded and unpacked.
func fakeRelease(t *testing.T, l oslocal.Layout, version string) {
	home := l.VersionHome(version)
	for name, body := range map[string]string{
		"bin/opensearch-service.bat":                    "",
		"config/jvm.options":                            "-Xms1g\n",
		"config/log4j2.properties":                      "status = error\n",
		"config/opensearch-security/internal_users.yml": "admin: demo\n",
	} {
		p := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(p, []byte(body), 0o644)
	}
}

// fakeUnpack makes the release in home in place of downloading it, and
// counts how many times it did.
func fakeUnpack(t *testing.T, l oslocal.Layout) *int {
	n := new(int)
	keep := unpackRelease
	unpackRelease = func(_ context.Context, _ io.Writer, _ oslocal.Layout, _ string, _ *http.Client, home string) error {
		*n++
		os.RemoveAll(home)
		fakeRelease(t, l, filepath.Base(home))
		return nil
	}
	t.Cleanup(func() { unpackRelease = keep })
	return n
}

func shortWaits(t *testing.T) {
	a, s, p, g := osAnswerWait, osSecurityWait, osPoll, osProgress
	osAnswerWait, osSecurityWait, osPoll, osProgress = 5*time.Second, 300*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { osAnswerWait, osSecurityWait, osPoll, osProgress = a, s, p, g })
}

func TestInstallOpenSearch(t *testing.T) {
	shortWaits(t)
	bits := ospki.KeyBits
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = bits })
	d := t.TempDir()
	l := oslocal.Layout{Home: filepath.Join(d, "home"), Data: filepath.Join(d, "data"), Client: filepath.Join(d, "signalith", "opensearch")}
	unpacked := fakeUnpack(t, l)
	// A program left in Home is not run: a new install unpacks the release.
	planted := filepath.Join(l.VersionHome(oslocal.Version), "bin", "planted")
	os.MkdirAll(filepath.Dir(planted), 0o755)
	os.WriteFile(planted, []byte("x"), 0o755)
	sys := &fakeOpenSearch{t: t, l: l}
	var out strings.Builder
	// OpenSearch does not load its security settings by itself: they are
	// loaded with its tool.
	if err := installOpenSearch(context.Background(), &out, sys, l, "", nil); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if sys.adminRuns != 1 || sys.installed != l.VersionHome(oslocal.Version) {
		t.Fatalf("securityadmin ran %d times, service runs %q", sys.adminRuns, sys.installed)
	}
	if _, err := os.Stat(planted); err == nil || *unpacked != 1 {
		t.Fatalf("a new install ran what was in Home (unpacked %d times)", *unpacked)
	}
	st, err := oslocal.LoadState(l)
	if err != nil || st == nil || st.Version != oslocal.Version {
		t.Fatalf("state %+v, %v", st, err)
	}
	yml, _ := os.ReadFile(filepath.Join(l.Config(), "opensearch.yml"))
	if !strings.Contains(string(yml), "http.port: "+strconv.Itoa(st.Port)) {
		t.Fatalf("opensearch.yml:\n%s", yml)
	}
	node, _ := os.ReadFile(filepath.Join(l.Certs(), ospki.NodeCertFile))

	// Run again (a repair or an upgrade of Signalith alone): kept as it is.
	sys.stop()
	out.Reset()
	if err := installOpenSearch(context.Background(), &out, sys, l, "", nil); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "is installed; checking it runs") {
		t.Fatalf("a second run did more than check:\n%s", out.String())
	}
	if again, _ := os.ReadFile(filepath.Join(l.Certs(), ospki.NodeCertFile)); string(again) != string(node) {
		t.Fatal("the certificates changed")
	}

	// An upgrade from an older OpenSearch: the new version's program, the
	// same port, data and certificates, and the old program removed.
	fakeRelease(t, l, "3.0.0")
	oslocal.SaveState(l, oslocal.State{Version: "3.0.0", Port: st.Port})
	sys.installed = l.VersionHome("3.0.0")
	os.RemoveAll(l.VersionHome(oslocal.Version))
	sys.stop()
	// It is stopped before its settings are written.
	yml = append(yml, "# before\n"...)
	os.WriteFile(filepath.Join(l.Config(), "opensearch.yml"), yml, 0o600)
	out.Reset()
	if err := installOpenSearch(context.Background(), &out, sys, l, "", nil); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(sys.stoppedYML, "# before") {
		t.Fatal("the settings were written while OpenSearch ran")
	}
	if b, _ := os.ReadFile(filepath.Join(l.Config(), "opensearch.yml")); strings.Contains(string(b), "# before") {
		t.Fatal("the settings were not written again")
	}
	if sys.installed != l.VersionHome(oslocal.Version) {
		t.Fatalf("the service runs %s after the upgrade", sys.installed)
	}
	if _, err := os.Stat(l.VersionHome("3.0.0")); err == nil {
		t.Fatal("the old version's program was kept")
	}
	if st2, _ := oslocal.LoadState(l); st2.Version != oslocal.Version || st2.Port != st.Port {
		t.Fatalf("state after the upgrade: %+v", st2)
	}

	// Remove keeps the data.
	if err := removeOpenSearch(io.Discard, sys, l); err != nil {
		t.Fatal(err)
	}
	if sys.exists() {
		t.Fatal("the service is still there")
	}
	if _, err := os.Stat(l.Home); err == nil {
		t.Fatal("the program is still there")
	}
	if _, err := os.Stat(filepath.Join(l.Certs(), ospki.NodeCertFile)); err != nil {
		t.Fatal("the data and certificates were not kept")
	}
}

// An upgrade whose new OpenSearch does not start goes back to the one that
// ran before, which is kept.
// A slow first start says it is still starting, rather than nothing.
func TestInstallOpenSearchSaysItIsStarting(t *testing.T) {
	shortWaits(t)
	bits := ospki.KeyBits
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = bits })
	d := t.TempDir()
	l := oslocal.Layout{Home: filepath.Join(d, "home"), Data: filepath.Join(d, "data"), Client: filepath.Join(d, "signalith", "opensearch")}
	fakeRelease(t, l, oslocal.Version)
	sys := &fakeOpenSearch{t: t, l: l, slow: time.Second}
	sys.loaded.Store(true)
	var out strings.Builder
	if err := installOpenSearch(context.Background(), &out, sys, l, "", nil); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if strings.Count(out.String(), "Waiting for OpenSearch to answer") != 1 || !strings.Contains(out.String(), "  still starting (") {
		t.Fatalf("no word while it starts:\n%s", out.String())
	}
}

func TestInstallOpenSearchGoesBack(t *testing.T) {
	shortWaits(t)
	bits := ospki.KeyBits
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = bits })
	d := t.TempDir()
	l := oslocal.Layout{Home: filepath.Join(d, "home"), Data: filepath.Join(d, "data"), Client: filepath.Join(d, "client")}
	fakeRelease(t, l, "3.0.0")
	fakeRelease(t, l, oslocal.Version)
	sys := &fakeOpenSearch{t: t, l: l, failHome: l.VersionHome(oslocal.Version)}
	sys.loaded.Store(true)
	os.MkdirAll(l.Data, 0o700)
	if err := oslocal.MakeCerts(l, time.Now()); err != nil {
		t.Fatal(err)
	}
	port, err := oslocal.FreePort(oslocal.FirstPort)
	if err != nil {
		t.Skip(err)
	}
	oslocal.SaveState(l, oslocal.State{Version: "3.0.0", Port: port})
	sys.installed = l.VersionHome("3.0.0")
	var out strings.Builder
	err = installOpenSearch(context.Background(), &out, sys, l, "", nil)
	if err == nil || !strings.Contains(err.Error(), "OpenSearch 3.0.0 runs again") {
		t.Fatalf("got %v\n%s", err, out.String())
	}
	if sys.installed != l.VersionHome("3.0.0") || sys.srv == nil {
		t.Fatalf("the service runs %q (started: %v), want 3.0.0", sys.installed, sys.srv != nil)
	}
	if st, _ := oslocal.LoadState(l); st.Version != "3.0.0" || st.Port != port {
		t.Fatalf("state %+v", st)
	}
	if _, err := os.Stat(filepath.Join(l.VersionHome("3.0.0"), "bin")); err != nil {
		t.Fatal("the old program was removed")
	}
}

func TestInstallOpenSearchRefusesFolderNotItsOwn(t *testing.T) {
	d := t.TempDir()
	l := oslocal.Layout{Home: filepath.Join(d, "home"), Data: filepath.Join(d, "data"), Client: filepath.Join(d, "client")}
	os.MkdirAll(l.Data, 0o700)
	os.WriteFile(filepath.Join(l.Data, "planted.yml"), []byte("x"), 0o600)
	err := installOpenSearch(context.Background(), io.Discard, &fakeOpenSearch{t: t, l: l}, l, "", nil)
	if err == nil || !strings.Contains(err.Error(), "already has files") {
		t.Fatalf("got %v", err)
	}
}

// An upgrade from an install made before the installer set up OpenSearch:
// the config's OpenSearch is set up only when it is the old default,
// untouched, and nothing answers there.
func TestAdoptOpenSearch(t *testing.T) {
	shortWaits(t)
	bits := ospki.KeyBits
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = bits })
	d := t.TempDir()
	path := filepath.Join(d, "signalith", "signalith.yaml")
	os.MkdirAll(filepath.Dir(path), 0o700)
	captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-opensearch", "http://127.0.0.1:9200", "-admin-password", "first-password"}); err != nil {
			t.Fatal(err)
		}
	})
	load := func() *config.Config {
		c, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	l := oslocal.Layout{Home: filepath.Join(d, "home"), Data: filepath.Join(d, "data"), Client: filepath.Join(d, "signalith", "opensearch")}
	fakeUnpack(t, l)
	sys := &fakeOpenSearch{t: t, l: l}
	nothing := func(string) bool { return false }

	// Kept: something answers there, or the config has more than the
	// old default address.
	for name, c := range map[string]struct {
		url     string
		answers bool
	}{
		"answers":   {"http://127.0.0.1:9200", true},
		"https":     {"https://127.0.0.1:9200", false},
		"elsewhere": {"http://search.example.com:9200", false},
	} {
		cfg := load()
		cfg.OpenSearch.URL = c.url
		var out strings.Builder
		if err := adoptOpenSearch(context.Background(), &out, sys, l, "", nil, path, cfg, func(string) bool { return c.answers }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(out.String(), "Keeping the OpenSearch") || sys.installed != "" {
			t.Fatalf("%s: %s", name, out.String())
		}
	}
	cfg := load()
	cfg.OpenSearch.Username = "admin"
	if why := openSearchInUse(cfg, nothing); why == "" {
		t.Fatal("a config with a username was taken for the old default")
	}

	// Set up: the old default, with nothing there.
	var out strings.Builder
	if err := adoptOpenSearch(context.Background(), &out, sys, l, "", nil, path, load(), nothing); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	st, err := oslocal.LoadState(l)
	if err != nil || st == nil {
		t.Fatalf("not installed: %v\n%s", err, out.String())
	}
	got := load().OpenSearch
	ca, cert, key := l.ClientFiles()
	if got.URL != st.URL() || got.CAFile != ca || got.CertFile != cert || got.KeyFile != key {
		t.Fatalf("config after adopting: %+v", got)
	}
	if !load().CheckPassword("signalithadmin", "first-password") {
		t.Fatal("the rest of the config changed")
	}
	// A stopped OpenSearch of the user's can still start on 9200, and the
	// config as it was is kept to go back to.
	if st.Port == oslocal.FirstPort {
		t.Fatalf("took port %d", st.Port)
	}
	if before, err := config.Load(path + ".before-opensearch"); err != nil || before.OpenSearch.URL != "http://127.0.0.1:9200" {
		t.Fatalf("the config before: %v", err)
	}

	// Again (a repair): nothing more to do.
	out.Reset()
	if err := adoptOpenSearch(context.Background(), &out, sys, l, "", nil, path, load(), nothing); err != nil || out.Len() != 0 {
		t.Fatalf("%v\n%s", err, out.String())
	}
}
