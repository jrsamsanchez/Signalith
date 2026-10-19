package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// node.id read while the server runs: missing, damaged and good.
func TestReadIdentity(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadIdentity(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("before the first start: %v", err)
	}
	if got, want := IdentityPath(dir), filepath.Join(dir, nodeFile); got != want {
		t.Errorf("identity path %s, want %s", got, want)
	}
	l, err := OpenLocal(dir, testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	id, err := ReadIdentity(dir)
	if err != nil || id.NodeID != l.Identity.NodeID || id.Name != "siem-a" {
		t.Errorf("identity %+v %v", id, err)
	}
	for _, body := range []string{"{nope", `{"node_id":"x_1"}`} {
		if err := os.WriteFile(IdentityPath(dir), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadIdentity(dir); err == nil || !strings.Contains(err.Error(), "damaged") {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// A state folder that cannot be made, and an identity that cannot be
// read, are refused; the computer's own name and id are used by default.
func TestOpenLocalRefusals(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(file, testOptions("siem-a")); err == nil || !strings.Contains(err.Error(), "could not make the state folder") {
		t.Errorf("a file as the state folder: %v", err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(IdentityPath(dir), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(dir, testOptions("siem-a")); err == nil || !strings.Contains(err.Error(), "could not read this server's identity") {
		t.Errorf("node.id a folder: %v", err)
	}
	// The lock was let go: the folder opens once node.id is fixed.
	if err := os.Remove(IdentityPath(dir)); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLocal(dir, LocalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.Identity.Name == "" || !strings.HasPrefix(l.Identity.NodeID, "n_") {
		t.Errorf("default identity %+v", l.Identity)
	}
	if w, err := CheckFolder(dir); err != nil {
		t.Errorf("a local folder: %v %v", w, err)
	}
}

// Host names that cannot be server names.
func TestHostNameFallbacks(t *testing.T) {
	for name, o := range map[string]LocalOptions{
		"no name":   {Hostname: func() (string, error) { return "", errors.New("no name") }},
		"only dots": {Hostname: func() (string, error) { return "...", nil }},
	} {
		if got := hostName(o); got != "signalith-1" {
			t.Errorf("%s: %q", name, got)
		}
	}
	long := strings.Repeat("a", 70) + " b"
	got := hostName(LocalOptions{Hostname: func() (string, error) { return long, nil }})
	if len(got) != 63 || strings.Trim(got, "a") != "" {
		t.Errorf("a long name: %q", got)
	}
}

// WhileStopped refuses while a server runs, and runs fn on a folder no
// server has used yet; ReplaceIdentity needs an identity.
func TestWhileStoppedRefusals(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLocal(dir, testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := WhileStopped(dir, func() error { ran = true; return nil }); !errors.Is(err, ErrRunning) || ran {
		t.Errorf("while running: %v ran %v", err, ran)
	}
	l.Close()
	fresh := t.TempDir()
	if err := WhileStopped(fresh, func() error { ran = true; return nil }); err != nil || !ran {
		t.Errorf("a new folder: %v ran %v", err, ran)
	}
	if _, err := ReplaceIdentity(fresh, time.Now()); err == nil {
		t.Error("replaced an identity there is not")
	}
}

// Every part of the fingerprints is named when it differs, and an
// older server that keeps in its files what the cluster shares is said
// to.
func TestFingerprintsDifferInWords(t *testing.T) {
	f := Fingerprints{Retention: "r", Feeds: "f", Detections: "d", Notify: "n", Playbooks: "p", Ticketing: "t", Archives: "a"}
	g := Fingerprints{Retention: SharedFingerprint("c1"), Feeds: "f2", Detections: "d2", Notify: "n2", Playbooks: "p2", Ticketing: "t2", Archives: "a2"}
	want := []string{
		"retention policies (one server keeps them in its own files: an older version, or not part of the cluster yet)",
		"threat intel feeds", "detections folder", "notification channels", "playbooks", "ticketing connections", "archive folder",
	}
	if got := f.Differ(g); !slices.Equal(got, want) {
		t.Errorf("differ %q", got)
	}
	if d := f.Differ(f); len(d) != 0 {
		t.Errorf("the same: %v", d)
	}
	if f.Combined() == (Fingerprints{Retention: "r", Feeds: "f", Detections: "d", Notify: "n", Playbooks: "p", Archives: "a"}).Combined() {
		t.Error("ticketing does not count")
	}
	h := sha256.Sum256([]byte("a\x00b\x00"))
	if got := Hash([]byte("a"), []byte("b")); got != "sha256:"+hex.EncodeToString(h[:]) {
		t.Errorf("hash %s", got)
	}
	for v, ok := range map[string]bool{"1.2.3": true, "2.0": true, "dev": false, "abc1234": false} {
		if ReadableVersion(v) != ok {
			t.Errorf("ReadableVersion(%q) != %v", v, ok)
		}
	}
}

// The runtime index is made when missing, for what is kept there before
// any server ran.
func TestEnsureRuntime(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	ctx := context.Background()
	if err := EnsureRuntime(ctx, c, "s"); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRuntime(ctx, c, "s"); err != nil {
		t.Errorf("again: %v", err)
	}
	if NodeDocID("n_1") != nodeDocID("n_1") || !strings.Contains(NodeDocID("n_1"), "n_1") {
		t.Errorf("node doc id %s", NodeDocID("n_1"))
	}
}
