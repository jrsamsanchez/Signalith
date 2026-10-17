package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

func TestDetPrints(t *testing.T) {
	p := newDetPrints()
	calls := 0
	p.set("acme", func() string { calls++; return "fp1" }, nil)
	if got := p.all(); got["acme"] != "fp1" || calls != 1 {
		t.Fatalf("%v, %d calls", got, calls)
	}
	p.all()
	if calls != 1 {
		t.Error("the files were hashed again within a minute")
	}
	old := p.set("acme", func() string { return "fp1" }, nil)
	p.set("acme", func() string { return "fp2" }, nil)
	p.drop("acme", old)
	if got := p.all(); got["acme"] != "fp2" {
		t.Errorf("an earlier start's drop took the new start's fingerprint: %v", got)
	}
}

// TestFingerprintOnlyWhileFollowing: a tenant's fingerprint is in the
// heartbeat only while this server follows its assignment, so a server
// whose follower never started (its indices could not be made) or has
// stopped is given none of its buckets: the job holder leaves servers
// without the tenant's fingerprint out (detect.TestAssignerLeavesOut).
func TestFingerprintOnlyWhileFollowing(t *testing.T) {
	p := newDetPrints()
	ds := &detSpread{tenant: "acme", prints: p, files: func() string { return "fp" }}
	if _, ok := p.all()["acme"]; ok {
		t.Fatal("a fingerprint before the follower started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var jobs sync.WaitGroup
	ds.publish(ctx, &jobs)
	if p.all()["acme"] != "fp" {
		t.Fatal("no fingerprint while following")
	}
	cancel()
	jobs.Wait()
	if _, ok := p.all()["acme"]; ok {
		t.Error("a fingerprint after the follower stopped")
	}
}

// TestFilesHash: line ends and byte order marks do not change it; a
// changed or added file does.
func TestFilesHash(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	write := func(dir, name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(a, "hosts.csv", "host,owner\nweb1,ops\n")
	write(b, "hosts.csv", "\ufeffhost,owner\r\nweb1,ops\r\n")
	if filesHash(a) != filesHash(b) {
		t.Error("line ends change the fingerprint")
	}
	write(b, "users.csv", "user\n")
	if filesHash(a) == filesHash(b) {
		t.Error("an added file does not change the fingerprint")
	}
	if filesHash(filepath.Join(a, "missing")) == filesHash(a) {
		t.Error("a missing folder fingerprints as the files")
	}
}

func TestDetViews(t *testing.T) {
	v := newDetViews()
	ctx, cancel := context.WithCancel(context.Background())
	var jobs sync.WaitGroup
	read := func(tenant string, n int) func(context.Context) (detect.SpreadView, error) {
		return func(context.Context) (detect.SpreadView, error) {
			sv := detect.SpreadView{Tenant: tenant, Buckets: detect.Buckets, Servers: map[string]detect.SpreadCount{}}
			if n > 0 {
				sv.Servers["a"] = detect.SpreadCount{Run: n}
			}
			return sv, nil
		}
	}
	v.add(ctx, &jobs, "zeta", read("zeta", 4))
	v.add(ctx, &jobs, "acme", read("acme", 64))
	v.add(ctx, &jobs, "idle", read("idle", 0))
	got := v.all(context.Background())
	if len(got) != 2 || got[0].Tenant != "acme" || got[1].Tenant != "zeta" {
		t.Errorf("%+v", got)
	}
	cancel()
	jobs.Wait()
	if got := v.all(context.Background()); len(got) != 0 {
		t.Errorf("views after the tenants stopped: %+v", got)
	}
}
