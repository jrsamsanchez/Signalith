package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetPrints(t *testing.T) {
	p := newDetPrints()
	calls := 0
	p.set("acme", func() string { calls++; return "fp1" })
	if got := p.all(); got["acme"] != "fp1" || calls != 1 {
		t.Fatalf("%v, %d calls", got, calls)
	}
	p.all()
	if calls != 1 {
		t.Error("the files were hashed again within a minute")
	}
	p.drop("acme")
	if got := p.all(); len(got) != 0 {
		t.Errorf("a stopped tenant still has a fingerprint: %v", got)
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
