package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A new identity is made only while the server is stopped: the old
// node.id is moved aside, and the next start makes another one.
func TestReplaceIdentityWhileStopped(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLocal(dir, testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	old := l.Identity.NodeID
	ran := false
	if err := WhileStopped(dir, func() error { ran = true; return nil }); !errors.Is(err, ErrRunning) || ran {
		t.Fatalf("while running: %v (ran %v)", err, ran)
	}
	l.Close()
	var moved string
	err = WhileStopped(dir, func() error {
		var err error
		moved, err = ReplaceIdentity(dir, time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(moved) != nodeFile+".replaced-20261014T093000Z" {
		t.Errorf("moved to %s", moved)
	}
	if _, err := os.Stat(moved); err != nil {
		t.Fatal(err)
	}
	l, err = OpenLocal(dir, testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.Identity.NodeID == old {
		t.Error("the next start kept the old identity")
	}
}
