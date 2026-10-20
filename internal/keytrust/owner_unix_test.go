// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package keytrust

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Run as root (sudo signalith content import-revocations), the kept list
// and its folder belong to whoever owns the state folder.
func TestKeptListOwnedLikeStateFolder(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	_, rootPriv := useRoot(t)
	state := t.TempDir()
	if err := os.Chown(state, 4321, 4322); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: filepath.Join(state, "keytrust")}
	data, sig := signedList(t, rootPriv, time.Now())
	if kept, err := s.Offer(data, sig); !kept || err != nil {
		t.Fatalf("offer: %v %v", kept, err)
	}
	for _, p := range []string{s.Dir, filepath.Join(s.Dir, keptFile)} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != 4321 || st.Gid != 4322 {
			t.Errorf("%s belongs to %d:%d, want 4321:4322", p, st.Uid, st.Gid)
		}
	}
}
