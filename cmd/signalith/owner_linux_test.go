//go:build linux

package main

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// recordGive is a change for giveTree that records the paths.
func recordGive(got *[]string) func(int, string, int, int) error {
	return func(_ int, p string, _, _ int) error {
		*got = append(*got, p)
		return nil
	}
}

func TestGiveTreeOnlyWhatJoinMade(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	_ = os.MkdirAll(filepath.Join(a, "b"), 0o700)
	_ = os.WriteFile(filepath.Join(a, "b", "f"), nil, 0o600)
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "secret"), nil, 0o600)
	// A link to a folder outside, a link to a file outside, and a second
	// name of a file outside: none is followed or changed.
	_ = os.Symlink(outside, filepath.Join(a, "dirlink"))
	_ = os.Symlink(filepath.Join(outside, "secret"), filepath.Join(a, "filelink"))
	if err := os.Link(filepath.Join(outside, "secret"), filepath.Join(a, "hardlink")); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := giveTree(a, 4242, 4343, recordGive(&got)); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(a, "b", "f"), filepath.Join(a, "b"), a}
	if !slices.Equal(got, want) {
		t.Errorf("gave %v, want %v (what is in a folder before the folder)", got, want)
	}
	got = nil
	if err := giveTree(filepath.Join(dir, "missing"), 1, 2, recordGive(&got)); err != nil || len(got) != 0 {
		t.Errorf("a missing path: %v %v", got, err)
	}
	// A single file.
	if err := giveTree(filepath.Join(a, "b", "f"), 1, 2, recordGive(&got)); err != nil || len(got) != 1 {
		t.Errorf("one file: %v %v", got, err)
	}
}

func TestGiveTreeRefusesLinksOthersCanMake(t *testing.T) {
	if os.Geteuid() == 0 {
		// Root's own temporary folders are root's: the link would be
		// followed, as one in /etc is.
		t.Skip("the folders here are root's")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	_ = os.MkdirAll(real, 0o700)
	_ = os.WriteFile(filepath.Join(real, "f"), nil, 0o600)
	_ = os.Symlink(real, filepath.Join(dir, "swapped"))
	var got []string
	if err := giveTree(filepath.Join(dir, "swapped", "f"), 1, 2, recordGive(&got)); err == nil || len(got) != 0 {
		t.Errorf("followed a link in a folder others than root can write: %v %v", got, err)
	}
}

func TestGiveTreeAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing owners needs root")
	}
	dir := t.TempDir()
	// The service's account could write in dir: a link it swapped in is
	// not followed further down.
	if err := os.Chown(dir, 4242, 4343); err != nil {
		t.Fatal(err)
	}
	made := filepath.Join(dir, "made")
	_ = os.MkdirAll(filepath.Join(made, "sub"), 0o700)
	_ = os.WriteFile(filepath.Join(made, "sub", "key.pem"), []byte("k"), 0o600)
	// The service's own file stays its own; another user's stays theirs.
	_ = os.WriteFile(filepath.Join(made, "theirs"), nil, 0o600)
	_ = os.Chown(filepath.Join(made, "theirs"), 5555, 5555)
	outside := t.TempDir()
	victim := filepath.Join(outside, "shadow")
	_ = os.WriteFile(victim, nil, 0o600)
	_ = os.Symlink(victim, filepath.Join(made, "shadow"))
	_ = os.Symlink(outside, filepath.Join(dir, "swapped"))

	if err := giveTree(made, 4242, 4343, chownFD); err != nil {
		t.Fatal(err)
	}
	owner := func(p string) [2]int {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		return [2]int{int(st.Uid), int(st.Gid)}
	}
	for _, p := range []string{made, filepath.Join(made, "sub"), filepath.Join(made, "sub", "key.pem")} {
		if got := owner(p); got != [2]int{4242, 4343} {
			t.Errorf("%s is %v", p, got)
		}
	}
	if got := owner(filepath.Join(made, "theirs")); got != [2]int{5555, 5555} {
		t.Errorf("another user's file became %v", got)
	}
	if got := owner(victim); got != [2]int{0, 0} {
		t.Errorf("the file a link points to became %v", got)
	}
	if err := giveTree(filepath.Join(dir, "swapped", "shadow"), 4242, 4343, chownFD); err == nil {
		t.Error("followed a link in a folder the service's account can write")
	}
	if got := owner(victim); got != [2]int{0, 0} {
		t.Errorf("the file behind a swapped folder became %v", got)
	}
}
