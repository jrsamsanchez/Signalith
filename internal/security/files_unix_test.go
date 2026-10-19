// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProbePermUnix(t *testing.T) {
	dir := t.TempDir()
	me := Account{UID: os.Getuid(), GID: os.Getgid()}
	for _, tc := range []struct {
		mode os.FileMode
		acct Account
		want Perm
	}{
		{0o600, me, Perm{}},
		{0o640, me, Perm{}}, // its own group
		{0o644, me, Perm{OtherRead: true}},
		{0o666, me, Perm{OtherRead: true, OtherWrite: true}},
		{0o640, Account{UID: me.UID, GID: me.GID + 1}, Perm{GroupRead: true}},
		{0o660, Account{UID: me.UID, GID: -1}, Perm{GroupRead: true, GroupWrite: true}},
	} {
		file := filepath.Join(dir, "f")
		os.Remove(file)
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, tc.mode); err != nil {
			t.Fatal(err)
		}
		p, err := probePerm(file, tc.acct)
		if err != nil {
			t.Fatal(err)
		}
		if p.OtherRead != tc.want.OtherRead || p.OtherWrite != tc.want.OtherWrite ||
			p.GroupRead != tc.want.GroupRead || p.GroupWrite != tc.want.GroupWrite || p.WrongOwner {
			t.Errorf("%o %+v: %+v", tc.mode, tc.acct, p)
		}
		if p.Owner == "" || p.Group == "" {
			t.Errorf("no owner or group: %+v", p)
		}
	}
	// Owned by an account that is neither Signalith's nor root.
	if os.Getuid() != 0 {
		p, err := probePerm(filepath.Join(dir, "f"), Account{UID: os.Getuid() + 1, GID: -1})
		if err != nil || !p.WrongOwner {
			t.Errorf("wrong owner: %+v %v", p, err)
		}
	}
	if _, err := probePerm(filepath.Join(dir, "none"), me); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
}

// A link's own mode is always 0777: what counts is the file it points to.
func TestProbePermFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	me := Account{UID: os.Getuid(), GID: os.Getgid()}
	target := filepath.Join(dir, "master.key")
	link := filepath.Join(dir, "link.key")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	p, err := probePerm(link, me)
	if err != nil || p.OtherRead || p.OtherWrite || p.GroupRead || p.GroupWrite {
		t.Errorf("private file behind a link: %+v %v", p, err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if p, err := probePerm(link, me); err != nil || !p.OtherRead {
		t.Errorf("readable file behind a link: %+v %v", p, err)
	}
}
