// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

// A folder Signalith may not look into: the disk under it can still be
// told when no mount point lies inside it and it isn't a memory
// filesystem standing in for a folder kept from the service.
func TestOnlyMountAbove(t *testing.T) {
	plain := parseMountinfo("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		"30 22 8:2 / /var rw - ext4 /dev/sda2 rw\n")
	if !onlyMountAbove(plain, "/var/lib/opensearch/data", "/var/lib/opensearch") {
		t.Error("a folder on /var")
	}
	inside := append(plain, parseMountinfo("40 30 253:0 / /var/lib/opensearch/data rw - xfs /dev/mapper/os rw\n")...)
	if onlyMountAbove(inside, "/var/lib/opensearch/data", "/var/lib/opensearch") {
		t.Error("a disk mounted inside the hidden folder")
	}
	// ProtectHome=yes: an empty, unreadable tmpfs over /home.
	home := append(plain, parseMountinfo("50 22 0:60 / /home ro - tmpfs tmpfs ro,mode=000\n")...)
	if onlyMountAbove(home, "/home/os/data", "/home") {
		t.Error("a memory filesystem standing in for /home")
	}
}

// Two mounts of one disk count once; filesystems without a device number
// go by their source.
func TestDiskKey(t *testing.T) {
	mounts := parseMountinfo("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		"30 22 8:1 /var/lib/signalith /var/lib/signalith rw - ext4 /dev/sda1 rw\n" +
		"31 22 0:45 /@data /data rw - btrfs /dev/sdb1 rw\n" +
		"32 22 0:46 /@logs /logs rw - btrfs /dev/sdb1 rw\n" +
		"33 22 0:47 / /mnt/share rw - nfs4 nas:/export rw\n")
	if diskKey(mounts, "/var/lib/signalith/keys") != diskKey(mounts, "/etc/signalith") {
		t.Error("one device, two mounts")
	}
	if diskKey(mounts, "/data/x") != diskKey(mounts, "/logs/y") {
		t.Error("one btrfs filesystem, two subvolumes")
	}
	if diskKey(mounts, "/mnt/share/a") == diskKey(mounts, "/data/x") {
		t.Error("a share and a disk")
	}
	if diskKey(nil, "/a") == diskKey(nil, "/b") {
		t.Error("no mounts: each path on its own")
	}
}
