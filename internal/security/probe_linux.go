// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package security

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// hostFS is the real /proc and /sys.
var hostFS sysFS = osFS{root: "/"}

// probeProcess reads how the server's process runs: this process when
// self, else process pid (the CLI, about the running service). systemd
// says whether it runs under systemd.
func probeProcess(pid string, self, systemd bool) (ProcessFacts, MemoryFacts, string) {
	var p ProcessFacts
	var m MemoryFacts
	cvm := confidentialVM(hostFS)
	if pid == "" {
		p.Why = NoServiceLine
		return p, m, cvm
	}
	if self {
		pid = "self"
	}
	if err := readProcess(hostFS, pid, &p); err != nil {
		p.Known = false
		if os.IsPermission(err) {
			p.Why = DeniedLine("linux")
		} else {
			p.Why = "Signalith couldn't read how its process runs."
		}
		return p, m, cvm
	}
	p.Systemd = systemd
	p.NoHiddenProc = !kernelAtLeast(5, 8)
	if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
		p.UserName = u.Username
	}
	m.Known = true
	if self {
		var lim unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err == nil {
			m.CoreOff = lim.Cur == 0
		}
		if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err == nil {
			m.NotDumpable = d == 0
		}
	} else {
		off, known := coreLimitOff(hostFS, pid)
		m.CoreOff, m.Known = off, known
		owner := -1
		var st unix.Stat_t
		if err := unix.Stat("/proc/"+pid+"/status", &st); err == nil {
			owner = int(st.Uid)
		}
		m.NotDumpable, m.DumpableUnknown = notDumpable(owner, p.UID)
	}
	swapFacts(hostFS, readText(hostFS, "/proc/"+pid+"/mountinfo"), pid, &m)
	return p, m, cvm
}

// probeDisks finds the filesystems that hold paths, each disk once.
func probeDisks(paths []string, inContainer bool, _ string) []Disk {
	mountinfo := readText(hostFS, "/proc/self/mountinfo")
	mounts := parseMountinfo(mountinfo)
	vm := detectVM(hostFS)
	var out []Disk
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		real, hidden := realPath(p)
		var d Disk
		switch {
		case hidden != "" && !onlyMountAbove(mounts, real, hidden):
			// A disk may be mounted inside the folder Signalith may not
			// look into, or the folder above is an empty one standing in
			// for it (as /home is under the systemd unit's ProtectHome).
			d = Disk{Kind: DiskDenied, Hidden: hidden}
		case inContainer:
			d = Disk{Path: p, Kind: DiskContainer}
			if m, ok := mountOf(mounts, real); ok {
				d.MountPoint, d.FSType, d.Source = m.Point, m.FSType, m.Source
			}
			if found := detectDisk(hostFS, mountinfo, real, vm); found.Kind == DiskNetwork || found.Kind == DiskMemory {
				d = found
			}
		default:
			d = detectDisk(hostFS, mountinfo, real, vm)
			d.Hidden = hidden
		}
		d.Path = p
		key := "hidden\x00" + p
		if d.Kind != DiskDenied {
			key = diskKey(mounts, real)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

// onlyMountAbove reports whether the filesystem that holds real can be
// known although hidden, a folder above it, may not be looked into: no
// mount point is inside hidden, and the filesystem isn't a memory one
// standing in for a folder kept from the service.
func onlyMountAbove(mounts []mount, real, hidden string) bool {
	for _, m := range mounts {
		if strings.HasPrefix(m.Point, strings.TrimSuffix(hidden, "/")+"/") {
			return false
		}
	}
	m, ok := mountOf(mounts, real)
	return ok && !slices.Contains(memoryFS, m.FSType)
}

// diskKey names the filesystem that holds p, so two mounts of one disk
// count once: the systemd unit's ReadOnlyPaths and ReadWritePaths each
// mount a folder of the same disk again. A real device goes by its
// major:minor number; one without (btrfs, network shares, tmpfs) by its
// source.
func diskKey(mounts []mount, p string) string {
	m, ok := mountOf(mounts, p)
	switch {
	case !ok:
		return "path\x00" + p
	case m.Major != 0:
		return "dev\x00" + strconv.Itoa(m.Major) + ":" + strconv.Itoa(m.Minor)
	}
	return "src\x00" + m.FSType + "\x00" + m.Source
}

// realPath resolves links in p, or in the longest part of it that
// exists, for a folder not made yet. hidden is set when a folder on the
// way may not be looked into: that folder, whose contents (links
// included) Signalith can't see.
func realPath(p string) (real, hidden string) {
	p = filepath.Clean(p)
	rest := ""
	denied := false
	for at := p; ; at = filepath.Dir(at) {
		r, err := filepath.EvalSymlinks(at)
		if err == nil {
			if denied {
				hidden = r
			}
			return filepath.Join(r, rest), hidden
		}
		denied = denied || errors.Is(err, fs.ErrPermission)
		if filepath.Dir(at) == at {
			return p, ""
		}
		rest = filepath.Join(filepath.Base(at), rest)
	}
}

// kernelAtLeast reports whether the running Linux is major.minor or
// newer; true when that can't be read, so nothing is excused by mistake.
func kernelAtLeast(major, minor int) bool {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return true
	}
	return releaseAtLeast(unix.ByteSliceToString(u.Release[:]), major, minor)
}

// DefaultGateway is the IPv4 default route's gateway: in a container,
// the address the host's port forwarding makes every sender seem to come
// from.
func DefaultGateway() (netip.Addr, bool) { return defaultGateway(hostFS) }

// ServiceAccount is the account the server runs as, for the CLI: that
// of process pid when it runs, else the owner of its state folder, else
// this one.
func ServiceAccount(pid, stateDir string) Account {
	if pid != "" {
		if a, ok := procAccount(hostFS, pid); ok {
			return a
		}
	}
	if a, ok := ownerOf(stateDir); ok {
		return a
	}
	return CurrentAccount()
}
