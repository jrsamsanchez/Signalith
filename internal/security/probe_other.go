// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package security

import (
	"net/netip"
	"os"
	"os/user"
	"strconv"
)

// probeProcess reads the account this process runs as; other facts are
// read only on Linux and Windows.
func probeProcess(pid string, self, _ bool) (ProcessFacts, MemoryFacts, string) {
	var p ProcessFacts
	if !self {
		p.Why = "Signalith can check its running process only on Linux and Windows."
		return p, MemoryFacts{}, ""
	}
	p.Known = true
	p.UID = os.Geteuid()
	p.Root = p.UID == 0
	if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
		p.UserName = u.Username
	}
	return p, MemoryFacts{}, ""
}

// probeDisks can't tell here.
func probeDisks(paths []string, inContainer bool, _ string) []Disk {
	var out []Disk
	for _, p := range paths {
		if p != "" {
			out = append(out, Disk{Path: p, Kind: DiskUnknown})
			break
		}
	}
	return out
}

// DefaultGateway is read only on Linux.
func DefaultGateway() (netip.Addr, bool) { return netip.Addr{}, false }

// ServiceAccount is the account the server runs as, for the CLI: the
// owner of its state folder, else this one.
func ServiceAccount(_ string, stateDir string) Account {
	if a, ok := ownerOf(stateDir); ok {
		return a
	}
	return CurrentAccount()
}
