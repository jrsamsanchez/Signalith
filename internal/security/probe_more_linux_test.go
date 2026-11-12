// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestProbeProcessOfAnotherPID(t *testing.T) {
	p, _, _ := probeProcess("", false, false)
	if p.Known || p.Why != NoServiceLine {
		t.Errorf("no pid: %+v", p)
	}
	p, _, _ = probeProcess("999999999", false, false)
	if p.Known || p.Why == "" {
		t.Errorf("missing pid: %+v", p)
	}
	// This process, read as the CLI reads the service's.
	p, m, _ := probeProcess(strconv.Itoa(os.Getpid()), false, true)
	if !p.Known || p.UID != os.Geteuid() || !p.Systemd {
		t.Errorf("own pid: %+v", p)
	}
	if !m.Known {
		t.Errorf("memory facts unknown: %+v", m)
	}
}

func TestProbeDisksSkipsEmptyAndRepeats(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, d := range []string{a, b} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	disks := probeDisks([]string{"", a, b}, false, "")
	if len(disks) != 1 || disks[0].Path != a {
		t.Errorf("one disk expected: %+v", disks)
	}
	in := probeDisks([]string{a}, true, "")
	if len(in) != 1 || in[0].Path != a || in[0].Kind == "" {
		t.Errorf("in a container: %+v", in)
	}
}

func TestServiceAccount(t *testing.T) {
	me := CurrentAccount()
	if me.UID != os.Geteuid() || me.GID != os.Getegid() || isService() {
		t.Errorf("current %+v", me)
	}
	if got := ServiceAccount(strconv.Itoa(os.Getpid()), ""); got.UID != me.UID {
		t.Errorf("by pid: %+v", got)
	}
	dir := t.TempDir()
	if got := ServiceAccount("", dir); got.UID != me.UID {
		t.Errorf("by state folder: %+v", got)
	}
	if got := ServiceAccount("999999999", filepath.Join(dir, "missing")); got != me {
		t.Errorf("fallback: %+v", got)
	}
	if _, ok := ownerOf(filepath.Join(dir, "missing")); ok {
		t.Error("owner of a missing path")
	}
	// The default gateway, when there is one, is an IPv4 address.
	if gw, ok := DefaultGateway(); ok && !gw.Is4() {
		t.Errorf("gateway %v", gw)
	}
}
