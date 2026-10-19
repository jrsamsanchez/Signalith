// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLinuxLowPorts(t *testing.T) {
	files := func(m map[string]string) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			if v, ok := m[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		}
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		// An older systemd unit: a plain user, no capabilities.
		{"plain user", map[string]string{"/proc/sys/net/ipv4/ip_unprivileged_port_start": "1024\n", "/proc/self/status": "Name:\tsignalith\nCapEff:\t0000000000000000\n"}, false},
		// The current unit grants CAP_NET_BIND_SERVICE (bit 10).
		{"unit with the capability", map[string]string{"/proc/sys/net/ipv4/ip_unprivileged_port_start": "1024\n", "/proc/self/status": "CapEff:\t0000000000000400\n"}, true},
		{"root", map[string]string{"/proc/self/status": "CapEff:\t000001ffffffffff\n"}, true},
		{"kernel lets everyone", map[string]string{"/proc/sys/net/ipv4/ip_unprivileged_port_start": "0\n", "/proc/self/status": "CapEff:\t0000000000000000\n"}, true},
		{"other capabilities only", map[string]string{"/proc/self/status": "CapEff:\t0000000000003000\n"}, false},
		{"nothing readable", nil, false},
	} {
		if got := linuxLowPorts(files(c.files)); got != c.want {
			t.Errorf("%s: low ports = %v, want %v", c.name, got, c.want)
		}
	}
	if linuxLowPorts(func(string) ([]byte, error) { return []byte("garbage"), nil }) {
		t.Error("garbage: want false")
	}
}

func TestVirtualNIC(t *testing.T) {
	for name, want := range map[string]bool{
		"eth0": false, "ens18": false, "wlan0": false, "Ethernet": false, "Wi-Fi": false, "vEthernet (External)": false,
		"docker0": true, "br-4f1c2d": true, "veth12ab": true, "virbr0": true, "vEthernet (WSL)": true, "vEthernet (Default Switch)": true,
	} {
		if got := virtualNIC(name); got != want {
			t.Errorf("virtualNIC(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestLocalAddresses checks the addresses offered to devices are ones
// they could send to: IPv4, not loopback or link-local, at most three.
func TestLocalAddresses(t *testing.T) {
	got := localAddresses()
	if got == nil || len(got) > 3 {
		t.Fatalf("addresses = %v", got)
	}
	for _, a := range got {
		ip, err := netip.ParseAddr(a)
		if err != nil || !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Errorf("address %q", a)
		}
	}
}

func TestRuntimeInfo(t *testing.T) {
	s := &Server{}
	r := s.runtimeInfo()
	if r.OS != runtime.GOOS || r.Addresses == nil || r.Exe == "" {
		t.Errorf("runtime = %+v", r)
	}
	if runtime.GOOS != "linux" && !r.LowPorts {
		t.Errorf("%s has no privileged ports: %+v", runtime.GOOS, r)
	}
	if r.Container && len(r.Addresses) > 0 {
		t.Errorf("container addresses are not the host's: %+v", r)
	}
	if abs, _ := filepath.Abs(r.Exe); abs != r.Exe {
		t.Errorf("exe %q is not absolute", r.Exe)
	}
	s.Runtime = &Runtime{OS: "windows", LowPorts: true, Addresses: []string{"192.0.2.20"}}
	if r := s.runtimeInfo(); r.OS != "windows" || r.Addresses[0] != "192.0.2.20" {
		t.Errorf("override = %+v", r)
	}
}
