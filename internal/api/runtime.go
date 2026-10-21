// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/incontainer"
)

// Runtime describes where the server runs, so the UI can give setup steps
// that work there: the commands for this system, whether port 514 can be
// opened, and the addresses devices can send to.
type Runtime struct {
	OS string `json:"os"` // linux, windows, ...
	// Container is true in Docker, Podman or Kubernetes, where the host's addresses
	// and paths are not this program's.
	Container bool `json:"container"`
	// Systemd is true when systemd started the server (a service).
	Systemd bool `json:"systemd"`
	// LowPorts is true when the server may open ports below 1024, such
	// as syslog's 514. On Linux that takes root or CAP_NET_BIND_SERVICE.
	LowPorts bool `json:"low_ports"`
	// Exe is this program, for commands such as "signalith validate".
	Exe string `json:"exe,omitempty"`
	// Addresses are this computer's IPv4 addresses, the one with the
	// default route first; none in a container.
	Addresses []string `json:"addresses"`
}

// runtimeInfo returns s.Runtime, or what this system looks like. The
// addresses are read every time, since DHCP can change them.
func (s *Server) runtimeInfo() Runtime {
	if s.Runtime != nil {
		return *s.Runtime
	}
	r := Runtime{OS: runtime.GOOS, LowPorts: true, Addresses: []string{}}
	r.Exe, _ = os.Executable()
	if runtime.GOOS == "linux" {
		r.Container = detectContainer()
		r.Systemd = os.Getenv("INVOCATION_ID") != ""
		r.LowPorts = linuxLowPorts(os.ReadFile)
	}
	if !r.Container {
		r.Addresses = localAddresses()
	}
	return r
}

// inContainer reports whether the server runs in a container.
func (s *Server) inContainer() bool {
	if s.Runtime != nil {
		return s.Runtime.Container
	}
	return detectContainer()
}

// detectContainer tells whether the server runs in a container (Docker,
// Podman, Kubernetes), once.
var detectContainer = incontainer.Here

// linuxLowPorts reports whether this process may open ports below 1024:
// the kernel lets everyone (net.ipv4.ip_unprivileged_port_start), or the
// process has CAP_NET_BIND_SERVICE, as root and the systemd unit do.
func linuxLowPorts(read func(string) ([]byte, error)) bool {
	if b, err := read("/proc/sys/net/ipv4/ip_unprivileged_port_start"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n <= 514 {
			return true
		}
	}
	b, err := read("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			const capNetBindService = 10
			return err == nil && caps&(1<<capNetBindService) != 0
		}
	}
	return false
}

// virtualNIC matches interfaces that only reach this computer's own
// containers and virtual machines, never the network devices send from.
func virtualNIC(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "vethernet") { // Hyper-V: only WSL and the Default Switch are internal
		return strings.Contains(n, "(wsl") || strings.Contains(n, "default switch")
	}
	for _, p := range []string{"docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "cni", "flannel", "cali", "podman", "lxcbr", "lxdbr"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// localAddresses lists this computer's IPv4 addresses that other machines
// could reach: the one the default route uses first, then the others, at
// most three. Connecting a UDP socket picks the route without sending.
func localAddresses() []string {
	var out []string
	add := func(a netip.Addr) {
		a = a.Unmap()
		if !a.Is4() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || len(out) >= 3 {
			return
		}
		for _, o := range out {
			if o == a.String() {
				return
			}
		}
		out = append(out, a.String())
	}
	if c, err := net.Dial("udp4", "192.0.2.1:9"); err == nil {
		if u, ok := c.LocalAddr().(*net.UDPAddr); ok {
			if a, ok := netip.AddrFromSlice(u.IP); ok {
				add(a)
			}
		}
		c.Close()
	}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || virtualNIC(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					add(ip)
				}
			}
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}
