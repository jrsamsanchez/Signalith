// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Route is how this server reaches one entry of a network: on a network
// it is on itself, through a router, or not at all.
type Route struct {
	Entry string
	// Direct is true when the entry is on a network this server is on,
	// Iface names that interface, and From is this server's address the
	// scan leaves from.
	Direct bool
	Iface  string
	From   netip.Addr
	// Err says why it is not reached: no route, or a name not found.
	Err string
}

// maxReachEntries is how many entries of one network are checked.
const maxReachEntries = 32

// LocalRoute finds how this server reaches entry, from its own network
// interfaces and routing table. It sends nothing to the network: a UDP
// socket that is only connected asks the system for the route.
func LocalRoute(ctx context.Context, entry string) Route {
	r := Route{Entry: entry}
	addr, pfx, ok := probeAddr(entry)
	if !ok {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(lctx, "ip", entry)
		cancel()
		if err != nil || len(ips) == 0 {
			r.Err = "the name was not found"
			return r
		}
		addr = ips[0].Unmap()
		pfx = netip.PrefixFrom(addr, addr.BitLen())
	}
	if addr.IsLoopback() {
		r.Direct, r.Iface, r.From = true, "loopback", addr
		return r
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(ipn.IP)
				if !ok {
					continue
				}
				ones, _ := ipn.Mask.Size()
				own := netip.PrefixFrom(ip.Unmap(), ones).Masked()
				if own.Overlaps(pfx) {
					r.Direct, r.Iface, r.From = true, ifc.Name, ip.Unmap()
					return r
				}
			}
		}
	}
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 9)))
	if err != nil {
		r.Err = "this server has no route to it"
		return r
	}
	defer c.Close()
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		r.From = la.AddrPort().Addr().Unmap()
	}
	return r
}

// probeAddr is the address whose route stands for entry, and the network
// entry covers; ok is false for a host name.
func probeAddr(entry string) (netip.Addr, netip.Prefix, bool) {
	if a, err := netip.ParseAddr(entry); err == nil {
		return a.Unmap(), netip.PrefixFrom(a.Unmap(), a.BitLen()), true
	}
	if p, err := netip.ParsePrefix(entry); err == nil {
		p = p.Masked()
		a := p.Addr()
		if p.Bits() < a.BitLen() {
			a = a.Next()
		}
		return a, p, true
	}
	if lo, hi, ok := lastOctetRange(entry); ok {
		base := entry[:strings.LastIndexByte(entry, '.')]
		a, err := netip.ParseAddr(fmt.Sprintf("%s.%d", base, max(lo, 1)))
		if err != nil {
			return netip.Addr{}, netip.Prefix{}, false
		}
		// The smallest network that holds the whole range.
		common := 8 - bits.Len8(uint8(lo^hi))
		return a, netip.PrefixFrom(a, 24+common).Masked(), true
	}
	return netip.Addr{}, netip.Prefix{}, false
}

// reachCheck says how this server reaches a network it scans.
func (c *Checker) reachCheck(ctx context.Context, t Target) Check {
	ck := Check{ID: "reach:" + t.ID, Title: "Reaches " + t.Name,
		Why: "Nmap finds only the hosts and ports this server can reach. A server on the network itself, or inside its network zone, sees every host; " +
			"one outside it sees only what routers and firewalls let through. This check reads this server's own network setup and sends nothing to the network."}
	reach := c.Reach
	if reach == nil {
		reach = LocalRoute
	}
	var direct, failed []string
	routed := map[string][]string{} // by the address scans leave from
	var froms []string
	entries := t.Networks
	if len(entries) > maxReachEntries {
		entries = entries[:maxReachEntries]
	}
	for _, e := range entries {
		r := reach(ctx, e)
		switch {
		case r.Err != "":
			failed = append(failed, e+" ("+r.Err+")")
		case r.Direct:
			direct = append(direct, e+" ("+r.Iface+")")
		default:
			from := "this server"
			if r.From.IsValid() {
				from = r.From.String()
			}
			if routed[from] == nil {
				froms = append(froms, from)
			}
			routed[from] = append(routed[from], e)
		}
	}
	var parts []string
	if len(direct) > 0 {
		parts = append(parts, "On this server's own network: "+strings.Join(direct, ", ")+".")
	}
	for _, f := range froms {
		parts = append(parts, "Through a router, from "+f+": "+strings.Join(routed[f], ", ")+".")
	}
	if len(failed) > 0 {
		parts = append(parts, "Not reached: "+strings.Join(failed, ", ")+".")
	}
	if n := len(t.Networks) - len(entries); n > 0 {
		parts = append(parts, fmt.Sprintf("%d more not checked.", n))
	}
	ck.Detail = strings.Join(parts, " ")
	switch {
	case len(failed) > 0:
		ck.State = CheckWarn
	case len(froms) > 0:
		ck.State = CheckInfo
	default:
		ck.State = CheckOK
	}
	if ck.State != CheckOK {
		ck.Fix = append(ck.Fix, "If "+t.Name+" is in a separate network zone, add a Signalith server inside it (Settings > Servers > Add a server), "+
			"then edit the network on the Vulnerabilities page and pick that server under Scanned by.")
	}
	if len(froms) > 0 {
		ck.Fix = append(ck.Fix, "Otherwise, let "+strings.Join(froms, " and ")+" through the firewalls to the network's hosts, on the ports you scan.")
	}
	if len(failed) > 0 {
		ck.Fix = append(ck.Fix, "Otherwise, add a route from this server to the network, or correct the host names in the network's addresses.")
	}
	return ck
}
