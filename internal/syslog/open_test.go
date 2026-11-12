// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"bytes"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// addrListener is a net.Listener that only says where it listens.
type addrListener struct {
	net.Listener
	addr net.Addr
}

func (l addrListener) Addr() net.Addr { return l.addr }

// A listener other computers can reach, with no syslog.allow, is named in
// a warning as the receiver starts; one on loopback, or any with an allow
// list, is not (ING-05).
func TestOpenListenersWarned(t *testing.T) {
	var logged bytes.Buffer
	r := New(Config{}, nil, slog.New(slog.NewTextHandler(&logged, nil)))
	r.lns = []net.Listener{
		addrListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1514}},
		addrListener{addr: &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 6514}},
	}
	r.listeners = []Listener{{Protocol: "tcp", Address: "127.0.0.1:1514"}, {Protocol: "tls", Address: "0.0.0.0:6514"}}
	if got := r.openListeners(); len(got) != 1 || got[0] != "tls 0.0.0.0:6514" {
		t.Fatalf("open listeners = %q", got)
	}
	r.warnOpen()
	if !strings.Contains(logged.String(), "syslog.allow is empty") || !strings.Contains(logged.String(), "tls 0.0.0.0:6514") {
		t.Errorf("logged %q", logged.String())
	}
	r.cfg.Allow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if got := r.openListeners(); got != nil {
		t.Errorf("with an allow list, open listeners = %q", got)
	}
}
