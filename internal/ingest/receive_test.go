// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

// receiving returns the receive budget in use in all, and what each
// sender address of the pipeline's tenant holds of it.
func (p *Pipeline) receiving() (total int64, by map[netip.Addr]int64) {
	l := p.limits()
	l.recvMu.Lock()
	defer l.recvMu.Unlock()
	by = map[netip.Addr]int64{}
	for k, v := range l.recvBy {
		if k.tenant == p.Tenant {
			by[k.addr] = v
		}
	}
	return l.recvUsed, by
}

// TestSlowBodiesHoldOnlyWhatArrived: a sender that announces a large body
// and then sends slowly holds only memory for what it has sent, not for
// what it announced.
func TestSlowBodiesHoldOnlyWhatArrived(t *testing.T) {
	p := &Pipeline{}
	a := netip.MustParseAddr("203.0.113.9")
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, release, err := p.ReadBody(pr, a, 15<<20)
		if err == nil {
			release()
		}
		done <- err
	}()
	pw.Write([]byte(`[{"log":"x"}`))
	if total, by := p.receiving(); total != receiveStep || by[a] != receiveStep {
		t.Errorf("after 12 bytes of an announced 15 MB: %d held (%v)", total, by)
	}
	pw.CloseWithError(io.ErrUnexpectedEOF)
	if err := <-done; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v", err)
	}
	if total, by := p.receiving(); total != 0 || len(by) != 0 {
		t.Errorf("after the sender went away: %d held (%v)", total, by)
	}
}

// TestReceiveBudget: bodies take memory from MaxReceiving as they arrive,
// one sender may hold a quarter of it, a shared address only counts
// towards the total, and release gives it back.
func TestReceiveBudget(t *testing.T) {
	p := &Pipeline{MaxReceiving: 1 << 20}
	body := func(n int) io.Reader { return bytes.NewReader(bytes.Repeat([]byte("x"), n)) }
	a, b := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::")

	got, relA, err := p.ReadBody(body(200<<10), a, -1)
	if err != nil || len(got) != 200<<10 {
		t.Fatalf("first body: %d bytes, %v", len(got), err)
	}
	// Grown by doubling: 64, 128, then 256 KB, a quarter of the budget.
	if total, _ := p.receiving(); total != 256<<10 {
		t.Errorf("held %d", total)
	}
	if _, _, err := p.ReadBody(body(10), a, 10); !errors.Is(err, ErrSenderBusy) {
		t.Errorf("same sender over its share: %v", err)
	}
	// With the length announced, a body takes just what it needs.
	_, relB, err := p.ReadBody(body(200<<10), b, 200<<10)
	if err != nil {
		t.Fatal(err)
	}
	if total, by := p.receiving(); total != 256<<10+200<<10+1 || by[b] != 200<<10+1 {
		t.Errorf("held %d (%v)", total, by)
	}
	// A shared address is not held to a quarter, only to the total.
	_, relShared, err := p.ReadBody(body(500<<10), netip.Addr{}, 500<<10)
	if err != nil {
		t.Fatalf("shared address: %v", err)
	}
	if _, _, err := p.ReadBody(body(100<<10), netip.MustParseAddr("198.51.100.1"), 100<<10); !errors.Is(err, ErrBusy) {
		t.Errorf("over the total: %v", err)
	}
	relA()
	relA() // twice is harmless
	if _, rel, err := p.ReadBody(body(100<<10), netip.MustParseAddr("198.51.100.1"), 100<<10); err != nil {
		t.Errorf("after a release: %v", err)
	} else {
		rel()
	}
	relB()
	relShared()
	if total, by := p.receiving(); total != 0 || len(by) != 0 {
		t.Errorf("after every release: %d held (%v)", total, by)
	}
}

func TestReadBodyRefusesOversizedBodies(t *testing.T) {
	p := &Pipeline{}
	for _, hint := range []int64{-1, MaxBodyBytes + 1, 100} {
		_, _, err := p.ReadBody(strings.NewReader(strings.Repeat(" ", MaxBodyBytes+1)), netip.Addr{}, hint)
		var bad *BodyError
		if !errors.As(err, &bad) || bad.Status != 413 {
			t.Errorf("hint %d: %v", hint, err)
		}
	}
	if total, _ := p.receiving(); total != 0 {
		t.Errorf("%d held after refusing", total)
	}
	// Exactly the limit is fine.
	got, rel, err := p.ReadBody(strings.NewReader(strings.Repeat(" ", MaxBodyBytes)), netip.Addr{}, -1)
	if err != nil || len(got) != MaxBodyBytes {
		t.Errorf("%d bytes, %v", len(got), err)
	} else {
		rel()
	}
	// An empty body.
	if got, rel, err := p.ReadBody(strings.NewReader(""), netip.Addr{}, 0); err != nil || len(got) != 0 {
		t.Errorf("empty: %q %v", got, err)
	} else {
		rel()
	}
}
