package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// readOctetCounted reads one octet-counted frame (RFC 6587), as a syslog
// receiver does.
func readOctetCounted(r *bufio.Reader) ([]byte, error) {
	n, err := r.ReadString(' ')
	if err != nil {
		return nil, err
	}
	size, err := strconv.Atoi(strings.TrimSuffix(n, " "))
	if err != nil {
		return nil, err
	}
	msg := make([]byte, size)
	_, err = io.ReadFull(r, msg)
	return msg, err
}

func TestOctetCountedRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 10, 14, 9, 5, 7, 0, time.UTC)
	want := [][]byte{
		syslogMessage("5424", "r1", 7, 1, now),
		syslogMessage("3164", "r1", 7, 2, now),
		[]byte("a message with a newline\ninside"),
	}
	for _, m := range want {
		buf.Write(octetCounted(m))
	}
	r := bufio.NewReader(&buf)
	for i, m := range want {
		got, err := readOctetCounted(r)
		if err != nil || !bytes.Equal(got, m) {
			t.Errorf("frame %d: %q %v", i, got, err)
		}
	}
	if string(want[0]) != "<134>1 2026-10-14T09:05:07.000Z device-0007 loadgen 1007 - - loadgen run=r1 source=7 seq=1" {
		t.Errorf("RFC 5424: %s", want[0])
	}
	if string(want[1]) != "<134>Oct 14 09:05:07 device-0007 loadgen[1007]: loadgen run=r1 source=7 seq=2" {
		t.Errorf("RFC 3164: %s", want[1])
	}
}

func TestSyslogDevicesTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var mu sync.Mutex
	got := map[string]int{}
	var proxied int
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				head, _ := r.Peek(12)
				if bytes.Equal(head, proxyV2Sig) {
					hdr := make([]byte, 16+12)
					if _, err := io.ReadFull(r, hdr); err != nil {
						return
					}
					mu.Lock()
					proxied++
					mu.Unlock()
				}
				for {
					m, err := readOctetCounted(r)
					if err != nil {
						return
					}
					f := strings.Fields(string(m))
					mu.Lock()
					got[f[len(f)-2]]++ // source=N
					mu.Unlock()
				}
			}()
		}
	}()
	m := newMetrics()
	m.SetPhase("p")
	d := &SyslogDevices{run: "r", load: SyslogLoad{Proto: "tcp", Sources: 4, Rate: 200, ProxyV2: true},
		targets: []string{l.Addr().String()}, m: m}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	d.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	sent := m.Count("", "syslog_sent")
	total := 0
	for _, n := range got {
		total += n
	}
	if sent < 50 || int64(total) != sent || len(got) != 4 {
		t.Errorf("sent %d, received %d from %d sources", sent, total, len(got))
	}
	if proxied != 4 {
		t.Errorf("%d connections started with a PROXY header, want 4", proxied)
	}
}

func TestSyslogDevicesUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	n := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			k, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if bytes.HasPrefix(buf[:k], []byte("<134>")) {
				n++
			}
		}
	}()
	m := newMetrics()
	d := &SyslogDevices{run: "r", load: SyslogLoad{Proto: "udp", Sources: 2, Rate: 100, Format: "3164"},
		targets: []string{pc.LocalAddr().String()}, m: m}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	d.Run(ctx)
	<-done
	if sent := m.Count("", "syslog_sent"); sent < 10 || int64(n) != sent {
		t.Errorf("sent %d, received %d", sent, n)
	}
}
