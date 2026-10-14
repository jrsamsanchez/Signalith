package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// syslogMessage is one message of device src, in RFC 5424 or RFC 3164
// form.
func syslogMessage(format, run string, src int, seq int64, now time.Time) []byte {
	host := fmt.Sprintf("device-%04d", src)
	body := fmt.Sprintf("loadgen run=%s source=%d seq=%d", run, src, seq)
	if format == "3164" {
		return fmt.Appendf(nil, "<134>%s %s loadgen[%d]: %s", now.UTC().Format(time.Stamp), host, 1000+src, body)
	}
	return fmt.Appendf(nil, "<134>1 %s %s loadgen %d - - %s", now.UTC().Format("2006-01-02T15:04:05.000Z07:00"), host, 1000+src, body)
}

// octetCounted frames a message for syslog over TCP or TLS (RFC 6587
// octet counting, as RFC 5425 requires): its length, a space, the
// message.
func octetCounted(msg []byte) []byte {
	out := strconv.AppendInt(nil, int64(len(msg)), 10)
	out = append(out, ' ')
	return append(out, msg...)
}

// SyslogDevices are simulated devices sending syslog, each on its own
// connection (or socket, for UDP), as separate devices do.
type SyslogDevices struct {
	run     string
	load    SyslogLoad
	targets []string
	tls     *tls.Config
	m       *Metrics
}

// Run sends until ctx ends.
func (d *SyslogDevices) Run(ctx context.Context) {
	if len(d.targets) == 0 {
		d.m.Add("syslog_no_target", 1)
		return
	}
	var wg sync.WaitGroup
	queues := make([]chan int64, d.load.Sources)
	for i := range queues {
		queues[i] = make(chan int64, 1024)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d.device(ctx, i, queues[i])
		}(i)
	}
	pace(ctx, d.load.Rate, d.m, func(n int64) {
		i := int(n % int64(d.load.Sources))
		select {
		case queues[i] <- n/int64(d.load.Sources) + 1:
		default:
			d.m.Add("syslog_dropped", 1)
		}
	})
	for _, q := range queues {
		close(q)
	}
	wg.Wait()
}

func (d *SyslogDevices) device(ctx context.Context, i int, queue <-chan int64) {
	target := d.targets[i%len(d.targets)]
	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	for seq := range queue {
		if ctx.Err() != nil {
			continue
		}
		if conn == nil {
			c, err := d.dial(ctx, i, target)
			if err != nil {
				d.m.Add("syslog_send_errors", 1)
				continue
			}
			conn = c
		}
		msg := syslogMessage(d.load.Format, d.run, i, seq, time.Now())
		if d.load.Proto != "udp" {
			msg = octetCounted(msg)
		} else if d.load.ProxyV2 {
			h, err := d.proxyHeader(i, conn)
			if err == nil {
				msg = append(h, msg...)
			}
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(msg); err != nil {
			d.m.Add("syslog_send_errors", 1)
			conn.Close()
			conn = nil
			d.m.Add("syslog_reconnects", 1)
			continue
		}
		d.m.Add("syslog_sent", 1)
	}
}

func (d *SyslogDevices) dial(ctx context.Context, i int, target string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	switch d.load.Proto {
	case "udp":
		return dialer.DialContext(ctx, "udp", target)
	case "tls":
		raw, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, err
		}
		if d.load.ProxyV2 {
			if err := d.writeProxy(i, raw); err != nil {
				raw.Close()
				return nil, err
			}
		}
		tc := d.tls.Clone()
		if host, _, err := net.SplitHostPort(target); err == nil {
			tc.ServerName = host
		}
		c := tls.Client(raw, tc)
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := c.HandshakeContext(hctx); err != nil {
			raw.Close()
			return nil, err
		}
		return c, nil
	default:
		c, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, err
		}
		if d.load.ProxyV2 {
			if err := d.writeProxy(i, c); err != nil {
				c.Close()
				return nil, err
			}
		}
		return c, nil
	}
}

func (d *SyslogDevices) proxyHeader(i int, c net.Conn) ([]byte, error) {
	dst, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	src := netip.AddrPortFrom(fakeSource(i, dst.Addr().Unmap().Is6()), uint16(20000+i%40000))
	return proxyV2Header(d.load.Proto == "udp", src, dst)
}

func (d *SyslogDevices) writeProxy(i int, c net.Conn) error {
	h, err := d.proxyHeader(i, c)
	if err != nil {
		return err
	}
	_, err = c.Write(h)
	return err
}
