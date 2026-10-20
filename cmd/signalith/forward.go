// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// cmdTCPForward passes TCP connections from -listen on to -to as they
// are, for the Docker quick start's cluster profile: it opens OpenSearch's
// port to the other servers while TLS and the client certificate still
// run between them and OpenSearch, end to end. It reads nothing it
// passes on.
func cmdTCPForward(args []string) error {
	fs := flag.NewFlagSet("tcp-forward", flag.ExitOnError)
	listen := fs.String("listen", "", "address and port to accept connections on, such as 0.0.0.0:9200")
	to := fs.String("to", "", "host and port to pass them on to, such as opensearch:9200")
	fs.Parse(args)
	if *listen == "" || *to == "" {
		return errors.New("usage: signalith tcp-forward -listen ADDR:PORT -to HOST:PORT")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "passing connections on %s to %s\n", *listen, *to)
	return forwardTCP(ctx, ln, *to)
}

// forwardTCP passes each connection ln accepts to addr until ctx ends.
func forwardTCP(ctx context.Context, ln net.Listener, addr string) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		in, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer in.Close()
			d := net.Dialer{Timeout: 10 * time.Second}
			out, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot reach %s: %v\n", addr, err)
				return
			}
			defer out.Close()
			stop := context.AfterFunc(ctx, func() { in.Close(); out.Close() })
			defer stop()
			done := make(chan struct{}, 2)
			pass := func(dst, src net.Conn) {
				io.Copy(dst, src)
				if c, ok := dst.(*net.TCPConn); ok {
					c.CloseWrite()
				}
				done <- struct{}{}
			}
			go pass(out, in)
			go pass(in, out)
			<-done
			<-done
		}()
	}
}
