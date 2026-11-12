// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// The asset list's found hosts are the osquery hosts and the scanned
// hosts, each address once.
func TestFeedFoundAssets(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es := endpoint.NewStore(cl, "ff")
	if err := es.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, n := range []*endpoint.Node{
		{ID: "n1", HostIdentifier: "uuid-1", Hostname: "web-01.corp.example", Platform: "linux", IPs: []string{"::ffff:10.0.0.1", "not an ip"}, EnrolledAt: now, LastSeen: now},
	} {
		if err := es.Enroll(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	vs := vulnscan.NewStore(cl, "ff")
	if err := vs.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if err := vs.SaveHosts(ctx, "t1", []*vulnscan.Host{
		{ID: "h1", TargetID: "t1", Address: "10.0.0.1"}, // the osquery host again
		{ID: "h2", TargetID: "t1", Address: "10.0.0.9", Hostname: "printer"},
	}); err != nil {
		t.Fatal(err)
	}
	lists, err := assets.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		feedFoundAssets(ctx, es, vs, nil, lists, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	var found []assets.Asset
	for time.Now().Before(deadline) {
		if found = lists.Found(); len(found) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	var endpointHost, scanned bool
	for _, a := range found {
		if slices.Contains(a.Category, "endpoint") && slices.Contains(a.Host, "web-01") {
			endpointHost = true
		}
		if slices.Contains(a.Category, "scanned") && slices.Contains(a.IP, "10.0.0.9") {
			scanned = true
		}
		if slices.Contains(a.Category, "scanned") && slices.Contains(a.IP, "10.0.0.1") {
			t.Errorf("the osquery host's address is listed twice: %+v", a)
		}
	}
	if !endpointHost || !scanned {
		t.Errorf("found %+v", found)
	}
}

// When OpenSearch cannot be read, nothing is set and the loop still stops.
func TestFeedFoundAssetsWithoutOpenSearch(t *testing.T) {
	cl := store.New(store.Config{URL: "http://" + freeAddr(t)})
	lists, err := assets.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	feedFoundAssets(ctx, endpoint.NewStore(cl, "ff"), vulnscan.NewStore(cl, "ff"), nil, lists, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if f := lists.Found(); len(f) != 0 {
		t.Errorf("found %+v", f)
	}
}
