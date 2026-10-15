package cluster

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The certificate authority a server uses goes into its heartbeat; a
// server that reports none writes no tls_ca.
func TestHeartbeatCarriesTLSStatus(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	l, err := OpenLocal(t.TempDir(), testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	n := New(Options{Local: l, Version: "1.0.0", Timing: fast})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		n.Close()
	})
	n.Start(ctx)
	n.Use(c, "s", Settings{Eligible: true})
	waitReady(t, n, 5*time.Second)
	if src := fos.Source(RuntimeIndex("s"), nodeDocID(n.ID())); src["tls_ca"] != nil {
		t.Fatalf("tls_ca written without a TLS func: %v", src["tls_ca"])
	}
	exp := time.Date(2027, 11, 13, 9, 0, 0, 0, time.UTC)
	n.Use(c, "s", Settings{Eligible: true, TLS: func() *TLSStatus {
		return &TLSStatus{Mode: "auto", CASHA256: "AB:CD", CACertPEM: "-----BEGIN CERTIFICATE-----", Cluster: true,
			Names: []string{"siem-a.lan", "10.0.0.1"}, Outside: []string{"siem.example.com"}, CoversShared: true,
			AdoptError: "a change is in progress", LeafExpires: &exp}
	}})
	until(t, 5*time.Second, "the heartbeat carries the certificate authority", func() bool {
		hb := heartbeatOf(t, fos, n.ID())
		s := hb.TLS
		return s != nil && s.Mode == "auto" && s.CASHA256 == "AB:CD" && s.Cluster && s.CoversShared &&
			slices.Equal(s.Names, []string{"siem-a.lan", "10.0.0.1"}) && slices.Equal(s.Outside, []string{"siem.example.com"}) &&
			s.AdoptError != "" && s.LeafExpires != nil && s.LeafExpires.Equal(exp) && s.CACertPEM != ""
	})
}
