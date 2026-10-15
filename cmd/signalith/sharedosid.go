package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterpki"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Each server's own OpenSearch identity (internal/clusterpki): when
// Signalith made OpenSearch's certificates, their certificate authority
// is handed to the cluster once (bootstrap-docker -export-ca-key drops it
// in <state>/import, or signalith cluster opensearch-ca import), and each
// server then signs in to OpenSearch with a certificate of its own,
// CN=signalith-server-<name>, which it renews itself. A server that signs
// in with a password, or with a certificate from elsewhere, keeps doing
// so.

// osIdentityPoll is how often a server looks for a certificate authority
// handed over and at its certificate; a change of the osca document
// wakes it at once.
var osIdentityPoll = 30 * time.Second

// osIdentity keeps this start's OpenSearch certificate while ctx lasts,
// and returns what the heartbeat says of it; nil on a server that does
// not use the shared settings.
func (r *runner) osIdentity(ctx context.Context, in *instance, c *config.Config) func() *cluster.OSIdentityStatus {
	ct, rt := r.sharedContent, r.shared
	if ct == nil || rt == nil || r.node == nil {
		return nil
	}
	conn := func() store.Config { return c.OpenSearchConnection() }
	id := clusterpki.NewIdentity(clusterpki.Options{
		OSCA: ct.osca, Name: r.node.Name(), NodeID: r.node.ID(), Conn: conn,
		ImportDir: filepath.Join(c.StateDir(), ospki.ImportDir),
		Writable:  rt.Writable, Flush: rt.FlushCacheBody, Log: r.log,
	})
	kick := make(chan struct{}, 1)
	ct.osca.OnChange(func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	})
	in.jobs.Go(func() {
		t := time.NewTicker(osIdentityPoll)
		defer t.Stop()
		for {
			id.Sync(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-kick:
			}
		}
	})
	return id.Status
}

// clusterOSIdentityAPI is OpenSearch's certificate authority as the API
// shows it, nil on a server that does not use the shared settings.
func (r *runner) clusterOSIdentityAPI() api.ClusterOSIdentity {
	if r.shared == nil || r.sharedContent == nil {
		return nil
	}
	return osIdentityAPI{osca: r.sharedContent.osca}
}

type osIdentityAPI struct{ osca *clusterpki.OSCA }

func (a osIdentityAPI) CA() (*clusterpki.Body, bool) { return a.osca.Get() }
