package main

import (
	"cmp"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// The cluster's one certificate authority (internal/clustertls): once the
// cluster reaches shared.LevelSharedTLS, the founder publishes its own
// (the tls importer) when every server uses it, or an admin chooses one
// and the server holding it publishes it (a tls_publish request). Every
// server then issues its HTTPS certificate from it: the certificate's
// Manager switches to the cluster's store while it runs (UseStore), its
// own certificate authority goes to tls/retired, and the names any server
// adds reach every server's certificate within a poll. A server of its
// own, or one below the level, keeps its own certificate authority
// exactly as before.

// tlsPoll is how often a server looks whether it should take the
// cluster's certificate authority or reissue its certificate; a change of
// the tls document wakes it at once.
var tlsPoll = 2 * time.Second

// sharedTLS links the tls document to the HTTPS certificate of each
// start. Like the shared content, it belongs to the process.
type sharedTLS struct {
	tls *clustertls.TLS
	// certs is the HTTPS certificate's Manager of the start running now,
	// nil when it needs none or has the admin's certificate files.
	certs atomic.Pointer[tlsauto.Manager]
	// attached is the Manager the cluster's store is in use on: a restart
	// that keeps the Manager keeps it.
	attached atomic.Pointer[tlsauto.Manager]
	// adoptErr says why this server has not taken the cluster's
	// certificate authority, for its heartbeat.
	adoptErr atomic.Pointer[string]
	kick     chan struct{}

	// mu serialises sync; the fields after it are its own.
	mu sync.Mutex
	// etag is the tls document's version the certificate was last
	// brought in line with; keyDone the Manager whose ca.key was dealt
	// with once the cluster kept it; retired a certificate authority this
	// server used before the cluster's, still to record in the tls
	// document; logged the last refusal logged.
	etag    string
	keyDone *tlsauto.Manager
	retired *x509.Certificate
	logged  string
}

func newSharedTLS() *sharedTLS {
	return &sharedTLS{tls: clustertls.New(), kick: make(chan struct{}, 1)}
}

// local returns this server's own certificate authority to publish: the
// running Manager's, or, from the command line, which has none, the one
// in the tls folder of the configuration cfg returns.
func (s *sharedTLS) local(cfg func() *config.Config) clustertls.LocalCA {
	return func() (*x509.Certificate, crypto.Signer, []string) {
		if m := s.certs.Load(); m != nil {
			return m.LocalPair()
		}
		var c *config.Config
		if cfg != nil {
			c = cfg()
		}
		if c == nil {
			return nil, nil, nil
		}
		o, ok := certOptions(c)
		if !ok || o.CertFile != "" {
			return nil, nil, nil
		}
		return tlsauto.LocalFiles(o.Dir)
	}
}

// importer is the tls importer, from the server and the command line
// alike.
func (s *sharedTLS) importer(f clustercfg.Files) shared.Importer {
	return clustertls.Importer(clustertls.ImporterOptions{
		TLS:   s.tls,
		Local: s.local(f.Config),
		Servers: func() []clustertls.Server {
			if f.Client == nil {
				return nil
			}
			cl, prefix := f.Client()
			if cl == nil {
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			hbs, err := readHeartbeats(ctx, cl, prefix)
			if err != nil {
				return nil
			}
			return clustertls.FromHeartbeats(hbs, "")
		},
		Node: f.Node,
		Log:  f.Log,
	})
}

// handler runs the tls_publish requests that name this server.
func (s *sharedTLS) handler(cfg func() *config.Config, node string, log *slog.Logger) shared.Handler {
	return clustertls.Handler(s.tls, s.local(cfg), node, log)
}

// readHeartbeats reads the servers' heartbeats.
func readHeartbeats(ctx context.Context, cl *store.Client, prefix string) ([]cluster.Heartbeat, error) {
	docs, err := cl.SearchDocs(ctx, cluster.RuntimeIndex(prefix), map[string]any{"term": map[string]any{"kind": "node"}})
	if err != nil {
		return nil, err
	}
	var out []cluster.Heartbeat
	for _, d := range docs {
		var hb cluster.Heartbeat
		if json.Unmarshal(d.Source, &hb) == nil && hb.NodeID != "" {
			out = append(out, hb)
		}
	}
	return out, nil
}

// sharedTLS links this start's HTTPS certificate certs to the cluster's
// certificate authority: it takes it at once when the cluster has one,
// and follows the tls document while ctx lasts. agents learns of the
// certificate authorities retired. It returns what the heartbeat says of
// the certificate.
func (r *runner) sharedTLS(ctx context.Context, in *instance, c *config.Config, certs *tlsauto.Manager, agents *agentinv.Inventory) func() *cluster.TLSStatus {
	host := hostOf(c.Server.PublicURL)
	ct := r.sharedContent
	if ct == nil {
		return func() *cluster.TLSStatus { return clustertls.StatusOf(certs, host, "") }
	}
	s := ct.tls
	if certs == nil || !certs.LocalCA() {
		s.certs.Store(nil)
		return func() *cluster.TLSStatus { return clustertls.StatusOf(certs, host, "") }
	}
	s.certs.Store(certs)
	// With the cluster's certificate authority, the certificate also
	// covers the address the other servers reach this one at, which the
	// move probe checks; on a server of its own nothing changes.
	nodeHost := hostOf(nodeURL(c))
	certs.SetSharedNames(func() []string {
		if nodeHost == "" || s.attached.Load() != certs {
			return nil
		}
		return []string{nodeHost}
	})
	if agents != nil {
		agents.Retired = func() []string { return s.retiredPins(certs) }
	}
	s.tls.OnChange(func(_, _ *clustertls.Body) { s.wake() })
	rt := r.shared
	s.sync(ctx, rt, certs, r.node.Name(), r.log)
	in.jobs.Go(func() { s.run(ctx, rt, certs, r.node.Name(), r.log) })
	return func() *cluster.TLSStatus { return clustertls.StatusOf(certs, host, s.adoptError()) }
}

// hostOf is the host of the URL u, "" for none.
func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Hostname()
}

func (s *sharedTLS) wake() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *sharedTLS) adoptError() string {
	if p := s.adoptErr.Load(); p != nil {
		return *p
	}
	return ""
}

// run follows the tls document for m until ctx ends.
func (s *sharedTLS) run(ctx context.Context, rt *shared.Runtime, m *tlsauto.Manager, node string, log *slog.Logger) {
	t := time.NewTicker(tlsPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
		s.sync(ctx, rt, m, node, log)
	}
}

// sync brings m in line with the tls document: it takes the cluster's
// certificate authority once there is one and the cluster's level says
// so, records the one it replaces, reissues the certificate when the
// names change, and, on the server that published its own, deletes
// ca.key once the cluster keeps it safely.
func (s *sharedTLS) sync(ctx context.Context, rt *shared.Runtime, m *tlsauto.Manager, node string, log *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certs.Load() != m {
		// A later start's Manager took over.
		return
	}
	b, ok := s.tls.Get()
	if rt == nil || !ok || b.CASHA256 == "" || !rt.SharedTLS() {
		s.setErr("", log)
		return
	}
	if s.attached.Load() != m || !clustertls.SameFingerprint(m.Fingerprint(), b.CASHA256) {
		var old *x509.Certificate
		if p := m.CAPEM(); p != nil {
			if block, _ := pem.Decode(p); block != nil {
				old, _ = x509.ParseCertificate(block.Bytes)
			}
		}
		if err := m.UseStore(s.tls.Store()); err != nil {
			s.setErr(err.Error(), log)
			return
		}
		s.attached.Store(m)
		s.etag, s.keyDone = "", nil
		if old != nil && !clustertls.SameFingerprint(tlsauto.Fingerprint(old.Raw), b.CASHA256) {
			s.retired = old
		}
		s.setErr("", log)
	}
	if s.retired != nil {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.tls.AddRetired(rctx, node, s.retired)
		cancel()
		if err == nil {
			s.retired = nil
		}
	}
	if d := s.tls.Doc(); d != nil && d.ETag() != s.etag {
		// The names (or the copy) changed: covering them again.
		etag := d.ETag()
		if err := m.Reissue(); err != nil {
			log.Warn("could not reissue the HTTPS certificate for the cluster's names; it tries again", "err", err)
		} else {
			s.etag = etag
		}
	}
	if s.keyDone != m && s.keyKept(ctx, rt) {
		if err := m.DropLocalKey(); err != nil {
			log.Warn("could not delete ca.key now that the cluster keeps the certificate authority's key; it tries again", "err", err)
		} else {
			s.keyDone = m
		}
	}
}

// keyKept reports whether the cluster keeps the certificate authority's
// key safely: the tls document read back from OpenSearch opens, and this
// server's copy of the shared settings (cache.enc) was written since.
func (s *sharedTLS) keyKept(ctx context.Context, rt *shared.Runtime) bool {
	d := s.tls.Doc()
	if d == nil {
		return false
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := d.Load(lctx); err != nil {
		return false
	}
	ca, key, err := s.tls.Store().Load()
	if err != nil || ca == nil || key == nil {
		return false
	}
	return rt.FlushCache() == nil
}

// setErr records why this server has not taken the cluster's certificate
// authority, and logs each new reason once.
func (s *sharedTLS) setErr(msg string, log *slog.Logger) {
	if msg == "" {
		s.adoptErr.Store(nil)
		s.logged = ""
		return
	}
	s.adoptErr.Store(&msg)
	if msg != s.logged {
		s.logged = msg
		log.Warn("this server keeps its own certificate authority for now instead of the cluster's", "reason", msg)
	}
}

// retiredPins are the pins of the certificate authorities retired, on m
// and on any server of the cluster: agents that trust only those need a
// new configuration.
func (s *sharedTLS) retiredPins(m *tlsauto.Manager) []string {
	var out []string
	add := func(fp string) {
		if p := agentinv.Pin(fp); p != "" {
			out = append(out, p)
		}
	}
	for _, in := range m.Retired() {
		add(in.Fingerprint)
	}
	if b, ok := s.tls.Get(); ok {
		for _, fp := range b.RetiredFingerprints() {
			add(fp)
		}
	}
	return out
}

// probeTLS is how the move probe checks the certificate of the server it
// probes: against the cluster's certificate authority (and the system's,
// for a server with its own certificate files), with its name. It is nil
// while the cluster has none, so the probe goes on without a check.
func (s *sharedTLS) probeTLS() *tls.Config {
	b, ok := s.tls.Get()
	if !ok || b.CACertPEM == "" {
		return nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(b.CACertPEM)) {
		return nil
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// tlsAPI is the cluster's certificate authority as the API uses it
// (api.ClusterTLS).
type tlsAPI struct {
	rt *shared.Runtime
	s  *sharedTLS
}

// clusterTLSAPI returns the API's view of the cluster's certificate
// authority, nil on a server that does not use the shared settings.
func (r *runner) clusterTLSAPI() api.ClusterTLS {
	if r.shared == nil || r.sharedContent == nil {
		return nil
	}
	return tlsAPI{rt: r.shared, s: r.sharedContent.tls}
}

func (a tlsAPI) Off() string {
	if m, why := a.rt.Mode(); m != shared.ModeMember {
		return "This server doesn't use the cluster's shared settings now (" + cmp.Or(why, m.Text()) + "), so each server keeps its own certificate authority."
	}
	if !a.rt.SharedTLS() {
		return fmt.Sprintf("Every server keeps its own certificate authority until all of them run a version that shares one (cluster level %d).", shared.LevelSharedTLS)
	}
	return ""
}

func (a tlsAPI) CA() (*clustertls.Body, bool) { return a.s.tls.Get() }

func (a tlsAPI) Founder() string {
	cb, _ := a.rt.Cluster().Get()
	return cb.CreatedByID
}

func (a tlsAPI) Writable() error { return a.rt.Writable() }

func (a tlsAPI) Publish(ctx context.Context, node, fp, by string) (*shared.Request, error) {
	return a.rt.Requests().Submit(ctx, clustertls.RequestPublish, node, clustertls.PublishArgs{CASHA256: fp}, by)
}
