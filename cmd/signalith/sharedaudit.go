package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterarchive"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Audit records and archives across servers. Once the cluster reaches
// shared.LevelSharedAudit, each server writes its audit log lines to
// monthly indices in OpenSearch (through a spool on disk, see
// internal/audit), and retention keeps its history, its archive manifests
// and the progress of restores in OpenSearch (internal/clusterarchive), so
// that every server shows the same and a takeover loses nothing. Like the
// shared configuration, the spool belongs to the process; each start of
// the components decides once whether they are shared, and a change
// restarts them in place (followShared).

// processAudit is the process's audit spool, and whether the components
// running now share the audit records.
type processAudit struct {
	sink *audit.Sink
	on   atomic.Bool
}

// auditSpoolDir is the spool's folder in the state folder.
const auditSpoolDir = "audit-spool"

// openAudit returns the process's audit spool, disabled until a start
// finds the cluster keeps audit records, and log with the spool hearing
// its audit lines. The spool's own problems go to log as it was, never
// as audit lines.
func openAudit(c *config.Config, node *cluster.Node, log *slog.Logger) (*processAudit, *slog.Logger) {
	sink := audit.NewSink(audit.SinkOptions{
		Dir:    filepath.Join(c.StateDir(), auditSpoolDir),
		Server: node.Name(), NodeID: node.ID(), Epoch: node.Lease().Epoch,
		Log: log,
	})
	sink.SetEnabled(false)
	return &processAudit{sink: sink}, slog.New(audit.Handler(log.Handler(), sink))
}

// auditOn reports whether the components running now share the audit
// records.
func (r *runner) auditOn() bool { return r.audit != nil && r.audit.on.Load() }

// wantAudit reports whether the components should share the audit
// records: the cluster keeps them, and the content comes from the shared
// settings.
func (r *runner) wantAudit() bool {
	return r.audit != nil && r.shared != nil && r.sharedContent != nil && r.sharedContent.on.Load() && r.shared.SharedAudit()
}

// useAudit decides, for one start, whether the audit records, the
// retention history and the archive manifests are shared, and points
// the spool and the retention manager at OpenSearch when they are.
func (r *runner) useAudit(ctx context.Context, in *instance, c *config.Config, cl *store.Client, ret *retention.Manager) {
	if r.audit == nil || r.node == nil {
		return
	}
	on := r.wantAudit()
	r.audit.on.Store(on)
	prefix := c.OpenSearch.IndexPrefix
	r.audit.sink.SetTarget(cl, prefix)
	r.audit.sink.SetIdentity(r.node.Name(), r.node.ID())
	r.audit.sink.SetEnabled(on)
	if !on {
		r.audit.sink.SetKeySource(nil)
		return
	}
	// The records are signed with the audit key of the cluster key in use
	// now. A server that has none at the moment (it has not been handed
	// the key yet) chains its records unsigned until it has one.
	sh := r.shared
	r.audit.sink.SetKeySource(func() (string, []byte) {
		if k := sh.Hub().Keys().Active(); k != nil {
			return k.ID(), k.AuditKey()
		}
		return "", nil
	})
	in.jobs.Go(func() { ensureAuditTemplate(ctx, cl, c, r.log) })
	node := r.node
	name, id := node.Name(), node.ID()
	ret.History = &clusterarchive.History{Client: cl, Prefix: prefix, Log: r.log, Server: name, NodeID: id, Epoch: node.Lease().Epoch}
	claims := &clusterarchive.Claimer{Client: cl, Prefix: prefix, Server: name, NodeID: id, Epoch: node.Lease().Epoch, Frozen: node.Lease().Frozen}
	ret.Claim = claims.Claim
	ret.Jobs = &clusterarchive.Jobs{Client: cl, Prefix: prefix, Server: name, NodeID: id, Epoch: node.Lease().Epoch}
	if ret.Archive != nil {
		ret.Archive.Server = name
		ret.Archive.Manifests = &clusterarchive.Manifests{Client: cl, Prefix: prefix, Server: name, NodeID: id}
		folders := archiveFolders(cl, prefix, name, id, ret.Archive)
		ret.CanArchive = func() (bool, string) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return folders.CanArchive(ctx)
		}
		ret.ArchiveOn = func() []string {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			on, _ := folders.On(ctx)
			return on
		}
		// Every server says which archive folder it sees, so the page can
		// say which of them can archive.
		in.jobs.Go(func() { reportArchiveFolder(ctx, folders, r.log) })
	}
}

// archiveFolders is the archive folder check of this server.
func archiveFolders(cl clusterarchive.Client, prefix, name, id string, a *retention.Archive) *clusterarchive.Folders {
	return &clusterarchive.Folders{Client: cl, Prefix: prefix, Server: name, NodeID: id, Dir: a.Dir, StoreID: a.StoreID}
}

// auditReplicas is the audit indices' auto_expand_replicas for
// opensearch.replicas.
func auditReplicas(c *config.Config) string {
	if n, ok := c.OpenSearch.Replicas.IndexSettings()["number_of_replicas"].(int); ok {
		return fmt.Sprintf("%d-%d", n, n)
	}
	return ""
}

// ensureAuditTemplate saves the audit indices' template, trying again
// for a while when OpenSearch does not answer.
func ensureAuditTemplate(ctx context.Context, cl *store.Client, c *config.Config, log *slog.Logger) {
	for wait := 5 * time.Second; ; wait = min(2*wait, 5*time.Minute) {
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := audit.EnsureTemplate(tctx, cl, c.OpenSearch.IndexPrefix, auditReplicas(c))
		cancel()
		if err == nil {
			return
		}
		log.Warn("could not save the audit records' index template; trying again", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// archiveFolderEvery is how often a server reports its archive folder.
const archiveFolderEvery = 10 * time.Minute

func reportArchiveFolder(ctx context.Context, f *clusterarchive.Folders, log *slog.Logger) {
	failing := false
	for {
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := f.Report(tctx)
		cancel()
		if err != nil && !failing && ctx.Err() == nil {
			log.Warn("could not record which archive folder this server sees", "err", err)
		}
		failing = err != nil
		select {
		case <-ctx.Done():
			return
		case <-time.After(archiveFolderEvery):
		}
	}
}

// auditAPI is the Audit page's backing for this start.
func (r *runner) auditAPI(c *config.Config, cl *store.Client) *api.Audit {
	on := r.auditOn()
	var keys func() *shared.KeySet
	if sh := r.shared; sh != nil {
		keys = func() *shared.KeySet { return sh.Hub().Keys() }
	}
	return &api.Audit{Client: cl, Prefix: c.OpenSearch.IndexPrefix, Shared: func() bool { return on },
		Keys: func() audit.KeyFunc { return auditKeys(c, keys) }}
}

// auditKeys returns the audit keys of every cluster key this server
// holds, by key id: those the cluster uses now (keys, when set) and those
// kept in the state folder, retired ones included, so records signed
// before a key rotation still verify. It returns nil when there are none.
func auditKeys(c *config.Config, keys func() *shared.KeySet) audit.KeyFunc {
	byID := map[string][]byte{}
	if saved, err := (shared.KeyStore{Dir: c.StateDir(), Master: c.Keyring()}).ClusterKeys(); err == nil {
		for _, k := range saved {
			byID[k.ID()] = k.AuditKey()
		}
	}
	if keys != nil {
		set := keys()
		for _, id := range set.IDs() {
			byID[id] = set.Get(id).AuditKey()
		}
	}
	if len(byID) == 0 {
		return nil
	}
	return func(kid string) []byte { return byID[kid] }
}

// auditJobs are the background jobs of the shared archives, run by the
// server that runs the background jobs: removing archives left
// unfinished, and the daily export of the shared settings into the
// archive folder.
func (r *runner) auditJobs(c *config.Config, cl *store.Client, ret *retention.Manager) []cluster.Job {
	if !r.auditOn() {
		return nil
	}
	jobs := []cluster.Job{r.auditCheckpointJob(c, cl)}
	if ret.Archive == nil || ret.Archive.Dir == "" {
		return jobs
	}
	prefix := c.OpenSearch.IndexPrefix
	manifests := &clusterarchive.Manifests{Client: cl, Prefix: prefix, Server: r.node.Name(), NodeID: r.node.ID()}
	dir, log := ret.Archive.Dir, r.log
	return append(jobs, cluster.Job{Name: "archive housekeeping", Run: func(ctx context.Context) {
		for {
			if n, err := manifests.Housekeep(ctx, dir); err != nil {
				if ctx.Err() == nil {
					log.Warn("could not remove archives left unfinished", "err", err)
				}
			} else if n > 0 {
				log.Info("removed archives left unfinished by a server that stopped while writing them", "archives", n)
			}
			if ret.CanArchive != nil {
				if ok, _ := ret.CanArchive(); ok {
					if file, err := exportSharedSettings(ctx, cl, prefix, dir, time.Now()); err != nil {
						log.Warn("could not export the shared settings into the archive folder", "err", err)
					} else if file != "" {
						log.Info("exported the shared settings into the archive folder", "file", file)
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Hour):
			}
		}
	}})
}

// auditCheckpointEvery is how often the server that runs the background
// jobs writes an audit checkpoint.
const auditCheckpointEvery = time.Hour

// auditCheckpointJob writes an audit.checkpoint record every hour,
// naming the latest audit record of each server in OpenSearch. Removing
// the last records of a server leaves no gap any later record of its own
// would show; the checkpoint, chained in this server's records, still
// names them (see audit.Verify).
func (r *runner) auditCheckpointJob(c *config.Config, cl *store.Client) cluster.Job {
	prefix, sink, log := c.OpenSearch.IndexPrefix, r.audit.sink, r.log
	return cluster.Job{Name: "audit checkpoint", Run: func(ctx context.Context) {
		// After a few minutes first, so the records spooled at the start
		// are written.
		wait := 5 * time.Minute
		failing := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = auditCheckpointEvery
			tctx, cancel := context.WithTimeout(ctx, time.Minute)
			heads, err := audit.Heads(tctx, cl, prefix)
			cancel()
			if err != nil {
				if !failing && ctx.Err() == nil {
					log.Warn("could not read the latest audit records for the hourly audit checkpoint", "err", err)
				}
				failing = true
				continue
			}
			failing = false
			if len(heads) > 0 {
				sink.Add(audit.CheckpointEvent(heads))
			}
		}
	}}
}

// configExportDir is the folder of the daily exports of the shared
// settings, in the archive folder.
const configExportDir = "config-export"

// exportSharedSettings writes the shared settings, as stored (signed, with
// stored passwords and keys still encrypted), to
// <archive>/config-export/YYYY-MM-DD.json, once a day. It returns the file
// written, or "" when today's is there already.
func exportSharedSettings(ctx context.Context, cl *store.Client, prefix, archive string, now time.Time) (string, error) {
	dir := filepath.Join(archive, configExportDir)
	file := filepath.Join(dir, now.UTC().Format(time.DateOnly)+".json")
	if _, err := os.Stat(file); err == nil {
		return "", nil
	}
	docs, _, err := shared.ReadAll(ctx, cl, prefix)
	if err != nil {
		return "", err
	}
	type exported struct {
		ID       string          `json:"_id"`
		Envelope shared.Envelope `json:"_source"`
	}
	list := make([]exported, 0, len(docs))
	for _, d := range docs {
		list = append(list, exported{ID: d.ID, Envelope: d.Envelope})
	}
	b, err := json.MarshalIndent(map[string]any{
		"format": "signalith-config-export/1", "index": shared.ConfigIndex(prefix),
		"exported": now.UTC().Format(time.RFC3339), "documents": list,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, file); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return file, nil
}

// auditHandlers are the handlers of the archive restore request, nil
// until the archives are shared (contentHandlers).
func (r *runner) auditHandlers(ret *retention.Manager) map[string]shared.Handler {
	if !r.auditOn() {
		return nil
	}
	return clusterarchive.Handlers(ret, r.shared.Requests().SetProgress)
}

// auditImporters move the founder's retention history and archive
// manifests into OpenSearch once the cluster reaches
// shared.LevelSharedAudit, reading what this start uses when they run.
func auditImporters(f clustercfg.Files) []shared.Importer {
	opts := func() (clusterarchive.ImportOptions, *store.Client) {
		c := f.Config()
		o := clusterarchive.ImportOptions{Server: f.Node, NodeID: f.NodeID, Log: f.Log,
			HistoryFile: filepath.Join(c.LookupsDir(), "retention_history.json"),
			Archive:     &retention.Archive{Dir: c.ArchiveDir()}}
		var cl *store.Client
		if f.Client != nil {
			cl, o.Prefix = f.Client()
			if cl != nil {
				o.Client = cl
			}
		}
		return o, cl
	}
	base, _ := opts()
	list := clusterarchive.Importers(base)
	for i := range list {
		name := list[i].Name
		pick := func(o clusterarchive.ImportOptions) shared.Importer {
			for _, im := range clusterarchive.Importers(o) {
				if im.Name == name {
					return im
				}
			}
			return shared.Importer{}
		}
		list[i].Source = func() (string, error) {
			o, _ := opts()
			return pick(o).Source()
		}
		list[i].Run = func(ctx context.Context, by string) error {
			o, cl := opts()
			if cl == nil {
				return errors.New("no OpenSearch to import into yet")
			}
			if err := audit.EnsureTemplate(ctx, cl, o.Prefix, auditReplicas(f.Config())); err != nil {
				return err
			}
			return pick(o).Run(ctx, by)
		}
	}
	return list
}
