package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/clusterlib"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// The shared library: the custom detections, the choices made for the
// shipped ones and the custom dashboards. Once the cluster is at
// shared.LevelSharedLibrary and the founder's folders were imported,
// every member reads and changes them in OpenSearch
// (internal/clusterlib), and its folders become inboxes: a file changed
// there is shared, and a change made on any server is written back. Any
// other server keeps using its folders, as before.

// sharedLibrary links the shared library's documents to the components
// of each start. Like the runtime, it belongs to the process.
type sharedLibrary struct {
	docs *clusterlib.Docs
	node *cluster.Node
	log  *slog.Logger
	cfg  func() *config.Config
	// on is true while the components running now take the library from
	// the shared settings.
	on atomic.Bool
}

func newSharedLibrary(docs *clusterlib.Docs, node *cluster.Node, cfg func() *config.Config, log *slog.Logger) *sharedLibrary {
	return &sharedLibrary{docs: docs, node: node, log: log, cfg: cfg}
}

// libraryFiles is what the library's importers read: the detections and
// dashboards folders of the configuration in use.
func libraryFiles(f clustercfg.Files) clusterlib.Files {
	return clusterlib.Files{
		DetectionsDir: func() string { return f.Config().DetectionsDir() },
		DashboardsDir: func() string { return f.Config().DashboardsDir() },
		Node:          f.Node,
		Log:           f.Log,
		Now:           f.Now,
	}
}

// files is what the inbox reads: this server's folders.
func (l *sharedLibrary) files() clusterlib.Files {
	return clusterlib.Files{
		DetectionsDir: func() string { return l.cfg().DetectionsDir() },
		DashboardsDir: func() string { return l.cfg().DashboardsDir() },
		Node:          l.node.Name(),
		Log:           l.log,
	}
}

// start makes lib and boards keep their detections and dashboards in the
// shared settings when on, and keeps this server's folders in step with
// them in jobs until ctx ends. Off, they keep using the folders.
func (l *sharedLibrary) start(ctx context.Context, rt *shared.Runtime, on bool, c *config.Config, lib *detect.Library, boards *dashboards.Store, jobs *sync.WaitGroup) error {
	l.on.Store(on)
	if !on {
		return nil
	}
	name := l.node.Name()
	if err := lib.UseBackend(&clusterlib.Detections{Docs: l.docs, Node: name, Writable: rt.Writable}); err != nil {
		return err
	}
	boards.UseBackend(&clusterlib.Dashboards{Docs: l.docs, Node: name, Writable: rt.Writable})
	in := &clusterlib.Inbox{Docs: l.docs, Files: l.files(), SeenFile: filepath.Join(c.StateDir(), clusterlib.SeenFileName),
		Mirror: func() bool { return c.Detections.Sync == config.SyncMirror }, Writable: rt.Writable}
	l.docs.OnDetections(in.Kick)
	l.docs.OnDashboards(in.Kick)
	jobs.Go(func() { in.Run(ctx) })
	n := len(lib.List())
	list, _, _ := boards.List()
	l.log.Info("detections and dashboards come from the shared settings; this server's folders are an inbox for them",
		"detections", n, "dashboards", len(list))
	return nil
}
