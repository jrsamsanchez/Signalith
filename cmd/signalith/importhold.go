package main

import (
	"context"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// When this server founds the cluster (or the cluster's level brings a
// feature in), its importers read its own files into the shared
// settings, and a restart in place then switches the components to them
// (followShared). Until that restart, the components of the start
// running now still save the pages to the files: a save made after the
// importer read them would go to a file that is no longer read, and be
// lost. So each importer of a page's file holds that file while it reads
// and moves it (importHold), and a save there takes the same hold:
// one made before the move moves with it, and one made after is refused
// with a shared.MovingError, which the pages show as "try again in a
// moment", until the restart, after which the page saves to the shared
// settings. The settings of the Settings page do the same with ownMu
// (settingsStore.HoldFile), and save to the shared settings instead.
//
// The feeds' status and the users' last sign-ins are not held: losing
// one only means a feed downloads sooner, or a sign-in time shows older.

// movingWhat names, by importer, the files a save is refused for while
// they move, as the pages say it.
var movingWhat = map[string]string{
	clustercfg.ImportFeeds:     "threat intel feeds",
	clustercfg.ImportRetention: "retention policies",
	shared.ImportUsers:         "users",
	shared.ImportDirectory:     "directory sign-in settings",
}

// importHold is the hold of one importer's files.
type importHold struct {
	mu sync.Mutex
	// cluster is the id of the cluster this server moved them into, once
	// its importer ran (under mu): the cluster document records the
	// import only after.
	cluster string
}

// importHolds are the holds, by importer.
type importHolds struct {
	mu sync.Mutex
	m  map[string]*importHold
}

func (h *importHolds) get(name string) *importHold {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.m == nil {
		h.m = map[string]*importHold{}
	}
	if h.m[name] == nil {
		h.m[name] = &importHold{}
	}
	return h.m[name]
}

// holdImporters makes each importer of a page's file hold it while it
// runs (see above).
func (ct *sharedContent) holdImporters(list []shared.Importer) []shared.Importer {
	for i, im := range list {
		if _, ok := movingWhat[im.Name]; !ok || im.Run == nil {
			continue
		}
		run, h := im.Run, ct.holds.get(im.Name)
		list[i].Run = func(ctx context.Context, by string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			if err := run(ctx, by); err != nil {
				return err
			}
			if rt := ct.rt.Load(); rt != nil && rt.Cluster() != nil {
				if b, ok := rt.Cluster().Get(); ok {
					h.cluster = b.ClusterID
				}
			}
			if hook := importHoldHook; hook != nil {
				hook(im.Name)
			}
			return nil
		}
	}
	return list
}

// importHoldHook, when set (tests), runs as an importer of a page's file
// ends, still holding it.
var importHoldHook func(name string)

// moving reports whether the files of the importer name moved, or are
// moving, into the shared settings of the cluster this server is in:
// its importer ran here, or the cluster document records that it ran.
// A component that still keeps them in this server's files then waits
// for the restart that switches it to the shared settings. The caller
// holds h.mu.
func (ct *sharedContent) moving(name string, h *importHold) bool {
	rt := ct.rt.Load()
	if rt == nil {
		return false
	}
	if m, _ := rt.Mode(); m.Legacy() {
		return false
	}
	cdoc := rt.Cluster()
	if cdoc == nil {
		return false
	}
	b, ok := cdoc.Get()
	if !ok {
		return false
	}
	if h.cluster != "" && h.cluster == b.ClusterID {
		return true
	}
	_, done := b.Import.Done[name]
	return done
}

// holdFile returns the hold of the files of the importer name for a
// save there (users.Store.Hold): it refuses the save once they moved
// into the shared settings. nil without a runtime.
func (ct *sharedContent) holdFile(name string) func() (func(), error) {
	if ct == nil {
		return nil
	}
	h := ct.holds.get(name)
	return func() (func(), error) {
		h.mu.Lock()
		if ct.moving(name, h) {
			h.mu.Unlock()
			return nil, &shared.MovingError{What: movingWhat[name]}
		}
		return h.mu.Unlock, nil
	}
}

// holdFeeds makes the feeds of a start that keeps them in this server's
// file hold it for each change (holdFile).
func (ct *sharedContent) holdFeeds(f *intel.Feeds) {
	if ct == nil {
		return
	}
	f.Saved = heldFeeds{FeedList: &intel.FileList{Path: f.File, Now: f.Now, Log: f.Log}, hold: ct.holdFile(clustercfg.ImportFeeds)}
}

// holdRetention makes the retention policies of a start that keeps them
// in this server's file hold it for each change (holdFile).
func (ct *sharedContent) holdRetention(ret *retention.Manager) {
	if ct == nil || ret.Store == nil {
		return
	}
	ret.Store = heldPolicies{PolicyStore: ret.Store, hold: ct.holdFile(clustercfg.ImportRetention)}
}

// heldFeeds is a feed list in this server's file, held for each change.
type heldFeeds struct {
	intel.FeedList
	hold func() (func(), error)
}

func (l heldFeeds) Mutate(ctx context.Context, by string, fn func(*intel.FeedSet) error) (intel.FeedSet, error) {
	release, err := l.hold()
	if err != nil {
		return intel.FeedSet{}, err
	}
	defer release()
	return l.FeedList.Mutate(ctx, by, fn)
}

// heldPolicies are retention policies in this server's file, held for
// each change.
type heldPolicies struct {
	retention.PolicyStore
	hold func() (func(), error)
}

func (p heldPolicies) Update(change func(*retention.Saved)) error {
	release, err := p.hold()
	if err != nil {
		return err
	}
	defer release()
	return p.PolicyStore.Update(change)
}
