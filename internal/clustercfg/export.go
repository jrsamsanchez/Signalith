package clustercfg

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Exporters return the exporters of the shared settings (signalith
// cluster export --to-files), the inverse of Importers, each named as the
// importer it inverts: the feed list (intel_feeds.yaml: the feeds of
// signalith.yaml go there too), the feeds' status (intel_feeds.json), the
// retention policies (retention.yaml), the settings of the Settings page
// (settings.yaml: the shared values and the -server server's own), and,
// when d has the users' documents, the users (users.json, password hashes
// as stored; the built-in admin stays in signalith.yaml) and the
// directory sign-in settings (directory.json). Each writes with the file
// store of the package that reads it, so the format is the one a server
// on its own reads, and passwords and keys are sealed with this server's
// master key.
func Exporters(d *Docs, f Files) []shared.Exporter {
	out := []shared.Exporter{
		{Name: ImportFeeds, Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
			return exportFeeds(d, f, t)
		}},
		{Name: "feed_status", Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
			return exportFeedStatus(ctx, f, t)
		}},
		{Name: ImportRetention, Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
			return exportRetention(d, f, t)
		}},
	}
	if a := d.Auth(); a != nil {
		out = append(out,
			shared.Exporter{Name: shared.ImportUsers, Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
				return exportUsers(ctx, a, f, t)
			}},
			shared.Exporter{Name: shared.ImportDirectory, Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
				return exportDirectory(ctx, a, f, t)
			}})
	}
	return append(out, shared.Exporter{Name: shared.ImportSettings, Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
		return exportSettings(ctx, d, f, t)
	}})
}

// exportPath returns where the file this server keeps at dest goes in
// the export, with its folder made.
func exportPath(t shared.ExportTarget, dest string) (string, error) {
	p := t.Under(dest)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return "", err
	}
	return p, nil
}

func exportFeeds(d *Docs, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	body, ok := d.Feeds().Get()
	if !ok {
		return nil, nil
	}
	open := opener(d.Hub().Keys())
	var set intel.FeedSet
	secret := false
	for _, e := range body.Feeds {
		e.Headers = maps.Clone(e.Headers)
		_ = eachSecret(&e, func(part, v string) (string, error) {
			plain, err := open.Open(SecretField(e.Name, part, e.URL), v)
			if err != nil {
				t.Logger().Warn("a feed's password or header cannot be opened with this server's cluster keys, so it is left out; enter it again after the downgrade",
					"feed", e.Name, "secret", part, "err", err)
				return "", nil
			}
			secret = true
			return plain, nil
		})
		s := specOf(e, open)
		s.From = ""
		set.UI = append(set.UI, s)
	}
	for _, k := range body.Kept {
		set.Kept = append(set.Kept, intel.KeptFeed{Name: k.Name, Until: k.Until})
	}
	dest := f.Config().IntelFeedsFile()
	p, err := exportPath(t, dest)
	if err != nil {
		return nil, err
	}
	if _, err := (&intel.FileList{Path: p, Now: f.Now, Log: t.Log}).Mutate(context.Background(), "", func(s *intel.FeedSet) error {
		*s = set
		return nil
	}); err != nil {
		return nil, err
	}
	return []shared.ExportedFile{{Path: p, Dest: dest, Secret: secret}}, nil
}

func exportFeedStatus(ctx context.Context, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	if f.Client == nil {
		return nil, errors.New("no OpenSearch to read the feeds' status from")
	}
	cl, prefix := f.Client()
	st := &StatusStore{Client: cl, Index: cluster.RuntimeIndex(prefix), Node: f.NodeID}
	all, err := st.read(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not read the feeds' status: %w", err)
	}
	if len(all) == 0 {
		return nil, nil
	}
	dest := FeedStatusFile(f.Config())
	p, err := exportPath(t, dest)
	if err != nil {
		return nil, err
	}
	sf := &intel.StatusFile{Path: p, Log: t.Log}
	for _, name := range slices.Sorted(maps.Keys(all)) {
		s := all[name]
		s.Running = false
		sf.Save(name, s)
	}
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("could not write %s: %w", p, err)
	}
	return []shared.ExportedFile{{Path: p, Dest: dest}}, nil
}

func exportRetention(d *Docs, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	body, ok := d.Retention().Get()
	if !ok {
		return nil, nil
	}
	if body.Confirm != nil {
		t.Logger().Warn("the shared retention policies wait to be confirmed; a server on its own has no such hold, so they apply as soon as it starts")
	}
	dest := RetentionFile(f.Config())
	p, err := exportPath(t, dest)
	if err != nil {
		return nil, err
	}
	saved := body.saved()
	saved.From = nil
	if err := retention.NewStore(p).Update(func(s *retention.Saved) { *s = saved }); err != nil {
		return nil, err
	}
	return []shared.ExportedFile{{Path: p, Dest: dest}}, nil
}

func exportUsers(ctx context.Context, a *clusterauth.Docs, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	list := a.Users().List()
	if len(list) == 0 {
		return nil, nil
	}
	recs, err := (&clusterauth.UsersBackend{Docs: a}).Load()
	if err != nil {
		return nil, err
	}
	var builtinLast *time.Time
	if f.Client != nil {
		seen, err := (&clusterauth.LastSeen{Client: f.Client, Node: f.Node}).All(ctx)
		if err != nil {
			t.Logger().Warn("the users' last sign-ins cannot be read, so they are left out", "err", err)
		}
		for name, r := range recs {
			if s, ok := seen[strings.ToLower(name)]; ok {
				at := s.At
				r.LastSignIn = &at
				recs[name] = r
			}
		}
		if s, ok := seen[strings.ToLower(a.BuiltinName())]; ok && a.BuiltinName() != "" {
			at := s.At
			builtinLast = &at
		}
	}
	for name, r := range recs {
		r.ETag = ""
		recs[name] = r
	}
	dest := f.Config().UsersFile()
	p, err := exportPath(t, dest)
	if err != nil {
		return nil, err
	}
	if err := users.WriteFile(p, recs, builtinLast); err != nil {
		return nil, err
	}
	return []shared.ExportedFile{{Path: p, Dest: dest, Secret: true}}, nil
}

func exportDirectory(ctx context.Context, a *clusterauth.Docs, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	if _, ok := a.Directory().Get(); !ok {
		return nil, nil
	}
	s, ok, problem := (&clusterauth.DirectoryBackend{Docs: a, Node: f.Node}).Load()
	if !ok {
		return nil, nil
	}
	if problem != "" {
		t.Logger().Warn("the directory sign-in service account password cannot be opened, so it is left out; enter it again on the Users page after the downgrade", "problem", problem)
	}
	dest := f.Config().DirectoryFile()
	p, err := exportPath(t, dest)
	if err != nil {
		return nil, err
	}
	dir, err := users.OpenDirectory(p, nil)
	if err != nil {
		return nil, err
	}
	if err := dir.Save(ctx, s); err != nil {
		return nil, err
	}
	return []shared.ExportedFile{{Path: p, Dest: dest, Secret: s.BindPassword != ""}}, nil
}

// exportSettings writes settings.yaml: every shared setting as a change
// of the Settings page (passwords and keys sealed again with this server's
// master key), and the own settings of the server t.Server. The shared
// agent tokens of older setups are left out: they came from signalith.yaml
// or the environment, where they still are.
func exportSettings(ctx context.Context, d *Docs, f Files, t shared.ExportTarget) ([]shared.ExportedFile, error) {
	keys := d.Hub().Keys()
	page := &config.PageSettings{}
	secret := false
	if b, ok := d.Settings().Get(); ok {
		for _, key := range slices.Sorted(maps.Keys(b.Values)) {
			sv := b.Values[key]
			if _, known := config.Lookup(key); !known {
				// A setting of a later version: left out.
				continue
			}
			if sv.Secret != "" {
				plain, err := openFor(keys, key, sv.Secret, sv.SentTo)
				if err != nil {
					t.Logger().Warn("a shared password or key cannot be opened with this server's cluster keys, so it is left out; enter it again after the downgrade",
						"setting", key, "err", err)
					continue
				}
				if err := page.SetSecret(key, plain, sv.SentTo, sv.From.By, sv.From.At); err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
				secret = true
				continue
			}
			if len(sv.Value) == 0 {
				continue
			}
			if err := page.Set(key, valueOf(key, sv.Value), sv.From.By, sv.From.At); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	nc, err := exportNodeCfg(ctx, d, f, t.Server)
	if err != nil {
		return nil, err
	}
	if nc != nil {
		for _, key := range slices.Sorted(maps.Keys(nc.Values)) {
			e := pageEntryOf(key, nc.Values[key])
			e.Refused, e.RefusedAt = "", time.Time{}
			if page.Settings == nil {
				page.Settings = map[string]*config.PageEntry{}
			}
			page.Settings[key] = e
		}
	}
	if page.Empty() {
		return nil, nil
	}
	dest := f.Config().SettingsFile()
	p, err := exportPath(t, dest)
	if err != nil {
		return nil, err
	}
	if err := config.WritePageSettings(p, page); err != nil {
		return nil, err
	}
	return []shared.ExportedFile{{Path: p, Dest: dest, Secret: secret}}, nil
}

// exportNodeCfg reads the nodecfg document of server nodeID: this
// server's from its own copy, another's from OpenSearch.
func exportNodeCfg(ctx context.Context, d *Docs, f Files, nodeID string) (*shared.NodeCfg, error) {
	if nodeID == "" || nodeID == f.NodeID {
		if f.NodeCfg == nil || f.NodeCfg() == nil {
			return nil, nil
		}
		nc, _ := f.NodeCfg().Get()
		return nc, nil
	}
	nc, _, _, err := shared.RemoteNodeCfg(d.Hub(), nodeID).Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not read the own settings of %s: %w", nodeID, err)
	}
	return nc, nil
}
