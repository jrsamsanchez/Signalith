// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterlib

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// listFile is the file of the list kind in the lookups folder.
func listFile(dir, kind string) string {
	if kind == assets.KindAssets {
		return filepath.Join(dir, assets.AssetsFile)
	}
	return filepath.Join(dir, assets.IdentitiesFile)
}

// LookupImporters returns the importer of the founder's asset and
// identity lists, which waits until the cluster is at
// shared.LevelSharedLookups. A list already shared is left as it is, and
// a list whose file is damaged is left out (with a warning), as the
// server itself does not use it.
func LookupImporters(d *Docs, f Files) []shared.Importer {
	return []shared.Importer{
		{Name: shared.ImportLookups, MinLevel: shared.LevelSharedLookups, Source: func() (string, error) {
			dir := dirOf(f.LookupsDir)
			if dir == "" {
				return "", nil
			}
			return hashFiles([]string{listFile(dir, assets.KindAssets), listFile(dir, assets.KindIdentities)})
		}, Run: func(ctx context.Context, by string) error {
			dir := dirOf(f.LookupsDir)
			b := &Lookups{Docs: d, Node: f.Node, Source: FromImport, Now: f.Now}
			for _, kind := range LookupNames {
				data, err := os.ReadFile(listFile(dir, kind))
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return err
				}
				if b.Head(kind) != nil {
					continue
				}
				if _, err := countRows(kind, data); err != nil {
					f.log().Warn("a list that cannot be read was left out of the shared settings", "file", listFile(dir, kind), "err", err)
					continue
				}
				if err := b.Put(ctx, by, kind, data, ""); err != nil {
					return err
				}
			}
			return nil
		}},
	}
}

// Once the lists are shared, each server's lookups folder is an inbox,
// like the detections folder: an assets.csv or identities.csv changed
// there (a copy from a CMDB export) is uploaded, and a list uploaded on
// any server is written back into every server's folder, where the
// server reads it. Only a file that changed since this server last saw
// it is uploaded, so a stale assets.csv left on one server never reverts
// another server's upload, and the files a server has when it starts to
// share the lists are only its starting point, as are the files of a
// new folder when the lookups folder is changed in the settings.

// LookupsSeenFileName is the record of the lists' files, in the state
// folder.
const LookupsSeenFileName = "lookups-seen.json"

// Lists is where the inbox writes a list changed on another server: an
// assets.Store, which saves it in its folder and uses it at once.
type Lists interface {
	Write(kind string, data []byte) error
}

// ListInbox keeps one server's lookups folder and the shared lists in
// step.
type ListInbox struct {
	Lookups *Lookups
	Files   Files
	Lists   Lists
	// SeenFile is where the inbox keeps what it last saw of each file.
	SeenFile string
	// Every is how often the folder is looked at, 15 seconds when 0.
	Every time.Duration

	mu   sync.Mutex
	seen map[string]string
	// seenDir is the folder the files were last seen in.
	seenDir string
	kick    chan struct{}
	kmu     sync.Mutex
}

// Kick asks for a look at the folder and the shared lists soon.
func (in *ListInbox) Kick() {
	in.kmu.Lock()
	if in.kick == nil {
		in.kick = make(chan struct{}, 1)
	}
	k := in.kick
	in.kmu.Unlock()
	select {
	case k <- struct{}{}:
	default:
	}
}

// Run keeps the folder and the shared lists in step until ctx ends.
func (in *ListInbox) Run(ctx context.Context) {
	in.Kick()
	in.kmu.Lock()
	k := in.kick
	in.kmu.Unlock()
	every := in.Every
	if every <= 0 {
		every = 15 * time.Second
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-k:
		case <-time.After(every):
		}
		if err := in.Sync(ctx); err != nil && ctx.Err() == nil {
			in.Files.log().Warn("could not bring the asset and identity lists in step with the shared settings; trying again", "err", err)
		}
	}
}

// Sync uploads a list file changed in the folder, writes back a list
// changed on another server, and deletes the chunks of lists replaced
// long enough ago.
func (in *ListInbox) Sync(ctx context.Context) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	baseline, err := in.loadSeen()
	if err != nil {
		return err
	}
	dir := dirOf(in.Files.LookupsDir)
	if !baseline && in.seenDir != "" && in.seenDir != dir {
		// The folder was changed in the settings: a stale list in the new
		// one is a starting point, and the shared list is written back.
		in.Files.log().Warn("the lookups folder changed; the files in it are a starting point and the shared lists are written back into it", "was", in.seenDir, "now", dir)
		baseline = true
	}
	in.seenDir = dir
	writable := in.Lookups.Writable == nil || in.Lookups.Writable() == nil
	var errs []error
	for _, kind := range LookupNames {
		data, err := os.ReadFile(listFile(dir, kind))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		local := ""
		if data != nil {
			local = hashOf(data)
		}
		if baseline {
			in.seen[kind] = local
		}
		head := in.Lookups.Head(kind)
		switch {
		case head != nil && head.SHA256 == local:
			in.seen[kind] = local
		case local != "" && local != in.seen[kind]:
			// Changed here since this server last saw it: upload it.
			if !writable {
				continue
			}
			if _, err := countRows(kind, data); err != nil {
				in.Files.log().Warn("a list file that cannot be read was not shared; fix it and it is shared then", "file", listFile(dir, kind), "err", err)
				in.seen[kind] = local
				continue
			}
			up := *in.Lookups
			up.Source = FromFile
			if err := up.Put(ctx, "file on "+in.Files.Node, kind, data, ""); err != nil {
				errs = append(errs, err)
				continue
			}
			in.seen[kind] = local
		case head != nil:
			// Changed on another server, and not here: write it back.
			list, h, err := in.Lookups.Read(ctx, kind)
			if err != nil || h == nil {
				errs = append(errs, err)
				continue
			}
			if err := in.Lists.Write(kind, list); err != nil {
				errs = append(errs, err)
				continue
			}
			in.seen[kind] = h.SHA256
		}
	}
	if writable {
		errs = append(errs, in.Lookups.Housekeep(ctx, "signalith"))
	}
	errs = append(errs, in.saveSeen())
	return errors.Join(errs...)
}

func (in *ListInbox) loadSeen() (bool, error) {
	if in.seen != nil {
		return false, nil
	}
	in.seen = map[string]string{}
	data, err := os.ReadFile(in.SeenFile)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		in.seen = nil
		return false, err
	}
	var s struct {
		Files map[string]string `json:"files"`
		Dir   string            `json:"dir"`
	}
	if json.Unmarshal(data, &s) != nil || s.Files == nil {
		return true, nil
	}
	in.seen = s.Files
	in.seenDir = s.Dir
	return false, nil
}

func (in *ListInbox) saveSeen() error {
	data, err := json.MarshalIndent(map[string]any{"version": 1, "files": in.seen, "dir": in.seenDir}, "", "  ")
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(in.SeenFile); err == nil && string(cur) == string(data) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(in.SeenFile), 0o750); err != nil {
		return err
	}
	return securefile.WriteFile(in.SeenFile, data)
}
