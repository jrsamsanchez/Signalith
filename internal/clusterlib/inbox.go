// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterlib

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Once the library is shared, each server's detections and dashboards
// folders are inboxes: a file added or changed there (a git pull, a copy)
// is pushed to the shared library, and a change made on any server is
// written back into every server's folder, so the folders keep showing
// what runs.
//
// Each server keeps, in SeenFile, the hash of every file as it last
// pushed it, wrote it or found it. Only a file whose content differs from
// that is pushed, so a stale file left in one server's folder never
// reverts a change made on another; the files a server has when it
// starts to share the library are only its starting point. A file
// removed from the folder removes the shared item only when Mirror says
// so (detections.sync: mirror). A folder that is missing or cannot be
// read is not taken for an empty one: nothing is pushed until it is
// back. When a folder is changed in the settings, what the new one holds
// is a starting point too, as the record names files by ID and not by
// folder.
//
// With Mirror, one pass that would remove many shared items at once (see
// massDelete) is refused, as a folder found empty (a volume made again,
// an rsync --delete from an empty folder) would otherwise delete the
// whole library on every server: the removals are not pushed and the
// files are written back. An AllowDeleteFile in the folder allows it
// once.

// SeenFileName is the inbox's record of the files, in the state folder.
const SeenFileName = "library-seen.json"

// AllowDeleteFile, in the detections or the dashboards folder, allows
// the next pass of Mirror to remove many shared items at once. It is
// removed once used.
const AllowDeleteFile = "allow-mass-delete"

// massDelete reports whether removing gone of the total files the record
// holds is too many for one pass: all of them, or more than 20 and more
// than half, once there are 3 or more.
func massDelete(gone, total int) bool {
	return gone >= 3 && (gone == total || gone > 20 && 2*gone > total)
}

// refusedFor is how long a refused mass removal stays a problem of this
// server, for the Servers page.
const refusedFor = 24 * time.Hour

// Inbox keeps one server's folders and the shared library in step.
type Inbox struct {
	Docs  *Docs
	Files Files
	// SeenFile is where the inbox keeps what it last saw of each file.
	SeenFile string
	// Mirror reports whether a file removed from a folder removes the
	// shared item.
	Mirror func() bool
	// Writable refuses pushes while the shared settings cannot be
	// changed (the files are then pushed later).
	Writable func() error
	// Every is how often the folders are looked at, 15 seconds when 0.
	Every time.Duration

	mu     sync.Mutex
	seen   *seenFile
	kick   chan struct{}
	kickMu sync.Mutex
	// refused is the last mass removal refused, for Problems.
	refused atomic.Pointer[refusal]
}

type refusal struct {
	at   time.Time
	text string
}

// Problems says what the Servers page should show about the folders:
// a mass removal refused in the last day.
func (in *Inbox) Problems() []string {
	r := in.refused.Load()
	if r == nil || in.Files.now().Sub(r.at) > refusedFor {
		return nil
	}
	return []string{r.text}
}

type seenFile struct {
	Version int                   `json:"version"`
	Files   map[string]*seenEntry `json:"files"`
	// Dirs is the folder the files of each area were read from.
	Dirs map[string]string `json:"dirs,omitempty"`
}

// seenEntry is what the inbox last saw of one file: its hash, and
// whether it holds a shared item (written back, pushed or found equal),
// so it is removed when the item is deleted elsewhere.
type seenEntry struct {
	SHA256 string `json:"sha256"`
	Shared bool   `json:"shared,omitempty"`
}

// The folders of the files, as the record names them.
const (
	areaDetections = "detections"
	areaDashboards = "dashboards"
)

// file is one file of the folders, by its name in the record
// (detections/<id>.yaml, detections/state/<id>.yaml or
// dashboards/<id>.yaml).
type file struct {
	path string
	data []byte
	hash string
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Kick asks for a look at the folders and the shared library soon.
func (in *Inbox) Kick() {
	in.kickMu.Lock()
	if in.kick == nil {
		in.kick = make(chan struct{}, 1)
	}
	k := in.kick
	in.kickMu.Unlock()
	select {
	case k <- struct{}{}:
	default:
	}
}

// Run keeps the folders and the shared library in step until ctx ends:
// at once, every Every, and soon after a shared change.
func (in *Inbox) Run(ctx context.Context) {
	in.Kick()
	in.kickMu.Lock()
	k := in.kick
	in.kickMu.Unlock()
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
			in.Files.log().Warn("could not bring the detections and dashboards folders in step with the shared library; trying again", "err", err)
		}
	}
}

// Sync pushes the files changed in the folders, then writes the shared
// library back into them.
func (in *Inbox) Sync(ctx context.Context) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	seen, baseline, err := in.loadSeen()
	if err != nil {
		return err
	}
	dirs := in.dirs()
	// A record of other folders says nothing of these: the folders were
	// changed in the settings, and what the new ones hold is a starting
	// point, not the removal of every file of the old ones. A record
	// written before the folders were kept in it takes them as they are.
	moved := !baseline && seen.Dirs != nil && !maps.Equal(seen.Dirs, dirs)
	files, err := in.scan(seen, baseline || moved)
	if err != nil {
		return err
	}
	if moved {
		in.Files.log().Warn("the detections or dashboards folder changed; the files in it are a starting point and the shared library is written back into it", "was", seen.Dirs, "now", dirs)
		seen.Files = map[string]*seenEntry{}
		baseline = true
	}
	seen.Dirs = dirs
	var errs []error
	if baseline {
		// What a server has when it starts to share the library is its
		// starting point, not a change.
		for name, f := range files {
			seen.Files[name] = &seenEntry{SHA256: f.hash}
		}
	} else if in.Writable == nil || in.Writable() == nil {
		errs = append(errs, in.push(ctx, seen, files))
	}
	errs = append(errs, in.writeBack(seen, files))
	errs = append(errs, in.saveSeen(seen))
	return errors.Join(errs...)
}

func (in *Inbox) loadSeen() (*seenFile, bool, error) {
	if in.seen != nil {
		return in.seen, false, nil
	}
	s := &seenFile{Version: 1, Files: map[string]*seenEntry{}}
	data, err := os.ReadFile(in.SeenFile)
	if errors.Is(err, fs.ErrNotExist) {
		in.seen = s
		return s, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		// A damaged record: start again from what is there now.
		in.Files.log().Warn("the record of the detections and dashboards files is damaged; starting again from the files as they are", "file", in.SeenFile, "err", err)
		s = &seenFile{Version: 1, Files: map[string]*seenEntry{}}
		in.seen = s
		return s, true, nil
	}
	if s.Files == nil {
		s.Files = map[string]*seenEntry{}
	}
	in.seen = s
	return s, false, nil
}

func (in *Inbox) saveSeen(s *seenFile) error {
	data, err := json.MarshalIndent(s, "", "  ")
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

// dirs returns the folders in use now, by area.
func (in *Inbox) dirs() map[string]string {
	return map[string]string{areaDetections: dirOf(in.Files.DetectionsDir), areaDashboards: dirOf(in.Files.DashboardsDir)}
}

// scan reads the files of the folders. A folder that cannot be read
// fails the scan, and so does a missing one the record holds files of
// (unless fresh: the record is started again), as taking it for empty
// would remove them all with Mirror.
func (in *Inbox) scan(seen *seenFile, fresh bool) (map[string]*file, error) {
	out := map[string]*file{}
	add := func(name, dir string) error {
		paths, err := readYAMLDir(dir)
		if errors.Is(err, fs.ErrNotExist) && (fresh || !recorded(seen, name)) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("the folder %s cannot be read, so nothing is pushed from it: %w", dir, err)
		}
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			out[name+"/"+filepath.Base(p)] = &file{path: p, data: data, hash: hashOf(data)}
		}
		return nil
	}
	if dir := dirOf(in.Files.DetectionsDir); dir != "" {
		if err := add(areaDetections, dir); err != nil {
			return nil, err
		}
		if err := add(areaDetections+"/"+detect.StateDir, filepath.Join(dir, detect.StateDir)); err != nil {
			return nil, err
		}
	}
	if dir := dirOf(in.Files.DashboardsDir); dir != "" {
		if err := add(areaDashboards, dir); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readYAMLDir lists the *.yaml files in dir, sorted, and fails when dir
// cannot be read.
func readYAMLDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

// recorded reports whether the record holds a file of the folder area
// (detections, detections/state or dashboards).
func recorded(seen *seenFile, area string) bool {
	for name := range seen.Files {
		if path.Dir(name) == area {
			return true
		}
	}
	return false
}

// kindOf says what a file of the record holds: a detection, a state or
// a dashboard, and its ID.
func kindOf(name string) (kind, id string) {
	id = strings.TrimSuffix(name[strings.LastIndex(name, "/")+1:], ".yaml")
	switch {
	case strings.HasPrefix(name, areaDetections+"/"+detect.StateDir+"/"):
		return "state", id
	case strings.HasPrefix(name, areaDetections+"/"):
		return DetectionKind, id
	default:
		return DashboardKind, id
	}
}

// push sends the files that changed since they were last seen, and with
// Mirror the removal of the files that are gone, to the shared library.
func (in *Inbox) push(ctx context.Context, seen *seenFile, files map[string]*file) error {
	type change struct {
		name string
		f    *file // nil: the file was removed
	}
	dets := map[string][]change{}
	boards := map[string][]change{}
	for name, f := range files {
		if e := seen.Files[name]; e != nil && e.SHA256 == f.hash {
			continue
		}
		kind, id := kindOf(name)
		if kind == DashboardKind {
			boards[id] = append(boards[id], change{name, f})
		} else {
			dets[id] = append(dets[id], change{name, f})
		}
	}
	mirror := in.Mirror != nil && in.Mirror()
	var gone []string
	for name := range seen.Files {
		if _, ok := files[name]; ok {
			continue
		}
		if !mirror {
			delete(seen.Files, name)
			continue
		}
		gone = append(gone, name)
	}
	log := in.Files.log()
	// allowed is the AllowDeleteFiles used, removed once the removal is
	// shared.
	var allowed []string
	if massDelete(len(gone), len(seen.Files)) {
		if allowed = in.allowFiles(); len(allowed) > 0 {
			log.Warn("removing many detections and dashboards from the shared library, as their files are gone from this server's folders and a file allowed it",
				"audit", true, "by", "file on "+in.Files.Node, "files", len(gone), "of", len(seen.Files), "allowed_by", allowed[0])
			in.refused.Store(nil)
		} else {
			text := fmt.Sprintf("Refused to remove %d of the %d shared detection and dashboard files at once. Their files are gone from this server's folders "+
				"(%s), which looks like an empty or replaced folder rather than a change, so nothing was removed from the shared library and the files were written back. "+
				"To remove them on purpose, put a file named %s in the detections folder and remove the files again.",
				len(gone), len(seen.Files), in.folders(), AllowDeleteFile)
			log.Warn("refused to remove many detections and dashboards from the shared library: their files are gone from this server's folders; nothing was removed",
				"audit", true, "by", "file on "+in.Files.Node, "files", len(gone), "of", len(seen.Files), "folders", in.folders(), "allow_file", AllowDeleteFile)
			in.refused.Store(&refusal{at: in.Files.now(), text: text})
			gone = nil
		}
	}
	for _, name := range gone {
		kind, id := kindOf(name)
		if kind == DashboardKind {
			boards[id] = append(boards[id], change{name, nil})
		} else {
			dets[id] = append(dets[id], change{name, nil})
		}
	}
	by := "file on " + in.Files.Node
	from := stamp(FromFile, in.Files.Node, in.Files.now())
	// done records what was pushed, or could not be (a file that is not
	// valid waits until it changes again).
	done := func(cs []change) {
		for _, c := range cs {
			if c.f == nil {
				delete(seen.Files, c.name)
			} else {
				seen.Files[c.name] = &seenEntry{SHA256: c.f.hash, Shared: true}
			}
		}
	}
	var errs []error
	if len(dets) > 0 {
		ids := sortedKeys(dets)
		_, _, err := in.Docs.Detections().MutateMany(ctx, by, ids, func(id string, cur *DetectionBody) (*DetectionBody, bool, error) {
			next := &DetectionBody{}
			if cur != nil {
				*next = *cur
			}
			for _, c := range dets[id] {
				kind, _ := kindOf(c.name)
				switch {
				case c.f == nil && kind == "state":
					next.State = nil
				case c.f == nil:
					next.YAML = ""
				case kind == "state":
					st, err := decodeStateFile(id, c.f.data)
					if err != nil {
						log.Warn("a detection state file is not valid, so it was not shared", "file", c.f.path, "err", err)
						continue
					}
					next.State = st
				default:
					if _, err := decodeDetectionFile(id+".yaml", c.f.data); err != nil {
						log.Warn("a detection file is not valid, so it was not shared", "file", c.f.path, "err", err)
						continue
					}
					next.YAML = string(c.f.data)
				}
			}
			if next.YAML == "" && next.State == nil {
				if cur == nil {
					return nil, false, nil
				}
				return nil, true, nil
			}
			if cur != nil && sameDetection(id, cur, next) {
				return nil, false, nil
			}
			next.From = from
			return next, true, nil
		})
		if err != nil {
			errs = append(errs, err)
		} else {
			for _, id := range ids {
				done(dets[id])
			}
			log.Info("pushed detection files changed in the folder to the shared library", "count", len(ids))
		}
	}
	if len(boards) > 0 {
		ids := sortedKeys(boards)
		_, _, err := in.Docs.Dashboards().MutateMany(ctx, by, ids, func(id string, cur *DashboardBody) (*DashboardBody, bool, error) {
			c := boards[id][0]
			if c.f == nil {
				return nil, cur != nil, nil
			}
			if dashboards.IsBuiltin(id) {
				return nil, false, nil
			}
			d, err := dashboards.DecodeFile(id+".yaml", c.f.data)
			if err != nil {
				log.Warn("a dashboard file is not valid, so it was not shared", "file", c.f.path, "err", err)
				return nil, false, nil
			}
			if cur != nil {
				if have, err := cur.decode(id); err == nil && dashboards.ETag(have) == dashboards.ETag(d) {
					return nil, false, nil
				}
			}
			body := &DashboardBody{YAML: string(c.f.data), From: from}
			if cur != nil {
				body.Extra = cur.Extra
			}
			return body, true, nil
		})
		if err != nil {
			errs = append(errs, err)
		} else {
			for _, id := range ids {
				done(boards[id])
			}
			log.Info("pushed dashboard files changed in the folder to the shared library", "count", len(ids))
		}
	}
	if len(errs) == 0 {
		for _, p := range allowed {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Warn("could not remove the file that allowed removing many detections and dashboards; remove it by hand", "file", p, "err", err)
			}
		}
	}
	return errors.Join(errs...)
}

// allowFiles lists the AllowDeleteFiles in the folders.
func (in *Inbox) allowFiles() []string {
	var out []string
	for _, dir := range []string{dirOf(in.Files.DetectionsDir), dirOf(in.Files.DashboardsDir)} {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, AllowDeleteFile)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// folders names the detections and dashboards folders, for messages.
func (in *Inbox) folders() string {
	var out []string
	for _, dir := range []string{dirOf(in.Files.DetectionsDir), dirOf(in.Files.DashboardsDir)} {
		if dir != "" && !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}
	return strings.Join(out, ", ")
}

// sameDetection reports whether two bodies hold the same detection and
// state, however their files are laid out.
func sameDetection(id string, a, b *DetectionBody) bool {
	da, sa, err1 := a.decode(id)
	db, sb, err2 := b.decode(id)
	return err1 == nil && err2 == nil && detect.ETag(da, sa) == detect.ETag(db, sb)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// want is a file the shared library says a folder should hold: its
// content, and how to tell a file that holds the same however laid out.
type want struct {
	data []byte
	same func([]byte) bool
}

// wanted lists the files the shared library says the folders should
// hold, by their name in the record.
func (in *Inbox) wanted() map[string]want {
	out := map[string]want{}
	if dirOf(in.Files.DetectionsDir) != "" {
		for _, it := range in.Docs.Detections().List() {
			if it.Value == nil {
				continue
			}
			d, st, err := it.Value.decode(it.Name)
			if err != nil {
				continue
			}
			if d != nil {
				etag := detect.ETag(d, nil)
				out[areaDetections+"/"+it.Name+".yaml"] = want{data: []byte(it.Value.YAML), same: func(data []byte) bool {
					have, err := decodeDetectionFile(it.Name+".yaml", data)
					return err == nil && detect.ETag(have, nil) == etag
				}}
			}
			if st != nil {
				data, err := detect.EncodeState(st)
				if err != nil {
					continue
				}
				etag := detect.ETag(nil, st)
				out[areaDetections+"/"+detect.StateDir+"/"+it.Name+".yaml"] = want{data: data, same: func(data []byte) bool {
					have, err := decodeStateFile(it.Name, data)
					return err == nil && detect.ETag(nil, have) == etag
				}}
			}
		}
	}
	if dirOf(in.Files.DashboardsDir) != "" {
		for _, it := range in.Docs.Dashboards().List() {
			if it.Value == nil {
				continue
			}
			d, err := it.Value.decode(it.Name)
			if err != nil {
				continue
			}
			etag := dashboards.ETag(d)
			out[areaDashboards+"/"+it.Name+".yaml"] = want{data: []byte(it.Value.YAML), same: func(data []byte) bool {
				have, err := dashboards.DecodeFile(it.Name+".yaml", data)
				return err == nil && dashboards.ETag(have) == etag
			}}
		}
	}
	return out
}

// pathOf returns where the file of the record name is, and refuses a
// name that is not a file under its folder.
func (in *Inbox) pathOf(name string) (string, error) {
	area, rest, _ := strings.Cut(name, "/")
	dir := dirOf(in.Files.DetectionsDir)
	if area == areaDashboards {
		dir = dirOf(in.Files.DashboardsDir)
	}
	p := filepath.Join(dir, filepath.FromSlash(rest))
	if rel, err := filepath.Rel(dir, p); dir == "" || err != nil || rel == "." || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("the file %q is not under the folder %s", name, dir)
	}
	return p, nil
}

// writeBack writes the shared library into the folders: a file that is
// missing or holds what this server last saw of it is replaced with the
// shared item; a file changed here and not pushed yet is left for the
// next push. A file that held a shared item since deleted is removed.
func (in *Inbox) writeBack(seen *seenFile, files map[string]*file) error {
	var errs []error
	wanted := in.wanted()
	for name, w := range wanted {
		f := files[name]
		e := seen.Files[name]
		switch {
		case f != nil && w.same(f.data):
			seen.Files[name] = &seenEntry{SHA256: f.hash, Shared: true}
			continue
		case f != nil && (e == nil || e.SHA256 != f.hash):
			// Changed here, and not pushed yet.
			continue
		}
		p, err := in.pathOf(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := writeFileAtomic(p, w.data); err != nil {
			errs = append(errs, err)
			continue
		}
		seen.Files[name] = &seenEntry{SHA256: hashOf(w.data), Shared: true}
	}
	for name, e := range seen.Files {
		if _, ok := wanted[name]; ok || !e.Shared {
			continue
		}
		f := files[name]
		if f != nil && f.hash != e.SHA256 {
			// Changed here since: it is pushed as a new item.
			continue
		}
		if f != nil {
			if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
				continue
			}
		}
		delete(seen.Files, name)
	}
	return errors.Join(errs...)
}

// writeFileAtomic replaces name with data whole.
func writeFileAtomic(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-"+strings.TrimSuffix(filepath.Base(name), ".yaml")+"-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), name)
}
