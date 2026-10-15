package clusterlib

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Files is this server's folders, which the founder imports and whose
// changes the inbox pushes.
type Files struct {
	// DetectionsDir and DashboardsDir return the folders in use now.
	DetectionsDir func() string
	DashboardsDir func() string
	// Node is this server's name.
	Node string
	Log  *slog.Logger
	Now  func() time.Time
}

func (f Files) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (f Files) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func dirOf(fn func() string) string {
	if fn == nil {
		return ""
	}
	return fn()
}

// Importers returns the importers of the library: the custom detections
// and the state chosen for shipped ones (the detections folder and its
// state folder), and the custom dashboards. They wait until the cluster
// is at shared.LevelSharedLibrary. Each is idempotent: an item already in
// the shared settings is left as it is.
func Importers(d *Docs, f Files) []shared.Importer {
	return []shared.Importer{
		{Name: shared.ImportDetections, MinLevel: shared.LevelSharedLibrary, Source: func() (string, error) {
			dir := dirOf(f.DetectionsDir)
			return hashFiles(yamlFiles(dir), yamlFiles(filepath.Join(dir, detect.StateDir)))
		}, Run: func(ctx context.Context, by string) error { return importDetections(ctx, d, f, by) }},
		{Name: shared.ImportDashboards, MinLevel: shared.LevelSharedLibrary, Source: func() (string, error) {
			return hashFiles(yamlFiles(dirOf(f.DashboardsDir)))
		}, Run: func(ctx context.Context, by string) error { return importDashboards(ctx, d, f, by) }},
	}
}

// yamlFiles lists the *.yaml files in dir, sorted; none when dir is "".
func yamlFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	slices.Sort(files)
	return files
}

// hashFiles hashes the names and contents of files, "" when there are
// none.
func hashFiles(lists ...[]string) (string, error) {
	h := sha256.New()
	n := 0
	for _, files := range lists {
		for _, p := range files {
			data, err := os.ReadFile(p)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return "", err
			}
			n++
			h.Write([]byte(filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)))
			h.Write([]byte{0})
			h.Write(data)
			h.Write([]byte{0})
		}
	}
	if n == 0 {
		return "", nil
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// readDetectionFiles reads the custom detections and states in dir, by
// ID; a file that is not valid is logged and left out.
func readDetectionFiles(dir string, log *slog.Logger) map[string]*DetectionBody {
	out := map[string]*DetectionBody{}
	for _, p := range yamlFiles(dir) {
		data, err := os.ReadFile(p)
		if err != nil {
			log.Warn("could not read a detection file", "file", p, "err", err)
			continue
		}
		d, err := decodeDetectionFile(filepath.Base(p), data)
		if err != nil {
			log.Warn("a detection file is not valid and was left out", "file", p, "err", err)
			continue
		}
		out[d.ID] = &DetectionBody{YAML: string(data)}
	}
	for _, p := range yamlFiles(filepath.Join(dir, detect.StateDir)) {
		id := strings.TrimSuffix(filepath.Base(p), ".yaml")
		data, err := os.ReadFile(p)
		if err != nil {
			log.Warn("could not read a detection state file", "file", p, "err", err)
			continue
		}
		st, err := decodeStateFile(id, data)
		if err != nil {
			log.Warn("a detection state file is not valid and was left out", "file", p, "err", err)
			continue
		}
		if st == nil {
			continue
		}
		b := out[id]
		if b == nil {
			b = &DetectionBody{}
			out[id] = b
		}
		b.State = st
	}
	return out
}

// decodeDetectionFile reads the custom detection in the file name.
func decodeDetectionFile(name string, data []byte) (*detect.Detection, error) {
	d, err := detect.Decode(data)
	if err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.ID+".yaml" != name {
		return nil, errors.New("its id " + d.ID + " does not match the file name")
	}
	return d, nil
}

// decodeStateFile reads the state of a shipped detection; nil when it
// holds nothing.
func decodeStateFile(id string, data []byte) (*detect.State, error) {
	st, err := detect.DecodeState(data)
	if err != nil {
		return nil, err
	}
	if p := detect.ExceptionProblems(st.Exceptions); len(p) > 0 {
		return nil, &detect.ValidationError{ID: id, Problems: p}
	}
	if st.Enabled == nil && len(st.Exceptions) == 0 {
		return nil, nil
	}
	return st, nil
}

func importDetections(ctx context.Context, d *Docs, f Files, by string) error {
	items := readDetectionFiles(dirOf(f.DetectionsDir), f.log())
	return importItems(ctx, d.Detections(), by, items, func(b *DetectionBody) {
		b.From = stamp(FromImport, f.Node, f.now())
	})
}

func importDashboards(ctx context.Context, d *Docs, f Files, by string) error {
	items := map[string]*DashboardBody{}
	for _, p := range yamlFiles(dirOf(f.DashboardsDir)) {
		name := filepath.Base(p)
		if dashboards.IsBuiltin(strings.TrimSuffix(name, ".yaml")) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			f.log().Warn("could not read a dashboard file", "file", p, "err", err)
			continue
		}
		db, err := dashboards.DecodeFile(name, data)
		if err != nil {
			f.log().Warn("a dashboard file is not valid and was left out", "file", p, "err", err)
			continue
		}
		items[db.ID] = &DashboardBody{YAML: string(data)}
	}
	return importItems(ctx, d.Dashboards(), by, items, func(b *DashboardBody) {
		b.From = stamp(FromImport, f.Node, f.now())
	})
}

// importItems adds the items the collection does not have yet, in one
// batch; an item already there was imported before (or made since) and
// is left as it is.
func importItems[T any](ctx context.Context, c *shared.Collection[T], by string, items map[string]*T, mark func(*T)) error {
	names := make([]string, 0, len(items))
	for n := range items {
		names = append(names, n)
	}
	slices.Sort(names)
	_, _, err := c.MutateMany(ctx, by, names, func(name string, cur *T) (*T, bool, error) {
		if cur != nil {
			return nil, false, nil
		}
		v := items[name]
		mark(v)
		return v, true, nil
	})
	return err
}
