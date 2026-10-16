package clusterarchive

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// ImportOptions are what the importers read and where they write.
type ImportOptions struct {
	Client Client
	Prefix string
	// HistoryFile is the founder's retention_history.json, and Archive its
	// archive folder.
	HistoryFile string
	Archive     *retention.Archive
	Server      string
	NodeID      string
	Log         *slog.Logger
}

// Importers returns the importers of the founder's retention history and
// archive manifests, named shared.ImportRetentionHistory and
// shared.ImportArchives, which run once the cluster reaches
// shared.LevelSharedAudit. Both are idempotent: history actions keep IDs
// derived from what they hold, and a manifest whose ID is there already
// is left alone.
func Importers(o ImportOptions) []shared.Importer {
	return []shared.Importer{
		{
			Name:     shared.ImportRetentionHistory,
			MinLevel: shared.LevelSharedAudit,
			Source:   func() (string, error) { return fileHash(o.HistoryFile) },
			Run:      func(ctx context.Context, _ string) error { return importHistory(ctx, o) },
		},
		{
			Name:     shared.ImportArchives,
			MinLevel: shared.LevelSharedAudit,
			Source:   func() (string, error) { return manifestsHash(o.Archive) },
			Run:      func(ctx context.Context, _ string) error { return importArchives(ctx, o) },
		},
	}
}

// fileHash is the hash of a file's content, "" when it is missing.
func fileHash(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// manifestsHash is a hash of the IDs of the manifest files in the
// archive folder, "" when there are none.
func manifestsHash(a *retention.Archive) (string, error) {
	if a == nil || a.Dir == "" {
		return "", nil
	}
	list, _, err := a.ListFiles()
	if err != nil || len(list) == 0 {
		return "", err
	}
	ids := make([]string, len(list))
	for i, m := range list {
		ids[i] = m.ID + "/" + m.SHA256
	}
	slices.Sort(ids)
	b, _ := json.Marshal(ids)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// importHistory writes the history file's actions as audit records, and
// its last run as retention:lastrun unless one is there.
func importHistory(ctx context.Context, o ImportOptions) error {
	run, acts, err := retention.ReadHistoryFile(o.HistoryFile)
	if err != nil {
		return err
	}
	evs := make([]audit.Event, 0, len(acts))
	for _, a := range acts {
		a.Server = o.Server
		b, _ := json.Marshal(a)
		sum := sha256.Sum256(b)
		evs = append(evs, audit.Event{
			Time: a.Time, Server: o.Server, NodeID: "import:" + o.NodeID, User: a.By, Action: ActionPrefix + a.Action,
			Target: a.Index, Message: ActionPrefix + a.Action + ": " + a.Reason, Level: "INFO",
			Fields: map[string]string{actField: string(b), "category": a.Category, "imported": "true"},
			// The ID comes from the action itself, so a second import
			// writes nothing new.
			Seq: int64(binary.BigEndian.Uint64(sum[:8]) >> 1),
		})
	}
	if err := audit.Write(ctx, o.Client, o.Prefix, evs); err != nil {
		return err
	}
	if run != nil {
		if _, _, found, err := read(ctx, o.Client, o.Prefix, LastRunID); err != nil {
			return err
		} else if !found {
			body, _ := json.Marshal(run)
			if err := put(ctx, o.Client, o.Prefix, LastRunID, doc{Kind: KindLastRun, Node: o.Server, NodeID: o.NodeID, At: time.Now().UTC(), Body: body}); err != nil {
				return err
			}
		}
	}
	if o.Log != nil {
		o.Log.Info("imported the retention history into the audit records", "actions", len(acts))
	}
	return nil
}

// importArchives records the manifest files of the archive folder. A
// manifest whose ID is recorded already (another server's archive of the
// same name in a shared folder) is left alone.
func importArchives(ctx context.Context, o ImportOptions) error {
	list, problems, err := o.Archive.ListFiles()
	if err != nil {
		return err
	}
	store := &Manifests{Client: o.Client, Prefix: o.Prefix, Server: o.Server, NodeID: o.NodeID}
	added := 0
	for _, m := range list {
		m.Server = o.Server
		ok, err := store.Import(ctx, m)
		if err != nil {
			return fmt.Errorf("%s: %w", m.ID, err)
		}
		if ok {
			added++
		}
	}
	if o.Log != nil {
		o.Log.Info("imported the archive manifests", "added", added, "files", len(list), "unreadable", len(problems))
	}
	return nil
}
