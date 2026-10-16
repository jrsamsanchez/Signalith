package clusterarchive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The archive folder the cluster archives to, and which servers see it.
const (
	KindFolder = "archive_folder"
	// FolderID records the folder (its id file's ID) the cluster archives
	// to: the first server to archive names it.
	FolderID = "retention:archive_folder"
	// FolderSeen is how recent a server's report must be to count.
	FolderSeen = time.Hour
)

// NodeFolderDocID is the id of the document in which a server reports the
// archive folder it sees.
func NodeFolderDocID(nodeID string) string { return KindFolder + ":" + nodeID }

// folderBody is the body of the folder documents.
type folderBody struct {
	StoreID string `json:"store_id,omitempty"`
	Dir     string `json:"dir,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Folders tells whether this server can archive to the cluster's archive
// folder, and which servers can. Each server reports the folder it sees
// (Report); the server that runs retention checks its own against the
// cluster's before it archives (CanArchive), so that archives of one
// cluster never end up in two folders.
type Folders struct {
	Client Client
	Prefix string
	Server string
	NodeID string
	// Dir is this server's archive folder, and StoreID the ID its id file
	// holds (retention.Archive.StoreID).
	Dir     string
	StoreID func() (string, error)
	Now     func() time.Time
}

// Report records the archive folder this server sees.
func (f *Folders) Report(ctx context.Context) error {
	var b folderBody
	b.Dir = f.Dir
	if id, err := f.StoreID(); err != nil {
		b.Error = err.Error()
	} else {
		b.StoreID = id
	}
	raw, _ := json.Marshal(b)
	return put(ctx, f.Client, f.Prefix, NodeFolderDocID(f.NodeID), doc{Kind: KindFolder, Name: b.StoreID, Node: f.Server, NodeID: f.NodeID,
		State: "reported", At: now(f.Now), Body: raw})
}

// CanArchive reports whether this server may archive now, with the reason
// when it may not. With no folder recorded yet, or none that a server
// reported within FolderSeen, this server's folder becomes the cluster's.
func (f *Folders) CanArchive(ctx context.Context) (bool, string) {
	own, err := f.StoreID()
	if err != nil {
		return false, "its archive folder cannot be used: " + err.Error()
	}
	for try := 0; try < 3; try++ {
		cur, v, found, err := read(ctx, f.Client, f.Prefix, FolderID)
		if err != nil {
			return false, "the cluster's archive folder cannot be read from OpenSearch: " + err.Error()
		}
		if found && cur.Name == own {
			return true, ""
		}
		if found {
			on, err := f.seen(ctx, cur.Name)
			if err != nil {
				return false, "the cluster's archive folder cannot be read from OpenSearch: " + err.Error()
			}
			if len(on) > 0 {
				return false, fmt.Sprintf("its archive folder (%s) is not the one the cluster archives to, which %s uses; set retention.archive_dir to that folder",
					f.Dir, cur.Node)
			}
		}
		raw, _ := json.Marshal(folderBody{StoreID: own, Dir: f.Dir})
		d := doc{Kind: KindFolder, Name: own, Node: f.Server, NodeID: f.NodeID, State: "cluster", At: now(f.Now), Body: raw}
		if found {
			_, err = f.Client.PutIf(ctx, cluster.RuntimeIndex(f.Prefix), FolderID, d, v, true)
		} else {
			_, err = f.Client.Create(ctx, cluster.RuntimeIndex(f.Prefix), FolderID, d, true)
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, "the cluster's archive folder cannot be recorded in OpenSearch: " + err.Error()
		}
		return true, ""
	}
	return false, "the cluster's archive folder kept changing; the next run tries again"
}

// On lists the servers, by name, that reported the cluster's archive
// folder within FolderSeen: those that can archive. With no folder
// recorded yet, it lists none.
func (f *Folders) On(ctx context.Context) ([]string, error) {
	cur, _, found, err := read(ctx, f.Client, f.Prefix, FolderID)
	if err != nil || !found {
		return nil, err
	}
	return f.seen(ctx, cur.Name)
}

// seen lists the servers that reported the folder storeID recently.
func (f *Folders) seen(ctx context.Context, storeID string) ([]string, error) {
	docs, err := f.Client.SearchDocs(ctx, cluster.RuntimeIndex(f.Prefix), map[string]any{"term": map[string]any{"kind": KindFolder}})
	if err != nil {
		return nil, err
	}
	since := now(f.Now).Add(-FolderSeen)
	var out []string
	for _, sd := range docs {
		if sd.ID == FolderID {
			continue
		}
		var d doc
		if json.Unmarshal(sd.Source, &d) != nil || d.Kind != KindFolder || d.Name != storeID || d.At.Before(since) {
			continue
		}
		if !slices.Contains(out, d.Node) {
			out = append(out, d.Node)
		}
	}
	slices.Sort(out)
	return out, nil
}
