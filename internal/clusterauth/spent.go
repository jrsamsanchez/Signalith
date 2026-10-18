package clusterauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// A sign-in proof that may be used once, such as a SAML assertion, is
// spent on every server of a cluster at once: the server that takes it
// creates <prefix>_runtime/spent:<hash>, and a server that finds the
// document already there refuses the proof. The create is atomic in
// OpenSearch, so two servers given the same proof at the same moment
// cannot both take it. The id is a hash of the cluster's id, the kind of
// proof and its id, so neither can be read back. When the document
// cannot be written, the proof is refused (fail closed): without the
// shared record, another server may have taken it already.
//
// The documents carry no MAC: one written by someone else can only refuse
// a proof, and whoever can write to OpenSearch can refuse sign-ins anyway.

// ErrSpent refuses a proof that was used already.
var ErrSpent = errors.New("this sign-in was used already")

// spentDoc is a spent document.
type spentDoc struct {
	Kind  string `json:"kind"`
	Use   string `json:"use"`
	Until string `json:"until"`
	Node  string `json:"node"`
	At    string `json:"at"`
}

// SpentID returns the id of the spent document of the proof id of kind
// use.
func SpentID(clusterID, use, id string) string {
	sum := sha256.Sum256([]byte(clusterID + "|" + use + "|" + id))
	return "spent:" + hex.EncodeToString(sum[:])
}

// Spent records the proofs used once across the servers of a cluster.
type Spent struct {
	Docs *Docs
	// Client returns the OpenSearch client and index prefix in use now.
	Client func() (*store.Client, string)
	// Node is this server's node id.
	Node string
	Now  func() time.Time
}

func (s *Spent) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Use spends the proof id of kind use, which is valid until until: nil
// the first time, ErrSpent after, and any other error when the record
// cannot be written, which must refuse the proof too.
func (s *Spent) Use(ctx context.Context, use, id string, until time.Time) error {
	cid := s.Docs.ClusterID()
	if cid == "" {
		return errors.New("this server is not a member of the cluster now")
	}
	cl, prefix := s.Client()
	doc := spentDoc{Kind: "spent", Use: use, Until: until.UTC().Format(time.RFC3339Nano), Node: s.Node,
		At: s.now().UTC().Format(time.RFC3339Nano)}
	_, err := cl.Create(ctx, runtimeIndex(prefix), SpentID(cid, use, id), doc, false)
	if errors.Is(err, store.ErrExists) {
		return ErrSpent
	}
	return err
}

// spentKeep is how long past its end a spent document is kept, so a
// server whose clock is behind still finds it.
const spentKeep = time.Hour

// Housekeep deletes the spent documents that ended.
func (s *Spent) Housekeep(ctx context.Context) (int, error) {
	cl, prefix := s.Client()
	var out struct {
		Deleted int `json:"deleted"`
	}
	q := map[string]any{"bool": map[string]any{"must": []any{
		map[string]any{"term": map[string]any{"kind": "spent"}},
		map[string]any{"range": map[string]any{"until": map[string]any{"lt": s.now().Add(-spentKeep).UTC().Format(time.RFC3339Nano)}}},
	}}}
	err := cl.Do(ctx, http.MethodPost, "/"+url.PathEscape(runtimeIndex(prefix))+"/_delete_by_query?conflicts=proceed&ignore_unavailable=true",
		map[string]any{"query": q}, &out)
	return out.Deleted, err
}
