package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Delivery statuses.
const (
	// StatusSending is a message claimed and being sent. One left like
	// this by a server that stopped is marked failed, never sent again:
	// it may have arrived.
	StatusSending = "sending"
	StatusSent    = "sent"
	StatusFailed  = "failed"
)

// Delivery is one message to one channel, kept in <prefix>_notifications
// for 30 days: the claim that it goes out once, its outcome, and what it
// said, so a failed one can be sent again later.
type Delivery struct {
	// ID is DeliveryID(finding, channel) for a finding, so one finding
	// goes to one channel at most once; a random ID for a test.
	ID          string `json:"id"`
	Kind        string `json:"kind"` // finding or test
	FindingID   string `json:"finding_id,omitempty"`
	Channel     string `json:"channel"`
	ChannelName string `json:"channel_name"`
	ChannelType string `json:"channel_type"`
	Rule        string `json:"rule,omitempty"`
	RuleName    string `json:"rule_name,omitempty"`
	Status      string `json:"status"`
	// Final is true for a failed delivery that is not tried again.
	Final    bool   `json:"final,omitempty"`
	Attempts int    `json:"attempts"`
	Error    string `json:"error,omitempty"`
	// DurationMS is how long the last attempt took.
	DurationMS int64 `json:"duration_ms,omitempty"`
	// Summary, above 0, is how many findings the message this delivery
	// went out in stood for (see FloodLimit).
	Summary int `json:"summary,omitempty"`
	// Message is what was sent, for a retry; it holds no event data.
	Message Message `json:"message"`
	// Server is the Signalith server that sent it last.
	Server  string     `json:"server,omitempty"`
	Created time.Time  `json:"created"`
	Updated time.Time  `json:"updated"`
	Claimed time.Time  `json:"claimed"`
	NextTry *time.Time `json:"next_try,omitempty"`
}

// DeliveryID is the ID of the delivery of a finding to a channel.
func DeliveryID(findingID, channelID string) string {
	sum := sha256.Sum256([]byte(findingID + "|" + channelID))
	return hex.EncodeToString(sum[:])
}

// Stored is a delivery as read, with its version for a conditional
// write.
type Stored struct {
	Delivery
	Version store.Version
}

// Deliveries keeps the deliveries.
type Deliveries interface {
	// Claim writes a new delivery: store.ErrExists when it is already
	// there, because the message was sent or is being sent.
	Claim(ctx context.Context, d *Delivery) (store.Version, error)
	// Existing returns which of ids are there.
	Existing(ctx context.Context, ids []string) (map[string]bool, error)
	// Update writes a delivery only if it is still at version v:
	// store.ErrConflict when it changed.
	Update(ctx context.Context, d *Delivery, v store.Version) (store.Version, error)
	// Due lists the failed deliveries to try again by now, and those
	// still sending that were claimed before stale.
	Due(ctx context.Context, now, stale time.Time) (retry, stuck []Stored, err error)
	// Recent lists the latest deliveries, newest first.
	Recent(ctx context.Context, limit int) ([]Delivery, error)
	// Purge deletes deliveries created before t.
	Purge(ctx context.Context, before time.Time) error
}

// Docs is what OpenSearch keeps deliveries with; *store.Client is one.
type Docs interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	MGetVersions(ctx context.Context, refs []store.Ref) (map[store.Ref]store.Version, error)
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// OpenSearch keeps deliveries in one index, "<prefix>_notifications".
// Its name uses "_" rather than "-" so event searches over "<prefix>-*"
// never include it.
type OpenSearch struct {
	Client Docs
	Index  string
	// Replicas are the index's replicas settings (opensearch.replicas,
	// see config.Replicas.IndexSettings); nil is auto.
	Replicas map[string]any
}

// NewOpenSearch returns the deliveries index of prefix.
func NewOpenSearch(c Docs, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_notifications"}
}

func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	return map[string]any{
		"id": kw, "kind": kw, "finding_id": kw, "channel": kw, "channel_name": kw, "channel_type": kw, "rule": kw,
		"rule_name": kw, "status": kw, "final": map[string]any{"type": "boolean"}, "attempts": map[string]any{"type": "integer"},
		"duration_ms": map[string]any{"type": "long"}, "summary": map[string]any{"type": "integer"}, "server": kw,
		"created": date, "updated": date, "claimed": date, "next_try": date,
		"error":   map[string]any{"type": "text", "index": false},
		"message": map[string]any{"type": "object", "enabled": false},
	}
}

// EnsureIndex creates the index if it does not exist. Any server may.
func (o *OpenSearch) EnsureIndex(ctx context.Context) error {
	body := map[string]any{
		"settings": store.SmallIndexSettings(o.Replicas),
		"mappings": map[string]any{"dynamic": "false", "properties": properties()},
	}
	err := o.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(o.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 400 && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// Replicate gives the notification deliveries index, when it was made with
// no copy on another node, the replicas settings new indices get (see
// store.Replicate). Only the server that runs the background jobs does,
// when it starts running them; doing it again changes nothing.
func (o *OpenSearch) Replicate(ctx context.Context) error {
	return store.Replicate(ctx, o.Client, o.Index, o.Replicas)
}

func (o *OpenSearch) Claim(ctx context.Context, d *Delivery) (store.Version, error) {
	return o.Client.Create(ctx, o.Index, d.ID, d, true)
}

func (o *OpenSearch) Existing(ctx context.Context, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	for len(ids) > 0 {
		n := min(len(ids), 500)
		refs := make([]store.Ref, n)
		for i, id := range ids[:n] {
			refs[i] = store.Ref{Index: o.Index, ID: id}
		}
		got, err := o.Client.MGetVersions(ctx, refs)
		if err != nil {
			return nil, err
		}
		for r := range got {
			out[r.ID] = true
		}
		ids = ids[n:]
	}
	return out, nil
}

func (o *OpenSearch) Update(ctx context.Context, d *Delivery, v store.Version) (store.Version, error) {
	return o.Client.PutIf(ctx, o.Index, d.ID, d, v, true)
}

func (o *OpenSearch) Due(ctx context.Context, now, stale time.Time) (retry, stuck []Stored, err error) {
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	q := map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
		map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"status": StatusFailed}},
			map[string]any{"range": map[string]any{"next_try": map[string]any{"lte": ts(now)}}},
		}, "must_not": []any{map[string]any{"term": map[string]any{"final": true}}}}},
		map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"status": StatusSending}},
			map[string]any{"range": map[string]any{"claimed": map[string]any{"lt": ts(stale)}}},
		}}},
	}}}
	docs, err := o.Client.SearchDocs(ctx, o.Index, q)
	if err != nil {
		return nil, nil, err
	}
	for _, doc := range docs {
		var d Delivery
		if err := json.Unmarshal(doc.Source, &d); err != nil {
			continue
		}
		s := Stored{Delivery: d, Version: doc.Version}
		if d.Status == StatusSending {
			stuck = append(stuck, s)
		} else {
			retry = append(retry, s)
		}
	}
	return retry, stuck, nil
}

func (o *OpenSearch) Recent(ctx context.Context, limit int) ([]Delivery, error) {
	var out struct {
		Hits struct {
			Hits []struct {
				Source Delivery `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	body := map[string]any{"size": limit, "sort": []any{map[string]any{"updated": "desc"}},
		"query": map[string]any{"match_all": map[string]any{}}}
	err := o.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(o.Index)+"/_search?ignore_unavailable=true&allow_no_indices=true", body, &out)
	if err != nil {
		return nil, err
	}
	list := make([]Delivery, 0, len(out.Hits.Hits))
	for _, h := range out.Hits.Hits {
		list = append(list, h.Source)
	}
	return list, nil
}

func (o *OpenSearch) Purge(ctx context.Context, before time.Time) error {
	return o.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(o.Index)+"/_delete_by_query?conflicts=proceed&ignore_unavailable=true",
		map[string]any{"query": map[string]any{"range": map[string]any{"created": map[string]any{"lt": before.UTC().Format(time.RFC3339Nano)}}}}, nil)
}

// Memory keeps deliveries in memory, for tests and for a server without
// OpenSearch.
type Memory struct {
	mu   sync.Mutex
	docs map[string]Stored
	seq  int64
}

// NewMemory returns an empty Memory.
func NewMemory() *Memory { return &Memory{docs: map[string]Stored{}} }

func (m *Memory) next() store.Version {
	m.seq++
	return store.Version{SeqNo: m.seq, PrimaryTerm: 1, Version: m.seq}
}

func (m *Memory) Claim(_ context.Context, d *Delivery) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.docs[d.ID]; ok {
		return store.Version{}, store.ErrExists
	}
	v := m.next()
	m.docs[d.ID] = Stored{Delivery: copyDelivery(*d), Version: v}
	return v, nil
}

func (m *Memory) Existing(_ context.Context, ids []string) (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for _, id := range ids {
		if _, ok := m.docs[id]; ok {
			out[id] = true
		}
	}
	return out, nil
}

func (m *Memory) Update(_ context.Context, d *Delivery, v store.Version) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.docs[d.ID]
	if !ok || !cur.Version.Same(v) {
		return store.Version{}, store.ErrConflict
	}
	nv := m.next()
	m.docs[d.ID] = Stored{Delivery: copyDelivery(*d), Version: nv}
	return nv, nil
}

func (m *Memory) Due(_ context.Context, now, stale time.Time) (retry, stuck []Stored, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.docs {
		switch {
		case s.Status == StatusFailed && !s.Final && s.NextTry != nil && !s.NextTry.After(now):
			retry = append(retry, Stored{Delivery: copyDelivery(s.Delivery), Version: s.Version})
		case s.Status == StatusSending && s.Claimed.Before(stale):
			stuck = append(stuck, Stored{Delivery: copyDelivery(s.Delivery), Version: s.Version})
		}
	}
	sort.Slice(retry, func(i, j int) bool { return retry[i].ID < retry[j].ID })
	sort.Slice(stuck, func(i, j int) bool { return stuck[i].ID < stuck[j].ID })
	return retry, stuck, nil
}

func (m *Memory) Recent(_ context.Context, limit int) ([]Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type item struct {
		d   Delivery
		seq int64
	}
	var all []item
	for _, s := range m.docs {
		all = append(all, item{copyDelivery(s.Delivery), s.Version.SeqNo})
	}
	// Newest change first; the write order breaks ties, since the clock
	// can give two changes the same time.
	sort.Slice(all, func(i, j int) bool {
		if !all[i].d.Updated.Equal(all[j].d.Updated) {
			return all[i].d.Updated.After(all[j].d.Updated)
		}
		return all[i].seq > all[j].seq
	})
	out := make([]Delivery, 0, min(limit, len(all)))
	for i := 0; i < len(all) && i < limit; i++ {
		out = append(out, all[i].d)
	}
	return out, nil
}

func (m *Memory) Purge(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.docs {
		if s.Created.Before(before) {
			delete(m.docs, id)
		}
	}
	return nil
}

// Get returns one delivery, for tests.
func (m *Memory) Get(id string) (Delivery, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.docs[id]
	return copyDelivery(s.Delivery), ok
}

func copyDelivery(d Delivery) Delivery {
	b, _ := json.Marshal(d)
	var out Delivery
	_ = json.Unmarshal(b, &out)
	return out
}
