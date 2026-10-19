// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Doer sends OpenSearch REST requests.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// OpenSearch implements Cluster over the OpenSearch REST API.
type OpenSearch struct {
	Client Doer
	// PageSize is how many documents an export reads per request.
	PageSize int
	// Poll is how often long-running tasks (force merges, deletes by
	// query) are checked; default 5s.
	Poll time.Duration
}

// NewOpenSearch returns a Cluster for one OpenSearch.
func NewOpenSearch(c Doer) *OpenSearch { return &OpenSearch{Client: c} }

func esc(s string) string { return url.PathEscape(s) }

func notFound(err error) bool {
	var oe *store.Error
	return errors.As(err, &oe) && oe.Status == http.StatusNotFound
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// Indices lists open indices with sizes from _cat/indices, read-only
// blocks from the index settings and the restored mark from the mapping's
// _meta.
func (o *OpenSearch) Indices(ctx context.Context, pattern string) ([]IndexInfo, error) {
	var rows []map[string]*string
	err := o.Client.Do(ctx, http.MethodGet, "/_cat/indices/"+esc(pattern)+
		"?format=json&bytes=b&expand_wildcards=open&h=index,uuid,health,pri,rep,docs.count,store.size,pri.store.size,segments.count", nil, &rows)
	if err != nil {
		if notFound(err) {
			return nil, nil
		}
		return nil, err
	}
	get := func(r map[string]*string, k string) string {
		if v := r[k]; v != nil {
			return *v
		}
		return ""
	}
	out := make([]IndexInfo, 0, len(rows))
	byName := map[string]int{}
	for _, r := range rows {
		pri, rep := atoi64(get(r, "pri")), atoi64(get(r, "rep"))
		ix := IndexInfo{
			Name:         get(r, "index"),
			UUID:         get(r, "uuid"),
			Health:       get(r, "health"),
			Docs:         atoi64(get(r, "docs.count")),
			Bytes:        atoi64(get(r, "store.size")),
			PrimaryBytes: atoi64(get(r, "pri.store.size")),
			Segments:     int(atoi64(get(r, "segments.count"))),
			Copies:       int(pri * (1 + rep)),
		}
		// A red index (a primary shard is not available) reports no
		// documents or size at all, which must not read as empty.
		ix.Unavailable = ix.Health == "red" || r["docs.count"] == nil
		byName[ix.Name] = len(out)
		out = append(out, ix)
	}
	if len(out) == 0 {
		return out, nil
	}
	var settings map[string]struct {
		Settings map[string]any `json:"settings"`
	}
	err = o.Client.Do(ctx, http.MethodGet, "/"+esc(pattern)+"/_settings/index.blocks.*,index.store.type,index.searchable_snapshot.*?flat_settings=true&expand_wildcards=open", nil, &settings)
	if err != nil && !notFound(err) {
		return nil, err
	}
	for name, s := range settings {
		if i, ok := byName[name]; ok {
			out[i].WriteBlocked = fmt.Sprint(s.Settings["index.blocks.write"]) == "true" ||
				fmt.Sprint(s.Settings["index.blocks.read_only"]) == "true"
			out[i].DiskBlocked = fmt.Sprint(s.Settings["index.blocks.read_only_allow_delete"]) == "true"
			if fmt.Sprint(s.Settings["index.store.type"]) == "remote_snapshot" {
				out[i].Cold = &ColdRef{Repository: fmt.Sprint(s.Settings["index.searchable_snapshot.repository"]),
					Snapshot: fmt.Sprint(s.Settings["index.searchable_snapshot.snapshot_id.name"])}
			}
		}
	}
	var meta map[string]struct {
		Mappings struct {
			Meta struct {
				Signalith struct {
					RestoredUntil string   `json:"restored_until"`
					RestoredFrom  []string `json:"restored_from"`
				} `json:"signalith"`
			} `json:"_meta"`
		} `json:"mappings"`
	}
	err = o.Client.Do(ctx, http.MethodGet, "/"+esc(pattern)+"/_mapping?expand_wildcards=open&filter_path=*.mappings._meta", nil, &meta)
	if err != nil && !notFound(err) {
		return nil, err
	}
	for name, m := range meta {
		if i, ok := byName[name]; ok {
			out[i].RestoredUntil = m.Mappings.Meta.Signalith.RestoredUntil
			out[i].RestoredFrom = m.Mappings.Meta.Signalith.RestoredFrom
		}
	}
	return out, nil
}

// Disk returns the fullest data path of any data node, the way OpenSearch
// itself checks disk watermarks.
func (o *OpenSearch) Disk(ctx context.Context) (*Disk, error) {
	type fs struct {
		Path      string `json:"path"`
		Total     int64  `json:"total_in_bytes"`
		Available int64  `json:"available_in_bytes"`
	}
	var out struct {
		Nodes map[string]struct {
			Name  string   `json:"name"`
			Roles []string `json:"roles"`
			FS    struct {
				Total fs   `json:"total"`
				Data  []fs `json:"data"`
			} `json:"fs"`
		} `json:"nodes"`
	}
	err := o.Client.Do(ctx, http.MethodGet,
		"/_nodes/stats/fs?filter_path=nodes.*.name,nodes.*.roles,nodes.*.fs.total,nodes.*.fs.data", nil, &out)
	if err != nil {
		return nil, err
	}
	var worst *Disk
	for _, n := range out.Nodes {
		if len(n.Roles) > 0 && !slices.ContainsFunc(n.Roles, func(r string) bool { return strings.HasPrefix(r, "data") }) {
			continue
		}
		paths := n.FS.Data
		if len(paths) == 0 {
			paths = []fs{n.FS.Total}
		}
		for _, p := range paths {
			d := &Disk{Node: n.Name, Path: p.Path, Total: p.Total, Available: p.Available}
			if d.Total > 0 && (worst == nil || d.Percent() > worst.Percent()) {
				worst = d
			}
		}
	}
	if worst == nil {
		return nil, errors.New("OpenSearch reported no data disks")
	}
	return worst, nil
}

// NodeBytes adds up the shard copies of each index on one node, from
// _cat/shards.
func (o *OpenSearch) NodeBytes(ctx context.Context, pattern, node string) (map[string]int64, error) {
	var rows []map[string]*string
	err := o.Client.Do(ctx, http.MethodGet, "/_cat/shards/"+esc(pattern)+
		"?format=json&bytes=b&h=index,node,store", nil, &rows)
	if err != nil && !notFound(err) {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range rows {
		if r["index"] == nil || r["node"] == nil || *r["node"] != node {
			continue
		}
		var n int64
		if r["store"] != nil {
			n = atoi64(*r["store"])
		}
		out[*r["index"]] += n
	}
	return out, nil
}

func (o *OpenSearch) BlockWrites(ctx context.Context, index string, block bool) error {
	var v any // null removes the setting
	if block {
		v = true
	}
	return o.Client.Do(ctx, http.MethodPut, "/"+esc(index)+"/_settings", map[string]any{"index.blocks.write": v}, nil)
}

// ForceMerge starts a merge to one segment as a background task and waits
// for it, since big merges take longer than one HTTP request should. A
// refresh then lets go of the old segments.
func (o *OpenSearch) ForceMerge(ctx context.Context, index string) error {
	var out struct {
		Task string `json:"task"`
	}
	err := o.Client.Do(ctx, http.MethodPost, "/"+esc(index)+"/_forcemerge?max_num_segments=1&wait_for_completion=false", nil, &out)
	if err != nil {
		return err
	}
	if out.Task != "" {
		if _, err := o.waitTask(ctx, out.Task); err != nil {
			return err
		}
	}
	return o.Refresh(ctx, index)
}

// waitTask polls a background task until it completes and returns its
// response.
func (o *OpenSearch) waitTask(ctx context.Context, id string) (json.RawMessage, error) {
	poll := o.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	for {
		var st struct {
			Completed bool            `json:"completed"`
			Response  json.RawMessage `json:"response"`
			Error     *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		}
		if err := o.Client.Do(ctx, http.MethodGet, "/_tasks/"+esc(id), nil, &st); err != nil {
			return nil, fmt.Errorf("checking OpenSearch task %s: %w", id, err)
		}
		if st.Completed {
			if st.Error != nil {
				return nil, fmt.Errorf("OpenSearch task failed: %s: %s", st.Error.Type, st.Error.Reason)
			}
			return st.Response, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

func (o *OpenSearch) DeleteIndex(ctx context.Context, index string) error {
	err := o.Client.Do(ctx, http.MethodDelete, "/"+esc(index), nil, nil)
	if notFound(err) {
		return nil
	}
	return err
}

func (o *OpenSearch) Count(ctx context.Context, index string) (int64, error) {
	var out struct {
		Count int64 `json:"count"`
	}
	err := o.Client.Do(ctx, http.MethodGet, "/"+esc(index)+"/_count", nil, &out)
	return out.Count, err
}

type hitsPage struct {
	ScrollID string `json:"_scroll_id"`
	Hits     struct {
		Hits []Doc `json:"hits"`
	} `json:"hits"`
}

// Export reads an index with the scroll API, one page at a time.
func (o *OpenSearch) Export(ctx context.Context, index string, fn func(Doc) error) error {
	size := o.PageSize
	if size <= 0 {
		size = 500
	}
	var page hitsPage
	err := o.Client.Do(ctx, http.MethodPost, "/"+esc(index)+"/_search?scroll=5m",
		map[string]any{"size": size, "sort": []string{"_doc"}}, &page)
	if err != nil {
		return err
	}
	defer func() {
		if page.ScrollID != "" {
			// Free the scroll now rather than when it times out.
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = o.Client.Do(cctx, http.MethodDelete, "/_search/scroll", map[string]any{"scroll_id": []string{page.ScrollID}}, nil)
			cancel()
		}
	}()
	for len(page.Hits.Hits) > 0 {
		for _, d := range page.Hits.Hits {
			if err := fn(d); err != nil {
				return err
			}
		}
		id := page.ScrollID
		page = hitsPage{}
		if err := o.Client.Do(ctx, http.MethodPost, "/_search/scroll", map[string]any{"scroll": "5m", "scroll_id": id}, &page); err != nil {
			page.ScrollID = id
			return err
		}
		if page.ScrollID == "" {
			page.ScrollID = id
		}
	}
	return nil
}

func (o *OpenSearch) CreateIndex(ctx context.Context, index string) error {
	err := o.Client.Do(ctx, http.MethodPut, "/"+esc(index), map[string]any{}, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusBadRequest && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// MarkRestored sets the index's _meta, which replaces what was there.
func (o *OpenSearch) MarkRestored(ctx context.Context, index, until string, from []string) error {
	return o.Client.Do(ctx, http.MethodPut, "/"+esc(index)+"/_mapping",
		map[string]any{"_meta": map[string]any{"signalith": map[string]any{"restored_until": until, "restored_from": from}}}, nil)
}

// Import indexes documents with the bulk API, keeping their IDs.
func (o *OpenSearch) Import(ctx context.Context, index string, docs []Doc) error {
	if len(docs) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, d := range docs {
		action := map[string]any{"_index": index}
		if d.ID != "" {
			action["_id"] = d.ID
		}
		if err := enc.Encode(map[string]any{"index": action}); err != nil {
			return err
		}
		if err := json.Compact(&buf, d.Source); err != nil {
			return fmt.Errorf("document %s is not valid JSON: %w", d.ID, err)
		}
		buf.WriteByte('\n')
	}
	var out struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			ID    string `json:"_id"`
			Error *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := o.Client.Do(ctx, http.MethodPost, "/_bulk", buf.Bytes(), &out); err != nil {
		return err
	}
	if !out.Errors {
		return nil
	}
	failed, first := 0, ""
	for _, item := range out.Items {
		for _, r := range item {
			if r.Error != nil {
				failed++
				if first == "" {
					first = r.Error.Type + ": " + r.Error.Reason
				}
			}
		}
	}
	return fmt.Errorf("OpenSearch rejected %d of %d documents; the first: %s", failed, len(docs), first)
}

func (o *OpenSearch) Refresh(ctx context.Context, index string) error {
	return o.Client.Do(ctx, http.MethodPost, "/"+esc(index)+"/_refresh", nil, nil)
}

// closedQuery selects resolved and closed records last changed before a
// time, leaving out findings in the given cases.
func closedQuery(before time.Time, keepCases []string) map[string]any {
	q := map[string]any{
		"filter": []any{
			map[string]any{"terms": map[string]any{"status": []string{findings.StatusResolved, findings.StatusClosed}}},
			map[string]any{"range": map[string]any{"updated": map[string]any{"lt": before.UTC().Format(time.RFC3339Nano)}}},
		},
	}
	if len(keepCases) > 0 {
		q["must_not"] = []any{map[string]any{"terms": map[string]any{"case_id": keepCases}}}
	}
	return map[string]any{"bool": q}
}

func (o *OpenSearch) CountClosed(ctx context.Context, index string, before time.Time, keepCases []string) (int64, error) {
	var out struct {
		Count int64 `json:"count"`
	}
	err := o.Client.Do(ctx, http.MethodPost, "/"+esc(index)+"/_count", map[string]any{"query": closedQuery(before, keepCases)}, &out)
	if notFound(err) {
		return 0, nil
	}
	return out.Count, err
}

// DeleteClosed runs a delete by query as a background task and waits for
// it. Records changed while it runs are skipped, not deleted.
func (o *OpenSearch) DeleteClosed(ctx context.Context, index string, before time.Time, keepCases []string) (int64, error) {
	var started struct {
		Task string `json:"task"`
	}
	err := o.Client.Do(ctx, http.MethodPost, "/"+esc(index)+"/_delete_by_query?conflicts=proceed&refresh=true&wait_for_completion=false",
		map[string]any{"query": closedQuery(before, keepCases)}, &started)
	if notFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	raw, err := o.waitTask(ctx, started.Task)
	if err != nil {
		return 0, err
	}
	var res struct {
		Deleted  int64             `json:"deleted"`
		Failures []json.RawMessage `json:"failures"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, err
	}
	if len(res.Failures) > 0 {
		return res.Deleted, fmt.Errorf("deleted %d, but OpenSearch reported %d failures: %s", res.Deleted, len(res.Failures), res.Failures[0])
	}
	return res.Deleted, nil
}

// maxCaseIDs is how many cases the findings policy can protect: a terms
// query takes at most 65,536 values by default.
const maxCaseIDs = 60000

// CaseIDs reads the ID of every case with the scroll API.
func (o *OpenSearch) CaseIDs(ctx context.Context, index string) ([]string, error) {
	var ids []string
	var page hitsPage
	err := o.Client.Do(ctx, http.MethodPost, "/"+esc(index)+"/_search?scroll=1m",
		map[string]any{"size": 1000, "_source": false, "sort": []string{"_doc"}}, &page)
	if notFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if page.ScrollID != "" {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = o.Client.Do(cctx, http.MethodDelete, "/_search/scroll", map[string]any{"scroll_id": []string{page.ScrollID}}, nil)
			cancel()
		}
	}()
	for len(page.Hits.Hits) > 0 {
		for _, h := range page.Hits.Hits {
			ids = append(ids, h.ID)
		}
		if len(ids) > maxCaseIDs {
			return nil, fmt.Errorf("there are more than %d investigations, too many to check which findings they hold", maxCaseIDs)
		}
		id := page.ScrollID
		page = hitsPage{}
		if err := o.Client.Do(ctx, http.MethodPost, "/_search/scroll", map[string]any{"scroll": "1m", "scroll_id": id}, &page); err != nil {
			page.ScrollID = id
			return nil, err
		}
		if page.ScrollID == "" {
			page.ScrollID = id
		}
	}
	return ids, nil
}

func (o *OpenSearch) RecordRange(ctx context.Context, index string) (time.Time, time.Time, error) {
	var out struct {
		Aggregations struct {
			Oldest struct {
				Value *float64 `json:"value"`
			} `json:"oldest"`
			Newest struct {
				Value *float64 `json:"value"`
			} `json:"newest"`
		} `json:"aggregations"`
	}
	err := o.Client.Do(ctx, http.MethodPost, "/"+esc(index)+"/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"oldest": map[string]any{"min": map[string]any{"field": "created"}},
			"newest": map[string]any{"max": map[string]any{"field": "created"}},
		},
	}, &out)
	if notFound(err) {
		return time.Time{}, time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	ms := func(v *float64) time.Time {
		if v == nil {
			return time.Time{}
		}
		return time.UnixMilli(int64(*v)).UTC()
	}
	return ms(out.Aggregations.Oldest.Value), ms(out.Aggregations.Newest.Value), nil
}

// ColdState reads the cold storage repository, which nodes can mount
// searchable snapshots, and the repository's <prefix>-* snapshots.
func (o *OpenSearch) ColdState(ctx context.Context, repo, prefix string) (*ColdState, error) {
	st := &ColdState{Repository: repo}
	var repos map[string]struct {
		Type string `json:"type"`
	}
	err := o.Client.Do(ctx, http.MethodGet, "/_snapshot/"+esc(repo), nil, &repos)
	var oe *store.Error
	switch {
	case notFound(err):
	case errors.As(err, &oe) && oe.Status == http.StatusForbidden:
		// Snapshot permissions are only granted to Signalith when cold
		// storage is turned on (the signalith_cold_storage role).
		st.Forbidden = true
		return st, nil
	case err != nil:
		return nil, fmt.Errorf("could not read the snapshot repository %s: %w", repo, err)
	default:
		r, ok := repos[repo]
		st.Registered, st.Type = ok, r.Type
	}
	var nodes struct {
		Nodes map[string]struct {
			Roles []string `json:"roles"`
		} `json:"nodes"`
	}
	if err := o.Client.Do(ctx, http.MethodGet, "/_nodes?filter_path=nodes.*.roles", nil, &nodes); err != nil {
		return nil, fmt.Errorf("could not read the nodes' roles: %w", err)
	}
	// OpenSearch 3 mounts searchable snapshots on nodes with the warm
	// role. OpenSearch 2 mounts them on search nodes, but there searches
	// of a mounted day fail on fields of the wildcard type, which every
	// Signalith event index has, so cold storage needs OpenSearch 3.
	for _, n := range nodes.Nodes {
		if slices.Contains(n.Roles, "warm") {
			st.Mountable = true
			break
		}
	}
	if !st.Registered {
		return st, nil
	}
	var snaps struct {
		Snapshots []struct {
			Name    string   `json:"snapshot"`
			State   string   `json:"state"`
			Indices []string `json:"indices"`
		} `json:"snapshots"`
	}
	err = o.Client.Do(ctx, http.MethodGet, "/_snapshot/"+esc(repo)+"/"+esc(prefix+"-*")+"?verbose=false&ignore_unavailable=true", nil, &snaps)
	if err != nil && !notFound(err) {
		return nil, fmt.Errorf("could not list the snapshots in %s: %w", repo, err)
	}
	for _, sn := range snaps.Snapshots {
		ix, ok := coldIndex(prefix, sn.Name)
		// Only complete snapshots of exactly their own index count; one
		// still being made, failed or partial is not a copy of the day.
		if !ok || sn.State != "" && sn.State != "SUCCESS" || len(sn.Indices) > 0 && !slices.Equal(sn.Indices, []string{ix}) {
			continue
		}
		st.Snapshots = append(st.Snapshots, ColdSnapshot{Name: sn.Name, Index: ix})
	}
	return st, nil
}

// SnapshotIndex snapshots one index and waits for the snapshot, checking
// it every Poll.
func (o *OpenSearch) SnapshotIndex(ctx context.Context, repo, name, index string) error {
	err := o.Client.Do(ctx, http.MethodPut, "/_snapshot/"+esc(repo)+"/"+esc(name)+"?wait_for_completion=false", map[string]any{
		"indices": index, "include_global_state": false, "ignore_unavailable": false, "partial": false,
	}, nil)
	if err != nil {
		return err
	}
	poll := o.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	for {
		var out struct {
			Snapshots []struct {
				State   string   `json:"state"`
				Indices []string `json:"indices"`
				Reason  string   `json:"reason"`
				Shards  struct {
					Total  int `json:"total"`
					Failed int `json:"failed"`
				} `json:"shards"`
			} `json:"snapshots"`
		}
		if err := o.Client.Do(ctx, http.MethodGet, "/_snapshot/"+esc(repo)+"/"+esc(name), nil, &out); err != nil {
			return fmt.Errorf("checking the snapshot: %w", err)
		}
		if len(out.Snapshots) != 1 {
			return errors.New("OpenSearch did not report the snapshot")
		}
		sn := out.Snapshots[0]
		switch sn.State {
		case "IN_PROGRESS", "STARTED", "INIT":
		case "SUCCESS":
			if sn.Shards.Failed > 0 || sn.Shards.Total == 0 || !slices.Equal(sn.Indices, []string{index}) {
				return fmt.Errorf("the snapshot is incomplete (%d of %d shards failed)", sn.Shards.Failed, sn.Shards.Total)
			}
			return nil
		default:
			return fmt.Errorf("the snapshot ended %s: %s", sn.State, sn.Reason)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// MountSnapshot restores the index as a searchable snapshot and waits
// until its primary shards are assigned. Its data stays in the
// repository, so a replica would add nothing: a node that fails is
// replaced from the repository.
func (o *OpenSearch) MountSnapshot(ctx context.Context, repo, name, index string) error {
	err := o.Client.Do(ctx, http.MethodPost, "/_snapshot/"+esc(repo)+"/"+esc(name)+"/_restore?wait_for_completion=true", map[string]any{
		"indices": index, "storage_type": "remote_snapshot", "include_global_state": false, "include_aliases": false,
		"index_settings": map[string]any{"index.number_of_replicas": 0, "index.auto_expand_replicas": false},
	}, nil)
	if err != nil {
		return err
	}
	var health struct {
		Status   string `json:"status"`
		TimedOut bool   `json:"timed_out"`
	}
	err = o.Client.Do(ctx, http.MethodGet, "/_cluster/health/"+esc(index)+"?wait_for_status=yellow&timeout=60s", nil, &health)
	if err != nil {
		return fmt.Errorf("checking the mounted index: %w", err)
	}
	if health.TimedOut || health.Status == "red" {
		return errors.New("the mounted index did not become available within 60 seconds")
	}
	return nil
}

func (o *OpenSearch) DeleteSnapshot(ctx context.Context, repo, name string) error {
	err := o.Client.Do(ctx, http.MethodDelete, "/_snapshot/"+esc(repo)+"/"+esc(name), nil, nil)
	if notFound(err) {
		return nil
	}
	return err
}
