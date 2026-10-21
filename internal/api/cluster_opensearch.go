// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// osCluster is what the OpenSearch card on the Servers page needs from
// the OpenSearch client, beyond Backend.
type osCluster interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	Endpoints() []store.EndpointStatus
	ShardRoom(ctx context.Context) (used, limit int, err error)
}

func (s *Server) routeClusterOpenSearch(api *router) {
	// Node names, disks and addresses are for admins, as the list of
	// servers is.
	api.admin("GET /api/cluster/opensearch", s.handleClusterOpenSearch)
}

// osDisk is one OpenSearch node's disk against the watermarks, each a
// percentage; nil when unknown (a watermark set in bytes, say).
type osDisk struct {
	Node        string   `json:"node"`
	UsedPercent *float64 `json:"used_percent"`
	Low         *float64 `json:"low"`
	High        *float64 `json:"high"`
	Flood       *float64 `json:"flood"`
}

// osEndpoint is one of this server's OpenSearch addresses. RetryIn is how
// long it is still skipped after failing, in this server's own time, so
// the page needs no right clock of its own.
type osEndpoint struct {
	URL     string `json:"url"`
	Down    bool   `json:"down"`
	RetryIn int    `json:"retry_in_seconds,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// osCard is GET /api/cluster/opensearch. Counts are nil when OpenSearch
// did not say (an older version, or a user without the right to ask).
type osCard struct {
	Status           string   `json:"status"`
	Problem          string   `json:"problem,omitempty"`
	Nodes            *int     `json:"nodes"`
	DataNodes        *int     `json:"data_nodes"`
	ManagerEligible  *int     `json:"manager_eligible"`
	UnassignedShards *int     `json:"unassigned_shards"`
	Disk             []osDisk `json:"disk"`
	NoReplicas       []string `json:"no_replicas"`
	ReplicasSetting  string   `json:"replicas_setting"`
	SuggestAuto      bool     `json:"suggest_auto"`
	// PrimariesTogether lists today's event indices (and their parts)
	// whose primary shards all sit on one node, though there are several
	// data nodes: that node alone does their indexing work.
	PrimariesTogether []string `json:"primaries_together"`
	// PreferPrimary is cluster.routing.allocation.balance.prefer_primary,
	// nil when not known.
	PreferPrimary *bool `json:"prefer_primary"`
	// RebalancePrimary is cluster.routing.allocation.rebalance.primary.enable,
	// nil when not known (OpenSearch before 2.12).
	RebalancePrimary *bool `json:"rebalance_primary"`
	// ShardsUsed and ShardLimit are the shard copies the cluster holds
	// and the most it allows (cluster.max_shards_per_node times the data
	// nodes): past that, OpenSearch refuses each new day's indices. Nil
	// when not known.
	ShardsUsed *int `json:"shards_used"`
	ShardLimit *int `json:"shard_limit"`
	// ShardsPerDay is how many shard copies the event indices add each
	// day: today's or yesterday's, whichever is more, per data model.
	ShardsPerDay *int `json:"shards_per_day"`
	// ShardsProjected is how many shards the cluster will hold once
	// retention keeps as many days of each data model written now as its
	// policy says, those kept forever counted as they are today.
	ShardsProjected *int `json:"shards_projected"`
	// ShardsFullInDays is, when data models written now are kept forever,
	// in about how many days the cluster holds ingest.ShardRoomWarn of its
	// limit; nil when none is.
	ShardsFullInDays *int         `json:"shards_full_in_days"`
	Endpoints        []osEndpoint `json:"endpoints"`
	Warnings         []string     `json:"warnings"`

	// keepDays is the most days retention keeps of a data model written
	// now, counting today, for the warning's text.
	keepDays int
}

// handleClusterOpenSearch says how safe the OpenSearch cluster is from
// losing a node: its health, nodes, disks, the Signalith indices with no
// copy on another node, and this server's addresses for it.
func (s *Server) handleClusterOpenSearch(w http.ResponseWriter, r *http.Request) {
	oc, ok := s.Backend.(osCluster)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, errors.New("OpenSearch details are not available on this server"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	conf := s.conf()
	out := osCard{Disk: []osDisk{}, NoReplicas: []string{}, PrimariesTogether: []string{}, Endpoints: []osEndpoint{}, Warnings: []string{},
		ReplicasSetting: strings.TrimSpace(string(conf.OpenSearch.Replicas))}
	for _, e := range oc.Endpoints() {
		oe := osEndpoint{URL: e.URL, Down: e.Down, Reason: e.Reason}
		if e.Down {
			oe.RetryIn = max(1, int(time.Until(e.Until).Round(time.Second)/time.Second))
		}
		out.Endpoints = append(out.Endpoints, oe)
	}
	if out.ReplicasSetting == "" {
		out.ReplicasSetting = "auto"
	}

	var health struct {
		Status     string `json:"status"`
		Nodes      *int   `json:"number_of_nodes"`
		DataNodes  *int   `json:"number_of_data_nodes"`
		Unassigned *int   `json:"unassigned_shards"`
	}
	if err := oc.Do(ctx, http.MethodGet, "/_cluster/health", nil, &health); err != nil {
		out.Status, out.Problem, _ = osTrouble(err)
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Status, out.Nodes, out.DataNodes, out.UnassignedShards = health.Status, health.Nodes, health.DataNodes, health.Unassigned

	// The rest is best effort: an answer that is missing or not understood
	// leaves its part unknown.
	var nodes []map[string]any
	if oc.Do(ctx, http.MethodGet, "/_cat/nodes?format=json&h=name,node.roles,disk.used_percent", nil, &nodes) == nil && len(nodes) > 0 {
		managers := 0
		for _, n := range nodes {
			name, _ := n["name"].(string)
			roles, _ := n["node.roles"].(string)
			if strings.Contains(roles, "m") {
				managers++
			}
			if name != "" {
				out.Disk = append(out.Disk, osDisk{Node: name, UsedPercent: percent(n["disk.used_percent"])})
			}
		}
		out.ManagerEligible = &managers
		sort.Slice(out.Disk, func(i, j int) bool { return out.Disk[i].Node < out.Disk[j].Node })
	}
	var settings map[string]map[string]any
	if oc.Do(ctx, http.MethodGet, "/_cluster/settings?include_defaults=true&flat_settings=true", nil, &settings) == nil {
		low, high, flood := watermark(settings, "low"), watermark(settings, "high"), watermark(settings, "flood_stage")
		for i := range out.Disk {
			out.Disk[i].Low, out.Disk[i].High, out.Disk[i].Flood = low, high, flood
		}
		out.PreferPrimary = clusterBool(settings, "cluster.routing.allocation.balance.prefer_primary")
		out.RebalancePrimary = clusterBool(settings, "cluster.routing.allocation.rebalance.primary.enable")
	}
	prefix := conf.OpenSearch.IndexPrefix
	var indices []struct {
		Index string `json:"index"`
		Pri   any    `json:"pri"`
		Rep   any    `json:"rep"`
	}
	var held []indexCopies
	path := "/_cat/indices/" + url.PathEscape(prefix+"-*") + "," + url.PathEscape(prefix+"_*") + "?format=json&h=index,pri,rep&expand_wildcards=open"
	listed := oc.Do(ctx, http.MethodGet, path, nil, &indices) == nil
	if listed {
		for _, ix := range indices {
			rep, ok := number(ix.Rep)
			if ok && rep == 0 && ix.Index != "" {
				out.NoReplicas = append(out.NoReplicas, ix.Index)
			}
			pri, okPri := number(ix.Pri)
			if !okPri || pri < 1 {
				pri = 1
			}
			held = append(held, indexCopies{Index: ix.Index, Copies: pri * (1 + max(rep, 0))})
		}
		sort.Strings(out.NoReplicas)
	}
	if used, limit, err := oc.ShardRoom(ctx); err == nil && limit > 0 {
		out.ShardsUsed, out.ShardLimit = &used, &limit
		if listed {
			settings := s.retentionSettings()
			keep := func(category string) int {
				p, _ := settings.For(category)
				return p.KeepDays
			}
			p := projectShards(prefix, held, used, limit, keep, time.Now())
			out.ShardsPerDay, out.ShardsProjected, out.ShardsFullInDays = &p.PerDay, &p.Projected, p.FullInDays
			out.keepDays = p.KeepDays
		}
	}

	if out.DataNodes != nil && *out.DataNodes > 1 {
		var shards []struct {
			Index  string `json:"index"`
			Shard  string `json:"shard"`
			PriRep string `json:"prirep"`
			Node   string `json:"node"`
		}
		today := url.PathEscape(prefix + "-*-" + time.Now().UTC().Format("2006.01.02") + "*")
		if oc.Do(ctx, http.MethodGet, "/_cat/shards/"+today+"?format=json&h=index,shard,prirep,node", nil, &shards) == nil {
			nodes := map[string]map[string]bool{}
			for _, sh := range shards {
				if sh.PriRep != "p" || sh.Node == "" || sh.Index == "" {
					continue
				}
				if nodes[sh.Index] == nil {
					nodes[sh.Index] = map[string]bool{}
				}
				nodes[sh.Index][sh.Shard+"\x00"+sh.Node] = true
			}
			out.PrimariesTogether = primariesTogether(nodes)
		}
	}
	if n, err := strconv.Atoi(out.ReplicasSetting); err == nil && n == 0 && out.DataNodes != nil && *out.DataNodes > 1 {
		out.SuggestAuto = true
	}
	out.Warnings = osWarnings(out)
	writeJSON(w, http.StatusOK, out)
}

// osWarnings says what in the card could lose events or stop the servers.
func osWarnings(c osCard) []string {
	var w []string
	if c.Nodes != nil && *c.Nodes == 1 {
		w = append(w, "One OpenSearch node: losing it stops every server.")
	} else if c.ManagerEligible != nil && *c.ManagerEligible < 3 {
		w = append(w, fmt.Sprintf("Only %d cluster-manager-eligible OpenSearch %s. OpenSearch needs a majority of them to work, so use three: then any one can stop.",
			*c.ManagerEligible, plural(*c.ManagerEligible, "node", "nodes")))
	}
	if c.UnassignedShards != nil && *c.UnassignedShards > 0 {
		w = append(w, fmt.Sprintf("%d %s on no node: OpenSearch could not place %s. Its cluster allocation explain API says why.",
			*c.UnassignedShards, plural(*c.UnassignedShards, "shard is", "shards are"), plural(*c.UnassignedShards, "it", "them")))
	}
	for _, d := range c.Disk {
		if d.UsedPercent != nil && d.Low != nil && *d.UsedPercent >= *d.Low {
			w = append(w, fmt.Sprintf("%s's disk is %.0f%% full, past the low watermark (%.0f%%): OpenSearch puts no new shards there.",
				d.Node, *d.UsedPercent, *d.Low))
		}
	}
	if n := len(c.PrimariesTogether); n > 0 {
		text := fmt.Sprintf("Every primary shard of %d of today's %s on one OpenSearch node, so that node alone does %s indexing work.",
			n, plural(n, "event indices is", "event indices are"), plural(n, "its", "their"))
		if c.PreferPrimary == nil || !*c.PreferPrimary {
			text += " Set cluster.routing.allocation.balance.prefer_primary to true, so OpenSearch spreads primary shards over the nodes."
		}
		if c.RebalancePrimary != nil && !*c.RebalancePrimary {
			text += " Set cluster.routing.allocation.rebalance.primary.enable to true, so OpenSearch moves primaries back after a node restarts."
		}
		w = append(w, text)
	}
	if text := shardWarning(c); text != "" {
		w = append(w, text)
	}
	if len(c.NoReplicas) > 0 && c.DataNodes != nil && *c.DataNodes > 1 {
		w = append(w, fmt.Sprintf("%d Signalith %s no copy on another node: losing the node %s on loses %s.",
			len(c.NoReplicas), plural(len(c.NoReplicas), "index has", "indices have"), plural(len(c.NoReplicas), "it is", "they are"),
			plural(len(c.NoReplicas), "it", "them")))
	}
	return w
}

// shardRoomAdvice is what to do when the cluster nears its shard limit.
const shardRoomAdvice = " To make room, keep fewer days on the Data retention page, send fewer data models, add an OpenSearch data node, " +
	"or raise cluster.max_shards_per_node, which is a soft limit (see Shards in the settings guide)."

// shardWarning says when the cluster holds, or at today's rate will
// hold, ingest.ShardRoomWarn of the shards it allows; "" when not.
func shardWarning(c osCard) string {
	if c.ShardsUsed == nil || c.ShardLimit == nil {
		return ""
	}
	used, limit := *c.ShardsUsed, *c.ShardLimit
	full := " Once it is full, OpenSearch refuses each new day's indices and events stop being stored."
	switch {
	case ingest.NearShardLimit(used, limit):
		return fmt.Sprintf("OpenSearch holds %d of the %d shards it allows (cluster.max_shards_per_node times the data nodes).", used, limit) +
			full + shardRoomAdvice
	case c.ShardsProjected != nil && c.ShardsPerDay != nil && ingest.NearShardLimit(*c.ShardsProjected, limit):
		return fmt.Sprintf("Each day adds %d %s (an index per data model written) and retention keeps up to %d days of them, so OpenSearch will hold about %d of the %d shards it allows.",
			*c.ShardsPerDay, plural(*c.ShardsPerDay, "shard", "shards"), c.keepDays, *c.ShardsProjected, limit) + full + shardRoomAdvice
	case c.ShardsFullInDays != nil && *c.ShardsFullInDays <= shardFullSoonDays:
		return fmt.Sprintf("Some data models are kept forever, so each day adds shards that are never deleted: in about %d %s OpenSearch will hold %.0f%% of the %d shards it allows.",
			*c.ShardsFullInDays, plural(*c.ShardsFullInDays, "day", "days"), ingest.ShardRoomWarn*100, limit) + full + shardRoomAdvice
	}
	return ""
}

// shardFullSoonDays is how many days ahead the card warns of data kept
// forever filling the shard limit.
const shardFullSoonDays = 90

// indexCopies is one index and its shard copies, primaries and replicas.
type indexCopies struct {
	Index  string
	Copies int
}

// shardProjection is what projectShards works out.
type shardProjection struct {
	PerDay, Projected int
	FullInDays        *int
	KeepDays          int
}

// projectShards works out how many shards the cluster will hold once
// retention keeps as many days of each data model written now as its
// policy says (keep returns a category's keep_days, 0 for forever): the
// shards it holds now, less those of the event indices that retention
// deletes, plus each such model's shards a day times the days kept
// (keep_days and today). A model's shards a day are its copies on today's
// or yesterday's indices, whichever is more, so the hours after midnight,
// before every model has written, do not count low. Models kept forever
// stay as they are now, and FullInDays says when, at their rate, the
// cluster holds ingest.ShardRoomWarn of limit.
func projectShards(prefix string, held []indexCopies, used, limit int, keep func(string) int, now time.Time) shardProjection {
	today := now.UTC().Truncate(24 * time.Hour)
	yesterday := today.AddDate(0, 0, -1)
	type days struct{ today, yesterday, held int }
	byModel := map[string]*days{}
	var models []string
	for _, ix := range held {
		category, day, ok := retention.ParseIndex(prefix, ix.Index)
		if !ok {
			continue
		}
		d := byModel[category]
		if d == nil {
			d = &days{}
			byModel[category] = d
			models = append(models, category)
		}
		d.held += ix.Copies
		switch {
		case day.Equal(today):
			d.today += ix.Copies
		case day.Equal(yesterday):
			d.yesterday += ix.Copies
		}
	}
	sort.Strings(models)
	var out shardProjection
	out.Projected = used
	forever := 0
	for _, m := range models {
		d := byModel[m]
		perDay := max(d.today, d.yesterday)
		if perDay == 0 {
			continue
		}
		out.PerDay += perDay
		k := keep(m)
		if k <= 0 {
			forever += perDay
			continue
		}
		out.Projected += perDay*(k+1) - d.held
		out.KeepDays = max(out.KeepDays, k+1)
	}
	out.Projected = max(out.Projected, 0)
	if forever > 0 {
		n := max(0, int((ingest.ShardRoomWarn*float64(limit)-float64(out.Projected))/float64(forever)))
		out.FullInDays = &n
	}
	return out
}

// retentionSettings returns the retention settings in effect, from
// signalith.yaml alone when retention does not run on this server.
func (s *Server) retentionSettings() retention.Settings {
	if s.Retention != nil {
		set, _ := s.Retention.Settings()
		return set
	}
	return retention.Effective(s.conf().RetentionPolicies(), retention.Saved{})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// primariesTogether lists the indices with two or more primary shards,
// all on one node, from each index's set of "shard\x00node" of its
// primaries.
func primariesTogether(prims map[string]map[string]bool) []string {
	out := []string{}
	for idx, set := range prims {
		if len(set) < 2 {
			continue
		}
		nodes := map[string]bool{}
		for k := range set {
			_, node, _ := strings.Cut(k, "\x00")
			nodes[node] = true
		}
		if len(nodes) == 1 {
			out = append(out, idx)
		}
	}
	sort.Strings(out)
	return out
}

// clusterBool reads a true/false cluster setting from the transient,
// persistent or default settings, in that order; nil when it is not there.
func clusterBool(settings map[string]map[string]any, key string) *bool {
	for _, layer := range []string{"transient", "persistent", "defaults"} {
		if v, ok := settings[layer][key]; ok {
			if b, err := strconv.ParseBool(strings.TrimSpace(fmt.Sprint(v))); err == nil {
				return &b
			}
			return nil
		}
	}
	return nil
}

// watermark returns a disk watermark as a percentage, from the
// transient, persistent or default cluster settings, in that order; nil
// when it is set in bytes or not there.
func watermark(settings map[string]map[string]any, which string) *float64 {
	key := "cluster.routing.allocation.disk.watermark." + which
	for _, layer := range []string{"transient", "persistent", "defaults"} {
		if v, ok := settings[layer][key]; ok {
			return percent(v)
		}
	}
	return nil
}

// percent reads "85%", "85", "85.5" or 85 as a percentage.
func percent(v any) *float64 {
	s := strings.TrimSuffix(strings.TrimSpace(fmt.Sprint(v)), "%")
	f, err := strconv.ParseFloat(s, 64)
	if v == nil || err != nil || f < 0 || f > 100 {
		return nil
	}
	return &f
}

// number reads a count that _cat answers as text or as a number.
func number(v any) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(v)))
	return n, v != nil && err == nil
}
