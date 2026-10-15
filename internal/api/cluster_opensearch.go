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

	"github.com/jrsamsanchez/signalith/internal/store"
)

// osCluster is what the OpenSearch card on the Servers page needs from
// the OpenSearch client, beyond Backend.
type osCluster interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	Endpoints() []store.EndpointStatus
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
	Status           string       `json:"status"`
	Problem          string       `json:"problem,omitempty"`
	Nodes            *int         `json:"nodes"`
	DataNodes        *int         `json:"data_nodes"`
	ManagerEligible  *int         `json:"manager_eligible"`
	UnassignedShards *int         `json:"unassigned_shards"`
	Disk             []osDisk     `json:"disk"`
	NoReplicas       []string     `json:"no_replicas"`
	ReplicasSetting  string       `json:"replicas_setting"`
	SuggestAuto      bool         `json:"suggest_auto"`
	Endpoints        []osEndpoint `json:"endpoints"`
	Warnings         []string     `json:"warnings"`
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
	out := osCard{Disk: []osDisk{}, NoReplicas: []string{}, Endpoints: []osEndpoint{}, Warnings: []string{},
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
	}
	prefix := conf.OpenSearch.IndexPrefix
	var indices []struct {
		Index string `json:"index"`
		Rep   any    `json:"rep"`
	}
	path := "/_cat/indices/" + url.PathEscape(prefix+"-*") + "," + url.PathEscape(prefix+"_*") + "?format=json&h=index,rep&expand_wildcards=open"
	if oc.Do(ctx, http.MethodGet, path, nil, &indices) == nil {
		for _, ix := range indices {
			if rep, ok := number(ix.Rep); ok && rep == 0 && ix.Index != "" {
				out.NoReplicas = append(out.NoReplicas, ix.Index)
			}
		}
		sort.Strings(out.NoReplicas)
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
	if len(c.NoReplicas) > 0 && c.DataNodes != nil && *c.DataNodes > 1 {
		w = append(w, fmt.Sprintf("%d Signalith %s no copy on another node: losing the node %s on loses %s.",
			len(c.NoReplicas), plural(len(c.NoReplicas), "index has", "indices have"), plural(len(c.NoReplicas), "it is", "they are"),
			plural(len(c.NoReplicas), "it", "them")))
	}
	return w
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
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
