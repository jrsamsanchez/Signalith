package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// TemplateVersion is the version of IndexTemplate's output, kept in the
// template's _meta. Bump it whenever that output changes (the test that
// hashes the template says so): a server only replaces a template of a
// lower version, so an older Signalith started next to a newer one does
// not put its older template back.
const TemplateVersion = 44

// totalFieldsLimit is index.mapping.total_fields.limit: the most fields one
// daily index may have. It leaves room above the known fields, a day's
// budget of new names and a burst of names from several servers before
// the mapping guard (mappingStop) sees them.
const totalFieldsLimit = 2400

// templateHash is the SHA-256 of IndexTemplate("p", auto replicas) as
// JSON, which TestTemplateVersionBumped compares, so a change to the
// template cannot go out without a new TemplateVersion.
const templateHash = "27436f25f1a55b620f18d4e1f2f28041bfb01ef3e02f9ff99d2c746afb6a2566"

// IndexTemplate returns the OpenSearch index template every Signalith index
// uses: strings are exact-match keywords (fast filters and stats), the raw
// message is full-text, and ports, IDs and counts stay numeric.
//
// Every field Signalith produces itself (knownFields) is mapped up front,
// so a sender cannot claim one with another type first (user as a number,
// say), and an event made of known fields always fits, however many other
// names a day's index has. Dates are not guessed from strings, so a user
// named like a date stays a keyword; and a value a field's type cannot
// take (a port "ssh") is left unindexed, not a reason to reject the event.
//
// The field limit leaves room for the names senders choose (generic JSON
// keys, syslog structured data, CEF extensions): the pipeline lets each
// daily index gain at most maxNewNamesPerIndex of them per run, which with
// the known fields stays well under the limit, even across a restart.
// device_time (an event's own time when it was too old or too far ahead
// to be the event time) is a keyword, so any value a sender wrote is
// stored rather than rejected as a bad date.
//
// replicas are the index settings for extra copies on other nodes (see
// config.Replicas.IndexSettings): number_of_replicas, or
// auto_expand_replicas, and number_of_shards when more than one (see
// config.OpenSearch.EventIndexSettings, and fitShards for automatic). They
// apply to each new day's indices; days already stored keep the copies
// and shards they have.
func IndexTemplate(prefix string, replicas map[string]any) map[string]any {
	props := map[string]any{}
	for name, typ := range knownFields {
		switch typ {
		case "keyword":
			props[name] = map[string]any{"type": "keyword", "ignore_above": 8191}
		case "wildcard":
			// Indexes the whole value however long, for *word* searches
			// inside it; lowercased so matches ignore case as keywords do.
			// No doc values (the default): they cannot hold a value over
			// 32,766 bytes and would refuse the event, so the field cannot
			// be a stats by field, as when it was text.
			props[name] = map[string]any{"type": "wildcard", "normalizer": "lowercase"}
		default:
			props[name] = map[string]any{"type": typ}
		}
	}
	settings := map[string]any{
		"number_of_shards": 1,
		"refresh_interval": "5s",
		"mapping": map[string]any{
			"total_fields":     map[string]any{"limit": totalFieldsLimit},
			"ignore_malformed": true,
		},
	}
	for k, v := range replicas {
		settings[k] = v
	}
	return map[string]any{
		"index_patterns": []string{prefix + "-*"},
		"priority":       100,
		"_meta":          map[string]any{"signalith": map[string]any{"template_version": TemplateVersion, "managed_by": "signalith"}},
		"template": map[string]any{
			"settings": settings,
			"mappings": map[string]any{
				"date_detection": false,
				"dynamic_templates": []any{
					map[string]any{"strings_as_keywords": map[string]any{
						"match_mapping_type": "string",
						"mapping":            map[string]any{"type": "keyword", "ignore_above": 8191},
					}},
				},
				"properties": props,
			},
		},
	}
}

// newerLogged is set once this process has said that a newer template is
// in place, so that is said once rather than at every start in place.
var newerLogged atomic.Bool

// PutIndexTemplate installs IndexTemplate, unless the template in place
// is already this one or comes from a newer Signalith. Several servers
// share one OpenSearch, and may run different versions while they are
// upgraded one by one: the newest template wins, whichever server starts
// last (see RestoreIndexTemplate for two that start together). A
// template of this version is written again only when its replicas or
// shards differ from this server's settings, so a changed setting still applies,
// and no start writes it for nothing. log may be nil.
//
// OpenSearch before 2.15 has no wildcard field type, so there the
// wildcard fields are keywords instead: they still match, except values
// longer than a keyword indexes.
func PutIndexTemplate(ctx context.Context, cl *store.Client, prefix string, replicas map[string]any, log *slog.Logger) error {
	_, err := putTemplate(ctx, cl, prefix, replicas, log, false)
	return err
}

// RestoreIndexTemplate installs IndexTemplate again only when the
// template in place is missing or from an older Signalith, and reports
// whether it did. Each server runs it every few minutes: during an
// upgrade, a server of the older version that started at the same time
// may have written its template over this one. A template of this
// version with other replicas or shards is left alone, so servers whose
// Replicas or Shards differ do not take turns rewriting it.
func RestoreIndexTemplate(ctx context.Context, cl *store.Client, prefix string, replicas map[string]any, log *slog.Logger) (bool, error) {
	return putTemplate(ctx, cl, prefix, replicas, log, true)
}

func putTemplate(ctx context.Context, cl *store.Client, prefix string, replicas map[string]any, log *slog.Logger, onlyOlder bool) (bool, error) {
	// Automatic shards follow the data nodes: a restore check rewrites a
	// template of this version whose shards no longer fit them, as every
	// server sizes them the same way from the same cluster.
	auto := fmt.Sprint(replicas["number_of_shards"]) == store.AutoShards
	replicas, err := fitShards(ctx, cl, prefix, replicas, log)
	if err != nil {
		return false, err
	}
	stored, found, err := getTemplate(ctx, cl, prefix)
	if err != nil {
		return false, err
	}
	if found {
		switch v := storedVersion(stored); {
		case v > TemplateVersion:
			if log != nil && !newerLogged.Swap(true) {
				log.Info("An index template from a newer Signalith is in place; this server leaves it as it is",
					"template", prefix, "version", v, "this_version", TemplateVersion)
			}
			return false, nil
		case v == TemplateVersion && sameReplicas(stored, replicas):
			return false, nil
		case v == TemplateVersion && onlyOlder && !auto:
			return false, nil
		}
	}
	tmpl := IndexTemplate(prefix, replicas)
	err = cl.PutIndexTemplate(ctx, prefix, tmpl)
	var se *store.Error
	if errors.As(err, &se) && se.Status == http.StatusBadRequest && strings.Contains(se.Body, "wildcard") {
		err = cl.PutIndexTemplate(ctx, prefix, withoutWildcard(tmpl))
	}
	if err == nil && log != nil && found {
		log.Info("index template updated; new days' indices get its settings", "template", prefix,
			"shards", tmpl["template"].(map[string]any)["settings"].(map[string]any)["number_of_shards"])
	}
	return err == nil, err
}

// MaxAutoShards is the most primary shards an automatic opensearch.shards
// gives each day's index: past that, each search of a day would fan out to
// more shards than it gains from, and rollover (see Rollover) keeps the
// shards of a busy day small instead.
const MaxAutoShards = 8

// autoShardRoom is the share of the cluster's shard limit in use above
// which automatic shards fall back to one per index: each day adds an
// index per data model, and once the limit is reached OpenSearch refuses
// new indices, which stops ingestion at the start of a day.
const autoShardRoom = 0.5

// roomLogged is set once this process has warned that automatic shards
// fell back to one, so the template checks every few minutes do not
// repeat it.
var roomLogged atomic.Bool

// fitShards sets number_of_shards for the data nodes OpenSearch has.
//
// Automatic (store.AutoShards) is one primary per data node, up to
// MaxAutoShards, so each node writes and merges a share of every day
// rather than one node doing a whole day's merges; on one node it is one.
// It is one as well while the cluster already holds more than half the
// shards it allows, so more shards cannot be what stops ingestion.
//
// A number is capped at the number of data nodes. OpenSearch refuses new
// indices once a node holds cluster.max_shards_per_node shards (1,000 by
// default), and each day adds an index per data model, so more shards
// than nodes would fill that limit sooner than one shard per index does
// on one node, and stop ingestion at the start of a day. With at most one
// shard per node, each node holds no more per day than a single node
// holds with one.
func fitShards(ctx context.Context, cl *store.Client, prefix string, settings map[string]any, log *slog.Logger) (map[string]any, error) {
	auto := fmt.Sprint(settings["number_of_shards"]) == store.AutoShards
	var want int
	if !auto {
		fmt.Sscan(fmt.Sprint(settings["number_of_shards"]), &want)
		if want <= 1 {
			return settings, nil
		}
	}
	nodes, err := cl.DataNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not count OpenSearch's data nodes for opensearch.shards: %w", err)
	}
	nodes = max(nodes, 1)
	out := maps.Clone(settings)
	if auto {
		want = min(nodes, MaxAutoShards)
		if want > 1 {
			used, limit, err := cl.ShardRoom(ctx)
			if err != nil {
				return nil, fmt.Errorf("could not read OpenSearch's shard limit for automatic opensearch.shards: %w", err)
			}
			if float64(used) > autoShardRoom*float64(limit) {
				if log != nil && !roomLogged.Swap(true) {
					log.Warn("OpenSearch holds more than half the shards it allows, so each new day's events get one shard per data model instead of one per data node; "+
						"keep fewer days, or raise cluster.max_shards_per_node",
						"template", prefix, "shards_in_use", used, "shard_limit", limit)
				}
				want = 1
			}
		}
	} else if want > nodes {
		if log != nil {
			log.Warn("opensearch.shards is more than OpenSearch's data nodes; each new day's events get one shard per data node instead",
				"template", prefix, "shards", want, "data_nodes", nodes)
		}
		want = nodes
	}
	if want <= 1 {
		delete(out, "number_of_shards")
	} else {
		out["number_of_shards"] = want
	}
	return out, nil
}

// getTemplate reads the index template called name, as OpenSearch keeps
// it; found is false when there is none.
func getTemplate(ctx context.Context, cl *store.Client, name string) (tmpl map[string]any, found bool, err error) {
	var out struct {
		Templates []struct {
			Name     string         `json:"name"`
			Template map[string]any `json:"index_template"`
		} `json:"index_templates"`
	}
	err = cl.Do(ctx, http.MethodGet, "/_index_template/"+url.PathEscape(name), nil, &out)
	var se *store.Error
	if errors.As(err, &se) && se.Status == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	for _, t := range out.Templates {
		if t.Name == name {
			return t.Template, true, nil
		}
	}
	return nil, false, nil
}

// storedVersion returns the template_version in a stored template's
// _meta, or 0 for a template from before there was one.
func storedVersion(tmpl map[string]any) int {
	meta, _ := tmpl["_meta"].(map[string]any)
	sig, _ := meta["signalith"].(map[string]any)
	var n int
	if v, ok := sig["template_version"]; ok {
		// A number, however it was decoded (json.Number with the store
		// client), or text.
		fmt.Sscan(fmt.Sprint(v), &n)
	}
	return n
}

// sameReplicas reports whether a stored template has the replica and
// shard settings want. OpenSearch gives settings back under "index", with
// values as text; a template put as is (a test's fake) has them as they
// were put.
func sameReplicas(tmpl map[string]any, want map[string]any) bool {
	inner, _ := tmpl["template"].(map[string]any)
	settings, _ := inner["settings"].(map[string]any)
	got := func(key string) string {
		if v, ok := settings[key]; ok {
			return fmt.Sprint(v)
		}
		if ix, ok := settings["index"].(map[string]any); ok {
			if v, ok := ix[key]; ok {
				return fmt.Sprint(v)
			}
		}
		if v, ok := settings["index."+key]; ok {
			return fmt.Sprint(v)
		}
		return ""
	}
	for _, key := range []string{"auto_expand_replicas", "number_of_replicas"} {
		w := ""
		if v, ok := want[key]; ok {
			w = fmt.Sprint(v)
		}
		g := got(key)
		if key == "auto_expand_replicas" && g == "false" {
			g = ""
		}
		if g != w {
			return false
		}
	}
	// One shard unless the settings ask for more (IndexTemplate always
	// writes the number; a fake template may leave it out).
	w, g := "1", got("number_of_shards")
	if v, ok := want["number_of_shards"]; ok {
		w = fmt.Sprint(v)
	}
	if g == "" {
		g = "1"
	}
	return g == w
}

// withoutWildcard maps a template's wildcard fields as keywords.
func withoutWildcard(tmpl map[string]any) map[string]any {
	props := tmpl["template"].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any)
	for name, typ := range knownFields {
		if typ == "wildcard" {
			props[name] = map[string]any{"type": "keyword", "ignore_above": 8191}
		}
	}
	return tmpl
}
