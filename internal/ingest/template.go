package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
const TemplateVersion = 1

// templateHash is the SHA-256 of IndexTemplate("p", auto replicas) as
// JSON, which TestTemplateVersionBumped compares, so a change to the
// template cannot go out without a new TemplateVersion.
const templateHash = "32940b90e934f8bb12b609a0c17e0ac9b13cca7cb92fa335547b480b56a6d1a2"

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
// auto_expand_replicas. They apply to each new day's indices; days
// already stored keep the copies they have.
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
			"total_fields":     map[string]any{"limit": 2000},
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
// template of this version is written again only when its replicas
// differ from this server's setting, so a changed setting still applies,
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
// version with other replicas is left alone, so servers whose Replicas
// differ do not take turns rewriting it.
func RestoreIndexTemplate(ctx context.Context, cl *store.Client, prefix string, replicas map[string]any, log *slog.Logger) (bool, error) {
	return putTemplate(ctx, cl, prefix, replicas, log, true)
}

func putTemplate(ctx context.Context, cl *store.Client, prefix string, replicas map[string]any, log *slog.Logger, onlyOlder bool) (bool, error) {
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
		case v == TemplateVersion && (onlyOlder || sameReplicas(stored, replicas)):
			return false, nil
		}
	}
	tmpl := IndexTemplate(prefix, replicas)
	err = cl.PutIndexTemplate(ctx, prefix, tmpl)
	var se *store.Error
	if errors.As(err, &se) && se.Status == http.StatusBadRequest && strings.Contains(se.Body, "wildcard") {
		err = cl.PutIndexTemplate(ctx, prefix, withoutWildcard(tmpl))
	}
	return err == nil, err
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

// sameReplicas reports whether a stored template has the replica settings
// want. OpenSearch gives settings back under "index", with values as
// text; a template put as is (a test's fake) has them as they were put.
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
	return true
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
