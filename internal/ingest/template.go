package ingest

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/store"
)

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
func IndexTemplate(prefix string, replicas int) map[string]any {
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
	return map[string]any{
		"index_patterns": []string{prefix + "-*"},
		"priority":       100,
		"template": map[string]any{
			"settings": map[string]any{
				"number_of_shards":   1,
				"number_of_replicas": replicas,
				"refresh_interval":   "5s",
				"mapping": map[string]any{
					"total_fields":     map[string]any{"limit": 2000},
					"ignore_malformed": true,
				},
			},
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

// PutIndexTemplate installs IndexTemplate. OpenSearch before 2.15 has no
// wildcard field type, so there the wildcard fields are keywords instead:
// they still match, except values longer than a keyword indexes.
func PutIndexTemplate(ctx context.Context, cl *store.Client, prefix string, replicas int) error {
	tmpl := IndexTemplate(prefix, replicas)
	err := cl.PutIndexTemplate(ctx, prefix, tmpl)
	var se *store.Error
	if errors.As(err, &se) && se.Status == http.StatusBadRequest && strings.Contains(se.Body, "wildcard") {
		return cl.PutIndexTemplate(ctx, prefix, withoutWildcard(tmpl))
	}
	return err
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
