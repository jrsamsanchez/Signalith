// Package shared keeps the configuration that every Signalith server of a
// cluster shares in OpenSearch, in the <prefix>_config index: one signed
// document per setting group (Doc) or per item of a list that grows
// (Collection). Each server holds an in-memory copy, checks every version
// it reads against a MAC made with the cluster key, refuses copies that
// were changed outside Signalith or rolled back, and polls the versions
// every 2 seconds to follow the other servers' changes (Hub). Writes are
// compare-and-set, so no change is lost when two servers save at once.
//
// The package knows nothing about what the documents hold: the stores of
// feeds, retention policies, users and the rest use it with their own
// types. It imports no domain package, so any of them may use it.
package shared

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// ConfigIndex is the index of the shared configuration. The underscore
// keeps it out of the event indices (<prefix>-*).
func ConfigIndex(prefix string) string { return prefix + "_config" }

// runtimeIndex is the cluster's runtime index (cluster.RuntimeIndex),
// where requests are kept.
func runtimeIndex(prefix string) string { return prefix + "_runtime" }

// Doer sends OpenSearch REST requests. *store.Client has it.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// configSettings and configMappings are the config index's. Only the
// envelope's fields are mapped; body, mac and write_id are kept but not
// indexed, so OpenSearch never looks into a body.
func configSettings() map[string]any {
	return map[string]any{"number_of_shards": 1, "auto_expand_replicas": "0-1", "refresh_interval": "1s"}
}

func configMappings() map[string]any {
	kw := map[string]any{"type": "keyword"}
	return map[string]any{
		"dynamic": "false",
		"properties": map[string]any{
			"kind": kw, "id": kw, "name": kw,
			"enabled": map[string]any{"type": "boolean"}, "deleted": map[string]any{"type": "boolean"},
			"format": map[string]any{"type": "integer"}, "rev": map[string]any{"type": "long"},
			"updated_at": map[string]any{"type": "date"},
			"updated_by": map[string]any{"properties": map[string]any{"user": kw, "node": kw}},
		},
	}
}

// EnsureConfig creates the config index if it is missing. Any server may,
// at any time; one that finds it already made carries on.
func EnsureConfig(ctx context.Context, c Doer, prefix string) error {
	err := c.Do(ctx, http.MethodPut, "/"+url.PathEscape(ConfigIndex(prefix)), map[string]any{"settings": configSettings(), "mappings": configMappings()}, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusBadRequest && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// EnsureConfigTemplate saves an index template with the config index's
// settings, so that a write after someone deleted the index does not make
// OpenSearch create it with its own defaults. A user who may not save
// templates still gets the index; the caller logs the error.
func EnsureConfigTemplate(ctx context.Context, c Doer, prefix string) error {
	name := ConfigIndex(prefix)
	return c.Do(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(name), map[string]any{
		"index_patterns": []string{name},
		// Above any catch-all template someone may have.
		"priority": 500,
		"template": map[string]any{"settings": configSettings(), "mappings": configMappings()},
		"_meta":    map[string]any{"managed_by": "signalith"},
	}, nil)
}

// SessionsIndex is the index of the sign-in sessions every member
// accepts.
func SessionsIndex(prefix string) string { return prefix + "_sessions" }

// sessionsSettings and sessionsMappings are the sessions index's. The MAC
// is kept but not indexed.
func sessionsSettings() map[string]any {
	return map[string]any{"number_of_shards": 1, "auto_expand_replicas": "0-1", "refresh_interval": "1s"}
}

func sessionsMappings() map[string]any {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	boolean := map[string]any{"type": "boolean"}
	return map[string]any{
		"dynamic": "false",
		"properties": map[string]any{
			"user": kw, "node": kw, "client": kw, "method": kw,
			"epoch":   map[string]any{"type": "long"},
			"created": date, "last_seen": date,
			"remember": boolean, "degraded": boolean,
		},
	}
}

// EnsureSessions creates the sessions index if it is missing. Any server
// may, at any time; one that finds it already made carries on.
func EnsureSessions(ctx context.Context, c Doer, prefix string) error {
	err := c.Do(ctx, http.MethodPut, "/"+url.PathEscape(SessionsIndex(prefix)), map[string]any{"settings": sessionsSettings(), "mappings": sessionsMappings()}, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusBadRequest && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// EnsureSessionsTemplate saves an index template with the sessions
// index's settings, as EnsureConfigTemplate does for the config index.
func EnsureSessionsTemplate(ctx context.Context, c Doer, prefix string) error {
	name := SessionsIndex(prefix)
	return c.Do(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(name), map[string]any{
		"index_patterns": []string{name},
		"priority":       500,
		"template":       map[string]any{"settings": sessionsSettings(), "mappings": sessionsMappings()},
		"_meta":          map[string]any{"managed_by": "signalith"},
	}, nil)
}

// IndexUUID returns the uuid OpenSearch gave the config index when it
// was created; an index deleted and created again has another. It is ""
// with no error when the index does not exist.
func IndexUUID(ctx context.Context, c Doer, prefix string) (string, error) {
	var out map[string]struct {
		Settings struct {
			Index struct {
				UUID string `json:"uuid"`
			} `json:"index"`
		} `json:"settings"`
	}
	err := c.Do(ctx, http.MethodGet, "/"+url.PathEscape(ConfigIndex(prefix))+"/_settings", nil, &out)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	// One entry, named after the index (or the index behind an alias).
	for _, ix := range out {
		if ix.Settings.Index.UUID != "" {
			return ix.Settings.Index.UUID, nil
		}
	}
	return "", fmt.Errorf("OpenSearch did not say the uuid of %s", ConfigIndex(prefix))
}
