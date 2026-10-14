package audit

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Doer sends one request to OpenSearch and decodes its JSON answer into
// out, as store.Client.Do does.
type Doer interface {
	Do(ctx context.Context, method, path string, body, out any) error
}

// IndexName returns the audit index for events of t's month (UTC), such
// as signalith_audit-2026.10.
func IndexName(prefix string, t time.Time) string {
	return prefix + "_audit-" + t.UTC().Format("2006.01")
}

// Pattern returns the index pattern matching every audit index.
func Pattern(prefix string) string { return prefix + "_audit-*" }

// TemplateName returns the name of the audit indices' index template.
func TemplateName(prefix string) string { return prefix + "_audit" }

// Template returns the index template for the audit indices. replicas,
// when set, is their auto_expand_replicas; otherwise it is "0-1".
func Template(prefix, replicas string) map[string]any {
	if replicas == "" {
		replicas = "0-1"
	}
	kw := map[string]any{"type": "keyword"}
	return map[string]any{
		"index_patterns": []string{Pattern(prefix)},
		// Above any catch-all template someone may have.
		"priority": 500,
		"template": map[string]any{
			"settings": map[string]any{"number_of_shards": 1, "auto_expand_replicas": replicas},
			"mappings": map[string]any{
				"dynamic": "false",
				"properties": map[string]any{
					"@timestamp": map[string]any{"type": "date"},
					"server":     kw, "node_id": kw, "user": kw, "action": kw,
					"target": kw, "source_ip": kw, "level": kw,
					"message": map[string]any{"type": "text",
						"fields": map[string]any{"keyword": map[string]any{"type": "keyword", "ignore_above": 1024}}},
					"epoch": map[string]any{"type": "long"},
					"seq":   map[string]any{"type": "long"},
					// Kept in the document, not searchable on their own.
					"fields": map[string]any{"type": "object", "enabled": false},
				},
			},
		},
		"_meta": map[string]any{"managed_by": "signalith"},
	}
}

// EnsureTemplate saves the audit indices' index template, so each new
// monthly index is created with the audit mappings.
func EnsureTemplate(ctx context.Context, c Doer, prefix, replicas string) error {
	return c.Do(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(TemplateName(prefix)), Template(prefix, replicas), nil)
}
