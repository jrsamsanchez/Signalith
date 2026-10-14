package shared

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestEnsureConfig(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Again: already there is fine.
	if err := EnsureConfig(ctx, e.c, testPrefix); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Settings map[string]any `json:"settings"`
		Mappings struct {
			Dynamic    string                    `json:"dynamic"`
			Properties map[string]map[string]any `json:"properties"`
		} `json:"mappings"`
	}
	if err := json.Unmarshal(e.os.IndexBody(testIndex), &body); err != nil {
		t.Fatal(err)
	}
	if body.Settings["number_of_shards"] != 1.0 || body.Settings["auto_expand_replicas"] != "0-1" || body.Mappings.Dynamic != "false" {
		t.Errorf("index %+v", body)
	}
	for _, f := range []string{"kind", "id", "rev", "updated_by"} {
		if body.Mappings.Properties[f] == nil {
			t.Errorf("%s is not mapped", f)
		}
	}
	for _, f := range []string{"body", "mac", "write_id"} {
		if body.Mappings.Properties[f] != nil {
			t.Errorf("%s is mapped", f)
		}
	}
	if err := EnsureConfigTemplate(ctx, e.c, testPrefix); err != nil {
		t.Fatal(err)
	}
	if tpl := string(e.os.Template(testIndex)); !strings.Contains(tpl, `"priority":500`) {
		t.Errorf("template %s", tpl)
	}

	u1, err := IndexUUID(ctx, e.c, testPrefix)
	if err != nil || u1 == "" {
		t.Fatalf("uuid %q %v", u1, err)
	}
	if err := e.c.Do(ctx, http.MethodDelete, "/"+testIndex, nil, nil); err != nil {
		t.Fatal(err)
	}
	if u, err := IndexUUID(ctx, e.c, testPrefix); u != "" || err != nil {
		t.Errorf("missing index: %q %v", u, err)
	}
	if err := EnsureConfig(ctx, e.c, testPrefix); err != nil {
		t.Fatal(err)
	}
	if u2, _ := IndexUUID(ctx, e.c, testPrefix); u2 == "" || u2 == u1 {
		t.Errorf("uuid after making it again: %q, before %q", u2, u1)
	}
}

func TestEnsureSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for range 2 {
		if err := EnsureSessions(ctx, e.c, testPrefix); err != nil {
			t.Fatal(err)
		}
	}
	var body struct {
		Settings map[string]any `json:"settings"`
		Mappings struct {
			Dynamic    string                    `json:"dynamic"`
			Properties map[string]map[string]any `json:"properties"`
		} `json:"mappings"`
	}
	if err := json.Unmarshal(e.os.IndexBody("s_sessions"), &body); err != nil {
		t.Fatal(err)
	}
	if body.Settings["number_of_shards"] != 1.0 || body.Settings["auto_expand_replicas"] != "0-1" || body.Settings["refresh_interval"] != "1s" || body.Mappings.Dynamic != "false" {
		t.Errorf("index %+v", body)
	}
	for f, typ := range map[string]string{"user": "keyword", "epoch": "long", "created": "date", "last_seen": "date",
		"remember": "boolean", "degraded": "boolean", "node": "keyword", "client": "keyword", "method": "keyword"} {
		if body.Mappings.Properties[f]["type"] != typ {
			t.Errorf("%s is mapped as %v", f, body.Mappings.Properties[f])
		}
	}
	if body.Mappings.Properties["mac"] != nil {
		t.Error("mac is mapped")
	}
	if err := EnsureSessionsTemplate(ctx, e.c, testPrefix); err != nil {
		t.Fatal(err)
	}
	if tpl := string(e.os.Template("s_sessions")); !strings.Contains(tpl, `"priority":500`) || !strings.Contains(tpl, `"s_sessions"`) {
		t.Errorf("template %s", tpl)
	}
}
