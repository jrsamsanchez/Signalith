package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestReplicasFromFile(t *testing.T) {
	auto := map[string]any{"auto_expand_replicas": "0-1"}
	for _, tc := range []struct {
		yaml string
		want map[string]any // nil: refused
	}{
		{"opensearch:\n  replicas: 0\n", map[string]any{"number_of_replicas": 0}},
		{"opensearch:\n  replicas: 2\n", map[string]any{"number_of_replicas": 2}},
		{"opensearch:\n  replicas: \"1\"\n", map[string]any{"number_of_replicas": 1}},
		{"opensearch:\n  replicas: auto\n", auto},
		{"opensearch:\n  replicas: AUTO\n", auto},
		{"", auto},
		{"opensearch:\n  index_prefix: signalith\n", auto},
		{"opensearch:\n  replicas: -1\n", nil},
		{"opensearch:\n  replicas: lots\n", nil},
		{"opensearch:\n  replicas: 1.5\n", nil},
	} {
		c, err := Load(writeConfig(t, tc.yaml))
		if tc.want == nil {
			if err == nil || !strings.Contains(err.Error(), "opensearch.replicas must be auto or a whole number of 0 or more") {
				t.Errorf("%q: err %v", tc.yaml, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.yaml, err)
			continue
		}
		if got := c.OpenSearch.Replicas.IndexSettings(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: settings %v, want %v", tc.yaml, got, tc.want)
		}
	}
}

func TestReplicasOnThePage(t *testing.T) {
	path := writeConfig(t, "")
	for raw, want := range map[string]string{"auto": "", "3": "", " 0 ": "", "two": "Enter auto, or a whole number", "-2": "Enter auto, or a whole number"} {
		res, err := CheckEdit(path, Edit{By: "alice", Values: map[string]any{"opensearch.replicas": raw}})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Fields["opensearch.replicas"]; want == "" && got != "" || !strings.Contains(got, want) {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
		if want == "" && string(res.Config.OpenSearch.Replicas) != strings.TrimSpace(raw) {
			t.Errorf("%q: saved %q", raw, res.Config.OpenSearch.Replicas)
		}
	}
}
