package store

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
)

// AutoReplicas is the replicas setting of Signalith's own small indices
// (findings, cases, threat intel and the like) when opensearch.replicas
// is auto: one copy on another node once OpenSearch has more than one,
// none on a single node, where a copy would have nowhere to go and only
// turn the cluster yellow.
const AutoReplicas = "0-1"

// SmallIndexSettings returns the settings a small index is created with:
// one shard, and the replicas settings given (opensearch.replicas, see
// config.Replicas.IndexSettings), or AutoReplicas when none are.
func SmallIndexSettings(replicas map[string]any) map[string]any {
	out := map[string]any{"number_of_shards": 1}
	if len(replicas) == 0 {
		out["auto_expand_replicas"] = AutoReplicas
		return out
	}
	maps.Copy(out, replicas)
	return out
}

// Replicate gives an index made with no copy on another node the
// replicas settings new indices get (as SmallIndexSettings). Indices made
// before Signalith asked for copies had a fixed number_of_replicas of 0,
// so losing a node lost what they held. Only such an index changes: one
// with auto_expand_replicas, or with a number_of_replicas other than 0
// that someone set, is left as it is, and so is a missing index. It may
// run any number of times.
func Replicate(ctx context.Context, cl interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}, index string, replicas map[string]any) error {
	want := SmallIndexSettings(replicas)
	delete(want, "number_of_shards")
	if n, ok := want["number_of_replicas"]; ok && fmt.Sprint(n) == "0" {
		return nil // no copies wanted: nothing to change
	}
	var got map[string]struct {
		Settings struct {
			Index struct {
				Replicas string `json:"number_of_replicas"`
				Auto     string `json:"auto_expand_replicas"`
			} `json:"index"`
		} `json:"settings"`
	}
	err := cl.Do(ctx, http.MethodGet, "/"+url.PathEscape(index)+"/_settings", nil, &got)
	if indexMissing(err) || err == nil && len(got) == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	for _, s := range got {
		if s.Settings.Index.Replicas != "0" || (s.Settings.Index.Auto != "" && s.Settings.Index.Auto != "false") {
			return nil
		}
	}
	err = cl.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_settings", map[string]any{"index": want}, nil)
	if indexMissing(err) {
		return nil
	}
	return err
}

func indexMissing(err error) bool {
	var oe *Error
	return errors.As(err, &oe) && oe.Status == http.StatusNotFound
}
