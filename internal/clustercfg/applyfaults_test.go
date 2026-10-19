// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercfg

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// applyChanged is a signalith.yaml that changes a value of each shared
// document: the retention policies, the feeds and the settings.
const applyChanged = "retention:\n  days: 40\n  default:\n    keep_days: 20\n  policies:\n    network_traffic:\n      keep_days: 10\n  guard:\n    max_disk_percent: 80\n" +
	"intel:\n  feeds:\n    - name: abuse\n      url: https://abuse.example.com/list\n      format: lines\n      type: ip\n" +
	"search:\n  max_events: 600\n"

// A changed signalith.yaml whose shared document cannot be written is
// reported, and the next start applies what was left.
func TestApplyWriteRefusals(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, "retention:\n  days: 30\n"), nil)
	a.load()
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("first apply %+v", res)
	}
	a.rewrite(applyChanged)
	ctx := context.Background()
	for _, id := range []string{RetentionID, FeedsID, SettingsID, "nodecfg:n_siem-a"} {
		o.fake.SetFault(func(method, path string) *ostest.Fault {
			if method != http.MethodGet && strings.Contains(path, "/_doc/"+id+"?") {
				return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
			}
			return nil
		})
		a.cycle()
		if res, err := Apply(ctx, a.rt, a.docs, a.cfg.Load(), a.name, a.log); err == nil {
			t.Errorf("%s not written, applied %+v", id, res)
		}
		o.fake.SetFault(nil)
	}
	// Each refusal came after the documents before it were written: the
	// last run wrote every value but did not record them, so this one
	// applies them again and records them.
	res := a.apply()
	want := []string{"retention.days", "retention.default", "retention.policies.network_traffic", "retention.guard", "intel.feeds[abuse]", "search.max_events"}
	if !slices.Equal(res.Applied, want) {
		t.Errorf("applied %v, want %v", res.Applied, want)
	}
	if res := a.apply(); len(res.Applied) != 0 {
		t.Errorf("applied again: %v", res.Applied)
	}
	body, _ := a.docs.Retention().Get()
	if body.Days == nil || *body.Days != 40 || body.Default == nil || body.Default.KeepDays != 20 ||
		body.Policies["network_traffic"].KeepDays != 10 || body.Guard == nil || body.Guard.MaxDiskPercent != 80 {
		t.Errorf("retention %+v", body)
	}
	for _, k := range []string{"days", "default", "policies.network_traffic", "guard"} {
		if f := body.From[k]; f.Source != FromYAML || f.Node != "siem-a" {
			t.Errorf("%s from %+v", k, f)
		}
	}
	if v, _ := a.setting("search.max_events"); rawString(v.Value) != "600" {
		t.Errorf("max events %+v", v)
	}
}
