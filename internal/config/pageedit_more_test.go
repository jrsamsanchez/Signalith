// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// Keys that are not settings are named in the result, for every kind of
// change; a change a restart set aside can be used again or replaced.
func TestCheckEditKinds(t *testing.T) {
	path := writeConfig(t, "")
	writePage(t, path, "settings:\n"+
		"  search.max_events:\n    value: 600\n    refused: it broke something\n    refused_at: 2026-10-12T09:00:00Z\n"+
		"  search.summary_days:\n    value: 7\n    refused: it broke something\n    refused_at: 2026-10-12T09:00:00Z\n")
	res, err := CheckEdit(path, Edit{
		Clear: []string{"no.such.clear"}, Reset: []string{"no.such.reset"}, Retry: []string{"no.such.retry", "search.max_events", "search.listen"},
		Values: map[string]any{"search.summary_days": float64(9)}, By: "sam", At: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"no.such.clear", "no.such.reset", "no.such.retry"} {
		if res.Fields[k] == "" {
			t.Errorf("%s has no problem: %v", k, res.Fields)
		}
	}
	e := res.Page.Settings["search.max_events"]
	if e == nil || e.Refused != "" {
		t.Errorf("the retried change is still set aside: %+v", e)
	}
	e = res.Page.Settings["search.summary_days"]
	if e == nil || e.Refused != "" || e.Value.Value != "9" {
		t.Errorf("the replaced change = %+v", e)
	}
	// Retrying a change that was not set aside changes nothing.
	res, err = CheckEdit(path, Edit{Retry: []string{"search.default_earliest"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range res.Changed {
		if k == "search.default_earliest" {
			t.Error("retrying a change that is not set aside changed it")
		}
	}
	// Only secrets can be cleared.
	res, err = CheckEdit(path, Edit{Clear: []string{"search.max_events"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Fields["search.max_events"], "Only passwords and keys can be cleared") {
		t.Errorf("clearing a plain setting = %v", res.Fields)
	}
}

func TestSecretInventoryOfAConfig(t *testing.T) {
	path := writeConfig(t, "opensearch:\n  url: https://admin:pw@os:9200\n")
	c, err := LoadFileOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	list := c.AddressSecretsInFile()
	if len(list) == 0 {
		t.Fatal("no address secret found in the file")
	}
	missing := DefaultFor(path + ".none")
	if got := missing.AddressSecretsInFile(); got != nil {
		t.Errorf("a missing file has address secrets: %v", got)
	}
	if _, errs := c.SecretInventory(); len(errs) != 0 {
		t.Errorf("SecretInventory errors = %v", errs)
	}
	// A settings file that cannot be read is listed by its path.
	file := writePage(t, path, "settings: [broken\n")
	if _, errs := c.SecretInventory(); errs[file] == nil {
		t.Errorf("SecretInventory of a broken settings file = %v", errs)
	}
}
