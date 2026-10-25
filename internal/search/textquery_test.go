// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"encoding/json"
	"strings"
	"testing"
)

// LP-04: a plain word also matches the start of a dotted or underscored
// word in the raw text (mimikatz finds mimikatz.exe); a phrase, or a word
// with other characters, is matched as written.
func TestTextQueryPrefixes(t *testing.T) {
	b, _ := json.Marshal(textQuery("Mimikatz"))
	got := string(b)
	for _, want := range []string{`"minimum_should_match":1`, `"query":"Mimikatz"`, `{"prefix":{"_raw":{"value":"mimikatz."}}}`, `{"prefix":{"_raw":{"value":"mimikatz_"}}}`} {
		if !strings.Contains(strings.ReplaceAll(got, StoredRawField, "_raw"), want) {
			t.Errorf("textQuery(Mimikatz) = %s, want %s in it", got, want)
		}
	}
	for _, v := range []string{"failed password", "mimi*", "a-b"} {
		b, _ := json.Marshal(textQuery(v))
		if strings.Contains(string(b), "prefix") {
			t.Errorf("textQuery(%q) = %s, want no prefix", v, b)
		}
	}
}
