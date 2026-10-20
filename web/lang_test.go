// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"io/fs"
	"regexp"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// TestEditorKnowsEveryCommand checks that the query editor's colouring and
// autocomplete list every command and function the parser accepts.
func TestEditorKnowsEveryCommand(t *testing.T) {
	src, err := fs.ReadFile(FS(), "app.js")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)const lang = \{(.*?)\n\};`).FindSubmatch(src)
	if block == nil {
		t.Fatal("app.js has no const lang = { ... }; block")
	}
	list := func(key string) map[string]bool {
		m := regexp.MustCompile(key + `: \[([^\]]*)\]`).FindSubmatch(block[1])
		if m == nil {
			t.Fatalf("lang has no %s list", key)
		}
		out := map[string]bool{}
		for _, w := range regexp.MustCompile(`'([a-z0-9_]+)'`).FindAllSubmatch(m[1], -1) {
			out[string(w[1])] = true
		}
		return out
	}
	cmds, aggs, funcs := list("commands"), list("functions"), list("evalFunctions")
	for _, c := range query.Commands {
		if !cmds[c] {
			t.Errorf("lang.commands in app.js is missing %s", c)
		}
	}
	for _, f := range query.AggFuncs {
		if !aggs[f] {
			t.Errorf("lang.functions in app.js is missing %s", f)
		}
	}
	for f := range query.EvalFuncs {
		if !funcs[f] {
			t.Errorf("lang.evalFunctions in app.js is missing %s", f)
		}
	}
	if len(funcs) != len(query.EvalFuncs) {
		t.Errorf("lang.evalFunctions lists %d functions, the parser %d", len(funcs), len(query.EvalFuncs))
	}
}
