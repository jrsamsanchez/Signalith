// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// Comparisons compile to the OpenSearch clause for their field and
// operator; exact values are not read as wildcards, and what OpenSearch
// cannot do is refused.
func TestCompareQueryForms(t *testing.T) {
	for _, c := range []struct {
		cmp  query.Compare
		want string
	}{
		{query.Compare{Field: RawField, Op: "=", Value: "a*b", Exact: true}, `{"match_phrase":{"message":"a*b"}}`},
		{query.Compare{Field: RawField, Op: "!=", Value: "a b", Exact: true}, `{"bool":{"must_not":[{"match_phrase":{"message":"a b"}}]}}`},
		{query.Compare{Field: IndexField, Op: "=", Value: "Signalith-X*", Exact: true}, `{"term":{"_index":{"value":"signalith-x*"}}}`},
		{query.Compare{Field: "_time", Op: "=", Value: "5", Exact: true}, `{"term":{"@timestamp":{"value":"5"}}}`},
		{query.Compare{Field: "n", Op: "=", Value: "5", Exact: true}, `{"term":{"n":{"value":"5"}}}`},
		{query.Compare{Field: "u", Op: "!=", Value: "a*", Exact: true}, `{"bool":{"must_not":[{"term":{"u":{"case_insensitive":true,"value":"a*"}}}]}}`},
		{query.Compare{Field: "_time", Op: "=", Value: "x"}, `{"term":{"@timestamp":{"case_insensitive":true,"value":"x"}}}`},
		{query.Compare{Field: RawField, Op: "=~", Value: "x"}, ``},
		{query.Compare{Field: "_time", Op: "=~", Value: "x"}, ``},
		{query.Compare{Field: "u", Op: "=~", Value: "("}, ``},
		{query.Compare{Field: "u", Op: "=~", Value: "^ab+$"}, `{"regexp":{"u":{"value":"ab+"}}}`},
		{query.Compare{Field: "u", Op: "<>", Value: "x"}, ``},
		{query.Compare{Field: "ip", Op: "=", Value: "10.0.0.0/0"}, `{"exists":{"field":"ip"}}`},
		{query.Compare{Field: "ip", Op: "=", Value: "::/0"}, `{"exists":{"field":"ip"}}`},
	} {
		q, err := compareQuery(&c.cmp)
		if c.want == "" {
			if err == nil {
				t.Errorf("%+v compiled to %v", c.cmp, q)
			}
			continue
		}
		b, _ := json.Marshal(q)
		if err != nil || string(b) != c.want {
			t.Errorf("%+v = %s %v, want %s", c.cmp, b, err, c.want)
		}
	}
	// An expression the compiler does not know is refused, and an error
	// inside an and, or or not stops it.
	bad := &query.Compare{Field: "u", Op: "<>", Value: "x"}
	for _, e := range []query.Expr{nil, &query.And{Children: []query.Expr{bad}}, &query.Or{Children: []query.Expr{bad}}, &query.Not{Child: bad}, &query.Cond{}} {
		q, err := compileExpr(e)
		if e == nil {
			if err != nil || q["match_all"] == nil {
				t.Errorf("nil = %v %v", q, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Errorf("%T: %v %v", e, q, err)
		}
	}
}
