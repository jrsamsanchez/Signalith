// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"fmt"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// DefaultEnrichFields are enriched when enrich names no fields.
var DefaultEnrichFields = []string{"user", "src_user", "src", "dest", "host", "src_host", "dest_host", "risk_object"}

// enrich adds <field>_owner, <field>_priority and similar columns from the
// asset and identity lists.
func (e *Engine) enrich(res *Result, c *query.Enrich) error {
	if e.Assets == nil {
		return fmt.Errorf("enrich needs asset and identity lists, which are not configured on this server")
	}
	fields := c.Fields
	if len(fields) == 0 {
		fields = DefaultEnrichFields
	}
	added := map[string]bool{}
	for _, r := range res.Rows {
		for _, f := range fields {
			v, ok := r[f].(string)
			if !ok || v == "" {
				continue
			}
			lookupField := f
			if f == "risk_object" {
				lookupField = "dest"
				if r["risk_object_type"] == "user" {
					lookupField = "user"
				}
			}
			ctx, ok := e.Assets.Lookup(lookupField, v)
			if !ok {
				continue
			}
			set := func(suffix string, val any) {
				if s, isStr := val.(string); isStr && s == "" {
					return
				}
				col := f + "_" + suffix
				r[col] = val
				added[col] = true
			}
			set("priority", ctx.Priority)
			set("category", strings.Join(ctx.Category, ", "))
			set("bunit", ctx.BUnit)
			if ctx.Kind == "identity" {
				set("name", ctx.Name)
				set("email", ctx.Email)
				set("manager", ctx.Owner)
				if ctx.Watchlist {
					set("watchlist", "true")
				}
			} else {
				set("owner", ctx.Owner)
				set("location", ctx.Location)
			}
		}
	}
	// New columns go right after the field they describe.
	var cols []string
	for _, col := range res.Columns {
		cols = append(cols, col)
		for _, suffix := range []string{"name", "email", "manager", "owner", "priority", "category", "bunit", "location", "watchlist"} {
			if added[col+"_"+suffix] && !slices.Contains(res.Columns, col+"_"+suffix) {
				cols = append(cols, col+"_"+suffix)
			}
		}
	}
	res.Columns = cols
	return nil
}
