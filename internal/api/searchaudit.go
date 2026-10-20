// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/safelog"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// maxAuditQuery is the most of a query's text an audit line keeps.
const maxAuditQuery = 2000

// auditSearch writes an audit line for a search someone ran, so the
// Audit page can answer who read which events and when: the person, the
// tenant, how they signed in, where from, and what action and attributes
// the caller adds. Events hold personal data, and reading them is as much
// an audited act as changing a setting (GDPR Article 5(2), NIST SP 800-53
// AU-2). The line is kept like every other audit line: admins only, chained
// and signed once audit records are kept in OpenSearch.
//
// A public demo's visitors are anonymous and search made-up data, and
// anyone can run as many searches as they like: their lines go only to
// the server's log, not to the audit records, which would grow with
// every visitor's searches.
func (s *Server) auditSearch(r *http.Request, msg string, attrs ...any) {
	p := principalOf(r)
	base := []any{"audit", true, "by", userOf(r)}
	if p != nil && p.Source == sourceDemo {
		base[0] = "demo"
	}
	if p != nil {
		if p.Active != "" {
			base = append(base, "tenant", p.Active)
		}
		base = append(base, "method", p.Method)
		if p.tokenID != "" {
			base = append(base, "token_id", p.tokenID)
		}
	}
	s.Log.Info(msg, slices.Concat(base, s.client(r).logAttrs(), attrs)...)
}

// searchAuditAttrs are the attributes of one query: its text, time range
// and the indices it reads, and how it ended.
func (s *Server) searchAuditAttrs(src string, q *query.Query, res *search.Result, err error, took time.Duration) []any {
	attrs := []any{"query", auditQuery(src)}
	if q != nil {
		attrs = append(attrs, "earliest", q.Earliest, "latest", q.Latest)
		if s.Engine != nil {
			if idx, ierr := s.Engine.IndexPattern(q); ierr == nil {
				attrs = append(attrs, "index", idx)
			}
		}
	}
	attrs = append(attrs, "took_ms", took.Milliseconds())
	if err != nil {
		return append(attrs, "outcome", "failed", "err", err)
	}
	if res != nil {
		attrs = append(attrs, "matched", res.Matched)
	}
	return append(attrs, "outcome", "ok")
}

// auditQuery is a query's text as an audit line keeps it.
func auditQuery(src string) string { return safelog.Cut(strings.TrimSpace(src), maxAuditQuery) }
