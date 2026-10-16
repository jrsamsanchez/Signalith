package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
)

func TestParseAuditDate(t *testing.T) {
	for _, tc := range []struct {
		in   string
		end  bool
		want time.Time
	}{
		{"", false, time.Time{}},
		{"2026-10-01", false, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		{"2026-10-01", true, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)},
		{"2026-10-01T12:30:00Z", true, time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC)},
	} {
		got, err := parseAuditDate(tc.in, tc.end)
		if err != nil || !got.Equal(tc.want) {
			t.Errorf("parseAuditDate(%q, %v) = %v, %v; want %v", tc.in, tc.end, got, err, tc.want)
		}
	}
	if _, err := parseAuditDate("yesterday", false); err == nil {
		t.Error("yesterday parsed")
	}
}

func TestPrintAuditReport(t *testing.T) {
	var buf bytes.Buffer
	printAuditReport(&buf, &audit.Report{Records: 5, OK: 4, Edited: 1, From: "2026-10-01T00:00:00Z",
		Servers:  []audit.ServerReport{{Server: "siem-a", NodeID: "n1", Records: 5, OK: 4, Problems: 1, Chains: 1}},
		Problems: []audit.Problem{{Kind: audit.ProblemEdited, Server: "siem-a", Seq: 3, ID: "abc", Detail: "the record was changed"}}})
	out := buf.String()
	for _, want := range []string{"Checked 5 audit records from 2026-10-01T00:00:00Z", "Changed", "siem-a", "seq 3: the record was changed (record abc)", "were changed or removed"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	buf.Reset()
	printAuditReport(&buf, &audit.Report{Records: 2, OK: 2})
	if !strings.Contains(buf.String(), "No audit record was changed or removed") {
		t.Errorf("clean report:\n%s", buf.String())
	}
}

// A server that signs its audit records notes so in the cluster
// document, out of reach of whoever can write to OpenSearch, once: the
// first time stays.
func TestMarkAuditSigned(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	eventually(t, "the shared settings are in use", func() bool {
		return rs.r.shared != nil && rs.r.shared.Cluster() != nil && rs.r.shared.Writable() == nil
	})
	id := rs.r.node.ID()
	first := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if err := markAuditSigned(t.Context(), rs.r.shared, id, first); err != nil {
		t.Fatal(err)
	}
	if err := markAuditSigned(t.Context(), rs.r.shared, id, first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := auditSignedSince(rs.r.shared)[id]; !got.Equal(first) {
		t.Fatalf("signed since %v, want %v", got, first)
	}
}
