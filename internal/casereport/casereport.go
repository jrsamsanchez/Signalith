// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package casereport makes the report of an investigation: everything
// the case holds, with the SHA-256 of each piece of evidence and of the
// whole report, as JSON for tools and as a page to read, print or attach
// to a ticket.
package casereport

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

// Format names the report's JSON; Version changes only when a field's
// meaning does.
const (
	Format  = "signalith-case-report"
	Version = 1
)

// Report is one case's report.
type Report struct {
	Format      string    `json:"format"`
	Version     int       `json:"version"`
	Generated   time.Time `json:"generated"`
	GeneratedBy string    `json:"generated_by"`
	// Server is the Signalith server's public address or name.
	Server   string     `json:"server,omitempty"`
	Case     cases.Case `json:"case"`
	Findings []Finding  `json:"findings"`
	// Missing are the IDs of linked findings that are gone (retention).
	Missing  []string   `json:"missing_findings,omitempty"`
	Evidence []Evidence `json:"evidence"`
	// SHA256 is the hash of the report as Canonical gives it.
	SHA256 string `json:"sha256"`
}

// Finding is a linked finding as the report shows it: without its raw
// result, which can hold anything the event did.
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	DetectionID string    `json:"detection_id"`
	Urgency     string    `json:"urgency"`
	Status      string    `json:"status"`
	Disposition string    `json:"disposition,omitempty"`
	Owner       string    `json:"owner,omitempty"`
	MITRE       []string  `json:"mitre,omitempty"`
	Created     time.Time `json:"created"`
}

// Evidence lists an evidence entry's hash and whether it still matches.
type Evidence struct {
	EntryID string    `json:"entry_id"`
	Kind    string    `json:"kind"`
	Added   time.Time `json:"added"`
	AddedBy string    `json:"added_by"`
	SHA256  string    `json:"sha256"`
	Intact  bool      `json:"intact"`
}

// New builds a case's report.
func New(c *cases.Case, linked []*findings.Finding, missing []string, by, server string, now time.Time) (*Report, error) {
	r := &Report{
		Format: Format, Version: Version, Generated: now.UTC(), GeneratedBy: by, Server: server,
		Case: *c, Findings: []Finding{}, Missing: missing, Evidence: []Evidence{},
	}
	for _, f := range linked {
		r.Findings = append(r.Findings, Finding{ID: f.ID, Title: f.Title, DetectionID: f.DetectionID, Urgency: f.EffectiveUrgency(),
			Status: f.Status, Disposition: f.Disposition, Owner: f.Owner, MITRE: f.MITRE, Created: f.Created})
	}
	for _, e := range c.Entries {
		if e.SHA256 == "" {
			continue
		}
		r.Evidence = append(r.Evidence, Evidence{EntryID: e.ID, Kind: e.Kind, Added: e.Time, AddedBy: e.Author, SHA256: e.SHA256, Intact: cases.EvidenceIntact(e)})
	}
	// Read the report back from its own JSON, so it holds what a file of
	// it holds (numbers as float64, times as text in events) and its page
	// is the one Verify makes again.
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		return nil, err
	}
	if b, err = back.Canonical(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	back.SHA256 = hex.EncodeToString(sum[:])
	return &back, nil
}

// Canonical is the report's JSON without its own hash: what SHA256 is
// taken over. The JSON round trip makes it the same whether the report
// was just built or read back from a file.
func (r *Report) Canonical() ([]byte, error) {
	cp := *r
	cp.SHA256 = ""
	b, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	var norm any
	if err := json.Unmarshal(b, &norm); err != nil {
		return nil, err
	}
	return json.Marshal(norm)
}

// JSON is the report as a file: indented, with its hash.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// dataStart and dataEnd fence the report's JSON in its page.
const (
	dataStart = `<pre id="report-data">`
	dataEnd   = `</pre>`
)

// Extract returns the report's JSON from a file that is either the JSON
// export or the page.
func Extract(data []byte) []byte {
	i := bytes.Index(data, []byte(dataStart))
	if i < 0 {
		return data
	}
	rest := data[i+len(dataStart):]
	j := bytes.Index(rest, []byte(dataEnd))
	if j < 0 {
		return data
	}
	return []byte(html.UnescapeString(string(rest[:j])))
}

// Verify checks a report read from a file, the JSON export or the page:
// its hash, and that its evidence hashes match its entries.
func Verify(data []byte) (*Report, error) {
	page := data
	data = Extract(data)
	isPage := len(data) != len(page)
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("this is not a case report: %w", err)
	}
	if r.Format != Format {
		return nil, errors.New("this is not a Signalith case report")
	}
	if r.Version > Version {
		return nil, fmt.Errorf("this report is version %d, from a newer Signalith", r.Version)
	}
	b, err := r.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != r.SHA256 {
		return &r, errors.New("the report was changed after it was made: its SHA-256 does not match")
	}
	for _, e := range r.Case.Entries {
		if !cases.EvidenceIntact(e) {
			return &r, fmt.Errorf("the evidence in timeline entry %s does not match its SHA-256", e.ID)
		}
	}
	if isPage {
		// The page is made from its JSON alone, so making it again shows
		// whether anything the reader sees was edited.
		again, err := r.HTML()
		if err != nil {
			return &r, err
		}
		norm := bytes.ReplaceAll(page, []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(again, norm) {
			return &r, errors.New("the report's page was changed after it was made: it differs from the page its data makes")
		}
	}
	return &r, nil
}

//go:embed report.html
var page string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"when": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"whenp": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"json": func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	},
	"short": func(s string) string {
		if len(s) > 16 {
			return s[:16] + "…"
		}
		return s
	},
	"title": func(s string) string {
		if s == "" {
			return s
		}
		return strings.ToUpper(s[:1]) + strings.ReplaceAll(s[1:], "_", " ")
	},
}).Parse(page))

// HTML renders the report as a page that stands alone: no scripts, no
// requests, everything escaped, with the report's JSON at the end so the
// page carries what its hash covers.
func (r *Report) HTML() ([]byte, error) {
	var b bytes.Buffer
	if err := tmpl.Execute(&b, r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
