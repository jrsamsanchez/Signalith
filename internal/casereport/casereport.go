// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package casereport makes the report of an investigation: everything
// the case holds, with the SHA-256 of each piece of evidence and of the
// whole report, as JSON for tools and as a page to read, print or attach
// to a ticket.
package casereport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
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
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
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
	Server string `json:"server,omitempty"`
	// Tenant is the index prefix of the tenant the case belongs to, so one
	// tenant's report cannot pass as another's.
	Tenant   string     `json:"tenant,omitempty"`
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
	// FileName and FileSHA256 name an attached file and the SHA-256 of
	// its bytes, so whoever has the file can check it.
	FileName   string `json:"file_name,omitempty"`
	FileSHA256 string `json:"file_sha256,omitempty"`
}

// New builds a case's report.
//
// fileIntact, when given, says whether an attached file's bytes still
// match the SHA-256 taken when it was added; the report holds the file's
// name and hashes, not its bytes.
func New(c *cases.Case, linked []*findings.Finding, missing []string, by, server, tenant string, now time.Time, fileIntact ...func(cases.Entry) bool) (*Report, error) {
	r := &Report{
		Format: Format, Version: Version, Generated: now.UTC(), GeneratedBy: by, Server: server, Tenant: tenant,
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
		ev := Evidence{EntryID: e.ID, Kind: e.Kind, Added: e.Time, AddedBy: e.Author, SHA256: e.SHA256, Intact: cases.EvidenceIntact(e)}
		if e.Kind == cases.KindFile {
			ev.FileName, ev.FileSHA256 = e.FileName, e.FileSHA256
			for _, ok := range fileIntact {
				ev.Intact = ev.Intact && ok(e)
			}
		}
		r.Evidence = append(r.Evidence, ev)
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

// JSON is the report's data: indented, with its hash. These are the
// bytes Sign signs.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// MaxSize caps a report Verify reads.
const MaxSize = 16 << 20

// PayloadType names the signed bytes in a report's JSON envelope.
const PayloadType = "application/vnd.signalith.case-report+json"

// Signed is a report with the exact bytes of its JSON, and the signature
// over those bytes when the server had a key to sign with.
type Signed struct {
	Report  *Report
	Payload []byte
	// KeyID and Sig (base64) are empty on an unsigned report.
	KeyID string
	Sig   string
}

// Sign signs the report's JSON with key; a nil key leaves it unsigned.
func (r *Report) Sign(key ed25519.PrivateKey) (*Signed, error) {
	b, err := r.JSON()
	if err != nil {
		return nil, err
	}
	s := &Signed{Report: r, Payload: b}
	if key != nil {
		pub, _ := key.Public().(ed25519.PublicKey)
		s.KeyID = reportkeys.KeyID(pub)
		s.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))
	}
	return s, nil
}

// SignatureLine is the signature as Signalith's other signatures are
// written: "<key ID> <base64 signature>", or "" when unsigned.
func (s *Signed) SignatureLine() string {
	if s.KeyID == "" {
		return ""
	}
	return s.KeyID + " " + s.Sig
}

type envelope struct {
	PayloadType string `json:"payload_type"`
	Payload     string `json:"payload"`
	KeyID       string `json:"key_id,omitempty"`
	Sig         string `json:"sig,omitempty"`
}

// JSON is the file a JSON export gives: the report itself when unsigned;
// signed, an envelope of the exact bytes signed (base64) and the
// signature, so no reformatting can make the two disagree.
func (s *Signed) JSON() ([]byte, error) {
	if s.KeyID == "" {
		return s.Payload, nil
	}
	b, err := json.MarshalIndent(envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(s.Payload), KeyID: s.KeyID, Sig: s.Sig}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// The page fences the signed bytes and the signature line.
const (
	dataStart = `<pre id="report-data">`
	sigStart  = `<pre id="report-signature">`
	preEnd    = `</pre>`
)

func fenced(page []byte, start string) ([]byte, bool) {
	i := bytes.Index(page, []byte(start))
	if i < 0 {
		return nil, false
	}
	rest := page[i+len(start):]
	j := bytes.Index(rest, []byte(preEnd))
	if j < 0 {
		return nil, false
	}
	return []byte(html.UnescapeString(string(rest[:j]))), true
}

// Extract returns the report's JSON from a file that is the page, the
// JSON export or its envelope.
func Extract(data []byte) []byte {
	if f, err := parse(data); err == nil {
		return f.payload
	}
	return data
}

// file is a report file taken apart.
type file struct {
	payload []byte
	keyID   string
	sig     string
	// page is the page, with Windows line ends made Unix ones, when the
	// file is one.
	page []byte
}

func parse(data []byte) (*file, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("the file is larger than %d MiB, more than any case report", MaxSize>>20)
	}
	if p := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")); bytes.Contains(p, []byte(dataStart)) {
		payload, ok := fenced(p, dataStart)
		if !ok {
			return nil, errors.New("this page holds no complete report data")
		}
		f := &file{payload: payload, page: p}
		if line, ok := fenced(p, sigStart); ok {
			id, sig, ok := strings.Cut(strings.TrimSpace(string(line)), " ")
			if !ok {
				return nil, errors.New("the report's signature line is not \"<key ID> <signature>\"")
			}
			f.keyID, f.sig = id, sig
		}
		return f, nil
	}
	var env envelope
	if json.Unmarshal(data, &env) == nil && env.PayloadType != "" {
		if env.PayloadType != PayloadType {
			return nil, errors.New("this is not a Signalith case report")
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			return nil, errors.New("the report's payload is not base64")
		}
		return &file{payload: payload, keyID: env.KeyID, sig: env.Sig}, nil
	}
	return &file{payload: data}, nil
}

// Keys finds a signing key by its ID; ok is false for a key it does not
// know.
type Keys func(id string) (k *reportkeys.Key, ok bool)

// Result is what Verify found.
type Result struct {
	Report *Report
	// Signed is true when the file carries a signature, and KeyID names
	// its key. KeyStatus is the key's status in the list Verify was
	// given (current, retired or revoked), or "" when it had none.
	Signed    bool
	KeyID     string
	KeyStatus string
}

// ErrChanged wraps every way a report can fail to verify: changed after
// it was made, or signed with a key Verify does not accept.
var ErrChanged = errors.New("the report did not verify")

func changed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrChanged}, args...)...)
}

// Verify checks a report read from a file, the page or the JSON export.
// The signature, when there is one and keys is not nil, is checked over
// the exact bytes first, before anything in them is read; then the
// report's hash, each piece of evidence, and for the page that nothing
// on it was edited. A report signed with a key keys does not know, or
// without a signature when keys is not nil and requireSigned is set,
// does not verify.
func Verify(data []byte, keys Keys, requireSigned bool) (*Result, error) {
	f, err := parse(data)
	if err != nil {
		return nil, err
	}
	res := &Result{Signed: f.keyID != "", KeyID: f.keyID}
	switch {
	case f.keyID != "" && keys != nil:
		k, ok := keys(f.keyID)
		if !ok {
			return res, changed("it was signed with key %s, which this server never used", f.keyID)
		}
		pub, err := k.PublicKey()
		if err != nil {
			return res, err
		}
		sig, err := base64.StdEncoding.DecodeString(f.sig)
		if err != nil || !ed25519.Verify(pub, f.payload, sig) {
			return res, changed("its signature does not match: it was changed after it was made, or not made by key %s", f.keyID)
		}
		res.KeyStatus = k.Status()
	case f.keyID == "" && keys != nil && requireSigned:
		return res, changed("it is not signed")
	}
	var r Report
	if err := json.Unmarshal(f.payload, &r); err != nil {
		return nil, fmt.Errorf("this is not a case report: %w", err)
	}
	if r.Format != Format {
		return nil, errors.New("this is not a Signalith case report")
	}
	if r.Version > Version {
		return nil, fmt.Errorf("this report is version %d, from a newer Signalith", r.Version)
	}
	res.Report = &r
	b, err := r.Canonical()
	if err != nil {
		return res, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != r.SHA256 {
		return res, changed("its SHA-256 does not match")
	}
	for _, e := range r.Case.Entries {
		if !cases.EvidenceIntact(e) {
			return res, changed("the evidence in timeline entry %s does not match its SHA-256", e.ID)
		}
	}
	if f.page != nil {
		// The page is made from its data alone, so making it again shows
		// whether anything the reader sees was edited.
		again, err := (&Signed{Report: &r, Payload: f.payload, KeyID: f.keyID, Sig: f.sig}).HTML()
		if err != nil {
			return res, err
		}
		if !bytes.Equal(again, f.page) {
			return res, changed("its page was edited: it differs from the page its data makes")
		}
	}
	return res, nil
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
// requests, everything escaped, with the exact bytes signed and the
// signature at the end.
func (s *Signed) HTML() ([]byte, error) {
	var b bytes.Buffer
	data := struct {
		*Report
		Payload   string
		Signature string
		KeyID     string
	}{s.Report, string(s.Payload), s.SignatureLine(), s.KeyID}
	if err := tmpl.Execute(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
