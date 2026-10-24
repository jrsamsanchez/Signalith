// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package compliancehist keeps the history of the compliance evidence:
// a record of every framework's control statuses, taken once a month by
// itself and whenever an admin asks, each signed with the server's report
// key. An auditor sees from it that a control was met all quarter, not
// only on the day the evidence was exported, and that no record was
// changed since.
package compliancehist

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

// Triggers say why a record was taken.
const (
	Monthly = "monthly"
	Manual  = "manual"
)

// Record is the compliance evidence at one time, as signed.
type Record struct {
	ID      string    `json:"id"`
	Taken   time.Time `json:"taken"`
	Trigger string    `json:"trigger"`
	// By is who asked for a manual record; empty for a monthly one.
	By           string       `json:"by,omitempty"`
	Server       string       `json:"server"`
	Version      string       `json:"version"`
	Tenant       string       `json:"tenant"`
	Frameworks   []Framework  `json:"frameworks"`
	Capabilities []Capability `json:"capabilities"`
	Notes        []string     `json:"notes,omitempty"`
}

// Framework is one framework's score and its controls' statuses.
type Framework struct {
	ID       string                    `json:"id"`
	Name     string                    `json:"name"`
	Score    int                       `json:"score"`
	Counts   map[compliance.Status]int `json:"counts"`
	Controls []Control                 `json:"controls,omitempty"`
}

// Control is one control's status, and the note an admin left on it.
type Control struct {
	ID     string            `json:"id"`
	Status compliance.Status `json:"status"`
	Note   string            `json:"note,omitempty"`
}

// Capability is one of Signalith's capabilities, as the report found it.
type Capability struct {
	ID     string            `json:"id"`
	Status compliance.Status `json:"status"`
	Detail string            `json:"detail,omitempty"`
}

// FromReport records rep.
func FromReport(rep *compliance.Report, id, trigger, by, server, version, tenant string) *Record {
	r := &Record{ID: id, Taken: rep.Generated.UTC().Truncate(time.Second), Trigger: trigger, By: by, Server: server, Version: version, Tenant: tenant, Notes: rep.Notes}
	for _, f := range rep.Frameworks {
		fw := Framework{ID: f.ID, Name: f.Name, Score: f.Score, Counts: f.Counts}
		for _, c := range f.Controls {
			ctl := Control{ID: c.ID, Status: c.Status}
			if c.Attestation != nil {
				ctl.Note = c.Attestation.Note
			}
			fw.Controls = append(fw.Controls, ctl)
		}
		r.Frameworks = append(r.Frameworks, fw)
	}
	for _, c := range rep.Capabilities {
		r.Capabilities = append(r.Capabilities, Capability{ID: c.ID, Status: c.Status, Detail: c.Detail})
	}
	return r
}

// MonthID is the ID of the monthly record for t's month (UTC).
func MonthID(t time.Time) string { return t.UTC().Format("2006-01") }

// ManualID is the ID of a record an admin asked for at t.
func ManualID(t time.Time) string { return t.UTC().Format("2006-01-02T150405Z") }

var validID = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}(-[0-9]{2}T[0-9]{6}Z)?$`)

// ValidID is true for an ID MonthID or ManualID could have made.
func ValidID(id string) bool { return validID.MatchString(id) }

// sigContext is signed before the record, so a signature over a record
// is never one over a case report, nor the other way round.
const sigContext = "signalith-compliance-history-v1\n"

// Signed is a record as stored: its exact bytes, their SHA-256, and the
// signature over them.
type Signed struct {
	ID      string    `json:"id"`
	Taken   time.Time `json:"taken"`
	Payload string    `json:"payload"`
	SHA256  string    `json:"sha256"`
	KeyID   string    `json:"key_id,omitempty"`
	Sig     string    `json:"sig,omitempty"`
}

// Sign makes the stored form of r; a nil key leaves it unsigned.
func Sign(r *Record, key ed25519.PrivateKey) (*Signed, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	s := &Signed{ID: r.ID, Taken: r.Taken, Payload: base64.StdEncoding.EncodeToString(b), SHA256: hex.EncodeToString(sum[:])}
	if key != nil {
		s.KeyID = reportkeys.KeyID(key.Public().(ed25519.PublicKey))
		s.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(sigContext), b...)))
	}
	return s, nil
}

// Check results.
const (
	Verified = "verified"
	Unsigned = "unsigned"
	Revoked  = "revoked"
	Changed  = "changed"
)

// Checked is a stored record read back and checked.
type Checked struct {
	Record *Record `json:"record,omitempty"`
	ID     string  `json:"id"`
	SHA256 string  `json:"sha256"`
	KeyID  string  `json:"key_id,omitempty"`
	// Check is Verified, Unsigned, Revoked or Changed; Problem says why
	// for the last three.
	Check   string `json:"check"`
	Problem string `json:"problem,omitempty"`
}

// Check reads s and checks its hash and signature against keys. Only a
// record whose signature matches keeps its Record: an unsigned one could
// have been written by anyone who can write to OpenSearch, hash and all,
// so nothing in it is shown as evidence (SEC-527-1).
func Check(s *Signed, keys func(id string) (*reportkeys.Key, bool)) *Checked {
	out := &Checked{ID: s.ID, SHA256: s.SHA256, KeyID: s.KeyID, Check: Changed}
	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		out.Problem = "its data is not base64"
		return out
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != s.SHA256 {
		out.Problem = "its data does not match its SHA-256"
		return out
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		out.Problem = "its data is not a record"
		return out
	}
	if r.ID != s.ID {
		out.Problem = "it is stored under another record's ID"
		return out
	}
	switch {
	case s.KeyID == "" && s.Sig == "":
		out.Check, out.Problem = Unsigned, "it is not signed, so nothing shows it was not made or changed by someone who can write to OpenSearch"
		return out
	case !reportkeys.ValidID(s.KeyID):
		out.Problem = "its signature is not one Signalith makes"
		return out
	default:
		k, ok := keys(s.KeyID)
		if !ok {
			out.Problem = fmt.Sprintf("it is signed with report key %s, which this server does not know", s.KeyID)
			return out
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		pub, perr := k.PublicKey()
		if err != nil || perr != nil || !ed25519.Verify(pub, append([]byte(sigContext), b...), sig) {
			out.Problem = "its signature does not match its data"
			return out
		}
		out.Check = Verified
		if k.Status() == reportkeys.Revoked {
			out.Check, out.Problem = Revoked, fmt.Sprintf("report key %s was revoked because it may have leaked: someone who had it could have made this record", s.KeyID)
		}
	}
	out.Record = &r
	return out
}

// ErrNotFound is a record the history does not have.
var ErrNotFound = errors.New("the compliance history has no such record")
