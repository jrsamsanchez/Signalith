// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// Sharing detections: an admin exports the detections they wrote as one
// YAML file, and another Signalith reads it back with Import rule, which
// takes that file, a single detection or a Sigma rule. Reading a file
// saves nothing: each rule is shown for review and added turned off, with
// the same create call (and audit line) as one written by hand.

// maxShareBody caps an uploaded rule file, and maxShareRules the rules
// read from one.
const (
	maxShareBody  = 4 << 20
	maxShareRules = 500
)

// exportDetections answers GET /api/detections?format=yaml: every
// detection written here (not the built-in or pack ones, which every
// Signalith has), turned off, as one multi-document YAML download.
// Exceptions often name this site's own hosts and users, so they are left
// out unless ?exceptions=true asks for them.
func (s *Server) exportDetections(w http.ResponseWriter, r *http.Request, ds []*detect.Detection) {
	keep := r.URL.Query().Get("exceptions") == "true"
	now := time.Now().UTC()
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Signalith detections, exported %s.\n", now.Format(time.RFC3339))
	buf.WriteString("# Add them on the Detections page with Import rule. Each one starts turned off.\n")
	n := 0
	for _, d := range ds {
		if d.Source != "custom" {
			continue
		}
		c := *d
		c.Enabled = false
		if !keep {
			c.Exceptions = nil
		}
		data, err := detect.Encode(&c)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		buf.WriteString("---\n")
		buf.Write(data)
		n++
	}
	s.audit(r, "detection.export: detections exported", "count", n, "exceptions", keep)
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="signalith-detections-`+now.Format("2006-01-02")+`.yaml"`)
	_, _ = w.Write(buf.Bytes())
}

// sharedRule is one rule read from an imported file.
type sharedRule struct {
	// Format is "signalith" or "sigma".
	Format    string            `json:"format"`
	Detection *detect.Detection `json:"detection,omitempty"`
	// Warnings are a Sigma conversion's approximations to review.
	Warnings []string `json:"warnings,omitempty"`
	// Problems stop the rule being added as it is; the editor can fix
	// most of them.
	Problems []string `json:"problems,omitempty"`
	// Exists is set when a detection of the same ID is already here.
	Exists bool `json:"exists,omitempty"`
}

// handleReadRules answers POST /api/detections/convert: the rules in a
// pasted or uploaded file, ready to review. It saves nothing.
func (s *Server) handleReadRules(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxShareBody+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(body) > maxShareBody {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the file is over %d MB; split it into smaller files", maxShareBody>>20))
		return
	}
	src := body
	if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Content-Type")), "application/json") {
		var req struct {
			Rule string `json:"rule"`
		}
		if err := decodeJSON(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		src = []byte(req.Rule)
	}
	rules, err := readRules(src)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	for _, rule := range rules {
		if rule.Detection != nil {
			if _, err := s.Detections.Get(rule.Detection.ID); err == nil {
				rule.Exists = true
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// readRules reads every YAML document in src as a Signalith detection
// (one with a query) or a Sigma rule (one with logsource and detection).
// A document that is neither, or does not read, is an error naming it,
// so nothing is half-imported without saying so.
func readRules(src []byte) ([]*sharedRule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var out []*sharedRule
	for i := 1; ; i++ {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("rule %d is not valid YAML: %w", i, err)
		}
		if len(doc.Content) == 0 || doc.Content[0].Kind == yaml.ScalarNode && doc.Content[0].Value == "" {
			// An empty document, such as one after a trailing ---.
			continue
		}
		if len(out) == maxShareRules {
			return nil, fmt.Errorf("the file has more than %d rules; split it into smaller files", maxShareRules)
		}
		top := doc.Content[0]
		if top.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("rule %d is not a detection or a Sigma rule", i)
		}
		raw, err := yaml.Marshal(&doc)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		switch {
		case hasKey(top, "query"):
			d, err := detect.Decode(raw)
			if err != nil {
				return nil, fmt.Errorf("rule %d is not a Signalith detection: %w", i, err)
			}
			d.Enabled = false
			d.Source = ""
			rule := &sharedRule{Format: "signalith", Detection: d}
			var ve *detect.ValidationError
			if err := d.Validate(); errors.As(err, &ve) {
				rule.Problems = ve.Problems
			} else if err != nil {
				rule.Problems = []string{err.Error()}
			}
			out = append(out, rule)
		case hasKey(top, "detection") && hasKey(top, "logsource"):
			res, err := detect.ConvertSigma(raw)
			if err != nil {
				return nil, fmt.Errorf("rule %d (Sigma) could not be converted: %w", i, err)
			}
			out = append(out, &sharedRule{Format: "sigma", Detection: res.Detection, Warnings: res.Warnings})
		default:
			return nil, fmt.Errorf("rule %d is not a detection or a Sigma rule: a detection has a query, a Sigma rule a logsource and a detection", i)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("there is no rule in it; paste a detection or a Sigma rule, or choose a file")
	}
	return out, nil
}

// hasKey says whether mapping node m has key k.
func hasKey(m *yaml.Node, k string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return true
		}
	}
	return false
}
