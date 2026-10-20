// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// UploadColumns are the CSV headers an upload accepts. Only value is
// required; separate several tags with |.
var UploadColumns = []string{"value", "type", "description", "weight", "expires", "tags"}

// LineError is a problem on one line of an upload.
type LineError struct {
	Line int    `json:"line"`
	Msg  string `json:"msg"`
}

// ParseError lists every bad line of an upload.
type ParseError struct{ Lines []LineError }

func (e *ParseError) Error() string {
	var parts []string
	for _, l := range e.Lines {
		parts = append(parts, fmt.Sprintf("line %d: %s", l.Line, l.Msg))
	}
	return strings.Join(parts, "; ")
}

// Input is an indicator as a person types it, before validation.
type Input struct {
	Value       string   `json:"value"`
	Type        string   `json:"type,omitempty"`
	Description string   `json:"description,omitempty"`
	Weight      string   `json:"weight,omitempty"`
	Expires     string   `json:"expires,omitempty"` // 2026-12-31, an RFC 3339 time, or a duration like 30d
	Tags        []string `json:"tags,omitempty"`
}

var durPattern = regexp.MustCompile(`^(\d+)\s*(m|h|d|w)$`)

// ParseDuration parses 30m, 12h, 7d or 2w.
func ParseDuration(s string) (time.Duration, error) {
	m := durPattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return 0, fmt.Errorf("%q is not a duration; use a number and a unit, like 30m, 12h, 7d or 2w", s)
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, nil
}

// ParseExpiry reads a date, a time or a duration from now.
func ParseExpiry(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "never") {
		return time.Time{}, nil
	}
	if d, err := ParseDuration(s); err == nil {
		return now.Add(d).UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expires %q must be a date like 2026-12-31 or a duration like 30d", s)
}

// Build validates an input and returns a manual indicator.
func (in Input) Build(now time.Time) (Indicator, error) {
	var msgs []string
	typ, val, err := Normalize(in.Type, in.Value)
	if err != nil {
		msgs = append(msgs, err.Error())
	}
	weight := 1.0
	if w := strings.TrimSpace(in.Weight); w != "" {
		if weight, err = strconv.ParseFloat(w, 64); err != nil || weight <= 0 || weight > 10 {
			msgs = append(msgs, fmt.Sprintf("weight %q must be a number above 0 and at most 10 (1 is normal)", in.Weight))
		}
	}
	exp, err := ParseExpiry(in.Expires, now)
	if err != nil {
		msgs = append(msgs, err.Error())
	} else if !exp.IsZero() && !exp.After(now) {
		msgs = append(msgs, fmt.Sprintf("expires %q is in the past", in.Expires))
	}
	if len(msgs) > 0 {
		return Indicator{}, errors.New(strings.Join(msgs, "; "))
	}
	var tags []string
	for _, t := range in.Tags {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}
	return Indicator{Type: typ, Value: val, Source: ManualSource, Description: strings.TrimSpace(in.Description),
		Weight: weight, Expires: exp, Tags: tags}, nil
}

// maxUploadIndicators caps one upload like maxIndicators caps a feed. An
// upload is all or nothing, so a larger one is refused, not cut short.
// Tests lower it.
var maxUploadIndicators = maxIndicators

// ParseUpload reads uploaded indicators: CSV with a header row naming
// UploadColumns, or a plain list with one value per line. Lines starting
// with # are comments. Every bad line is reported and nothing is
// returned unless the whole file is valid. An error reading src is
// returned as it is, so a caller can tell a body that was too large.
func ParseUpload(src io.Reader, now time.Time) ([]Indicator, error) {
	br := bufio.NewReader(src)
	if bom, _ := br.Peek(3); bytes.Equal(bom, []byte("\xef\xbb\xbf")) {
		_, _ = br.Discard(3)
	}
	r := csv.NewReader(br)
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	r.Comment = '#'
	r.LazyQuotes = true
	var header []string
	var out []Indicator
	var bad []LineError
	seen := map[string]int{}
	rows := 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		var ce *csv.ParseError
		if err != nil && !errors.As(err, &ce) {
			return nil, err
		}
		line, _ := r.FieldPos(0)
		if err != nil {
			bad = append(bad, LineError{Line: line, Msg: err.Error()})
			break
		}
		if header == nil && len(out) == 0 && len(bad) == 0 {
			lower := make([]string, len(rec))
			for i, h := range rec {
				lower[i] = strings.ToLower(strings.TrimSpace(h))
			}
			if slices.Contains(lower, "value") {
				for _, h := range lower {
					if !slices.Contains(UploadColumns, h) {
						return nil, fmt.Errorf("unknown column %q; columns are: %s", h, strings.Join(UploadColumns, ", "))
					}
				}
				header = lower
				continue
			}
			header = []string{"value"}
		}
		in := Input{}
		empty := true
		for i, v := range rec {
			v = strings.TrimSpace(v)
			if v != "" {
				empty = false
			}
			if i >= len(header) {
				if len(header) == 1 && v != "" && i == 1 {
					in.Description = v // "value,description" lists without a header
				}
				continue
			}
			switch header[i] {
			case "value":
				in.Value = v
			case "type":
				in.Type = v
			case "description":
				in.Description = v
			case "weight":
				in.Weight = v
			case "expires":
				in.Expires = v
			case "tags":
				in.Tags = strings.Split(v, "|")
			}
		}
		if empty {
			continue
		}
		if rows++; rows > maxUploadIndicators {
			return nil, fmt.Errorf("the file has more than %d indicators, the most one upload takes; split it into smaller files", maxUploadIndicators)
		}
		ind, err := in.Build(now)
		if err != nil {
			bad = append(bad, LineError{Line: line, Msg: err.Error()})
			continue
		}
		k := ind.Type + "\x00" + ind.Value
		if prev, dup := seen[k]; dup {
			out[prev] = ind // the last line wins
			continue
		}
		seen[k] = len(out)
		out = append(out, ind)
	}
	if len(bad) > 0 {
		return nil, &ParseError{Lines: bad}
	}
	return out, nil
}
