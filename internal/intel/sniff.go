// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// sniffRows is how many data rows Sniff looks at.
const sniffRows = 50

// Sniff guesses how to read a feed from its content: a STIX bundle or
// TAXII envelope is stix; a CSV file with a header row is csv, with the
// column that holds the most indicators of type typ (column, when given,
// is kept if the header has it); anything else is lines.
func Sniff(data []byte, typ, column string) (format, col string) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if looksLikeSTIX(data) {
		return FormatSTIX, ""
	}
	if c, ok := sniffCSV(data, typ, column); ok {
		return FormatCSV, c
	}
	return FormatLines, ""
}

// looksLikeJSON reports whether data starts like a JSON object or array.
func looksLikeJSON(data []byte) bool {
	t := bytes.TrimSpace(data)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

func looksLikeSTIX(data []byte) bool {
	t := bytes.TrimSpace(data)
	if !looksLikeJSON(t) {
		return false
	}
	type head struct {
		Type    string          `json:"type"`
		Objects json.RawMessage `json:"objects"`
	}
	if t[0] == '[' {
		var arr []head
		if json.Unmarshal(t, &arr) != nil || len(arr) == 0 {
			return false
		}
		return arr[0].Type != ""
	}
	var h head
	if json.Unmarshal(t, &h) != nil {
		return false
	}
	return h.Type == "bundle" || h.Type == "indicator" || len(h.Objects) > 0
}

// sniffCSV finds a header row (the first row, or the last # comment line
// before the data, as abuse.ch writes it) whose rows have the same number
// of fields, and picks the column with the most valid indicators.
func sniffCSV(data []byte, typ, column string) (string, bool) {
	var lastComment string
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() && len(lines) <= sniffRows {
		t := strings.TrimSpace(sc.Text())
		switch {
		case t == "":
		case strings.HasPrefix(t, "#"):
			if len(lines) == 0 {
				lastComment = strings.TrimSpace(strings.TrimLeft(t, "# "))
			}
		case isComment(t):
		default:
			lines = append(lines, t)
		}
	}
	if len(lines) == 0 {
		return "", false
	}
	parsed := make([][]string, len(lines))
	for i, l := range lines {
		parsed[i] = splitCSV(l)
	}
	header, rows := parsed[0], parsed[1:]
	if !isHeader(header, rows) {
		header, rows = splitCSV(lastComment), parsed
		if !isHeader(header, rows) {
			return "", false
		}
	}
	if len(rows) == 0 {
		return "", false
	}
	same := 0
	for _, rec := range rows {
		if len(rec) == len(header) {
			same++
		}
	}
	if same*5 < len(rows)*4 {
		return "", false // under 80% of rows match the header
	}
	if column = strings.TrimSpace(column); column != "" {
		if n, err := strconv.Atoi(column); err == nil && n >= 1 && n <= len(header) {
			return column, true
		}
		for _, h := range header {
			if strings.EqualFold(strings.TrimSpace(h), column) {
				return column, true
			}
		}
	}
	best, bestScore := -1, 0
	for i := range header {
		score := 0
		for _, rec := range rows {
			if i < len(rec) {
				if _, _, err := Normalize(typ, rec[i]); err == nil {
					score++
				}
			}
		}
		// Prefer a column named like an indicator when two score the same,
		// such as url over urlhaus_link.
		if score > bestScore || (score == bestScore && score > 0 && preferredColumn(header[i]) && !preferredColumn(header[best])) {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return "", false
	}
	name := strings.TrimSpace(header[best])
	dup := 0
	for _, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			dup++
		}
	}
	if name == "" || dup > 1 {
		return strconv.Itoa(best + 1), true
	}
	return name, true
}

func splitCSV(line string) []string {
	r := csv.NewReader(strings.NewReader(line))
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	rec, err := r.Read()
	if err != nil {
		return nil
	}
	return rec
}

// isHeader reports whether a row looks like column names: two or more
// fields, at least one of them a word, and none of them an indicator.
// Dotted column names such as source.ip or url.domain (Elastic ECS,
// OpenCTI exports) read as domain names, so a row of them still counts
// as a header when a name ends in a word no domain ends in, or when a
// column's data clearly holds another kind of value than its first row.
func isHeader(rec []string, rows [][]string) bool {
	if len(rec) < 2 {
		return false
	}
	words, dotted, named := 0, false, false
	for _, f := range rec {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.IndexFunc(f, func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }) >= 0 {
			words++
		}
		typ, _, err := Normalize("auto", f)
		if err != nil {
			continue
		}
		if typ != TypeDomain {
			return false // an IP address, URL, hash or email: data
		}
		dotted = true
		if i := strings.LastIndexByte(f, '.'); i >= 0 && slices.Contains(fieldWords, strings.ToLower(f[i+1:])) {
			named = true
		}
	}
	if words == 0 {
		return false
	}
	if !dotted || named {
		return true
	}
	for i := range rec {
		if c := columnClass(rows, i); c != "" && c != fieldClass(rec[i]) {
			return true
		}
	}
	return false
}

// fieldWords end dotted column names (source.ip, file.hash.sha256); no
// top-level domain is named like them.
var fieldWords = []string{"ip", "address", "domain", "url", "full", "original", "hostname", "hash", "md5", "sha1", "sha256",
	"value", "type", "port", "path", "indicator", "ioc", "registered_domain", "subdomain", "top_level_domain"}

// columnClass is the indicator class (see Class) of at least 80% of a
// column's values, or "".
func columnClass(rows [][]string, col int) string {
	counts := map[string]int{}
	n := 0
	for _, rec := range rows {
		if col >= len(rec) {
			continue
		}
		n++
		if c := fieldClass(rec[col]); c != "" {
			counts[c]++
		}
	}
	for c, k := range counts {
		if k*5 >= n*4 {
			return c
		}
	}
	return ""
}

func fieldClass(v string) string {
	typ, _, err := Normalize("auto", strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	return Class(typ)
}

var preferredNames = []string{"ioc", "ioc_value", "indicator", "value", "url", "domain", "hostname", "host",
	"ip", "ip_address", "ipaddress", "dst_ip", "dstip", "src_ip", "md5", "md5_hash", "sha1", "sha1_hash",
	"sha256", "sha256_hash", "email", "network", "cidr"}

// preferredColumn reports whether a column is named like an indicator,
// such as dst_ip, or file.hash.sha256 by its last part.
func preferredColumn(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.LastIndexByte(h, '.'); i >= 0 {
		h = h[i+1:]
	}
	return slices.Contains(preferredNames, h)
}

// SuggestType names the feed type that fits the indicators found: one
// type or class when they all share it, otherwise auto.
func SuggestType(byType map[string]int) string {
	classes := map[string]bool{}
	types := 0
	last := ""
	for t, n := range byType {
		if n > 0 {
			classes[Class(t)] = true
			types++
			last = t
		}
	}
	switch {
	case len(classes) != 1:
		return "auto"
	case types == 1:
		return last
	}
	for c := range classes {
		return c // ip (addresses and networks) or hash (several kinds)
	}
	return "auto"
}
