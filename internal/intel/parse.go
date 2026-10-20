// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Feed formats.
const (
	FormatLines = "lines" // one indicator per line, # comments
	FormatCSV   = "csv"   // one column of a CSV file
	FormatSTIX  = "stix"  // a STIX 2.1 bundle of indicator objects
	// FormatAuto detects one of the others from the content; see Sniff.
	FormatAuto = "auto"
)

// Formats lists the feed formats a download can be read as.
var Formats = []string{FormatLines, FormatCSV, FormatSTIX}

// ParseOptions say how to read a feed.
type ParseOptions struct {
	Format string
	Type   string // auto, hash or one type
	// Column is the CSV column: a header name or a 1-based number.
	Column string
	Now    time.Time
	// Keep, when above 0, keeps only the first Keep indicators while still
	// counting all of them (Found, ByType), so a preview of a large feed
	// does not hold every indicator in memory.
	Keep int
}

// ParseResult is what a feed contained.
type ParseResult struct {
	Indicators []Indicator
	// Found counts the valid indicators, and ByType counts them by type;
	// with ParseOptions.Keep, Indicators holds only the first few.
	Found  int
	ByType map[string]int
	// Skipped counts values that were not valid indicators of the type.
	Skipped int
	// Example is the first skipped value, to help fix a feed's settings.
	Example string
	// Reserved counts private, reserved and overly broad IP addresses and
	// networks, which are skipped so a feed never matches your own network.
	Reserved int
	// Format and Column are what the feed was read as, after detection.
	Format string
	Column string
}

// maxIndicators caps one feed, so a wrong URL cannot fill memory.
const maxIndicators = 2_000_000

func (r *ParseResult) add(o ParseOptions, value, desc string, expires time.Time, tags []string, seen map[string]bool) {
	if r.Found >= maxIndicators {
		r.Skipped++
		return
	}
	typ, val, err := Normalize(o.Type, value)
	if err != nil {
		r.Skipped++
		if r.Example == "" {
			r.Example = value
			if len(r.Example) > 120 {
				r.Example = r.Example[:120] + "…"
			}
		}
		return
	}
	if (typ == TypeIP || typ == TypeCIDR) && reservedNet(val) {
		r.Reserved++
		return
	}
	if seen[typ+"\x00"+val] {
		return
	}
	seen[typ+"\x00"+val] = true
	r.Found++
	if r.ByType == nil {
		r.ByType = map[string]int{}
	}
	r.ByType[typ]++
	if o.Keep > 0 && len(r.Indicators) >= o.Keep {
		return
	}
	r.Indicators = append(r.Indicators, Indicator{Type: typ, Value: val, Description: desc, Expires: expires, Tags: tags})
}

// Parse reads a downloaded feed.
func Parse(data []byte, o ParseOptions) (*ParseResult, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if o.Format == FormatAuto {
		o.Format, o.Column = Sniff(data, o.Type, o.Column)
	}
	var res *ParseResult
	var err error
	switch o.Format {
	case "", FormatLines:
		o.Format = FormatLines
		res, err = parseLines(data, o)
	case FormatCSV:
		res, err = parseCSV(data, o)
	case FormatSTIX:
		res, err = parseSTIX(data, o)
	default:
		return nil, fmt.Errorf("format %q must be one of %s", o.Format, strings.Join(specFormats, ", "))
	}
	if res != nil {
		res.Format, res.Column = o.Format, o.Column
	}
	return res, err
}

// reserved are networks no threat feed should list: private, loopback,
// link-local, multicast and other special ranges. A feed that lists them
// (FireHOL level 1 includes the bogon ranges, for blocking at a firewall)
// would otherwise match every internal address.
var reserved = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"::/127", "fc00::/7", "fe80::/10", "ff00::/8"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// reservedNet reports whether a normalized IP address or network is
// reserved, or too broad to be an indicator (shorter than /8, or /16 for
// IPv6).
func reservedNet(v string) bool {
	p, err := netip.ParsePrefix(v)
	if err != nil {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
		return true
	}
	for _, r := range reserved {
		if r.Overlaps(p) {
			return true
		}
	}
	return false
}

func isComment(line string) bool {
	return line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//")
}

// parseLines takes the first word of each line, so lists like Spamhaus
// DROP ("1.2.3.0/24 ; SBL123"), "value,comment" lists and hosts files
// ("0.0.0.0 evil.com") work: in a hosts file the second word is the
// indicator. A URL is cut only at white space, since URLs may contain ;
// and commas.
func parseLines(data []byte, o ParseOptions) (*ParseResult, error) {
	res := &ParseResult{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if isComment(line) {
			continue
		}
		v := firstWord(line)
		if v == "0.0.0.0" || v == "127.0.0.1" {
			if rest := strings.TrimSpace(strings.TrimLeft(line[len(v):], ";, \t")); rest != "" && !isComment(rest) {
				v = firstWord(rest)
			}
		}
		if v == "" {
			continue
		}
		res.add(o, v, "", time.Time{}, nil, seen)
	}
	return res, sc.Err()
}

// firstWord returns a line's first value: up to white space, and, unless
// it is a URL, up to a ; or a comma.
func firstWord(line string) string {
	v, _, _ := strings.Cut(line, " ")
	v, _, _ = strings.Cut(v, "\t")
	if !strings.Contains(v, "://") {
		if i := strings.IndexAny(v, ";,"); i >= 0 {
			v = v[:i]
		}
	}
	return v
}

// parseCSV reads one column. A named column is found in the first row,
// or in the last comment line before the data, which is where abuse.ch
// feeds put their header ("# first_seen_utc,dst_ip,...").
func parseCSV(data []byte, o ParseOptions) (*ParseResult, error) {
	col := -1
	if n, err := strconv.Atoi(strings.TrimSpace(o.Column)); err == nil {
		if n < 1 {
			return nil, errors.New("column numbers start at 1")
		}
		col = n - 1
	}
	name := strings.ToLower(strings.TrimSpace(o.Column))
	if col < 0 && name == "" {
		return nil, errors.New("csv feeds need a column: a header name or a number starting at 1")
	}
	var lastComment string
	var body bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			if body.Len() == 0 {
				lastComment = strings.TrimSpace(strings.TrimLeft(t, "# "))
			}
			continue
		}
		if t == "" {
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	r := csv.NewReader(&body)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	findIn := func(rec []string) int {
		for i, h := range rec {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				return i
			}
		}
		return -1
	}
	res := &ParseResult{}
	seen := map[string]bool{}
	first := true
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if first {
			first = false
			if col < 0 {
				if i := findIn(rec); i >= 0 {
					col = i
					continue // the header row
				}
				if lastComment != "" {
					hr := csv.NewReader(strings.NewReader(lastComment))
					hr.LazyQuotes = true
					if h, err := hr.Read(); err == nil {
						col = findIn(h)
					}
				}
				if col < 0 {
					return nil, fmt.Errorf("no column named %q; the first row is: %s", o.Column, strings.Join(rec, ","))
				}
			}
		}
		if col >= len(rec) {
			res.Skipped++
			continue
		}
		res.add(o, rec[col], "", time.Time{}, nil, seen)
	}
	return res, nil
}

// STIX objects Signalith reads.
type stixObject struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type"`
	ValidUntil  string   `json:"valid_until"`
	Revoked     bool     `json:"revoked"`
	Labels      []string `json:"labels"`
	// Indicator types in STIX 2.1, such as malicious-activity.
	IndicatorTypes []string `json:"indicator_types"`
}

// stixComparison matches one "object:path = 'value'" in a pattern.
var stixComparison = regexp.MustCompile(`([a-z0-9-]+):([A-Za-z0-9_.'\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'`)

// stixType maps a STIX object path to an indicator type.
func stixType(object, path string) string {
	path = strings.ToLower(strings.ReplaceAll(path, "'", ""))
	switch object {
	case "ipv4-addr", "ipv6-addr":
		if path == "value" {
			return "ip"
		}
	case "domain-name":
		if path == "value" {
			return TypeDomain
		}
	case "url":
		if path == "value" {
			return TypeURL
		}
	case "email-addr":
		if path == "value" {
			return TypeEmail
		}
	case "email-message":
		if path == "from_ref.value" || path == "sender_ref.value" {
			return TypeEmail
		}
	case "file", "artifact":
		switch path {
		case "hashes.md5":
			return TypeMD5
		case "hashes.sha-1", "hashes.sha1":
			return TypeSHA1
		case "hashes.sha-256", "hashes.sha256":
			return TypeSHA256
		}
	}
	return ""
}

// parseSTIX reads a STIX 2.x bundle, a TAXII 2.1 envelope ({"objects":
// [...]}), a bare array of objects or a single indicator. Every
// comparison in an indicator's pattern becomes an indicator; patterns of
// other languages and revoked or expired indicators are skipped.
func parseSTIX(data []byte, o ParseOptions) (*ParseResult, error) {
	objs, err := decodeSTIX(data)
	if err != nil {
		return nil, err
	}
	return stixIndicators(objs, o), nil
}

// decodeSTIX reads the objects of a bundle, envelope, array or single
// indicator.
func decodeSTIX(data []byte) ([]stixObject, error) {
	var objs []stixObject
	trimmed := bytes.TrimSpace(data)
	switch {
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &objs); err != nil {
			return nil, fmt.Errorf("not a STIX bundle: %v", err)
		}
	default:
		var env struct {
			Type    string       `json:"type"`
			Objects []stixObject `json:"objects"`
		}
		if err := json.Unmarshal(trimmed, &env); err != nil {
			return nil, fmt.Errorf("not a STIX bundle: %v", err)
		}
		if env.Objects != nil {
			objs = env.Objects
		} else if env.Type == "indicator" {
			var one stixObject
			_ = json.Unmarshal(trimmed, &one)
			objs = []stixObject{one}
		} else {
			return nil, errors.New(`not a STIX bundle: expected {"type": "bundle", "objects": [...]}`)
		}
	}
	return objs, nil
}

// stixIndicators turns indicator objects into indicators.
func stixIndicators(objs []stixObject, o ParseOptions) *ParseResult {
	res := &ParseResult{}
	seen := map[string]bool{}
	for _, obj := range objs {
		if obj.Type != "indicator" || obj.Revoked || (obj.PatternType != "" && obj.PatternType != "stix") {
			continue
		}
		var exp time.Time
		if obj.ValidUntil != "" {
			if t, err := time.Parse(time.RFC3339, obj.ValidUntil); err == nil {
				if !o.Now.IsZero() && !t.After(o.Now) {
					continue
				}
				exp = t.UTC()
			}
		}
		desc := obj.Name
		if obj.Description != "" {
			if desc != "" {
				desc += ": "
			}
			desc += obj.Description
		}
		if len(desc) > 500 {
			desc = desc[:500] + "…"
		}
		tags := append(append([]string{}, obj.IndicatorTypes...), obj.Labels...)
		for _, m := range stixComparison.FindAllStringSubmatch(obj.Pattern, -1) {
			typ := stixType(m[1], m[2])
			if typ == "" {
				continue
			}
			value := strings.ReplaceAll(strings.ReplaceAll(m[3], `\'`, `'`), `\\`, `\`)
			sub := o
			if sub.Type == "" || sub.Type == "auto" {
				sub.Type = typ
			} else if sub.Type != typ && !(sub.Type == "hash" && Class(typ) == "hash") && Class(sub.Type) != Class(typ) {
				continue // the feed is limited to another type
			}
			res.add(sub, value, desc, exp, tags, seen)
		}
	}
	return res
}
