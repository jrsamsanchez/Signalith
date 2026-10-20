// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package intel is Signalith's threat intelligence framework, like the
// Splunk ES threat intelligence framework: indicators (IP addresses and
// networks, domains, URLs, file hashes and email addresses) come from
// feeds the server downloads on a schedule, from manual entries and from
// CSV uploads. Searches and the threat activity detection match events
// against them.
//
// Indicators are stored in OpenSearch (index "<prefix>_intel", which event
// searches never read) and every server keeps an in-memory copy of the
// active ones, so lookups need no round trip and the threatmatch command
// can send indicator values to OpenSearch as terms filters.
package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Indicator types.
const (
	TypeIP     = "ip"
	TypeCIDR   = "cidr"
	TypeDomain = "domain"
	TypeURL    = "url"
	TypeMD5    = "md5"
	TypeSHA1   = "sha1"
	TypeSHA256 = "sha256"
	TypeEmail  = "email"
)

// Types lists every indicator type.
var Types = []string{TypeIP, TypeCIDR, TypeDomain, TypeURL, TypeMD5, TypeSHA1, TypeSHA256, TypeEmail}

// FeedTypes are the values a feed's or upload's type may take: a single
// type, "hash" for any of the three hash types, or "auto" to detect the
// type of each value.
var FeedTypes = append([]string{"auto", "hash"}, Types...)

// ManualSource is the source of indicators added by hand or uploaded.
const ManualSource = "manual"

// SampleSource is the source of indicators loaded with the sample data (see
// the sample package). Like ManualSource it is never removed by the feed
// sync, so sample intel survives a feed refresh and is removed only when the
// sample data itself is removed. Feed names are lowercase with no spaces,
// so no feed can ever have this name.
const SampleSource = "Sample data"

// Indicator is one piece of threat intel.
type Indicator struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Source      string    `json:"source"` // feed name, or "manual"
	Description string    `json:"description,omitempty"`
	Weight      float64   `json:"weight"` // multiplies the risk a match adds; 1 is normal
	Tags        []string  `json:"tags,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Expires     time.Time `json:"expires,omitzero"` // zero means never
	Updated     time.Time `json:"updated"`
}

// Expired reports whether the indicator has expired at now.
func (i *Indicator) Expired(now time.Time) bool {
	return !i.Expires.IsZero() && !now.Before(i.Expires)
}

// MakeID returns the stable ID of a value from a source: the same value
// from two feeds is two indicators, each aging out with its own feed.
func MakeID(source, typ, value string) string {
	h := sha256.Sum256([]byte(source + "\x00" + typ + "\x00" + value))
	return hex.EncodeToString(h[:12])
}

// Class groups types that are looked up the same way: the three hash
// types share one class, and IP addresses and networks are matched
// together.
func Class(typ string) string {
	switch typ {
	case TypeMD5, TypeSHA1, TypeSHA256:
		return "hash"
	case TypeCIDR:
		return TypeIP
	}
	return typ
}

var (
	hexPattern    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	domainPattern = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$`)
	refang        = strings.NewReplacer("[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "[:]", ":", "[@]", "@", "[at]", "@")
)

// Normalize checks a value against a type and returns its canonical type
// and form. typ may be "", "auto" or "hash" to detect the type. Defanged
// values such as hxxp://evil[.]com are accepted.
func Normalize(typ, value string) (string, string, error) {
	v := strings.TrimSpace(value)
	v = strings.Trim(v, `"'`)
	v = refang.Replace(v)
	if l := strings.ToLower(v); strings.HasPrefix(l, "hxxp") {
		v = "http" + v[4:]
	}
	if v == "" {
		return "", "", errors.New("value is empty")
	}
	typ = strings.ToLower(strings.TrimSpace(typ))
	switch typ {
	case "", "auto":
		return detect(v)
	case "hash":
		t, n, err := normHash(v)
		if err != nil {
			return "", "", err
		}
		return t, n, nil
	case TypeIP, TypeCIDR:
		t, n, err := normIP(v)
		if err != nil {
			return "", "", err
		}
		return t, n, nil
	case TypeDomain:
		n, err := normDomain(v)
		return TypeDomain, n, err
	case TypeURL:
		n, err := normURL(v)
		return TypeURL, n, err
	case TypeMD5, TypeSHA1, TypeSHA256:
		t, n, err := normHash(v)
		if err != nil {
			return "", "", err
		}
		if t != typ {
			return "", "", fmt.Errorf("%q is not a %s hash", value, typ)
		}
		return t, n, nil
	case TypeEmail:
		n, err := normEmail(v)
		return TypeEmail, n, err
	}
	return "", "", fmt.Errorf("type %q must be one of %s", typ, strings.Join(FeedTypes, ", "))
}

func detect(v string) (string, string, error) {
	if strings.Contains(v, "://") {
		n, err := normURL(v)
		return TypeURL, n, err
	}
	if t, n, err := normIP(v); err == nil {
		return t, n, nil
	}
	if t, n, err := normHash(v); err == nil {
		return t, n, nil
	}
	if strings.Contains(v, "@") {
		n, err := normEmail(v)
		return TypeEmail, n, err
	}
	if n, err := normDomain(v); err == nil {
		return TypeDomain, n, nil
	}
	return "", "", fmt.Errorf("%q is not an IP address, network, domain, URL, hash or email address", v)
}

func normIP(v string) (string, string, error) {
	if a, err := netip.ParseAddr(v); err == nil {
		return TypeIP, a.Unmap().String(), nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return "", "", fmt.Errorf("%q is not an IP address or network like 10.0.0.0/8", v)
	}
	p = p.Masked()
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
	}
	if p.IsSingleIP() {
		return TypeIP, p.Addr().String(), nil
	}
	return TypeCIDR, p.String(), nil
}

func normHash(v string) (string, string, error) {
	if !hexPattern.MatchString(v) {
		return "", "", fmt.Errorf("%q is not a hash (hex digits only)", v)
	}
	switch len(v) {
	case 32:
		return TypeMD5, strings.ToLower(v), nil
	case 40:
		return TypeSHA1, strings.ToLower(v), nil
	case 64:
		return TypeSHA256, strings.ToLower(v), nil
	}
	return "", "", fmt.Errorf("%q is not an MD5, SHA-1 or SHA-256 hash (32, 40 or 64 hex digits)", v)
}

func normDomain(v string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(v), ".")
	d = strings.TrimPrefix(d, "*.")
	if len(d) > 253 || !domainPattern.MatchString(d) {
		return "", fmt.Errorf("%q is not a domain name like example.com", v)
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", fmt.Errorf("%q is an IP address, not a domain", v)
	}
	return d, nil
}

// normURL lowercases the scheme and host and keeps the rest as written.
func normURL(v string) (string, error) {
	u, err := url.Parse(v)
	scheme := ""
	if err == nil {
		scheme = strings.ToLower(u.Scheme)
	}
	if err != nil || u.Host == "" || (scheme != "http" && scheme != "https" && scheme != "ftp") {
		return "", fmt.Errorf("%q is not a URL like http://example.com/path", v)
	}
	rest := v[len(u.Scheme)+3:]
	host, path, _ := strings.Cut(rest, "/")
	if i := strings.IndexAny(host, "?#"); i >= 0 {
		host, path = host[:i], host[i:]
	} else if path != "" || strings.HasSuffix(rest, "/") {
		path = "/" + path
	}
	return scheme + "://" + strings.ToLower(host) + path, nil
}

func normEmail(v string) (string, error) {
	e := strings.ToLower(strings.Trim(v, "<>"))
	local, domain, ok := strings.Cut(e, "@")
	if !ok || local == "" || strings.ContainsAny(local, " \t,;<>") {
		return "", fmt.Errorf("%q is not an email address", v)
	}
	if _, err := normDomain(domain); err != nil {
		return "", fmt.Errorf("%q is not an email address", v)
	}
	return e, nil
}

// URLHost returns the host of a URL, for matching URLs against domain
// indicators.
func URLHost(v string) string {
	if !strings.Contains(v, "://") {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ParseHashes splits a Sysmon-style hash list such as
// "SHA256=AB..,MD5=CD.." into its hash values. A plain hash is returned
// as is.
func ParseHashes(v string) []string {
	if !strings.Contains(v, "=") {
		return []string{v}
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if _, h, ok := strings.Cut(part, "="); ok && h != "" {
			out = append(out, strings.TrimSpace(h))
		}
	}
	return out
}
