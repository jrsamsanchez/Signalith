// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"net/url"
	"strings"
)

// CatalogEntry is a free public feed Signalith knows how to read, offered
// on the Threat intel page so it can be added with one click.
type CatalogEntry struct {
	ID          string `json:"id"` // also the feed's name when added
	Title       string `json:"title"`
	Provider    string `json:"provider"`
	Description string `json:"description"` // one plain sentence
	URL         string `json:"url"`
	Format      string `json:"format"`
	Type        string `json:"type"`
	Column      string `json:"column,omitempty"`
	Interval    string `json:"interval"`
	MaxAge      string `json:"max_age"`
	// Weight multiplies the risk a match adds: below 1 for lists that are
	// not malicious by themselves.
	Weight   float64  `json:"weight"`
	Tags     []string `json:"tags,omitempty"`
	Homepage string   `json:"homepage"`
	// NeedsKey means downloads fail without an API key, sent in the
	// KeyHeader header. A KeyHeader without NeedsKey is an optional key.
	NeedsKey  bool   `json:"needs_key"`
	KeyHeader string `json:"key_header,omitempty"`
	KeyHelp   string `json:"key_help,omitempty"` // where to get a free key
	KeyURL    string `json:"key_url,omitempty"`
	// Recommended feeds are a small, high-signal set with few false
	// positives, added together by "Add recommended feeds".
	Recommended bool `json:"recommended"`
}

// abuse.ch gives free keys; its bulk downloads have not needed one, but a
// key lifts rate limits and keeps working if that changes.
const (
	abuseKeyHeader = "Auth-Key"
	abuseKeyHelp   = "Optional. abuse.ch gives free keys after you sign in at auth.abuse.ch."
	abuseKeyURL    = "https://auth.abuse.ch/"
)

// Catalog is the built-in list of free feeds. Only long-standing,
// publicly documented feeds are listed. Intervals follow each provider's
// update rate and requests, and are never below 30 minutes.
var Catalog = []CatalogEntry{
	{
		ID: "feodo-tracker", Title: "Feodo Tracker botnet C2", Provider: "abuse.ch",
		Description: "IP addresses of botnet command-and-control servers that were recently active.",
		URL:         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		Format:      FormatLines, Type: TypeIP, Interval: "1h", MaxAge: "7d", Weight: 1.5,
		Tags: []string{"botnet", "c2"}, Homepage: "https://feodotracker.abuse.ch/blocklist/",
		KeyHeader: abuseKeyHeader, KeyHelp: abuseKeyHelp, KeyURL: abuseKeyURL, Recommended: true,
	},
	{
		ID: "urlhaus", Title: "URLhaus malware URLs", Provider: "abuse.ch",
		Description: "URLs that served malware in the last 30 days.",
		URL:         "https://urlhaus.abuse.ch/downloads/text_recent/",
		Format:      FormatLines, Type: TypeURL, Interval: "1h", MaxAge: "7d", Weight: 1,
		Tags: []string{"malware-download"}, Homepage: "https://urlhaus.abuse.ch/",
		KeyHeader: abuseKeyHeader, KeyHelp: abuseKeyHelp, KeyURL: abuseKeyURL, Recommended: true,
	},
	{
		ID: "malwarebazaar", Title: "MalwareBazaar recent samples", Provider: "abuse.ch",
		Description: "SHA-256 hashes of malware files shared in the last 48 hours.",
		URL:         "https://bazaar.abuse.ch/export/txt/sha256/recent/",
		Format:      FormatLines, Type: TypeSHA256, Interval: "1h", MaxAge: "7d", Weight: 1,
		Tags: []string{"malware"}, Homepage: "https://bazaar.abuse.ch/export/",
		KeyHeader: abuseKeyHeader, KeyHelp: abuseKeyHelp, KeyURL: abuseKeyURL, Recommended: true,
	},
	{
		ID: "et-compromised", Title: "Emerging Threats compromised hosts", Provider: "Proofpoint Emerging Threats",
		Description: "IP addresses of hosts known to be compromised and attacking others.",
		URL:         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
		Format:      FormatLines, Type: TypeIP, Interval: "12h", MaxAge: "7d", Weight: 1,
		Tags: []string{"compromised"}, Homepage: "https://rules.emergingthreats.net/blockrules/",
		Recommended: true,
	},
	{
		ID: "spamhaus-drop", Title: "Spamhaus DROP", Provider: "Spamhaus",
		Description: "Networks hijacked or run by criminals, which Spamhaus advises never to route or accept traffic from.",
		URL:         "https://www.spamhaus.org/drop/drop.txt",
		Format:      FormatLines, Type: TypeCIDR, Interval: "12h", MaxAge: "7d", Weight: 1.5,
		Tags: []string{"hijacked-network"}, Homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
		Recommended: true,
	},
	{
		ID: "openphish", Title: "OpenPhish community feed", Provider: "OpenPhish",
		Description: "URLs of active phishing pages.",
		URL:         "https://openphish.com/feed.txt",
		Format:      FormatLines, Type: TypeURL, Interval: "12h", MaxAge: "3d", Weight: 1,
		Tags: []string{"phishing"}, Homepage: "https://openphish.com/",
	},
	{
		ID: "cins-army", Title: "CINS Army list", Provider: "Sentinel IPS (CINS Score)",
		Description: "IP addresses with a poor reputation from attacks such as scanning and brute force seen by Sentinel IPS sensors.",
		URL:         "http://cinsscore.com/list/ci-badguys.txt",
		Format:      FormatLines, Type: TypeIP, Interval: "6h", MaxAge: "3d", Weight: 0.5,
		Tags: []string{"attacker"}, Homepage: "https://cinsscore.com/",
	},
	{
		ID: "blocklist-de", Title: "blocklist.de attackers", Provider: "blocklist.de",
		Description: "IP addresses reported in the last 48 hours for attacks such as SSH, mail and web login brute force.",
		URL:         "https://lists.blocklist.de/lists/all.txt",
		Format:      FormatLines, Type: TypeIP, Interval: "6h", MaxAge: "3d", Weight: 0.5,
		Tags: []string{"attacker", "brute-force"}, Homepage: "https://www.blocklist.de/en/export.html",
	},
	{
		ID: "firehol-level1", Title: "FireHOL level 1", Provider: "FireHOL",
		Description: "A combined blocklist of attack sources and criminal networks from several providers, built to have few false positives.",
		URL:         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		Format:      FormatLines, Type: TypeIP, Interval: "12h", MaxAge: "7d", Weight: 1,
		Tags: []string{"attacker"}, Homepage: "https://iplists.firehol.org/?ipset=firehol_level1",
	},
	{
		ID: "tor-exits", Title: "Tor exit nodes", Provider: "The Tor Project",
		Description: "IP addresses of Tor exit relays; Tor use is not malicious by itself.",
		URL:         "https://check.torproject.org/torbulkexitlist",
		Format:      FormatLines, Type: TypeIP, Interval: "3h", MaxAge: "2d", Weight: 0.25,
		Tags: []string{"tor", "anonymizer"}, Homepage: "https://www.torproject.org/",
	},
}

// CatalogByID returns a catalog entry.
func CatalogByID(id string) (CatalogEntry, bool) {
	for _, e := range Catalog {
		if e.ID == id {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// Spec returns the feed settings for a catalog entry.
func (e CatalogEntry) Spec() FeedSpec {
	return FeedSpec{
		Name: e.ID, Kind: KindURL, URL: e.URL, Format: e.Format, Type: e.Type, Column: e.Column,
		Interval: e.Interval, MaxAge: e.MaxAge, Weight: e.Weight, Description: e.Description,
		Tags: append([]string{}, e.Tags...), Catalog: e.ID,
	}
}

// CatalogView is a catalog entry and whether it is already a feed.
type CatalogView struct {
	CatalogEntry
	Added bool `json:"added"`
	// Feed is the name of the feed that has it, when added.
	Feed string `json:"feed,omitempty"`
}

// sameURL compares feed URLs, ignoring the case of the scheme and host
// and a trailing slash.
func sameURL(a, b string) bool {
	norm := func(s string) string {
		u, err := url.Parse(strings.TrimSpace(s))
		if err != nil {
			return s
		}
		u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
		return strings.TrimSuffix(u.String(), "/")
	}
	return norm(a) == norm(b)
}

// sameServer reports whether two URLs reach the same server: the same
// scheme, host name and port. Saved secrets are only sent there.
func sameServer(a, b string) bool {
	key := func(s string) (string, bool) {
		u, err := url.Parse(strings.TrimSpace(s))
		if err != nil || u.Host == "" {
			return "", false
		}
		scheme := strings.ToLower(u.Scheme)
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[scheme]
		}
		return scheme + "://" + strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")) + ":" + port, true
	}
	ka, okA := key(a)
	kb, okB := key(b)
	return okA && okB && ka == kb
}

// Catalog lists the built-in catalog, marking entries already added.
func (f *Feeds) Catalog() []CatalogView {
	f.mu.Lock()
	list := f.all()
	f.mu.Unlock()
	return catalogViews(list)
}

// catalogViews marks the entries already added: a feed made from the
// entry, or with its URL. A feed that only shares the entry's name is
// another feed; adding the entry then names it with a number.
func catalogViews(list []Feed) []CatalogView {
	out := make([]CatalogView, 0, len(Catalog))
	for _, e := range Catalog {
		v := CatalogView{CatalogEntry: e}
		v.Tags = append([]string{}, e.Tags...)
		for _, fd := range list {
			if fd.Catalog == e.ID || sameURL(fd.URL, e.URL) {
				v.Added, v.Feed = true, fd.Name
				break
			}
		}
		out = append(out, v)
	}
	return out
}
