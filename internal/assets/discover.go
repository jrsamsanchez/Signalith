package assets

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// Passive discovery: the hosts a network sensor's Zeek learns about by
// watching the traffic (known_hosts, known_services, software and DHCP
// leases) become found hosts of the asset list, as osquery hosts and
// scanned hosts do. Like them they are kept in memory only, never
// written to the user's list, and the user's list (and the sample data)
// wins over them.

// DiscoveredCategory is the category of the hosts a network sensor
// found; each service Zeek saw them offer adds "service:<name>" (such
// as service:ssh), except DNS (see ParseDiscovery).
const DiscoveredCategory = "discovered"

// DiscoveryWindow is how far back the sensor's logs are read: a host
// not seen for that long drops out of the found hosts.
const DiscoveryWindow = 7 * 24 * time.Hour

// maxDiscovered caps the hosts read, and maxServices the services kept
// per host.
const (
	maxDiscovered = 5000
	maxServices   = 8
)

// discoverySourcetypes are the Zeek logs that name a host of your
// network (Zeek logs them only for Site::local_nets by default).
var discoverySourcetypes = []string{"zeek:known_hosts", "zeek:known_services", "zeek:software"}

// Fields ingest sets on every event an agent token sent (see
// ingest.IntakeField and ingest.TokenPurposeField), which no sender can
// set itself. Only what came with a token made for a network sensor is
// read: a Linux or Windows agent's token (or an OpenTelemetry sender)
// could otherwise post an event with sourcetype zeek:known_services and
// add hosts, names and categories of its choosing to the asset list.
const (
	intakeField       = "signalith_intake"
	tokenPurposeField = "signalith_token_purpose"
)

// exemptCategory is what the built-in DNS detections leave out (a host
// whose category says it is a resolver or a domain controller): only the
// list's owner may give a host such a category, never the network.
var exemptCategory = regexp.MustCompile(`dns|domain.?controller`)

// DiscoveryIndex is the index pattern the discovery query reads: the
// Other data model's daily indices, where these logs are stored.
func DiscoveryIndex(prefix string) string {
	return datamodel.IndexName(prefix, "Other", "*")
}

// DiscoveryQuery is the OpenSearch search that reads what the sensor
// learned since since: each host Zeek named (dest of known_hosts,
// known_services and software) with the services it offers (app), and
// each address a DHCP server leased (src) with the latest name the
// client gave (src_host). Only events a network sensor's token sent are
// read, and the sample data's events are left out.
func DiscoveryQuery(since time.Time) map[string]any {
	terms := func(field string, size int) map[string]any {
		return map[string]any{"field": field, "size": size}
	}
	return map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{
			"filter": []any{
				map[string]any{"terms": map[string]any{"sourcetype": append(slices.Clone(discoverySourcetypes), "zeek:dhcp")}},
				map[string]any{"term": map[string]any{intakeField: "agent"}},
				map[string]any{"term": map[string]any{tokenPurposeField: "sensor"}},
				map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
			},
			"must_not": []any{map[string]any{"exists": map[string]any{"field": datamodel.SampleField}}},
		}},
		"aggs": map[string]any{
			"hosts": map[string]any{
				"filter": map[string]any{"terms": map[string]any{"sourcetype": discoverySourcetypes}},
				"aggs": map[string]any{"ip": map[string]any{
					"terms": terms("dest", maxDiscovered),
					"aggs":  map[string]any{"svc": map[string]any{"terms": terms("app", maxServices)}},
				}},
			},
			"leases": map[string]any{
				"filter": map[string]any{"term": map[string]any{"sourcetype": "zeek:dhcp"}},
				"aggs": map[string]any{"ip": map[string]any{
					"terms": terms("src", maxDiscovered),
					"aggs": map[string]any{"name": map[string]any{
						"terms": map[string]any{"field": "src_host", "size": 1, "order": map[string]any{"last": "desc"}},
						"aggs":  map[string]any{"last": map[string]any{"max": map[string]any{"field": "@timestamp"}}},
					}},
				}},
			},
		},
	}
}

// ParseDiscovery reads DiscoveryQuery's answer into found hosts, one per
// address, sorted by address: category discovered and the services
// seen, and the DHCP name (with its short form) when there is one.
// Values that are not addresses or host names are left out: the sensor
// read them off the network.
func ParseDiscovery(resp map[string]any) []Asset {
	byIP := map[netip.Addr]*Asset{}
	get := func(ip string) *Asset {
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil || addr.Zone() != "" {
			return nil
		}
		addr = addr.Unmap()
		if a, ok := byIP[addr]; ok {
			return a
		}
		if len(byIP) >= maxDiscovered {
			return nil
		}
		a := &Asset{IP: []string{addr.String()}, Category: []string{DiscoveredCategory}}
		byIP[addr] = a
		return a
	}
	for _, b := range buckets(resp, "hosts", "ip") {
		a := get(keyOf(b))
		if a == nil {
			continue
		}
		for _, s := range buckets(b, "svc") {
			// Not DNS, nor anything named a domain controller: an asset
			// category like that leaves the host out of the DNS
			// detections (a resolver asks for everyone), which only the
			// list's owner should decide. Zeek's service names are
			// analyzer names, made of letters, digits, _ and -.
			svc := strings.ToLower(keyOf(s))
			if validName(svc, 64) && hostName(svc) && !exemptCategory.MatchString(svc) {
				cat := "service:" + svc
				if !slices.Contains(a.Category, cat) && len(a.Category) <= maxServices {
					a.Category = append(a.Category, cat)
				}
			}
		}
	}
	for _, b := range buckets(resp, "leases", "ip") {
		names := buckets(b, "name")
		if len(names) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(keyOf(names[0]), "."))
		if !validName(name, 253) || !hostName(name) {
			continue
		}
		a := get(keyOf(b))
		if a == nil || len(a.Host) > 0 {
			continue
		}
		a.Host = []string{name}
		if short, _, ok := strings.Cut(name, "."); ok && short != "" {
			a.Host = append(a.Host, short)
		}
	}
	addrs := make([]netip.Addr, 0, len(byIP))
	for addr := range byIP {
		addrs = append(addrs, addr)
	}
	slices.SortFunc(addrs, func(x, y netip.Addr) int { return x.Compare(y) })
	out := make([]Asset, 0, len(addrs))
	for _, addr := range addrs {
		a := byIP[addr]
		slices.Sort(a.Category[1:])
		out = append(out, *a)
	}
	return out
}

// buckets returns the buckets of the aggregation at path (each part an
// aggregation's name, inside the one before).
func buckets(m map[string]any, path ...string) []map[string]any {
	if aggs, ok := m["aggregations"].(map[string]any); ok {
		m = aggs
	}
	for _, p := range path {
		next, ok := m[p].(map[string]any)
		if !ok {
			return nil
		}
		m = next
	}
	list, _ := m["buckets"].([]any)
	out := make([]map[string]any, 0, len(list))
	for _, b := range list {
		if bm, ok := b.(map[string]any); ok {
			out = append(out, bm)
		}
	}
	return out
}

func keyOf(b map[string]any) string {
	s, _ := b["key"].(string)
	return s
}

// validName reports whether s is a short value without spaces or
// control characters, and nothing a spreadsheet would run as a formula.
func validName(s string, max int) bool {
	return s != "" && len(s) <= max && !strings.ContainsFunc(s, func(c rune) bool { return c <= ' ' || c == 0x7f }) &&
		SafeCell(s) == s
}

// hostName reports whether s is made of the characters of a host name.
func hostName(s string) bool {
	for _, c := range s {
		if !(c == '.' || c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}
