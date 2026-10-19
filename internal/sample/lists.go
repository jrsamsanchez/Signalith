// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/intel"
)

// sampleLists returns the asset and identity entries that give the sample's
// hosts and users business context, so enrichment, risk scaling and urgency
// have something to work with. They go into the asset store's overlay,
// never into the user's own lists, and a user's own entry always wins a
// lookup. Every entry is tagged bunit "Sample data" so it is recognisable.
func sampleLists(o *org) ([]assets.Asset, []assets.Identity) {
	var as []assets.Asset
	addHost := func(h Host) {
		as = append(as, assets.Asset{
			Host:     []string{h.Name, h.FQDN()},
			IP:       []string{h.IP},
			Owner:    "IT Operations",
			Priority: h.Priority,
			Category: []string{h.Category},
			BUnit:    SampleBUnit,
			Location: h.Location,
		})
	}
	for _, h := range o.Hosts {
		addHost(h)
	}
	for _, h := range o.OT {
		addHost(h)
	}
	// The documentation networks the sample's external activity uses, so a
	// search that enriches an external IP shows it as sample infrastructure
	// rather than an unknown asset.
	as = append(as, assets.Asset{
		CIDR: []string{"203.0.113.0/24"}, Owner: "Sample threat infrastructure",
		Priority: "low", Category: []string{"external"}, BUnit: SampleBUnit, Location: "Internet",
	})

	var ids []assets.Identity
	for _, u := range o.Users {
		id := assets.Identity{
			Identity:  []string{u.Login, u.Winuser(), u.Email()},
			Name:      u.Name,
			Email:     u.Email(),
			Manager:   u.Manager,
			Priority:  u.Priority,
			Category:  []string{categoryFor(u)},
			BUnit:     SampleBUnit,
			Watchlist: u.Watchlist,
		}
		ids = append(ids, id)
	}
	return as, ids
}

func categoryFor(u User) string {
	switch {
	case u.Admin:
		return "privileged"
	case u.Watchlist:
		return "watched"
	default:
		return "standard"
	}
}

// sampleIndicators returns the threat-intel indicators the stories match
// against. They use only reserved addresses (RFC 5737), example/test domains
// and made-up hashes, and all carry the source SampleIntelSource so
// DeleteSource removes exactly them.
func sampleIndicators(now time.Time) []intel.Indicator {
	seen := now.Add(-5 * 24 * time.Hour)
	ind := func(typ, val, desc string, weight float64) intel.Indicator {
		return intel.Indicator{
			Type: typ, Value: val, Source: SampleIntelSource, Description: desc,
			Weight: weight, FirstSeen: seen, LastSeen: now, Tags: []string{"sample", "demo"},
		}
	}
	return []intel.Indicator{
		ind(intel.TypeIP, ipC2Beacon, "Sample C2: beaconing destination", 2),
		ind(intel.TypeIP, ipExfil, "Sample C2: data exfiltration drop", 2),
		ind(intel.TypeIP, ipC2, "Sample C2: brute-force and command-and-control", 1.5),
		ind(intel.TypeDomain, "updates.corp-sync.example", "Sample C2: malware update domain", 2),
		ind(intel.TypeDomain, phishDomain, "Sample phishing domain", 1.5),
		ind(intel.TypeSHA256, hashBeacon, "Sample malware: implant (update.exe)", 2),
		ind(intel.TypeSHA256, hashMimikatz, "Sample malware: credential dumper", 2),
	}
}

// phishDomain is the look-alike sign-in domain the phishing story's link
// points at (a .test name, RFC 6761).
const phishDomain = "login-corp.example-sso.test"

// Made-up file hashes (not real malware) the endpoint stories set, so
// threatmatch has process hashes to match.
const (
	hashBeacon   = "11111111111111111111111111111111111111111111111111111111deadbeef"
	hashMimikatz = "22222222222222222222222222222222222222222222222222222222feedface"
)
