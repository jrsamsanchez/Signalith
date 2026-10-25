// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
)

// Distributions fix CVEs in their own builds without changing the upstream
// version, so the version a scan reads from a banner cannot say whether a
// package is fixed (ASI-02). The packages a host's osquery lists can: each
// has the exact distribution version, which is matched here to the
// distribution's own advisories, as OSV.dev publishes them in one format
// for Debian, Ubuntu, Red Hat, AlmaLinux and Rocky Linux. A package is
// vulnerable only when its installed version sorts before the version the
// distribution fixed (ASI-19).

// Ecosystem is a distribution release as OSV.dev names it.
type Ecosystem struct {
	// Name is how advisories name it: Debian:12, Ubuntu:22.04:LTS,
	// AlmaLinux:9, Rocky Linux:9, or for Red Hat the start of names such
	// as Red Hat:enterprise_linux:9::appstream.
	Name string
	// Feed is the folder of its bulk download, <base>/<Feed>/all.zip.
	Feed string
	// Kind is the package format: deb or rpm.
	Kind string
	// Distro is how the page names it: Ubuntu 22.04.
	Distro string
}

// EcosystemFor is the ecosystem of a system as osquery names it: its
// platform (ubuntu, debian, rhel, rocky, almalinux) and major.minor
// version. ok is false for a system OSV.dev has no advisories for here.
func EcosystemFor(platform, version string) (Ecosystem, bool) {
	majorS, minorS, _ := strings.Cut(strings.TrimSpace(version), ".")
	major, err := strconv.Atoi(majorS)
	if err != nil || major <= 0 || major > 999 {
		return Ecosystem{}, false
	}
	minor, err := strconv.Atoi(minorS)
	if err != nil || minor < 0 || minor > 99 {
		minor = 0
	}
	m := strconv.Itoa(major)
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "debian":
		return Ecosystem{Name: "Debian:" + m, Feed: "Debian:" + m, Kind: "deb", Distro: "Debian " + m}, true
	case "ubuntu":
		v := fmt.Sprintf("%d.%02d", major, minor)
		name := "Ubuntu:" + v
		// Long-term support releases are the April ones of even years.
		if major%2 == 0 && minor == 4 {
			name += ":LTS"
		}
		return Ecosystem{Name: name, Feed: name, Kind: "deb", Distro: "Ubuntu " + v}, true
	case "almalinux":
		return Ecosystem{Name: "AlmaLinux:" + m, Feed: "AlmaLinux", Kind: "rpm", Distro: "AlmaLinux " + m}, true
	case "rocky":
		return Ecosystem{Name: "Rocky Linux:" + m, Feed: "Rocky Linux", Kind: "rpm", Distro: "Rocky Linux " + m}, true
	case "rhel":
		return Ecosystem{Name: "Red Hat:enterprise_linux:" + m, Feed: "Red Hat", Kind: "rpm", Distro: "Red Hat Enterprise Linux " + m}, true
	}
	return Ecosystem{}, false
}

// Has reports whether an advisory's ecosystem name is this release. Red
// Hat names each repository of a release (::baseos, ::appstream) and
// newer releases with their minor version (:10.2).
func (e Ecosystem) Has(name string) bool {
	if name == e.Name {
		return true
	}
	if strings.HasPrefix(e.Name, "Red Hat:") {
		return strings.HasPrefix(name, e.Name+":") || strings.HasPrefix(name, e.Name+".")
	}
	return false
}

// Compare compares two package versions as the release's package manager
// does.
func (e Ecosystem) Compare(a, b string) int {
	if e.Kind == "rpm" {
		return CompareRPM(a, b)
	}
	return CompareDebian(a, b)
}

// osvRecord is one OSV advisory, the parts read here.
type osvRecord struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Upstream  []string `json:"upstream"`
	Related   []string `json:"related"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Specific struct {
			UbuntuPriority string `json:"ubuntu_priority"`
			Urgency        string `json:"urgency"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// osvAdvisory is what is kept of an advisory.
type osvAdvisory struct {
	ID          string
	CVEs        []string
	Description string
	CVSS        float64
	CVSSVersion string
	Published   string
}

// osvEvent is one event of a range: introduced, fixed or last_affected.
type osvEvent struct {
	kind    byte // i, f or l
	version string
}

// osvAffected is one package's ranges in one advisory.
type osvAffected struct {
	adv      *osvAdvisory
	severity string // the distribution's own rating, for an advisory with no CVSS 3 vector
	ranges   [][]osvEvent
}

// OSVIndex is one release's advisories, by package name.
type OSVIndex struct {
	Ecosystem Ecosystem
	// Advisories counts the advisories kept.
	Advisories int
	pkgs       map[string][]osvAffected
	// cves are the advisories about one CVE each, by CVE.
	cves map[string]*osvAdvisory
}

// NewOSVIndex returns an empty index for a release.
func NewOSVIndex(e Ecosystem) *OSVIndex {
	return &OSVIndex{Ecosystem: e, pkgs: map[string][]osvAffected{}, cves: map[string]*osvAdvisory{}}
}

// Add reads one advisory and keeps the ranges it gives packages of the
// release. Withdrawn advisories, and advisories that name no CVE (bug
// fixes and enhancements), are left out.
func (x *OSVIndex) Add(raw []byte) error {
	var r osvRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	if r.ID == "" || r.Withdrawn != "" {
		return nil
	}
	adv := &osvAdvisory{ID: short(r.ID, 80), CVEs: recordCVEs(r)}
	if len(adv.CVEs) == 0 {
		return nil
	}
	kept := false
	for _, a := range r.Affected {
		if !x.Ecosystem.Has(a.Package.Ecosystem) || a.Package.Name == "" {
			continue
		}
		var ranges [][]osvEvent
		for _, rg := range a.Ranges {
			if rg.Type != "ECOSYSTEM" {
				continue
			}
			var evs []osvEvent
			fix := false
			for _, e := range rg.Events {
				switch {
				case e["introduced"] != "":
					evs = append(evs, osvEvent{'i', e["introduced"]})
				case e["fixed"] != "":
					evs = append(evs, osvEvent{'f', e["fixed"]})
					fix = true
				case e["last_affected"] != "":
					evs = append(evs, osvEvent{'l', e["last_affected"]})
				}
			}
			// A range with no fix can never be reported (fixedAfter).
			if fix {
				ranges = append(ranges, evs)
			}
		}
		if len(ranges) == 0 {
			continue
		}
		if !kept {
			kept = true
			fillAdvisory(adv, r)
		}
		sev := distroSeverity(a.Specific.UbuntuPriority, a.Specific.Urgency, r.Summary)
		if adv.CVSS == 0 {
			for _, s := range a.Severity {
				if score, v, ok := CVSS3Score(s.Score); ok && s.Type == "CVSS_V3" {
					adv.CVSS, adv.CVSSVersion = score, v
					break
				}
			}
		}
		x.pkgs[a.Package.Name] = append(x.pkgs[a.Package.Name], osvAffected{adv: adv, severity: sev, ranges: ranges})
	}
	if !kept {
		return nil
	}
	x.Advisories++
	// An advisory about one CVE describes and scores it best, also for
	// the notices that name it with others.
	if len(adv.CVEs) == 1 {
		if old := x.cves[adv.CVEs[0]]; old == nil || (old.CVSS == 0 && adv.CVSS > 0) {
			x.cves[adv.CVEs[0]] = adv
		}
	}
	return nil
}

// recordCVEs are the CVEs an advisory is about: its own ID, or the ones
// it names as aliases, upstream or related.
func recordCVEs(r osvRecord) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if _, ok := cveKey(id); ok && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	add(r.ID)
	// UBUNTU-CVE-2023-38408 and DEBIAN-CVE-... are about one CVE.
	if i := strings.Index(strings.ToUpper(r.ID), "CVE-"); i > 0 {
		add(r.ID[i:])
	}
	for _, list := range [][]string{r.Aliases, r.Upstream, r.Related} {
		for _, id := range list {
			add(id)
		}
	}
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func fillAdvisory(adv *osvAdvisory, r osvRecord) {
	d := strings.TrimSpace(r.Details)
	if s := strings.TrimSpace(r.Summary); s != "" {
		d = strings.TrimSpace(strings.TrimSuffix(s, ".") + ". " + d)
	}
	adv.Description = truncate(d, maxDescLen)
	if len(r.Published) >= 10 {
		adv.Published = r.Published[:10]
	}
	for _, s := range r.Severity {
		if score, v, ok := CVSS3Score(s.Score); ok && s.Type == "CVSS_V3" {
			adv.CVSS, adv.CVSSVersion = score, v
			return
		}
	}
}

// distroSeverity is the distribution's own rating of an advisory: Ubuntu's
// priority, Debian's urgency, or the Critical, Important, Moderate or Low
// that starts a Red Hat, AlmaLinux or Rocky Linux advisory's summary.
func distroSeverity(ubuntu, urgency, summary string) string {
	for _, v := range []string{ubuntu, strings.TrimRight(urgency, "*")} {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "critical":
			return "critical"
		case "high":
			return "high"
		case "medium":
			return "medium"
		case "low", "negligible", "unimportant":
			return "low"
		}
	}
	word, _, _ := strings.Cut(summary, ":")
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "critical":
		return "critical"
	case "important":
		return "high"
	case "moderate":
		return "medium"
	case "low":
		return "low"
	}
	return "unknown"
}

// fixedAfter returns the version the distribution fixed a package in,
// when version is in one of its affected ranges and a fix exists. A
// range with no fix yet (only introduced, or last_affected) is not
// reported: the point is a package that an update would fix.
func (a osvAffected) fixedAfter(version string, cmp func(a, b string) int) (string, bool) {
	best := ""
	for _, evs := range a.ranges {
		sorted := append([]osvEvent(nil), evs...)
		sort.SliceStable(sorted, func(i, j int) bool {
			x, y := sorted[i], sorted[j]
			if x.kind == 'i' && x.version == "0" {
				return !(y.kind == 'i' && y.version == "0")
			}
			if y.kind == 'i' && y.version == "0" {
				return false
			}
			return cmp(x.version, y.version) < 0
		})
		affected, fix := false, ""
	events:
		for _, e := range sorted {
			switch e.kind {
			case 'i':
				if e.version != "0" && cmp(version, e.version) < 0 {
					break events
				}
				affected = true
			case 'f':
				if cmp(version, e.version) < 0 {
					if affected {
						fix = e.version
					}
					break events
				}
				affected = false
			case 'l':
				if cmp(version, e.version) <= 0 {
					// Affected, with no fix known in this range.
					break events
				}
				affected = false
			}
		}
		if affected && fix != "" && (best == "" || cmp(fix, best) > 0) {
			best = fix
		}
	}
	return best, best != ""
}

// Limits on one bulk download.
const (
	maxOSVFiles  = 500000
	maxOSVRecord = 4 << 20
)

// ReadOSVZip reads a bulk download (all.zip, one JSON advisory a file)
// into an index for a release. Advisories larger than maxOSVRecord, or
// that are not valid, are skipped.
func ReadOSVZip(r io.ReaderAt, size int64, e Ecosystem) (*OSVIndex, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("the advisories are not a zip file: %w", err)
	}
	if len(zr.File) > maxOSVFiles {
		return nil, fmt.Errorf("the advisories hold more than %d files", maxOSVFiles)
	}
	x := NewOSVIndex(e)
	read := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > maxOSVRecord {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxOSVRecord+1))
		rc.Close()
		if err != nil || len(b) > maxOSVRecord {
			continue
		}
		if x.Add(b) == nil {
			read++
		}
	}
	if read == 0 {
		return nil, errors.New("the advisories hold no OSV records")
	}
	return x, nil
}

// SourcePackage marks a CVE matched to an installed package.
const SourcePackage = "package"

// ConfidencePackage is the vuln_confidence of a CVE matched to a
// package's exact distribution version, older than the version the
// distribution fixed it in.
const ConfidencePackage = "package"

// Match returns the CVEs that apply to a host's packages: one service
// (port 0, named package) per source package, with its CVEs and the
// version that fixes each.
func (x *OSVIndex) Match(pkgs []endpoint.Package) []HostService {
	type group struct {
		svc   HostService
		vulns map[string]*Vuln
	}
	groups := map[string]*group{}
	for _, p := range pkgs {
		if p.Type != x.Ecosystem.Kind {
			continue
		}
		key, ver, name := p.Name, p.Version, p.Name
		if p.Type == "deb" {
			key, ver = debSource(p)
			name = key
		} else if s := rpmSourceName(p.Source); s != "" {
			name = s
		}
		for _, a := range x.pkgs[key] {
			fixed, ok := a.fixedAfter(ver, x.Ecosystem.Compare)
			if !ok {
				continue
			}
			g := groups[name]
			if g == nil {
				g = &group{svc: HostService{Service: Service{Name: SourcePackage, Product: name, Version: ver, Extra: p.Type + " package"}}, vulns: map[string]*Vuln{}}
				groups[name] = g
			}
			for _, id := range a.adv.CVEs {
				// The advisory about this CVE alone, when there is one,
				// describes and scores it; else the one that matched.
				info := a.adv
				if c := x.cves[id]; c != nil && (c.CVSS > 0 || info.CVSS == 0) {
					info = c
				}
				sev := a.severity
				if info.CVSS > 0 {
					sev = SeverityFor(info.CVSS)
				}
				v := g.vulns[id]
				if v == nil {
					v = &Vuln{CVE: id, Description: info.Description, CVSS: info.CVSS, CVSSVersion: info.CVSSVersion, Severity: sev,
						Published: info.Published, Source: SourcePackage, Fixed: fixed, Ecosystem: x.Ecosystem.Distro}
					if !strings.Contains(strings.ToUpper(a.adv.ID), id) {
						v.Advisory = a.adv.ID
					}
					g.vulns[id] = v
					continue
				}
				// Several advisories (a CVE record and the notice that
				// fixed it) name the same CVE: the newest fix fixes all.
				if x.Ecosystem.Compare(fixed, v.Fixed) > 0 {
					v.Fixed = fixed
					if !strings.Contains(strings.ToUpper(a.adv.ID), id) {
						v.Advisory = a.adv.ID
					}
				}
				if v.Severity == "unknown" && sev != "unknown" {
					v.Severity = sev
				}
			}
		}
	}
	out := make([]HostService, 0, len(groups))
	for _, g := range groups {
		for _, v := range g.vulns {
			g.svc.Vulns = append(g.svc.Vulns, *v)
		}
		sort.Slice(g.svc.Vulns, func(i, j int) bool {
			a, b := g.svc.Vulns[i], g.svc.Vulns[j]
			if a.CVSS != b.CVSS {
				return a.CVSS > b.CVSS
			}
			return a.CVE > b.CVE
		})
		out = append(out, g.svc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Product < out[j].Product })
	return out
}

// debSource is the source package a deb was built from, and the source's
// version: dpkg names the source only when it differs from the package,
// and its version only when that differs too, as in "openssl (3.0.11-1)".
func debSource(p endpoint.Package) (name, version string) {
	name, version = strings.TrimSpace(p.Source), p.Version
	if n, v, ok := strings.Cut(name, " ("); ok {
		name = strings.TrimSpace(n)
		if v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), ")")); v != "" {
			version = v
		}
	}
	if name == "" {
		name = p.Name
	}
	return name, version
}

// rpmSourceName is the name of the source RPM a package was built from:
// openssh of openssh-8.0p1-19.el8_8.src.rpm.
func rpmSourceName(src string) string {
	s := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(src), ".rpm"), ".src")
	s = strings.TrimSuffix(s, ".nosrc")
	for range 2 {
		i := strings.LastIndexByte(s, '-')
		if i <= 0 {
			return ""
		}
		s = s[:i]
	}
	return s
}
