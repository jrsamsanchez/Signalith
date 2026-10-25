// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Docs is what the store needs from OpenSearch. *store.Client has it.
type Docs interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	Update(ctx context.Context, index, id string, fields map[string]any, refresh bool) (store.Version, error)
	DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// Document kinds in the vulnerabilities index.
const (
	kindSettings = "settings"
	kindScan     = "scan"
	kindHost     = "host"
	kindCVEs     = "cves"
	kindReport   = "scanner"
)

// Scan states.
const (
	StateQueued      = "queued"
	StateRunning     = "running"
	StateDone        = "done"
	StateFailed      = "failed"
	StateStopped     = "stopped"
	StateInterrupted = "interrupted"
)

// How a scan started.
const (
	TriggerSchedule = "schedule"
	TriggerManual   = "manual"
)

// Scan is one run of Nmap over one network.
type Scan struct {
	ID          string `json:"id"`
	TargetID    string `json:"target_id"`
	TargetName  string `json:"target_name"`
	State       string `json:"state"`
	Trigger     string `json:"trigger"`
	RequestedBy string `json:"requested_by,omitempty"`
	// Scanner names the server that ran the scan, and ScannerID is its
	// node ID.
	Scanner    string    `json:"scanner,omitempty"`
	ScannerID  string    `json:"scanner_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  time.Time `json:"started_at,omitzero"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	// Heartbeat is written while the scan runs; one that stops beating
	// was cut off (its server stopped).
	Heartbeat time.Time `json:"heartbeat,omitzero"`
	Progress  Progress  `json:"progress"`
	Counts    Counts    `json:"counts"`
	Error     string    `json:"error,omitempty"`
	// CVEError says why CVEs could not be looked up for some or all of
	// the software found.
	CVEError string `json:"cve_error,omitempty"`
	// OpenVASError says why OpenVAS did not scan, for a network that asks
	// for it; Nmap's results are kept.
	OpenVASError string `json:"openvas_error,omitempty"`
	// Stop asks the scanner to stop the scan.
	Stop   bool   `json:"stop,omitempty"`
	StopBy string `json:"stop_by,omitempty"`
}

// Counts sums up what a scan or a host has.
type Counts struct {
	Hosts    int `json:"hosts"`
	Services int `json:"services"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	// KEV counts CVEs that attackers are known to use.
	KEV int `json:"kev"`
	// Likely counts the others EPSS says are likely to be used
	// (LikelyEPSS or more).
	Likely int `json:"likely"`
}

func (c *Counts) add(sev string, kev bool) {
	switch sev {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	default:
		c.Low++
	}
	if kev {
		c.KEV++
	}
}

// Total is the number of CVEs counted.
func (c Counts) Total() int { return c.Critical + c.High + c.Medium + c.Low }

// Host is one host as its network's latest scan found it.
type Host struct {
	ID         string `json:"id"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	Address    string `json:"address"`
	Hostname   string `json:"hostname,omitempty"`
	MAC        string `json:"mac,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	// EndpointID is the osquery host's node ID, for a host whose
	// installed packages were checked (PackagesTarget).
	EndpointID string        `json:"endpoint_id,omitempty"`
	Services   []HostService `json:"services"`
	Counts     Counts        `json:"counts"`
	MaxCVSS    float64       `json:"max_cvss"`
	MaxEPSS    float64       `json:"max_epss,omitempty"`
	ScanID     string        `json:"scan_id"`
	FirstSeen  time.Time     `json:"first_seen"`
	LastSeen   time.Time     `json:"last_seen"`
}

// HostService is an open port with the CVEs of the software on it.
type HostService struct {
	Service
	Vulns []Vuln `json:"vulns,omitempty"`
}

// Vuln is a CVE that applies to software a scan found.
type Vuln struct {
	CVE         string  `json:"cve"`
	Description string  `json:"description,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	CVSSVersion string  `json:"cvss_version,omitempty"`
	Severity    string  `json:"severity"`
	Published   string  `json:"published,omitempty"`
	KEV         bool    `json:"kev,omitempty"`
	KEVAdded    string  `json:"kev_added,omitempty"`
	// From CISA's catalog: the date U.S. agencies must fix it by, and
	// whether ransomware gangs are known to use it.
	KEVDue     string `json:"kev_due,omitempty"`
	Ransomware bool   `json:"ransomware,omitempty"`
	// EPSS is FIRST's probability (0 to 1) that it is exploited in the
	// next 30 days, and EPSSPercentile its rank among all CVEs.
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	CPE            string  `json:"cpe"`
	// Source is where it came from: "" for a CVE matched to the software
	// version Nmap found, openvas for a weakness OpenVAS tested for, or
	// package for a CVE matched to a package osquery found installed.
	Source string `json:"source,omitempty"`
	// Distro is the Linux distribution the service's banner says built
	// it ("Ubuntu"), for a CVE matched by version only: distributions fix
	// CVEs without changing the upstream version, so it may be fixed
	// there already (ASI-02).
	Distro string `json:"distro,omitempty"`
	// For a CVE matched to an installed package (Source package): the
	// version the distribution fixed it in, the distribution's advisory
	// when it is not the CVE itself (USN-6242-1, ALSA-2023:4419), and the
	// release, such as Ubuntu 22.04 (ASI-19).
	Fixed     string `json:"fixed,omitempty"`
	Advisory  string `json:"advisory,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	// From OpenVAS: the test's OID and name, every CVE it names (CVE is
	// the newest of them, or empty), and how to fix it.
	OID      string   `json:"oid,omitempty"`
	Name     string   `json:"name,omitempty"`
	CVEs     []string `json:"cves,omitempty"`
	Solution string   `json:"solution,omitempty"`
}

// ConfidenceVersionOnly is the vuln_confidence of a CVE matched by the
// upstream version on a service a distribution built.
const ConfidenceVersionOnly = "version_only"

// SourceOpenVAS marks a weakness OpenVAS found.
const SourceOpenVAS = "openvas"

// Key names the weakness: its CVE, or OpenVAS's test.
func (v Vuln) Key() string {
	if v.CVE != "" {
		return v.CVE
	}
	return v.OID
}

// Report is what a scanner found when it checked itself: whether Nmap is
// there and works, and whether CVE lookups reach the database.
type Report struct {
	Server string `json:"server"`
	// NodeID is the server's node ID; empty from a version before
	// per-zone scanners.
	NodeID string    `json:"node_id,omitempty"`
	At     time.Time `json:"at"`
	Checks []Check   `json:"checks"`
	Ready  bool      `json:"ready"`
}

// Store keeps the settings, scans, hosts and looked-up CVEs in
// <prefix>_vulns.
type Store struct {
	Docs  Docs
	Index string
	Now   func() time.Time
	// Keys encrypts the secrets of the scan logins; nil refuses to save
	// any.
	Keys Keys

	mu       sync.Mutex
	settings *cachedSettings
}

type cachedSettings struct {
	s       Settings
	v       store.Version
	fetched time.Time
}

const settingsTTL = 10 * time.Second

// ErrNotFound is a scan or host that is not there.
var ErrNotFound = errors.New("not found")

// NewStore returns a store using index "<prefix>_vulns".
func NewStore(d Docs, prefix string) *Store {
	return &Store{Docs: d, Index: prefix + "_vulns"}
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// EnsureIndex creates the index if it is missing.
func (s *Store) EnsureIndex(ctx context.Context) error {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	body := map[string]any{
		"settings": map[string]any{"number_of_shards": 1, "auto_expand_replicas": "0-1", "refresh_interval": "1s"},
		"mappings": map[string]any{"dynamic": "false", "properties": map[string]any{
			"kind": kw, "id": kw, "target_id": kw, "state": kw, "address": kw, "trigger": kw, "server": kw,
			"created_at": date, "started_at": date, "finished_at": date, "last_seen": date, "fetched_at": date,
		}},
	}
	err := s.Docs.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusBadRequest && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// NewID returns a random ID.
func NewID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:10])
}

type settingsDoc struct {
	Kind string `json:"kind"`
	Settings
}

// Settings returns the saved settings, or the defaults, and their version
// (zero when never saved).
func (s *Store) Settings(ctx context.Context) (Settings, store.Version, error) {
	src, v, found, err := s.Docs.Get(ctx, s.Index, kindSettings)
	if err != nil {
		return Settings{}, store.Version{}, err
	}
	if !found {
		return DefaultSettings(), store.Version{}, nil
	}
	set := DefaultSettings()
	if err := json.Unmarshal(src, &set); err != nil {
		return Settings{}, store.Version{}, err
	}
	if set.Targets == nil {
		set.Targets = []Target{}
	}
	s.mu.Lock()
	s.settings = &cachedSettings{set, v, s.now()}
	s.mu.Unlock()
	return set, v, nil
}

// CachedSettings returns the settings read in the last few seconds, or
// reads them.
func (s *Store) CachedSettings(ctx context.Context) (Settings, error) {
	s.mu.Lock()
	c := s.settings
	s.mu.Unlock()
	if c != nil && s.now().Sub(c.fetched) < settingsTTL {
		return c.s, nil
	}
	set, _, err := s.Settings(ctx)
	return set, err
}

// SaveSettings validates and saves settings, only if they are still at
// version v (zero: never saved). A network new since v gets its creator
// and time.
func (s *Store) SaveSettings(ctx context.Context, set Settings, v store.Version, by string) (Settings, error) {
	old, _, err := s.Settings(ctx)
	if err != nil {
		return Settings{}, err
	}
	known := map[string]Target{}
	for _, t := range old.Targets {
		known[t.ID] = t
	}
	now := s.now().UTC()
	for i := range set.Targets {
		t := &set.Targets[i]
		if o, ok := known[t.ID]; ok {
			t.CreatedBy, t.CreatedAt = o.CreatedBy, o.CreatedAt
		} else {
			t.CreatedBy, t.CreatedAt = by, now
		}
	}
	if err := set.Validate(); err != nil {
		return Settings{}, err
	}
	set.UpdatedBy, set.UpdatedAt = by, now
	doc := settingsDoc{Kind: kindSettings, Settings: set}
	if v == (store.Version{}) {
		_, err = s.Docs.Create(ctx, s.Index, kindSettings, doc, true)
		if errors.Is(err, store.ErrExists) {
			err = store.ErrConflict
		}
	} else {
		_, err = s.Docs.PutIf(ctx, s.Index, kindSettings, doc, v, true)
	}
	if err != nil {
		return Settings{}, err
	}
	s.mu.Lock()
	s.settings = nil
	s.mu.Unlock()
	return set, nil
}

type scanDoc struct {
	Kind string `json:"kind"`
	*Scan
}

func scanDocID(id string) string { return "scan:" + id }

// NewScan records a scan waiting to start.
func (s *Store) NewScan(ctx context.Context, t Target, trigger, by string) (*Scan, error) {
	sc := &Scan{ID: NewID(), TargetID: t.ID, TargetName: t.Name, State: StateQueued, Trigger: trigger,
		RequestedBy: by, CreatedAt: s.now().UTC()}
	if _, err := s.Docs.Create(ctx, s.Index, scanDocID(sc.ID), scanDoc{kindScan, sc}, true); err != nil {
		return nil, err
	}
	return sc, nil
}

// Scan returns one scan.
func (s *Store) Scan(ctx context.Context, id string) (*Scan, store.Version, error) {
	src, v, found, err := s.Docs.Get(ctx, s.Index, scanDocID(id))
	if err != nil {
		return nil, v, err
	}
	if !found {
		return nil, v, ErrNotFound
	}
	var sc Scan
	if err := json.Unmarshal(src, &sc); err != nil {
		return nil, v, err
	}
	return &sc, v, nil
}

// PutScan writes a scan whole.
func (s *Store) PutScan(ctx context.Context, sc *Scan, v store.Version) (store.Version, error) {
	return s.Docs.PutIf(ctx, s.Index, scanDocID(sc.ID), scanDoc{kindScan, sc}, v, true)
}

// ClaimScan starts a queued scan on this server: it marks it running with
// fields, unless another server started, stopped or removed it first.
// ok is false then.
func (s *Store) ClaimScan(ctx context.Context, id string, fields map[string]any) (ok bool, err error) {
	src, v, found, err := s.Docs.Get(ctx, s.Index, scanDocID(id))
	if err != nil || !found {
		return false, err
	}
	var doc map[string]any
	if err := json.Unmarshal(src, &doc); err != nil {
		return false, err
	}
	if doc["state"] != StateQueued || doc["stop"] == true {
		return false, nil
	}
	for k, val := range fields {
		doc[k] = val
	}
	doc["state"] = StateRunning
	if _, err := s.Docs.PutIf(ctx, s.Index, scanDocID(id), doc, v, true); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// RequeueScan puts a scan this server was running back in the queue, so
// it runs again from the start: on this server once it is back, or on the
// one that takes the network. ok is false when the scan is no longer this
// server's to give back (it ended, was stopped or removed, or another
// server holds it).
func (s *Store) RequeueScan(ctx context.Context, id, nodeID string) (ok bool, err error) {
	src, v, found, err := s.Docs.Get(ctx, s.Index, scanDocID(id))
	if err != nil || !found {
		return false, err
	}
	var doc map[string]any
	if err := json.Unmarshal(src, &doc); err != nil {
		return false, err
	}
	holder, _ := doc["scanner_id"].(string)
	if doc["state"] != StateRunning || doc["stop"] == true || holder != nodeID {
		return false, nil
	}
	for _, k := range []string{"started_at", "heartbeat", "scanner", "scanner_id", "progress"} {
		delete(doc, k)
	}
	doc["state"] = StateQueued
	if _, err := s.Docs.PutIf(ctx, s.Index, scanDocID(id), doc, v, true); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// UpdateScan changes some fields of a scan.
func (s *Store) UpdateScan(ctx context.Context, id string, fields map[string]any) error {
	_, err := s.Docs.Update(ctx, s.Index, scanDocID(id), fields, true)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// Scans returns every scan kept, newest first.
func (s *Store) Scans(ctx context.Context) ([]*Scan, error) {
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"term": map[string]any{"kind": kindScan}})
	if err != nil {
		return nil, err
	}
	out := make([]*Scan, 0, len(docs))
	for _, d := range docs {
		var sc Scan
		if json.Unmarshal(d.Source, &sc) == nil && sc.ID != "" {
			out = append(out, &sc)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// keepScans is how many finished scans are kept.
const keepScans = 200

// PruneScans deletes finished scans beyond the newest keepScans, and
// scans of networks no longer listed.
func (s *Store) PruneScans(ctx context.Context, targets map[string]bool) error {
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"term": map[string]any{"kind": kindScan}})
	if err != nil {
		return err
	}
	type entry struct {
		d  store.Doc
		sc Scan
	}
	var list []entry
	for _, d := range docs {
		var sc Scan
		if json.Unmarshal(d.Source, &sc) == nil {
			list = append(list, entry{d, sc})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].sc.CreatedAt.After(list[j].sc.CreatedAt) })
	finished := 0
	for _, e := range list {
		active := e.sc.State == StateQueued || e.sc.State == StateRunning
		drop := !targets[e.sc.TargetID] && !active
		if !active {
			finished++
			drop = drop || finished > keepScans
		}
		if drop {
			if err := s.Docs.DeleteIf(ctx, s.Index, e.d.ID, e.d.Version, false); err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
				return err
			}
		}
	}
	return nil
}

type hostDoc struct {
	Kind string `json:"kind"`
	*Host
}

// HostID is the ID of a host found on a network.
func HostID(targetID, address string) string { return hashID(targetID, address) }

func hostDocID(id string) string { return "host:" + id }

// SaveHosts replaces a network's hosts with the ones its latest scan
// found, keeping when each was first seen.
func (s *Store) SaveHosts(ctx context.Context, targetID string, hosts []*Host) error {
	old, err := s.hostDocs(ctx, targetID)
	if err != nil {
		return err
	}
	prev := map[string]store.Doc{}
	first := map[string]time.Time{}
	for _, d := range old {
		var h Host
		if json.Unmarshal(d.Source, &h) == nil {
			prev[h.ID] = d
			first[h.ID] = h.FirstSeen
		}
	}
	for _, h := range hosts {
		if f, ok := first[h.ID]; ok && !f.IsZero() {
			h.FirstSeen = f
		}
		doc := hostDoc{kindHost, h}
		if d, ok := prev[h.ID]; ok {
			if _, err := s.Docs.PutIf(ctx, s.Index, d.ID, doc, d.Version, false); err != nil && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			delete(prev, h.ID)
			continue
		}
		if _, err := s.Docs.Create(ctx, s.Index, hostDocID(h.ID), doc, false); err != nil && !errors.Is(err, store.ErrExists) {
			return err
		}
	}
	// Hosts the scan did not find up are gone from the network.
	for _, d := range prev {
		if err := s.Docs.DeleteIf(ctx, s.Index, d.ID, d.Version, false); err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return nil
}

// SampleTarget is the network the sample data's scan results are kept
// under (internal/sample). It is never one of the scan settings' networks,
// and DropHosts leaves it to the sample data.
const SampleTarget = "sample-data"

// PackagesTarget is the network the CVEs of osquery hosts' installed
// packages are kept under (PackageCheck). Like SampleTarget it is never
// one of the scan settings' networks, and DropHosts leaves it.
const PackagesTarget = "installed-packages"

// DropHosts deletes the hosts of networks no longer listed, but for the
// sample data's (SampleTarget) and the installed packages'
// (PackagesTarget).
func (s *Store) DropHosts(ctx context.Context, targets map[string]bool) error {
	docs, err := s.hostDocs(ctx, "")
	if err != nil {
		return err
	}
	for _, d := range docs {
		var h Host
		if json.Unmarshal(d.Source, &h) == nil && !targets[h.TargetID] && h.TargetID != SampleTarget && h.TargetID != PackagesTarget {
			if err := s.Docs.DeleteIf(ctx, s.Index, d.ID, d.Version, false); err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
				return err
			}
		}
	}
	return nil
}

func (s *Store) hostDocs(ctx context.Context, targetID string) ([]store.Doc, error) {
	q := map[string]any{"term": map[string]any{"kind": kindHost}}
	if targetID != "" {
		q = map[string]any{"bool": map[string]any{"filter": []any{q, map[string]any{"term": map[string]any{"target_id": targetID}}}}}
	}
	return s.Docs.SearchDocs(ctx, s.Index, q)
}

// Reprioritize applies the exploit feeds again to every host kept, so a
// CVE added to the KEV catalog, or whose EPSS score moved, shows at once
// rather than at the network's next scan. A host a scan is saving at the
// same time is left to it. It returns how many hosts changed.
func (s *Store) Reprioritize(ctx context.Context, x *Exploits) (int, error) {
	docs, err := s.hostDocs(ctx, "")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range docs {
		var h Host
		if json.Unmarshal(d.Source, &h) != nil || h.ID == "" {
			continue
		}
		if !x.Apply([]*Host{&h}) {
			continue
		}
		if _, err := s.Docs.PutIf(ctx, s.Index, d.ID, hostDoc{kindHost, &h}, d.Version, false); err != nil {
			if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
				continue
			}
			return n, err
		}
		n++
	}
	return n, nil
}

// Hosts returns every host found, worst first.
func (s *Store) Hosts(ctx context.Context) ([]*Host, error) {
	docs, err := s.hostDocs(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]*Host, 0, len(docs))
	for _, d := range docs {
		var h Host
		if json.Unmarshal(d.Source, &h) == nil && h.ID != "" {
			out = append(out, &h)
		}
	}
	SortHosts(out)
	return out, nil
}

// SortHosts puts hosts with known exploited CVEs first, then those with
// CVEs likely to be exploited, then by highest score, most CVEs and
// address.
func SortHosts(hs []*Host) {
	sort.Slice(hs, func(i, j int) bool {
		a, b := hs[i], hs[j]
		if (a.Counts.KEV > 0) != (b.Counts.KEV > 0) {
			return a.Counts.KEV > 0
		}
		if (a.Counts.Likely > 0) != (b.Counts.Likely > 0) {
			return a.Counts.Likely > 0
		}
		if a.MaxCVSS != b.MaxCVSS {
			return a.MaxCVSS > b.MaxCVSS
		}
		if a.Counts.Total() != b.Counts.Total() {
			return a.Counts.Total() > b.Counts.Total()
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.TargetID < b.TargetID
	})
}

// Host returns one host.
func (s *Store) Host(ctx context.Context, id string) (*Host, error) {
	src, _, found, err := s.Docs.Get(ctx, s.Index, hostDocID(id))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	var h Host
	if err := json.Unmarshal(src, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// cveDoc caches one product's CVEs.
type cveDoc struct {
	Kind      string    `json:"kind"`
	Key       string    `json:"key"`
	FetchedAt time.Time `json:"fetched_at"`
	CVEs      []CVE     `json:"cves"`
}

func cveDocID(key string) string { return "cves:" + hashID(key) }

// CachedCVEs returns a product's CVEs as last looked up, and when.
func (s *Store) CachedCVEs(ctx context.Context, key string) ([]CVE, time.Time, bool, error) {
	src, _, found, err := s.Docs.Get(ctx, s.Index, cveDocID(key))
	if err != nil || !found {
		return nil, time.Time{}, false, err
	}
	var d cveDoc
	if err := json.Unmarshal(src, &d); err != nil || d.Key != key {
		return nil, time.Time{}, false, err
	}
	return d.CVEs, d.FetchedAt, true, nil
}

// PutCVEs caches a product's CVEs.
func (s *Store) PutCVEs(ctx context.Context, key string, cves []CVE) error {
	doc := cveDoc{Kind: kindCVEs, Key: key, FetchedAt: s.now().UTC(), CVEs: cves}
	if doc.CVEs == nil {
		doc.CVEs = []CVE{}
	}
	id := cveDocID(key)
	_, v, found, err := s.Docs.Get(ctx, s.Index, id)
	if err != nil {
		return err
	}
	if !found {
		_, err = s.Docs.Create(ctx, s.Index, id, doc, false)
		if errors.Is(err, store.ErrExists) {
			return nil
		}
		return err
	}
	_, err = s.Docs.PutIf(ctx, s.Index, id, doc, v, false)
	if errors.Is(err, store.ErrConflict) {
		return nil
	}
	return err
}

type reportDoc struct {
	Kind string `json:"kind"`
	*Report
}

// PutReport keeps a scanner's latest check of itself.
func (s *Store) PutReport(ctx context.Context, r *Report) error {
	key := r.Server
	if r.NodeID != "" {
		key = "node:" + r.NodeID
	}
	id := "scanner:" + hashID(key)
	doc := reportDoc{kindReport, r}
	_, v, found, err := s.Docs.Get(ctx, s.Index, id)
	if err != nil {
		return err
	}
	if !found {
		_, err = s.Docs.Create(ctx, s.Index, id, doc, true)
		return err
	}
	_, err = s.Docs.PutIf(ctx, s.Index, id, doc, v, true)
	return err
}

// Reports returns every scanner's latest check of itself, newest first.
func (s *Store) Reports(ctx context.Context) ([]*Report, error) {
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"term": map[string]any{"kind": kindReport}})
	if err != nil {
		return nil, err
	}
	var out []*Report
	for _, d := range docs {
		var r Report
		if json.Unmarshal(d.Source, &r) == nil && r.Server != "" {
			out = append(out, &r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}
