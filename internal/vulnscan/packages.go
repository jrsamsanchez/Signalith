// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// DefaultOSVURL is where OSV.dev keeps its bulk downloads, one zip of
// advisories per ecosystem: <base>/<ecosystem>/all.zip.
const DefaultOSVURL = "https://osv-vulnerabilities.storage.googleapis.com"

// OSVHost is the host those downloads come from.
const OSVHost = "osv-vulnerabilities.storage.googleapis.com"

// OSVOff, as the advisories address, turns the package check off.
const OSVOff = "off"

// Timings and limits of the package check.
const (
	osvFresh = 24 * time.Hour
	osvRetry = time.Hour
	// packagesEvery is how often hosts' package lists are checked again.
	packagesEvery = time.Hour
	// packagesStale leaves out a host that sent no package list for this
	// long: it is gone, or osquery stopped.
	packagesStale = 3 * 24 * time.Hour
	// packageEventsEvery is how often a host's unchanged CVEs are written
	// as events again, as a daily scan would.
	packageEventsEvery = 24 * time.Hour
	// PackagesTargetName names PackagesTarget on the page and in events.
	PackagesTargetName = "Installed packages"
)

// maxOSVZip caps one download: Ubuntu's, the largest, is about 160 MB for
// one release. A var so tests can lower it.
var maxOSVZip int64 = 512 << 20

// PackageInventory lists hosts' installed packages. *endpoint.Store has
// it.
type PackageInventory interface {
	HostPackages(ctx context.Context) ([]*endpoint.HostPackages, error)
}

// PackageCheck matches the packages osquery hosts have installed to their
// distribution's advisories from OSV.dev (ASI-19). It downloads the
// advisories only of the releases its hosts run, once a day, and keeps
// what applies as hosts of PackagesTarget, written as events like a
// scan's. Only the server that runs the background jobs runs it.
type PackageCheck struct {
	Store     *Store
	Inventory PackageInventory
	// HTTP downloads the advisories; the server gives it the client of
	// feed downloads, which never reaches this machine, its OpenSearch or
	// a cloud metadata service.
	HTTP   *http.Client
	Events EventWriter
	// Server names this server in events.
	Server string
	Log    *slog.Logger
	Now    func() time.Time
	// TempDir holds a download while it is read; "" is the system's.
	TempDir string

	mu      sync.Mutex
	base    string
	feeds   map[string]*osvFeed
	running bool
	lastRun time.Time
	hosts   int
	written map[string]writtenEvents
}

type osvFeed struct {
	eco    Ecosystem
	index  *OSVIndex
	status FeedStatus
}

type writtenEvents struct {
	sig string
	at  time.Time
}

// NewPackageCheck returns a check of the hosts inv lists, with advisories
// from base (DefaultOSVURL when empty).
func NewPackageCheck(st *Store, inv PackageInventory, base string) *PackageCheck {
	p := &PackageCheck{Store: st, Inventory: inv, HTTP: &http.Client{Timeout: 10 * time.Minute}}
	p.Set(base)
	return p
}

// Set changes where advisories come from: an http(s) address, a folder on
// this server holding <ecosystem>/all.zip, or off.
func (p *PackageCheck) Set(base string) {
	base = strings.TrimSpace(base)
	if base == "" {
		base = DefaultOSVURL
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.base != "" && p.base != base {
		// A new address is tried at once.
		p.feeds = nil
		p.lastRun = time.Time{}
	}
	p.base = base
}

func (p *PackageCheck) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *PackageCheck) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

// Active reports whether the last run checked any host, so the exploit
// feeds that rank its CVEs are worth downloading.
func (p *PackageCheck) Active() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hosts > 0
}

// PackageStatus is how the package check stands, kept for the Scanners
// page.
type PackageStatus struct {
	Kind string `json:"kind"`
	// Hosts are the hosts checked, and Unsupported those that run a
	// system OSV.dev has no advisories for here.
	Hosts       int                   `json:"hosts"`
	Unsupported int                   `json:"unsupported"`
	RanAt       time.Time             `json:"ran_at,omitzero"`
	Off         bool                  `json:"off,omitempty"`
	Feeds       map[string]FeedStatus `json:"feeds"`
}

const (
	kindPackages   = "packages"
	packagesMetaID = "packages:meta"
)

// Status returns the package check's last stored status.
func (p *PackageCheck) Status(ctx context.Context) (PackageStatus, error) {
	var st PackageStatus
	src, _, found, err := p.Store.Docs.Get(ctx, p.Store.Index, packagesMetaID)
	if err != nil || !found {
		return st, err
	}
	err = json.Unmarshal(src, &st)
	return st, err
}

func (p *PackageCheck) putStatus(ctx context.Context, st PackageStatus) error {
	st.Kind = kindPackages
	_, v, found, err := p.Store.Docs.Get(ctx, p.Store.Index, packagesMetaID)
	if err != nil {
		return err
	}
	if !found {
		_, err = p.Store.Docs.Create(ctx, p.Store.Index, packagesMetaID, st, true)
		return err
	}
	_, err = p.Store.Docs.PutIf(ctx, p.Store.Index, packagesMetaID, st, v, true)
	return err
}

// Run checks the hosts' packages when an hour has passed or new
// advisories came in, downloading the advisories that are a day old. x
// ranks what is found; nil leaves it as the advisories have it.
func (p *PackageCheck) Run(ctx context.Context, x *Exploits) error {
	if p == nil || p.Inventory == nil {
		return nil
	}
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = true
	base, lastRun := p.base, p.lastRun
	if p.feeds == nil {
		p.feeds = map[string]*osvFeed{}
	}
	feeds := p.feeds
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
	}()
	now := p.now()
	if base == OSVOff {
		if !lastRun.IsZero() {
			return nil
		}
		// What was found before is dropped: nothing keeps it current.
		if err := p.Store.SaveHosts(ctx, PackagesTarget, nil); err != nil {
			return err
		}
		p.mu.Lock()
		p.lastRun, p.hosts = now, 0
		p.mu.Unlock()
		return p.putStatus(ctx, PackageStatus{Off: true, RanAt: now.UTC(), Feeds: map[string]FeedStatus{}})
	}
	if !lastRun.IsZero() && now.Sub(lastRun) < packagesEvery {
		// Within the hour, only advisories that are due bring a run
		// forward; the hosts are not read.
		due := false
		for _, f := range feeds {
			due = due || feedDue(f.status, now)
		}
		if !due {
			return nil
		}
	}
	listed, err := p.Inventory.HostPackages(ctx)
	if err != nil {
		return err
	}
	type hostEco struct {
		hp  *endpoint.HostPackages
		eco Ecosystem
	}
	var hosts []hostEco
	ecos := map[string]Ecosystem{}
	unsupported := 0
	for _, hp := range listed {
		if now.Sub(hp.At) > packagesStale {
			continue
		}
		eco, ok := EcosystemFor(hp.OS, hp.OSVersion)
		if !ok {
			unsupported++
			continue
		}
		hosts = append(hosts, hostEco{hp, eco})
		ecos[eco.Name] = eco
	}
	refreshed := false
	var errs []error
	names := make([]string, 0, len(ecos))
	for name := range ecos {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f := feeds[name]
		if f == nil {
			f = &osvFeed{eco: ecos[name]}
			feeds[name] = f
		}
		if !feedDue(f.status, now) {
			continue
		}
		f.status.TriedAt = now.UTC()
		idx, err := p.fetch(ctx, base, f.eco)
		if err != nil {
			f.status.Error = err.Error()
			errs = append(errs, err)
			p.log().Warn("package check: could not download a distribution's advisories; the last copy is used", "ecosystem", name, "err", err)
			continue
		}
		f.index, refreshed = idx, true
		f.status = FeedStatus{Count: idx.Advisories, FetchedAt: now.UTC(), TriedAt: now.UTC()}
		p.log().Info("package check: advisories downloaded", "ecosystem", name, "advisories", idx.Advisories)
	}
	// Releases no host runs any more are let go.
	p.mu.Lock()
	for name := range feeds {
		if _, ok := ecos[name]; !ok {
			delete(feeds, name)
		}
	}
	p.mu.Unlock()
	if !refreshed && !lastRun.IsZero() && now.Sub(lastRun) < packagesEvery {
		return errors.Join(errs...)
	}

	old := map[string]*Host{}
	if docs, err := p.Store.hostDocs(ctx, PackagesTarget); err == nil {
		for _, d := range docs {
			var h Host
			if json.Unmarshal(d.Source, &h) == nil && h.ID != "" {
				old[h.ID] = &h
			}
		}
	} else {
		return err
	}
	var out, fresh []*Host
	for _, he := range hosts {
		id := HostID(PackagesTarget, he.hp.NodeID)
		f := feeds[he.eco.Name]
		if f == nil || f.index == nil {
			// No advisories yet: what was found before stays.
			if h := old[id]; h != nil {
				out = append(out, h)
			}
			continue
		}
		h := &Host{ID: id, TargetID: PackagesTarget, TargetName: PackagesTargetName, Address: hostAddress(he.hp),
			Hostname: he.hp.Hostname, EndpointID: he.hp.NodeID, ScanID: PackagesTarget, FirstSeen: now.UTC(), LastSeen: he.hp.At.UTC(),
			Services: f.index.Match(he.hp.Packages)}
		out = append(out, h)
		fresh = append(fresh, h)
	}
	x.Apply(out)
	if err := p.Store.SaveHosts(ctx, PackagesTarget, out); err != nil {
		return err
	}
	if err := p.writeEvents(ctx, fresh, now); err != nil {
		errs = append(errs, err)
	}
	p.mu.Lock()
	p.lastRun, p.hosts = now, len(hosts)
	st := PackageStatus{Hosts: len(hosts), Unsupported: unsupported, RanAt: now.UTC(), Feeds: map[string]FeedStatus{}}
	for name, f := range feeds {
		st.Feeds[name] = f.status
	}
	p.mu.Unlock()
	if err := p.putStatus(ctx, st); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func feedDue(st FeedStatus, now time.Time) bool {
	if !st.FetchedAt.IsZero() && now.Sub(st.FetchedAt) < osvFresh {
		return false
	}
	return st.TriedAt.IsZero() || now.Sub(st.TriedAt) >= osvRetry
}

// hostAddress is the address a host's findings show: its first IPv4
// address, else its first address, else its name.
func hostAddress(hp *endpoint.HostPackages) string {
	for _, ip := range hp.IPs {
		if a, err := netip.ParseAddr(ip); err == nil && a.Unmap().Is4() {
			return a.Unmap().String()
		}
	}
	if len(hp.IPs) > 0 {
		return hp.IPs[0]
	}
	return hp.Hostname
}

// writeEvents writes the CVEs of hosts whose findings changed, or were
// last written a day ago, as events.
func (p *PackageCheck) writeEvents(ctx context.Context, hosts []*Host, now time.Time) error {
	if p.Events == nil {
		return nil
	}
	p.mu.Lock()
	if p.written == nil {
		p.written = map[string]writtenEvents{}
	}
	var due []*Host
	sigs := map[string]string{}
	for _, h := range hosts {
		sig := findingsSig(h)
		if w, ok := p.written[h.ID]; ok && w.sig == sig && now.Sub(w.at) < packageEventsEvery {
			continue
		}
		due = append(due, h)
		sigs[h.ID] = sig
	}
	p.mu.Unlock()
	evs := PackageEvents(p.Server, due, now)
	if len(evs) > maxScanEvents {
		p.log().Warn("package check found more than can be written as events; the Vulnerabilities page has them all", "events", len(evs), "written", maxScanEvents)
		evs = evs[:maxScanEvents]
	}
	ctx = ingest.WithOrigin(ctx, ingest.Origin{Intake: ingest.IntakeScanner})
	for i := 0; i < len(evs); i += eventBatch {
		if _, err := p.Events.IngestEvents(ctx, evs[i:min(i+eventBatch, len(evs))]); err != nil {
			return err
		}
	}
	p.mu.Lock()
	for id, sig := range sigs {
		p.written[id] = writtenEvents{sig, now}
	}
	p.mu.Unlock()
	return nil
}

// findingsSig sums up what was found on a host, to tell when it changed.
func findingsSig(h *Host) string {
	sum := sha256.New()
	for _, svc := range h.Services {
		for _, v := range svc.Vulns {
			fmt.Fprintf(sum, "%s|%s|%s|%s|%t|%v\n", svc.Product, svc.Version, v.CVE, v.Fixed, v.KEV, v.EPSS >= LikelyEPSS)
		}
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// fetch reads one release's advisories: downloaded to a temporary file,
// as a zip is read from its end, or from a folder on this server.
func (p *PackageCheck) fetch(ctx context.Context, base string, eco Ecosystem) (*OSVIndex, error) {
	if dir, ok := osvFolder(base); ok {
		// Windows allows no : in a folder name, so Debian_12 also works.
		fh, err := os.Open(filepath.Join(dir, eco.Feed, "all.zip"))
		if err != nil {
			fh, err = os.Open(filepath.Join(dir, strings.ReplaceAll(eco.Feed, ":", "_"), "all.zip"))
		}
		if err != nil {
			return nil, err
		}
		defer fh.Close()
		fi, err := fh.Stat()
		if err != nil {
			return nil, err
		}
		if fi.Size() > maxOSVZip {
			return nil, fmt.Errorf("the advisories are larger than %d MB", maxOSVZip>>20)
		}
		return ReadOSVZip(fh, fi.Size(), eco)
	}
	src := strings.TrimRight(base, "/") + "/" + url.PathEscape(eco.Feed) + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Signalith")
	hc := p.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s for %s", hostOf(src), resp.Status, eco.Feed)
	}
	if resp.ContentLength > maxOSVZip {
		return nil, fmt.Errorf("the advisories are larger than %d MB", maxOSVZip>>20)
	}
	tmp, err := os.CreateTemp(p.TempDir, "signalith-osv-*.zip")
	if err != nil {
		return nil, err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxOSVZip+1))
	if err != nil {
		return nil, err
	}
	if n > maxOSVZip {
		return nil, fmt.Errorf("the advisories are larger than %d MB", maxOSVZip>>20)
	}
	return ReadOSVZip(tmp, n, eco)
}

// osvFolder reports whether an advisories address is a folder on this
// server (a path, or file:///path), for a network with no internet.
func osvFolder(base string) (string, bool) {
	if p, ok := strings.CutPrefix(base, "file://"); ok {
		return p, true
	}
	if strings.HasPrefix(base, "/") || (len(base) > 2 && base[1] == ':') {
		return base, true
	}
	return "", false
}

// packagesCheck says how the package check stands, as the server that
// runs the background jobs last stored it.
func (c *Checker) packagesCheck(ctx context.Context, lookups bool) Check {
	ck := Check{ID: "packages", Title: "Installed packages: distribution advisories from OSV.dev",
		Why: "Linux hosts that run osquery list their installed packages with the exact version their distribution built. Signalith matches them to the distribution's own advisories " +
			"(Debian, Ubuntu, Red Hat, AlmaLinux and Rocky Linux, as OSV.dev publishes them), so a package is reported only when it is older than the version that fixed the CVE. " +
			"Only the advisories of the releases your hosts run are downloaded, once a day; nothing about your hosts is sent."}
	st, err := c.Packages.Status(ctx)
	switch {
	case !lookups:
		ck.State, ck.Detail = CheckInfo, "CVE lookups are turned off in the scan settings, so installed packages are not checked."
	case err != nil:
		ck.State, ck.Detail = CheckWarn, "The status could not be read: "+err.Error()
	case st.Off:
		ck.State, ck.Detail = CheckInfo, "Turned off: the advisories address is set to off."
	case st.RanAt.IsZero():
		ck.State, ck.Detail = CheckInfo, "Not run yet. It runs once a Linux host with osquery has listed its packages."
	case st.Hosts == 0 && st.Unsupported == 0:
		ck.State, ck.Detail = CheckInfo, "No Linux host with osquery has listed its packages in the last 3 days."
	default:
		var bad []string
		for name, f := range st.Feeds {
			if f.Error != "" {
				bad = append(bad, name+": "+f.Error)
			}
		}
		sort.Strings(bad)
		ck.State = CheckOK
		ck.Detail = fmt.Sprintf("%d %s checked against %d %s.", st.Hosts, plural(st.Hosts, "host", "hosts"), len(st.Feeds), plural(len(st.Feeds), "release", "releases"))
		if st.Unsupported > 0 {
			ck.Detail += fmt.Sprintf(" %d %s a system that is not covered.", st.Unsupported, plural(st.Unsupported, "host runs", "hosts run"))
		}
		if len(bad) > 0 {
			ck.State = CheckWarn
			ck.Detail += " The last download failed for " + strings.Join(bad, "; ") + "."
			ck.Fix = []string{
				"Allow outbound HTTPS (port 443) from the server that runs the background jobs to " + OSVHost + ", or set HTTPS_PROXY for the Signalith service.",
				"With no internet, copy each release's all.zip into a folder on that server, as <release>/all.zip (Debian:12/all.zip, or Debian_12/all.zip on Windows), and enter the folder as Distribution advisories address in Settings, under Vulnerability scans.",
				"Signalith tries again every hour; meanwhile the last results stay.",
			}
		}
	}
	return ck
}
