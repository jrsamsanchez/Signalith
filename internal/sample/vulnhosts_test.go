// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"context"
	"errors"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// fakeVulns keeps the hosts saved for each network.
type fakeVulns struct {
	hosts   map[string][]*vulnscan.Host
	ensured int
	err     error // EnsureIndex fails with it
}

func (f *fakeVulns) EnsureIndex(context.Context) error { f.ensured++; return f.err }

func (f *fakeVulns) SaveHosts(_ context.Context, target string, hosts []*vulnscan.Host) error {
	if f.hosts == nil {
		f.hosts = map[string][]*vulnscan.Host{}
	}
	f.hosts[target] = hosts
	return nil
}

// The sample's scan results are also kept as the Vulnerabilities page
// reads them: the same hosts, ports and CVEs as its events.
func TestSampleVulnHosts(t *testing.T) {
	d := Generate(Options{Now: fixedNow})
	if len(d.VulnHosts) != 7 {
		t.Fatalf("%d sample scan hosts, want 7", len(d.VulnHosts))
	}
	by := map[string]*vulnscan.Host{}
	for _, h := range d.VulnHosts {
		if h.TargetID != VulnTarget || h.ID != vulnscan.HostID(VulnTarget, h.Address) || h.Address == "" || h.Counts.Hosts != 1 {
			t.Errorf("host %+v", h)
		}
		by[h.Hostname] = h
	}
	web := by["web-01"]
	if web == nil || web.Counts.Critical != 2 || web.Counts.High != 1 || web.Counts.KEV != 2 || web.MaxCVSS != 9.8 || web.Counts.Services != 2 {
		t.Errorf("web-01 = %+v", web)
	}
	app := by["app-01"]
	if app == nil || app.Counts.Likely != 1 || app.Counts.KEV != 0 {
		t.Errorf("app-01 = %+v", app)
	}
	// Most urgent first, as the page lists them.
	if d.VulnHosts[0].Hostname != "web-01" {
		t.Errorf("first host %q, want web-01", d.VulnHosts[0].Hostname)
	}
	// The events name the same CVEs.
	cves := map[string]bool{}
	for _, ev := range d.Events {
		if c, ok := ev.Fields["cve"].(string); ok && ev.Model == "Vulnerabilities" {
			cves[c] = true
		}
	}
	for _, h := range d.VulnHosts {
		for _, s := range h.Services {
			for _, v := range s.Vulns {
				if !cves[v.CVE] {
					t.Errorf("%s on %s has no event", v.CVE, h.Hostname)
				}
			}
		}
	}
}

// Loading adds the scan results, and removing takes them out again.
func TestLoadAndRemoveSampleVulnHosts(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	fv := &fakeVulns{}
	l.Vulns = fv
	if _, err := l.Load(ctx, SizeStandard, nil); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(fv.hosts[VulnTarget]) != 7 || fv.ensured == 0 {
		t.Fatalf("after loading: %d hosts, index ensured %d times", len(fv.hosts[VulnTarget]), fv.ensured)
	}
	if _, err := l.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if h, ok := fv.hosts[VulnTarget]; !ok || len(h) != 0 {
		t.Errorf("after removing: %v", h)
	}

	// Scan results that cannot be written stop neither a load nor a removal.
	fv.err = errors.New("index_create_block_exception")
	if _, err := l.Load(ctx, SizeStandard, nil); err != nil {
		t.Fatalf("Load with no vulnerabilities index: %v", err)
	}
	if _, err := l.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove with no vulnerabilities index: %v", err)
	}
}
