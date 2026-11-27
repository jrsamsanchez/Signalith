// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func checksByID(checks []Check) map[string]Check {
	out := map[string]Check{}
	for _, c := range checks {
		out[c.ID] = c
	}
	return out
}

func TestChecksNmapFailures(t *testing.T) {
	ctx := context.Background()
	// Nmap is there but does not start: the scan test waits for it.
	c := &Checker{FindNmap: func() string { return "/opt/nmap" }, GOOS: "linux",
		Version: func(context.Context, string) (string, error) { return "", errors.New("exec format error") }}
	byID := checksByID(func() []Check { cs, _ := c.Run(ctx, DefaultSettings(), nil); return cs }())
	if n := byID["nmap"]; n.State != CheckFail || !strings.Contains(n.Detail, "did not start: exec format error") || len(n.Fix) == 0 {
		t.Errorf("nmap: %+v", n)
	}
	if r := byID["nmap_runs"]; r.State != CheckInfo {
		t.Errorf("nmap_runs: %+v", r)
	}
	// On Windows a failed scan test says to reinstall with Npcap.
	c = &Checker{FindNmap: func() string { return `C:\Nmap\nmap.exe` }, GOOS: "windows",
		Version:  func(context.Context, string) (string, error) { return "7.95", nil },
		SelfTest: func(context.Context, string) error { return errors.New("no Npcap") }}
	byID = checksByID(func() []Check { cs, _ := c.Run(ctx, DefaultSettings(), nil); return cs }())
	if r := byID["nmap_runs"]; r.State != CheckFail || !strings.Contains(strings.Join(r.Fix, " "), "Npcap") {
		t.Errorf("nmap_runs on Windows: %+v", r)
	}
	// In Docker the fix is a newer image.
	c = &Checker{FindNmap: func() string { return "" }, Docker: true}
	byID = checksByID(func() []Check { cs, _ := c.Run(ctx, DefaultSettings(), nil); return cs }())
	if n := byID["nmap"]; !strings.Contains(strings.Join(n.Fix, " "), "docker compose pull") {
		t.Errorf("nmap in Docker: %+v", n)
	}
}

func TestChecksCVELookups(t *testing.T) {
	ctx := context.Background()
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer ok.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer failing.Close()
	gone := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	goneURL := gone.URL
	gone.Close()

	set := DefaultSettings()
	set.CVELookup = true
	tests := []struct {
		name    string
		nvd     *NVD
		state   string
		detail  string
		fix     bool
		keyOK   bool
		disable bool
	}{
		{"answers", &NVD{URL: ok.URL, Gap: time.Millisecond}, CheckOK, "answered", false, false, false},
		{"with a key", &NVD{URL: ok.URL, APIKey: "k", Gap: time.Millisecond}, CheckOK, "answered", false, true, false},
		{"fails", &NVD{URL: failing.URL, Gap: time.Millisecond}, CheckWarn, "lookup failed", false, false, false},
		{"unreachable", &NVD{URL: goneURL, Gap: time.Millisecond}, CheckWarn, "lookup failed", true, false, false},
		{"not available", nil, CheckInfo, "not available", false, false, false},
		{"turned off", &NVD{URL: ok.URL}, CheckInfo, "turned off", false, false, true},
	}
	for _, tc := range tests {
		s := set
		s.CVELookup = !tc.disable
		c := &Checker{FindNmap: func() string { return "" }, NVD: tc.nvd}
		checks, _ := c.Run(ctx, s, nil)
		byID := checksByID(checks)
		cve := byID["cve"]
		if cve.State != tc.state || !strings.Contains(cve.Detail, tc.detail) || (len(cve.Fix) > 0) != tc.fix {
			t.Errorf("%s: cve %+v", tc.name, cve)
		}
		if (byID["nvd_key"].State == CheckOK) != tc.keyOK {
			t.Errorf("%s: nvd_key %+v", tc.name, byID["nvd_key"])
		}
	}
}

func TestNamesAddsAliases(t *testing.T) {
	got := names(CPE{Part: "a", Vendor: "igor_sysoev", Product: "nginx", Version: "1.18.0"})
	if len(got) != 3 {
		t.Fatalf("names = %+v", got)
	}
	for _, c := range got {
		if c.Version != "1.18.0" || c.Product != "nginx" {
			t.Errorf("alias %+v", c)
		}
	}
	if got := names(CPE{Part: "a", Vendor: "apache", Product: "http_server"}); len(got) != 1 {
		t.Errorf("a product without aliases: %+v", got)
	}
}
