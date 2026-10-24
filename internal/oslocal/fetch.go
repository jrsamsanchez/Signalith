// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package oslocal

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// Room the install needs: the release's .zip while it is checked (in
// Data), and the unpacked program (in Home), with some to spare.
const (
	zipRoom     = 1500 << 20
	programRoom = 2000 << 20
)

// CheckRoom refuses to start when the disks Data and Home are on have too
// little room for the download and the unpacked program, before anything
// is downloaded or changed.
func CheckRoom(l Layout) error {
	need := map[string]int64{existing(l.Data): zipRoom}
	home := existing(l.Home)
	if filepath.VolumeName(home) == filepath.VolumeName(existing(l.Data)) {
		need[existing(l.Data)] += programRoom
	} else {
		need[home] = programRoom
	}
	for dir, n := range need {
		free, err := freeBytes(dir)
		if err != nil {
			// Not knowing is no reason to stop: a full disk still fails
			// clearly when the download is written.
			continue
		}
		if free < n {
			return fmt.Errorf("the disk %s is on has %d MB free; installing OpenSearch needs %d MB there "+
				"(about 1 GB for the download and 1.3 GB for the program). Free some room and run the installer again",
				dir, free>>20, n>>20)
		}
	}
	return nil
}

// diskSpaceOf is diskSpace; the tests change it.
var diskSpaceOf = diskSpace

func freeBytes(dir string) (int64, error) {
	free, _, err := diskSpaceOf(dir)
	return free, err
}

// OpenSearch's disk watermarks, which Signalith leaves at their defaults:
// above the high one it creates no index (and Signalith's own indexes
// with it), and the retention disk guard deletes the oldest days to stay
// under the low one.
const (
	lowWatermark  = 85
	highWatermark = 90
)

// DiskWarning is a warning when the disk OpenSearch keeps its data on
// will be past the low watermark once the program is installed, or ""
// when there is room (or the disk cannot be read).
func DiskWarning(l Layout) string {
	dir := existing(l.Data)
	free, total, err := diskSpaceOf(dir)
	if err != nil || total <= 0 {
		return ""
	}
	if filepath.VolumeName(existing(l.Home)) == filepath.VolumeName(dir) {
		free -= programRoom
	}
	used := float64(total-free) * 100 / float64(total)
	if used < lowWatermark {
		return ""
	}
	// Room to get back under the low watermark, rounded up to a GB.
	short := (int64(float64(total)*(100-lowWatermark)/100) - free + 1<<30 - 1) >> 30
	return fmt.Sprintf("The disk %s is on will be %.0f%% full. Above %d%% OpenSearch creates no new indexes, so Signalith cannot "+
		"store new events, and Signalith deletes its oldest events to stay under %d%%. Free about %d GB there.",
		dir, used, highWatermark, lowWatermark, short)
}

// existing is dir, or its nearest parent that exists.
func existing(dir string) string {
	for {
		if _, err := osStat(dir); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}

// Client returns the HTTP client the release is downloaded with. proxy,
// when given, is the proxy to go through (http://host:port); else the
// computer's own proxy setting is used: on Windows the machine-wide one
// (netsh winhttp), which the installer, running as SYSTEM, sees where it
// sees no user's; then HTTPS_PROXY and NO_PROXY.
func Client(proxy string) (*http.Client, error) {
	p, err := proxyFunc(proxy)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 p,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
	}}, nil
}

func proxyFunc(proxy string) (func(*http.Request) (*url.URL, error), error) {
	if proxy == "" {
		if u := systemProxy(); u != nil {
			return http.ProxyURL(u), nil
		}
		return http.ProxyFromEnvironment, nil
	}
	u, err := parseProxy(proxy)
	if err != nil {
		return nil, err
	}
	return http.ProxyURL(u), nil
}

// parseProxy reads a proxy's address: host:port, or http://host:port.
// One with a user name or password in it is refused, as it would be
// written in the installer's log.
func parseProxy(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	// Checked before parsing, and the address never shown: it may hold a
	// password, which the installer's log would keep.
	u, err := url.Parse(s)
	if strings.Contains(s, "@") || err == nil && u.User != nil {
		return nil, errors.New("a proxy address with a user name or password in it is not supported, " +
			"since the installer's log would keep it: download the OpenSearch .zip on another computer and install with OPENSEARCHZIP instead")
	}
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("the proxy address given is not one: give it as host:port or http://host:port")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("the proxy %s must be an http:// or https:// proxy", u.Redacted())
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		return nil, fmt.Errorf("give the proxy as host:port, not %s", u.Redacted())
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// winHTTPProxy picks the proxy for https:// addresses from a WinHTTP
// proxy list ("host:port", or "http=host:port;https=host:port").
func winHTTPProxy(list string) *url.URL {
	var plain, httpOnly string
	for _, e := range strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == ' ' }) {
		scheme, addr, ok := strings.Cut(e, "=")
		switch {
		case !ok:
			if plain == "" {
				plain = e
			}
		case strings.EqualFold(scheme, "https"):
			if u, err := parseProxy(addr); err == nil {
				return u
			}
		case strings.EqualFold(scheme, "http"):
			httpOnly = addr
		}
	}
	for _, a := range []string{plain, httpOnly} {
		if a == "" {
			continue
		}
		if u, err := parseProxy(a); err == nil {
			return u
		}
	}
	return nil
}
