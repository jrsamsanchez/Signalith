// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Since 0.3.1 the Docker quick start's signalith.yaml takes syslog over
// TLS only: plain syslog over UDP and TCP is unencrypted and can be
// forged. The quick start is updated by replacing that file (git pull),
// so an install from before would lose the plain syslog it had. To keep
// it, the first start of a version with this file decides once whether
// the install was there before, from the state folder (HoldsState: the
// data volume of a new install holds none of Signalith's own files yet),
// and keeps the answer in the state folder. An install that was there
// keeps plain syslog on where it was: UDP and TCP on 0.0.0.0:5514, which
// the quick start publishes as 514, as the quick start had them. It
// applies as signalith.yaml's own values do, so a value saved on the
// Settings page, shared between servers or set in the environment still
// wins, and turning plain syslog off on the Settings page stays off.

// plainSyslogFile, in the state folder, keeps that decision.
const plainSyslogFile = "plain-syslog.json"

// QuickStartPlainAddr is where the Docker quick start receives plain
// syslog over UDP and TCP, and QuickStartPublicPort the port its
// docker-compose.yml publishes for it.
const (
	QuickStartPlainAddr  = "0.0.0.0:5514"
	QuickStartPublicPort = 514
)

// PlainSyslog is the decision about plain syslog on a Docker quick start.
type PlainSyslog struct {
	// Kept is true when the install was there before this version, so it
	// keeps the plain syslog its older signalith.yaml had.
	Kept bool `json:"kept"`
	// Decided is when Signalith decided.
	Decided time.Time `json:"decided"`
}

// PlainSyslogFileIn is where the decision is kept in the state folder dir.
func PlainSyslogFileIn(dir string) string { return filepath.Join(dir, plainSyslogFile) }

// ReadPlainSyslog reads the decision kept in the state folder dir: nil
// when there is none yet.
func ReadPlainSyslog(dir string) (*PlainSyslog, error) {
	path := PlainSyslogFileIn(dir)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p PlainSyslog
	if err := json.Unmarshal(b, &p); err != nil || p.Decided.IsZero() {
		return nil, fmt.Errorf("%s is damaged", path)
	}
	return &p, nil
}

// DecidePlainSyslog makes the decision for the Docker quick start whose
// config is c, once: it returns the decision and whether it was made now.
// Elsewhere, and once decided, it changes nothing. The server calls it at
// its start, before it writes anything in the state folder, and loads its
// config again when it was made now. A damaged file is decided again,
// from the same evidence only while the state folder holds nothing else.
func DecidePlainSyslog(c *Config, now time.Time) (*PlainSyslog, bool, error) {
	if !c.quickStart {
		return nil, false, nil
	}
	dir := c.StateDir()
	if p, err := ReadPlainSyslog(dir); err == nil && p != nil {
		return p, false, nil
	}
	p := &PlainSyslog{Kept: HoldsState(dir), Decided: now.UTC()}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, false, err
	}
	if err := securefile.Replace(PlainSyslogFileIn(dir), append(b, '\n')); err != nil {
		return p, false, err
	}
	return p, true, nil
}

// keepPlainSyslog gives an upgraded Docker quick start the plain syslog
// its older signalith.yaml had, when the file it has now turns it off and
// the environment does not set it.
func (c *Config) keepPlainSyslog() {
	if !c.quickStart || c.Syslog.UDP != "" || c.Syslog.TCP != "" ||
		os.Getenv("SIGNALITH_SYSLOG_UDP") != "" || os.Getenv("SIGNALITH_SYSLOG_TCP") != "" {
		return
	}
	p, _ := ReadPlainSyslog(c.StateDir())
	if p == nil || !p.Kept {
		return
	}
	c.Syslog.UDP, c.Syslog.TCP = QuickStartPlainAddr, QuickStartPlainAddr
	if c.Syslog.PublicPort == 0 {
		c.Syslog.PublicPort = QuickStartPublicPort
	}
	c.plainSyslogKept = true
}

// PlainSyslogKept reports whether this Docker quick start receives plain
// syslog because it was upgraded from a version that did (see
// DecidePlainSyslog), not because a setting says so.
func (c *Config) PlainSyslogKept() bool { return c.plainSyslogKept }
