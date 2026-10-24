// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package snapshots keeps Signalith's scheduled OpenSearch snapshots: an
// OpenSearch Snapshot Management policy, <prefix>-daily, that snapshots
// Signalith's own indices into a registered repository on a schedule and
// deletes the oldest beyond a count. The server that runs the background
// jobs writes the policy; OpenSearch takes the snapshots by itself, so
// they go on while Signalith is stopped. Every server can read how they
// went for the Health page. See docs/backup.md.
package snapshots

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the zone names, on servers without a zone database
)

// Defaults of the settings (backup.* in signalith.yaml).
const (
	// DefaultRepository is the repository the Docker quick start
	// registers (deploy/docker/opensearch/snapshot.sh).
	DefaultRepository = "signalith"
	DefaultEvery      = "1d"
	// DefaultAt is a quiet hour: after midnight's new daily indices, and
	// before the working day.
	DefaultAt   = "02:30"
	DefaultKeep = 14
	// MaxKeep bounds backup.snapshot_keep.
	MaxKeep = 1000
)

// Everies are the schedules backup.snapshot_every can name, and how long
// each period is.
var Everies = map[string]time.Duration{
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"12h": 12 * time.Hour,
	"1d":  24 * time.Hour,
}

// Settings are the backup.* settings.
type Settings struct {
	// On turns the scheduled snapshots on (backup.snapshots).
	On bool
	// Repository is the registered snapshot repository they go to.
	Repository string
	// Every is how often: 1h, 6h, 12h or 1d.
	Every string
	// At is the time of day, HH:MM, of the first snapshot of each day.
	At string
	// TimeZone is the IANA time zone of At; empty is UTC.
	TimeZone string
	// Keep is how many snapshots OpenSearch keeps; older ones are deleted.
	Keep int
}

// Normal returns s with the defaults for what it leaves empty.
func (s Settings) Normal() Settings {
	s.Repository = strings.TrimSpace(s.Repository)
	if s.Repository == "" {
		s.Repository = DefaultRepository
	}
	s.Every = strings.ToLower(strings.TrimSpace(s.Every))
	if _, ok := Everies[s.Every]; !ok {
		s.Every = DefaultEvery
	}
	s.At = strings.TrimSpace(s.At)
	if _, _, ok := clock(s.At); !ok {
		s.At = DefaultAt
	}
	s.TimeZone = strings.TrimSpace(s.TimeZone)
	if s.TimeZone == "" {
		s.TimeZone = "UTC"
	}
	if s.Keep <= 0 {
		s.Keep = DefaultKeep
	}
	return s
}

// repoName is what OpenSearch accepts as a repository name, and nothing
// that would change the path of a request.
var repoName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// Problems lists what is wrong with s, naming each setting by its key.
// The values themselves are not repeated: the problems are answers to
// whoever saved them.
func (s Settings) Problems() []string {
	var p []string
	if r := strings.TrimSpace(s.Repository); r != "" && !repoName.MatchString(r) {
		p = append(p, "backup.snapshot_repository must be a repository name: lower-case letters, digits, '.', '_' and '-'")
	}
	if e := strings.ToLower(strings.TrimSpace(s.Every)); e != "" {
		if _, ok := Everies[e]; !ok {
			p = append(p, "backup.snapshot_every must be 1h, 6h, 12h or 1d (empty: 1d)")
		}
	}
	if a := strings.TrimSpace(s.At); a != "" {
		if _, _, ok := clock(a); !ok {
			p = append(p, "backup.snapshot_at must be a time of day such as 02:30 (empty: "+DefaultAt+")")
		}
	}
	if err := CheckTimeZone(s.TimeZone); err != nil {
		p = append(p, "backup.snapshot_timezone: "+err.Error())
	}
	if s.Keep < 0 || s.Keep > MaxKeep {
		p = append(p, fmt.Sprintf("backup.snapshot_keep must be from 1 to %d (empty: %d)", MaxKeep, DefaultKeep))
	}
	return p
}

// CheckTimeZone checks an IANA time zone name such as Europe/Berlin, or
// empty for UTC. OpenSearch refuses a policy with a zone it does not know.
func CheckTimeZone(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || name == "UTC" {
		return nil
	}
	if len(name) > 64 {
		return errors.New("the time zone name is too long")
	}
	// Local and Factory load too, but mean the server's own zone or
	// nothing; OpenSearch would read them differently.
	if _, err := time.LoadLocation(name); err != nil || !strings.Contains(name, "/") {
		return errors.New("unknown time zone; use an IANA name such as Europe/Berlin or America/New_York (empty: UTC)")
	}
	return nil
}

// clock reads HH:MM.
func clock(s string) (h, m int, ok bool) {
	hs, ms, found := strings.Cut(s, ":")
	if !found || len(ms) != 2 || len(hs) < 1 || len(hs) > 2 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(hs)
	m, err2 := strconv.Atoi(ms)
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// Period is how long apart the snapshots are.
func (s Settings) Period() time.Duration { return Everies[s.Normal().Every] }

// Cron is the schedule as the cron expression the policy gives OpenSearch,
// in TimeZone: the snapshots start at At and every period after it.
func (s Settings) Cron() string {
	n := s.Normal()
	h, m, _ := clock(n.At)
	step := int(Everies[n.Every] / time.Hour)
	if step <= 1 {
		return fmt.Sprintf("%d * * * *", m)
	}
	var hours []string
	for x := h % step; x < 24; x += step {
		hours = append(hours, strconv.Itoa(x))
	}
	return fmt.Sprintf("%d %s * * *", m, strings.Join(hours, ","))
}

// Describe words the schedule: "every day at 02:30 UTC".
func (s Settings) Describe() string {
	n := s.Normal()
	h, m, _ := clock(n.At)
	at := fmt.Sprintf("%02d:%02d", h, m)
	switch n.Every {
	case "1h":
		return fmt.Sprintf("every hour at minute %02d", m)
	case "1d":
		return "every day at " + at + " " + n.TimeZone
	default:
		return fmt.Sprintf("every %d hours from %s %s", int(Everies[n.Every]/time.Hour), at, n.TimeZone)
	}
}

// Next is when the schedule next starts a snapshot after t, worked out as
// OpenSearch's cron does: for the Health page until OpenSearch says
// itself (it does once the policy first ran).
func (s Settings) Next(t time.Time) time.Time {
	n := s.Normal()
	loc, err := time.LoadLocation(n.TimeZone)
	if err != nil {
		loc = time.UTC
	}
	h0, m, _ := clock(n.At)
	step := int(Everies[n.Every] / time.Hour)
	lt := t.In(loc)
	day := time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, loc)
	for d := 0; d < 3; d++ {
		for h := 0; h < 24; h++ {
			if step > 1 && (h-h0%step)%step != 0 {
				continue
			}
			c := time.Date(day.Year(), day.Month(), day.Day()+d, h, m, 0, 0, loc)
			if c.After(t) {
				return c.UTC()
			}
		}
	}
	return t.Add(n.Period()).UTC()
}
