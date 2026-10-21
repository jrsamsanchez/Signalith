// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Events are stored in the daily index of their own time (UTC), and a busy
// day continues in parts, <prefix>-<model>-YYYY.MM.DD-2 and so on. A search
// over the last hour therefore needs only today's indices, but a pattern
// such as signalith-* makes OpenSearch send it to every shard of every day
// it keeps, each of which then finds nothing. Naming the days instead lets
// the search reach the few shards that can hold its events.

// maxEventAhead is how far past its receipt an event's time may be
// (ingest.MaxEventAhead); a search without latest= reads that far ahead.
const maxEventAhead = time.Hour

// dayPad widens the days a search names past its time range, as OpenSearch
// resolves relative times like -24h on its own clock.
const dayPad = time.Hour

// maxIndexList bounds the index list a search names, escaped as it goes
// into the request's URL, well under OpenSearch's 4 KB request line. A
// longer range keeps the whole pattern.
const maxIndexList = 2048

// modelPattern matches the model part of <prefix>-<model>-*.
var modelPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// searchSpan returns the times a search's events fall between, from its
// earliest= and latest=, or ok false when it has no start or a time that
// is not understood here.
func searchSpan(earliest, latest string, now time.Time, loc *time.Location) (from, to time.Time, ok bool) {
	if earliest == "" || strings.TrimSpace(earliest) == "0" {
		return time.Time{}, time.Time{}, false
	}
	from, ok = resolveTimeIn(earliest, now, loc)
	if !ok || from.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	if strings.TrimSpace(latest) == "" {
		// No upper bound: events up to the newest ingest stores.
		to = now.Add(maxEventAhead)
	} else if to, ok = resolveTimeIn(latest, now, loc); !ok {
		return time.Time{}, time.Time{}, false
	}
	return from.UTC(), to.UTC(), true
}

// narrowToDays limits the index pattern of a search to the daily indices,
// and their parts, of the days from from through to. Whole months and
// years in the range are named as one pattern each. Patterns it does not
// know, ranges that end before they start and ranges too long to list are
// returned unchanged.
func narrowToDays(index, prefix string, from, to time.Time) string {
	parts := strings.Split(index, ",")
	base := parts[0]
	for _, p := range parts[1:] {
		if !strings.HasPrefix(p, "-") {
			return index
		}
	}
	var stem string
	switch m, ok := strings.CutPrefix(base, prefix+"-"); {
	case !ok:
		return index
	case m == "*":
		stem = prefix + "-*-"
	case strings.HasSuffix(m, "-*") && modelPattern.MatchString(strings.TrimSuffix(m, "-*")):
		stem = strings.TrimSuffix(base, "*")
	default:
		return index
	}
	day := func(t time.Time) time.Time {
		t = t.UTC()
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
	start, end := day(from.Add(-dayPad)), day(to.Add(dayPad))
	if end.Before(start) || start.Year() < 1000 || end.Year() > 9999 {
		return index
	}
	var list []string
	size := 0
	for d := start; !d.After(end); {
		var period string
		var next time.Time
		switch {
		case d.YearDay() == 1 && !d.AddDate(1, 0, -1).After(end):
			period, next = d.Format("2006")+".*", d.AddDate(1, 0, 0)
		case d.Day() == 1 && !d.AddDate(0, 1, -1).After(end):
			period, next = d.Format("2006.01")+".*", d.AddDate(0, 1, 0)
		default:
			// The day's index and its parts, YYYY.MM.DD-2 and on.
			period, next = d.Format("2006.01.02")+"*", d.AddDate(0, 0, 1)
		}
		p := stem + period
		if size += len(url.PathEscape(p)) + len("%2C"); size > maxIndexList {
			return index
		}
		list = append(list, p)
		d = next
	}
	return strings.Join(append(list, parts[1:]...), ",")
}
