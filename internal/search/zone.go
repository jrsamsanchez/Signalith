// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // the zone names, on servers without a zone database
)

// zones caches the time zones searches name.
var zones sync.Map

// zoneOf returns the IANA time zone name names, or UTC for an empty or
// unknown name.
func zoneOf(name string) *time.Location {
	if name == "" || name == "UTC" {
		return time.UTC
	}
	if l, ok := zones.Load(name); ok {
		return l.(*time.Location)
	}
	l, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	zones.Store(name, l)
	return l
}

// ValidTimeZone checks a time zone a search request names: an IANA name
// such as America/New_York, or empty for UTC.
func ValidTimeZone(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 64 {
		return fmt.Errorf("time zone %.64q... is too long", name)
	}
	// Local, posixrules and Factory load too, but mean the server's own
	// zone or nothing; OpenSearch would read them differently.
	_, err := time.LoadLocation(name)
	if err != nil || (!strings.Contains(name, "/") && name != "UTC" && name != "GMT") {
		return fmt.Errorf("unknown time zone %q; use an IANA name such as America/New_York", name)
	}
	return nil
}

type zoneKey struct{}

// withZone makes loc the time zone of the commands a search runs.
func withZone(ctx context.Context, loc *time.Location) context.Context {
	return context.WithValue(ctx, zoneKey{}, loc)
}

// zoneFrom returns the search's time zone, UTC when it names none.
func zoneFrom(ctx context.Context) *time.Location {
	if ctx != nil {
		if l, ok := ctx.Value(zoneKey{}).(*time.Location); ok {
			return l
		}
	}
	return time.UTC
}

// zoneOffset is how many seconds t's wall clock in loc is ahead of UTC.
func zoneOffset(t time.Time, loc *time.Location) int64 {
	_, off := t.In(loc).Zone()
	return int64(off)
}

// wallSeconds is t's wall clock in loc counted as seconds since Unix time
// 0, for buckets of whole days: a day in loc is then a day from midnight.
func wallSeconds(t time.Time, secs int64, loc *time.Location) int64 {
	if secs%86400 != 0 || loc == time.UTC {
		return t.Unix()
	}
	return t.Unix() + zoneOffset(t, loc)
}

// fromWallSeconds turns wallSeconds back into a time, the start of a
// bucket.
func fromWallSeconds(w, secs int64, loc *time.Location) time.Time {
	if secs%86400 != 0 || loc == time.UTC {
		return time.Unix(w, 0).UTC()
	}
	u := time.Unix(w, 0).UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), u.Hour(), u.Minute(), u.Second(), 0, loc).UTC()
}
