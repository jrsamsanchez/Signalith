// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
)

// raiseWaiting says why the cluster's level is not raised although this
// server reads a higher one: next is the level it waits for, and blockers
// the servers seen within LevelSeen whose version does not read it. ok is
// false when nothing waits (the level is as high as this version reads,
// the servers are not known yet, or none holds it back).
func (rt *Runtime) raiseWaiting() (next int, blockers []Peer, ok bool) {
	body, found := rt.Cluster().Get()
	if !found || body == nil || body.Level >= rt.maxLevel() {
		return 0, nil, false
	}
	peers, known := rt.peersSeen()
	if !known {
		return 0, nil, false
	}
	next = body.Level + 1
	for _, p := range peers {
		if p.NodeID == rt.opts.Self.NodeID || !p.Live && p.SeenAgo >= LevelSeen {
			continue
		}
		if max(p.LevelMax, LevelMin) < next {
			blockers = append(blockers, p)
		}
	}
	slices.SortFunc(blockers, func(a, b Peer) int { return strings.Compare(a.Name, b.Name) })
	return next, blockers, len(blockers) > 0
}

// levelWarning says, in amber, which servers hold back what this
// server's version adds: the cluster's level rises once every server seen
// in the last 24 hours runs a version that reads the next one. nil when
// nothing waits.
func (rt *Runtime) levelWarning() *Warning {
	_, blockers, ok := rt.raiseWaiting()
	if !ok {
		return nil
	}
	mine := cmp.Or(rt.opts.Version, "this server's version")
	versions := []string{}
	if rt.opts.Version != "" {
		versions = append(versions, rt.opts.Version)
	}
	peers, _ := rt.peersSeen()
	for _, p := range peers {
		if p.NodeID == rt.opts.Self.NodeID || !p.Live && p.SeenAgo >= LevelSeen || p.Version == "" || slices.Contains(versions, p.Version) {
			continue
		}
		versions = append(versions, p.Version)
	}
	slices.Sort(versions)
	now := rt.clock.Now()
	var names []string
	offline := false
	for _, b := range blockers {
		name := b.Name
		if b.Version != "" {
			name += " (" + b.Version + ")"
		}
		if !b.Live {
			offline = true
			since := now.Add(-b.SeenAgo)
			if b.OfflineSince != nil {
				since = *b.OfflineSince
			}
			name += fmt.Sprintf(", offline since %s, stops counting at %s, or remove it", clockTime(now, since), clockTime(now, since.Add(LevelSeen)))
		}
		names = append(names, name)
	}
	text := ""
	if len(versions) > 1 {
		text = "The servers run " + andList(versions) + ". "
	}
	text += fmt.Sprintf("What %s adds waits until every server runs it: upgrade %s.", mine, strings.Join(names, "; "))
	if !offline {
		text += " A server stopped for 24 hours stops counting."
	}
	return &Warning{Level: "amber", Text: text}
}

// clockTime writes t for someone reading it at now, in this server's
// time zone, which it names (a container runs in UTC, the reader may
// not): "10:42 UTC" today, "10:42 UTC tomorrow", else with its date
// ("2026-10-12 10:42 UTC").
func clockTime(now, t time.Time) string {
	t = t.In(now.Location())
	y, m, d := now.Date()
	ty, tm, td := t.Date()
	switch {
	case y == ty && m == tm && d == td:
		return t.Format("15:04 MST")
	case now.AddDate(0, 0, 1).Format(time.DateOnly) == t.Format(time.DateOnly):
		return t.Format("15:04 MST") + " tomorrow"
	}
	return t.Format("2006-01-02 15:04 MST")
}

// andList writes "a", "a and b", "a, b and c".
func andList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
