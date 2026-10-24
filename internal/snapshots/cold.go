// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package snapshots

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Cold storage (internal/retention) keeps old days as searchable
// snapshots in the <prefix>-cold repository: mounted indices whose
// index.store.type is remote_snapshot. OpenSearch 2.17 and 3.9 snapshot
// such an index without complaint, but copy none of its data (the files
// stay in the cold snapshot), and restoring the copy mounts the cold
// snapshot again, which leaves the cluster red once retention has
// deleted that. A red cluster also stops Snapshot Management from
// running at all. So the policy leaves the mounted indices out: its
// indices end in a -<name> exclusion for each, which Signalith refreshes
// when the cold set changes (Snapshot Management takes no other way to
// say "not these"). Retention mounts missing cold days again by itself.

// MaxIndices is the most the policy's indices expression may hold.
// OpenSearch has no limit of its own below its 100 MB request size, and
// 2.17 and 3.9 took and ran a 113 KB one; Signalith stays at about half
// that, as Snapshot Management reads the whole policy at every run.
const MaxIndices = 64 << 10

var (
	monthOf = regexp.MustCompile(`^(.*\d{4}\.\d{2})\.\d{2}$`)
	yearOf  = regexp.MustCompile(`^(.*\d{4})\.\d{2}\.\d{2}$`)
)

// IndicesLeavingOut is Indices(prefix) with each of cold left out. When
// the names one by one make it longer than MaxIndices, it leaves whole
// months out (-<name-yyyy.mm>.*), then whole years (or else months),
// wherever no index of hot falls under them. all is false when even that is too long: the
// expression then leaves out none, and the snapshots hold the mounted
// indices empty.
func IndicesLeavingOut(prefix string, cold, hot []string) (expr string, all bool) {
	base := Indices(prefix)
	if len(cold) == 0 {
		return base, true
	}
	for _, by := range [][]*regexp.Regexp{nil, {monthOf}, {yearOf, monthOf}} {
		if e := base + exclusions(cold, hot, by); len(e) <= MaxIndices {
			return e, true
		}
	}
	return base, false
}

// exclusions is ",-<name>" for each of cold, or ",-<group>.*" for the
// first group of it in by that no index of hot falls under.
func exclusions(cold, hot []string, by []*regexp.Regexp) string {
	out := map[string]bool{}
	for _, c := range cold {
		ex := c
		for _, re := range by {
			if m := re.FindStringSubmatch(c); m != nil && !under(m[1]+".", hot) {
				ex = m[1] + ".*"
				break
			}
		}
		out[ex] = true
	}
	names := make([]string, 0, len(out))
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(",-")
		b.WriteString(n)
	}
	return b.String()
}

func under(prefix string, names []string) bool {
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// coldIndices reads which of Signalith's indices are mounted from cold
// storage, and which are not.
func (m *Manager) coldIndices(ctx context.Context) (cold, hot []string, err error) {
	var settings map[string]struct {
		Settings map[string]any `json:"settings"`
	}
	// OpenSearch leaves out an index that has none of the settings asked
	// for, and only mounted ones have a store.type: index.uuid lists the
	// rest.
	err = m.Client.Do(ctx, http.MethodGet, "/"+Indices(m.Prefix)+"/_settings/index.store.type,index.uuid?flat_settings=true&expand_wildcards=open,closed&ignore_unavailable=true&allow_no_indices=true", nil, &settings)
	if notFound(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for name, s := range settings {
		if fmt.Sprint(s.Settings["index.store.type"]) == "remote_snapshot" {
			cold = append(cold, name)
		} else {
			hot = append(hot, name)
		}
	}
	sort.Strings(cold)
	sort.Strings(hot)
	return cold, hot, nil
}

// indices is the policy's indices expression as things are now: every
// index of Signalith's but the mounted ones.
func (m *Manager) indices(ctx context.Context) (string, error) {
	cold, hot, err := m.coldIndices(ctx)
	if err != nil {
		return "", err
	}
	expr, all := IndicesLeavingOut(m.Prefix, cold, hot)
	m.mu.Lock()
	warn := !all && !m.tooMany
	m.tooMany = !all
	m.mu.Unlock()
	if warn {
		m.log().Warn("too many indices mounted from cold storage to leave out of the scheduled snapshots: they are snapshotted empty, and a restore of those snapshots needs the cold repository's snapshots too",
			"policy", PolicyName(m.Prefix), "cold", len(cold))
	}
	return expr, nil
}
