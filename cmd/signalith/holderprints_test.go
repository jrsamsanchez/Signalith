// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster"
)

// Without the shared settings in use here, or a cluster to compare with,
// the holder's fingerprints stay as they are.
func TestHolderFingerprintsWithoutSharedSettings(t *testing.T) {
	fp := cluster.Fingerprints{Retention: "sha256:r", Feeds: "sha256:f", Detections: "sha256:d"}
	if got := holderFingerprints(fp, "n_a", nil, true); got != fp {
		t.Errorf("no runtime: %+v", got)
	}
	if got := holderFingerprints(fp, "", nil, false); got != fp {
		t.Errorf("not shared: %+v", got)
	}
}

// Once this server takes its files from the shared settings, the
// founder's own retention and feed fingerprints count as the shared ones,
// since it moved those files there; another holder's do not.
func TestHolderFingerprintsOfTheFounder(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, name: "siem-a"})
	eventually(t, "the content is shared", rs.r.sharedContent.on.Load)
	rt := rs.r.shared
	b, ok := rt.Cluster().Get()
	if !ok || b.Import.By == "" {
		t.Fatalf("cluster document %+v", b)
	}
	s := cluster.SharedFingerprint(rt.Status().ClusterID)
	own := cluster.Fingerprints{Retention: "sha256:r", Feeds: "sha256:f", Archives: "sha256:a"}
	got := holderFingerprints(own, b.Import.By, rt, true)
	if got.Retention != s || got.Feeds != s || got.Archives != own.Archives {
		t.Errorf("the founder's: %+v", got)
	}
	if got := holderFingerprints(own, "n_other", rt, true); got != own {
		t.Errorf("another holder's: %+v", got)
	}
	if got := holderFingerprints(own, b.Import.By, rt, false); got != own {
		t.Errorf("before this server switched: %+v", got)
	}
}
