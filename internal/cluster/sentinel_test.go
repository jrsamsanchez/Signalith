package cluster

import (
	"strings"
	"testing"
)

// U23: two members share the sentinel, so they agree on retention and
// feeds; a server that keeps them in its own files (an older version, or
// not part of the cluster yet) never agrees with a member, and the reason
// says so.
func TestSharedSentinelFingerprint(t *testing.T) {
	member := Fingerprints{Retention: SharedFingerprint("c_1"), Feeds: SharedFingerprint("c_1"), Detections: "sha256:d"}
	other := member
	if d := member.Differ(other); len(d) != 0 || member.Combined() != other.Combined() {
		t.Fatalf("two members differ: %v", d)
	}
	legacy := Fingerprints{Retention: "sha256:r", Feeds: "sha256:f", Detections: "sha256:d"}
	d := legacy.Differ(member)
	if legacy.Combined() == member.Combined() || len(d) != 2 {
		t.Fatalf("a server with its own files agrees with a member: %v", d)
	}
	for _, s := range d {
		if !strings.Contains(s, "keeps them in its own files") {
			t.Errorf("reason %q does not say why", s)
		}
	}
	// Another cluster's members differ, and that is not about files.
	if d := member.Differ(Fingerprints{Retention: SharedFingerprint("c_2"), Feeds: SharedFingerprint("c_1"), Detections: "sha256:d"}); len(d) != 1 || strings.Contains(d[0], "own files") {
		t.Errorf("another cluster: %v", d)
	}
}
