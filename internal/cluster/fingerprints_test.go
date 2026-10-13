package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
)

// Servers without notifications hash their files as servers from before
// notifications did, so a mixed-version cluster still agrees; servers
// whose notification channels differ are told so.
func TestFingerprintsNotify(t *testing.T) {
	f := Fingerprints{Retention: "r", Feeds: "f", Detections: "d"}
	h := sha256.New()
	for _, p := range []string{"r", "f", "d", ""} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	if want := "sha256:" + hex.EncodeToString(h.Sum(nil)); f.Combined() != want {
		t.Errorf("combined without notifications changed: %s", f.Combined())
	}
	g := f
	g.Notify = "n"
	if g.Combined() == f.Combined() {
		t.Error("notifications do not count")
	}
	if d := f.Differ(g); !slices.Equal(d, []string{"notification channels"}) {
		t.Errorf("differ %v", d)
	}
	if msg := fixFiles([]string{"notification channels"}, "siem-b", "siem-a"); msg != "Make siem-b's notification channels and rules (notifications.yaml in the lookups folder) the same as siem-a's, then restart siem-b." {
		t.Errorf("fix %q", msg)
	}
}

// Playbooks count only when a server has some, like notifications.
func TestFingerprintsPlaybooks(t *testing.T) {
	f := Fingerprints{Retention: "r", Feeds: "f", Detections: "d", Notify: "n"}
	g := f
	g.Playbooks = "p"
	if g.Combined() == f.Combined() {
		t.Error("playbooks do not count")
	}
	if d := f.Differ(g); !slices.Equal(d, []string{"playbooks"}) {
		t.Errorf("differ %v", d)
	}
	if msg := fixFiles([]string{"playbooks"}, "siem-b", "siem-a"); msg != "Make siem-b's playbooks (playbooks.yaml in the lookups folder) the same as siem-a's, then restart siem-b." {
		t.Errorf("fix %q", msg)
	}
}
