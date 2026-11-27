// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"errors"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// A document not read yet has no ETag and no one who changed it.
func TestDocBeforeItIsRead(t *testing.T) {
	e := newEnv(t)
	h, _ := e.hub("siem-a")
	d := NewDoc[testBody](h, "users", "users", 1)
	if d.ETag() != "" {
		t.Errorf("ETag = %q", d.ETag())
	}
	if by, at, rev := d.Updated(); by != (By{}) || at != "" || rev != 0 {
		t.Errorf("Updated = %+v %q %d", by, at, rev)
	}
	// An entry from before the index had an id is tagged by its version.
	en := &entry{ver: store.Version{SeqNo: 3, PrimaryTerm: 1}}
	if en.etag() != en.ver.String() {
		t.Errorf("etag = %q", en.etag())
	}
}

// failingSealer cannot seal or open.
type failingSealer struct{}

func (failingSealer) Seal(string, string) (string, error) { return "", errors.New("no master key") }
func (failingSealer) Open(string, string) (string, error) { return "", errors.New("no master key") }

// Without a master key to seal under, no key is kept.
func TestKeyStoreWithoutAMasterKey(t *testing.T) {
	ks := KeyStore{Dir: t.TempDir(), Master: failingSealer{}}
	if _, err := ks.NodeKey(); err == nil {
		t.Error("a node key kept without a master key")
	}
	k, _ := NewClusterKey()
	if err := ks.SaveClusterKey(k); err == nil {
		t.Error("a cluster key kept without a master key")
	}
}
