package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
)

// Level 5 keeps the cluster's one certificate authority in the shared
// settings (the tls document, internal/clustertls): every server issues
// its own HTTPS certificate from it, so an agent set up against one
// server trusts them all. A server whose version reads only the level below would
// keep a certificate authority of its own, so the level is raised once
// every server seen lately reads it, the same way as the levels before.
const LevelSharedTLS = 5

// ImportTLS is the name of the importer of the founder's certificate
// authority in cluster.import.done. It is recorded whether or not it
// published one: several servers with different certificate authorities
// leave the choice to an admin, and whether the tls document exists says
// whether one was chosen.
const ImportTLS = "tls"

// SharedTLS reports whether cluster certificate authority handling is on:
// the settings are shared, the cluster is at LevelSharedTLS and the tls
// importer ran. It does not say a certificate authority was chosen yet.
func (rt *Runtime) SharedTLS() bool {
	return rt.SharedSettings() && rt.sharedAt(LevelSharedTLS, ImportTLS)
}

// ErrNoCache: this server keeps no copy of the shared settings
// (cache.enc) now.
var ErrNoCache = errors.New("this server keeps no copy of the shared settings (cache.enc) now")

// FlushCacheBody writes cache.enc now, reads it back, and returns the body
// of the document id as the copy holds it: ErrNoCache when this server
// keeps no copy, an error wrapping fs.ErrNotExist when the copy does not
// hold the document. The cluster's certificate authority key leaves the
// founder's disk only once the copy is known to hold it.
func (rt *Runtime) FlushCacheBody(id string) (string, error) {
	rt.mu.Lock()
	w := rt.cacheWriter
	rt.mu.Unlock()
	if w == nil {
		return "", ErrNoCache
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	d, err := w.cache.Read(rt.clock.Now())
	if err != nil {
		return "", err
	}
	for _, doc := range d.Docs {
		if doc.ID != id {
			continue
		}
		var e Envelope
		if err := json.Unmarshal(doc.Source, &e); err != nil {
			return "", fmt.Errorf("the copy of %s cannot be read: %w", id, err)
		}
		if e.Deleted {
			break
		}
		return e.Body, nil
	}
	return "", fmt.Errorf("the copy of the shared settings does not hold %s: %w", id, fs.ErrNotExist)
}
