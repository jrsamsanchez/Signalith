// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/archivecrypt"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Archive files are encrypted (internal/archivecrypt) with a key of their
// own, which is kept in the file encrypted with this server's master key
// and, on servers that share their settings, with the cluster key too, so
// that any server of the cluster can read any archive. Archives are read
// with every key this server has: the master key, the previous one kept
// after a rotation, and the cluster keys in its state folder.

// manifestMACField is what archive manifests are authenticated as.
const manifestMACField = "retention.archive_manifest"

// archiveCrypto makes a encrypt the archives it writes, unless
// retention.encrypt_archives is false, and read encrypted ones. cluster,
// when set, gives the cluster key in use now, nil when there is none.
func archiveCrypto(a *retention.Archive, c *config.Config, cluster func() *secrets.Key) {
	if a == nil {
		return
	}
	keys := c.Keyring()
	store := shared.KeyStore{Dir: c.StateDir(), Master: keys}
	a.Unseal = func(r io.Reader) (io.Reader, error) {
		openers := []secrets.Opener{keys}
		if cluster != nil {
			if k := cluster(); k != nil {
				openers = append(openers, k)
			}
		}
		// Cluster keys this server joined with earlier, still kept.
		if saved, err := store.ClusterKeys(); err == nil {
			for _, k := range saved {
				openers = append(openers, k.SecretsKey())
			}
		}
		return archivecrypt.Unseal(r, secrets.Chain(openers...))
	}
	// Manifests are authenticated with the same keys, so that a manifest
	// cannot be rewritten to call an encrypted archive plain.
	encrypt := c.ArchiveEncryption()
	a.MAC = func(msg []byte) ([]string, error) {
		var macs []string
		tag, err := keys.MAC(manifestMACField, msg)
		switch {
		case err == nil:
			macs = append(macs, tag)
		case encrypt:
			// Seal needs the master key too.
			return nil, err
		}
		if cluster != nil {
			if k := cluster(); k != nil {
				macs = append(macs, k.MAC(manifestMACField, msg))
			}
		}
		return macs, nil
	}
	a.Authenticate = func(msg []byte, macs []string) (bool, error) {
		checkers := []interface {
			CheckMAC(field string, msg []byte, tag string) error
		}{keys}
		if cluster != nil {
			if k := cluster(); k != nil {
				checkers = append(checkers, k)
			}
		}
		if saved, err := store.ClusterKeys(); err == nil {
			for _, k := range saved {
				checkers = append(checkers, k.SecretsKey())
			}
		}
		ok := false
		for _, tag := range macs {
			for _, ch := range checkers {
				err := ch.CheckMAC(manifestMACField, msg, tag)
				if err == nil {
					ok = true
					break
				}
				if !errors.Is(err, secrets.ErrMACKey) {
					return false, err
				}
			}
		}
		return ok, nil
	}
	a.RequireAuthenticated = encrypt
	a.AllowUnauthenticated = c.Retention.AllowUnauthenticatedArchives
	legacy := legacyArchivesFile(c, a.Dir)
	a.Legacy = func(m retention.Manifest) bool { return legacyArchive(legacy, m) }
	if !encrypt {
		return
	}
	a.Encryption = archivecrypt.Scheme
	a.Seal = func(w io.Writer) (io.WriteCloser, []string, error) {
		wrappers := []archivecrypt.Wrapper{keys}
		if cluster != nil {
			if k := cluster(); k != nil {
				wrappers = append(wrappers, k)
			}
		}
		return archivecrypt.Seal(w, wrappers...)
	}
}

// clusterKey is the cluster key in use now, nil when this server has
// none.
func (r *runner) clusterKey() *secrets.Key {
	if r.shared == nil {
		return nil
	}
	if k := r.shared.Hub().Keys().Active(); k != nil {
		return k.SecretsKey()
	}
	return nil
}

// archivesNeedKey refuses when an archive in the archive folder was
// encrypted with the master key kid alone, so removing that key would
// make it unreadable. Archives also encrypted with a cluster key are
// left out: the cluster key still opens them.
func archivesNeedKey(c *config.Config, kid, file string) error {
	// The manifests are read as they are, whether or not their data files
	// are still beside them.
	dir := c.ArchiveDir()
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("the previous master key was not removed: the archive folder %s cannot be read to check whether archives need it: %w", dir, err)
	}
	var need []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m retention.Manifest
		if json.Unmarshal(b, &m) != nil || m.Format != retention.ArchiveFormat || m.Encryption == "" || m.KID == "" {
			continue
		}
		if ids := strings.Split(m.KID, ","); !slices.ContainsFunc(ids, func(id string) bool { return id != kid }) {
			need = append(need, m.ID)
		}
	}
	slices.Sort(need)
	if len(need) == 0 {
		return nil
	}
	names := need
	if len(names) > 5 {
		names = append(slices.Clone(names[:5]), fmt.Sprintf("and %d more", len(need)-5))
	}
	return fmt.Errorf("the previous master key was not removed: %d archived %s in %s %s encrypted with it and would no longer open: %s. "+
		"Keep the previous key as long as you keep those archives (move its file, %s, only together with a backup of them)",
		len(need), plural(len(need), "day", "days"), dir, plural(len(need), "is", "are"), strings.Join(names, ", "), file)
}

// Encrypted archives written before manifests had MACs (0.3.0 to 0.4.1)
// have none, and the encryption of their files names no index or day, so
// a MAC is what stops one day's archive standing in for another's
// (CRYPTO-01). So that upgrading keeps them readable without an override,
// the server lists them the first time this version starts, in its state
// folder (which the archive folder's owner cannot write): each such
// archive's ID and checksum. A manifest without a MAC is then accepted
// only when it is on that list with the same checksum; any other needs
// retention.allow_unauthenticated_archives.

// legacyArchiveList is the file legacyArchivesFile names.
type legacyArchiveList struct {
	Format int    `json:"format"`
	Dir    string `json:"dir"`
	// Manifests maps an archive ID to its file's SHA-256.
	Manifests map[string]string `json:"manifests"`
}

// legacyArchivesFile is the list of an archive folder's encrypted
// archives without MACs, in the state folder.
func legacyArchivesFile(c *config.Config, dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(c.StateDir(), "archive-legacy-"+hex.EncodeToString(sum[:6])+".json")
}

// legacyArchive reports whether m is on the list in file.
func legacyArchive(file string, m retention.Manifest) bool {
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	var l legacyArchiveList
	if json.Unmarshal(data, &l) != nil {
		return false
	}
	sum, ok := l.Manifests[m.ID]
	return ok && m.SHA256 != "" && sum == m.SHA256
}

// recordLegacyArchives writes the list of a's encrypted archives without
// MACs, once: the first time a server of this version starts with this
// archive folder. Later archives always have MACs.
func recordLegacyArchives(a *retention.Archive, c *config.Config) error {
	if a == nil || a.Dir == "" {
		return nil
	}
	file := legacyArchivesFile(c, a.Dir)
	if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	list, _, err := a.ListFiles()
	if err != nil {
		// Try again at the next start rather than list nothing.
		return err
	}
	l := legacyArchiveList{Format: 1, Dir: a.Dir, Manifests: map[string]string{}}
	for _, m := range list {
		if m.Encryption != "" && len(m.MAC) == 0 {
			l.Manifests[m.ID] = m.SHA256
		}
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, werr := f.Write(append(data, '\n'))
	if err := f.Close(); werr == nil {
		werr = err
	}
	return werr
}
