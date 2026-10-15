package main

import (
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
	if !c.ArchiveEncryption() {
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
