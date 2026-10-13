package config

import (
	"errors"
	"io/fs"
	"os"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// SecretFile is a file that keeps passwords or keys.
type SecretFile struct {
	Path string
	// Reseal passes each stored value through a secrets.Reseal.
	Reseal func([]byte, secrets.Reseal) ([]byte, int, error)
	// Server is true for the files the server writes. It also encrypts
	// their plain values when it starts.
	Server bool
	// Replace is true for a file a link in place of is replaced rather
	// than followed, as the server does (see securefile.Replace).
	Replace bool
}

// SecretFiles lists the files with passwords or keys: signalith.yaml,
// which only the secrets commands and "signalith init" write, then the
// files the server keeps, the Settings page's settings.yaml among them.
// "signalith secrets" and the Security page both go by this list.
func (c *Config) SecretFiles() []SecretFile {
	return []SecretFile{
		{Path: c.Path(), Reseal: ResealFile},
		{Path: c.DirectoryFile(), Reseal: users.ResealDirectoryFile, Server: true},
		{Path: c.IntelFeedsFile(), Reseal: intel.ResealFeedsFile, Server: true},
		{Path: c.NotifyFile(), Reseal: notify.Reseal, Server: true},
		{Path: c.ResponseFile(), Reseal: respond.ResealFile, Server: true},
		{Path: c.SettingsFile(), Reseal: ResealSettingsFile, Server: true, Replace: true},
	}
}

// ListSecrets returns the values stored in the text of a file with
// reseal, its SecretFile.Reseal.
func ListSecrets(reseal func([]byte, secrets.Reseal) ([]byte, int, error), data []byte) ([]secrets.Stored, error) {
	var out []secrets.Stored
	_, _, err := reseal(data, func(s secrets.Stored) (string, error) {
		out = append(out, s)
		return s.Value, nil
	})
	return out, err
}

// StoredSecret is one password or key kept in a file: which file, which
// setting, and whether it is plain text or encrypted with the master key
// in use, the previous one, or one that is not here. It never holds the
// value.
type StoredSecret struct {
	File    string
	Setting string // the field, such as opensearch.password
	Label   string // for people, such as "header X-OTX-API-KEY of feed otx"
	State   secrets.State
}

// SecretInventory lists the passwords and keys stored in SecretFiles.
// Values from environment variables are not stored, so they are not
// listed. A file that cannot be read is listed in errs, by path.
func (c *Config) SecretInventory() (list []StoredSecret, errs map[string]error) {
	keys := c.Keyring()
	for _, f := range c.SecretFiles() {
		data, err := os.ReadFile(f.Path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			if errs == nil {
				errs = map[string]error{}
			}
			errs[f.Path] = err
			continue
		}
		stored, err := ListSecrets(f.Reseal, data)
		if err != nil {
			if errs == nil {
				errs = map[string]error{}
			}
			errs[f.Path] = err
			continue
		}
		for _, s := range stored {
			st, _ := keys.Check(s.Field, s.Value)
			list = append(list, StoredSecret{File: f.Path, Setting: s.Field, Label: s.Label, State: st})
		}
	}
	return list, errs
}

// AddressSecretsInFile lists the passwords and keys written into
// addresses in signalith.yaml, where they cannot be encrypted, or nil
// when it cannot be read.
func (c *Config) AddressSecretsInFile() []AddressSecret {
	data, err := os.ReadFile(c.Path())
	if err != nil {
		return nil
	}
	return AddressSecrets(data)
}
