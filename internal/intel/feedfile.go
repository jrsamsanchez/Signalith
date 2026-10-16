package intel

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"gopkg.in/yaml.v3"
)

// The feeds added on the Threat intel page are kept in a YAML file
// (default intel_feeds.yaml in the lookups folder), next to the status
// file. Signalith rewrites it whole on each change, through a temporary
// file and a rename, so a crash never leaves half a file. It holds API
// keys, so only the server's own account may read it, and each password
// and header value is encrypted with the master key (package secrets) for
// its feed and setting (see FeedsFileField). One that cannot be decrypted
// is kept as it is, and the feed shows a problem until it is entered
// again.

// feedsFile is the file's content.
type feedsFile struct {
	Feeds []FeedSpec `yaml:"feeds"`
	// Kept lists deleted feeds whose indicators were kept to age out, so
	// a restart does not remove them early.
	Kept []KeptFeed `yaml:"kept,omitempty"`
}

// KeptFeed is a deleted feed whose indicators stay until they expire.
type KeptFeed struct {
	Name  string    `yaml:"name"`
	Until time.Time `yaml:"until"`
}

const feedsFileHeader = `# Threat intel feeds added on the Threat intel page of Signalith.
# Signalith rewrites this file when feeds change there; to change a feed,
# use the page. It holds API keys and passwords, so keep it private.
# Feeds in signalith.yaml (intel.feeds) are not listed here.
`

// FileError is a feeds file that cannot be read.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string {
	return fmt.Sprintf("The feeds file %s could not be read (%v). Fix or delete it, then reload this page.", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// FeedsFileField is the setting a secret in the feeds file is encrypted
// for: part is password or headers.<header name>, as in
// intel_feeds[otx].headers.X-OTX-API-KEY. A value copied to another feed
// or setting cannot be decrypted there.
func FeedsFileField(feed, part string) string { return "intel_feeds[" + feed + "]." + part }

// eachSecret replaces the password and every header value of s with what
// fn returns for it, headers in name order. part names the secret as
// FeedsFileField does, label for people. It changes s.Headers in place,
// so call it on a clone of a spec that is shared.
func (s *FeedSpec) eachSecret(fn func(part, label, v string) (string, error)) error {
	if s.Password != "" {
		v, err := fn("password", "password", s.Password)
		if err != nil {
			return err
		}
		s.Password = v
	}
	names := make([]string, 0, len(s.Headers))
	for k := range s.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if s.Headers[k] == "" {
			continue
		}
		v, err := fn("headers."+k, "header "+k, s.Headers[k])
		if err != nil {
			return err
		}
		s.Headers[k] = v
	}
	return nil
}

// undecrypted lists the secrets of s still encrypted after loading,
// because they could not be decrypted.
func (s FeedSpec) undecrypted() []string {
	var out []string
	if secrets.IsSealed(s.Password) {
		out = append(out, "password")
	}
	names := make([]string, 0, len(s.Headers))
	for k, v := range s.Headers {
		if secrets.IsSealed(v) {
			names = append(names, "header "+k)
		}
	}
	sort.Strings(names)
	return append(out, names...)
}

// ResealFeedsFile passes every password and header value in the feeds
// file text data through fn and returns the file with what fn returned,
// and how many values that changed. The file is written again whole, as
// Signalith always writes it.
func ResealFeedsFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	var ff feedsFile
	if err := yaml.Unmarshal(data, &ff); err != nil {
		return nil, 0, fmt.Errorf("not valid YAML: %w", err)
	}
	n := 0
	for i := range ff.Feeds {
		s := &ff.Feeds[i]
		err := s.eachSecret(func(part, label, v string) (string, error) {
			nv, err := fn(secrets.Stored{Field: FeedsFileField(s.Name, part), Label: "feeds[" + s.Name + "] " + label, Value: v})
			if err == nil && nv != v {
				n++
			}
			return nv, err
		})
		if err != nil {
			return nil, 0, err
		}
	}
	if n == 0 {
		return data, 0, nil
	}
	out, err := encodeFeedsFile(ff)
	return out, n, err
}

// encodeFeedsFile writes the feeds file's text.
func encodeFeedsFile(ff feedsFile) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(feedsFileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(ff); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
