package clusterauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Sources of the directory sign-in settings, in DirectoryBody.From.
const (
	FromYAML   = "yaml"
	FromEnv    = "env"
	FromPage   = "page"
	FromImport = "import"
)

// From says where the shared directory sign-in settings came from: the
// Users page, a server's signalith.yaml or environment (applied when it
// changed) or the founder's files, on which server and when.
type From struct {
	Source string `json:"source"`
	Node   string `json:"node,omitempty"`
	At     string `json:"at,omitempty"`
}

// DirectoryBody is the body of <prefix>_config/directory: the directory
// sign-in settings, and the service account password sealed with the
// cluster key for the connection the settings make (users.BindField), so
// it cannot be opened once moved to settings that would send it
// elsewhere.
type DirectoryBody struct {
	// Settings leaves the password out (it is not written as JSON).
	Settings     users.LDAPSettings `json:"settings"`
	BindPassword string             `json:"bind_password,omitempty"`
	From         *From              `json:"from,omitempty"`
	shared.Extra `json:"-"`
}

// DirectoryBackend keeps the directory sign-in settings of a
// users.Directory in the shared settings.
type DirectoryBackend struct {
	Docs *Docs
	// Node is this server's name, for From.
	Node string
	Now  func() time.Time

	mu sync.Mutex
	// open is the settings last opened, for the copy at etag.
	open struct {
		etag     string
		kids     string
		settings users.LDAPSettings
		problem  string
	}
}

var _ users.DirectoryBackend = (*DirectoryBackend)(nil)

func (b *DirectoryBackend) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// defaults are the settings before any were saved: Active Directory's,
// switched off.
func defaults() users.LDAPSettings {
	off := false
	s := users.Preset(users.TypeActiveDirectory)
	s.Enabled = &off
	s.Normalize()
	return s
}

// opener opens values sealed with any of the cluster keys this server
// has.
func opener(keys *shared.KeySet) secrets.Opener {
	var out []secrets.Opener
	if keys != nil {
		for _, id := range keys.IDs() {
			if k := keys.Get(id); k != nil {
				out = append(out, k.SecretsKey())
			}
		}
	}
	return secrets.Chain(out...)
}

// passwordProblem is what Problem says when the service account password
// cannot be opened.
const passwordProblem = "Directory sign-in cannot search for users until the service account password is entered again (open Users, then Directory sign-in): "

// Load returns the shared settings with the service account password. A
// password that cannot be opened (sealed with another cluster key, or for
// a connection the settings no longer make) is left out, and the problem
// says to enter it again.
func (b *DirectoryBackend) Load() (users.LDAPSettings, bool, string) {
	doc := b.Docs.Directory()
	body, ok := doc.Get()
	if !ok {
		return defaults(), false, ""
	}
	etag := doc.ETag()
	keys := b.Docs.keys()
	kids := ""
	if keys != nil {
		for _, id := range keys.IDs() {
			kids += id + ","
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open.etag == etag && b.open.kids == kids && etag != "" {
		return b.open.settings.Clone(), true, b.open.problem
	}
	s := body.Settings.Clone()
	s.BindPassword = ""
	problem := ""
	if body.BindPassword != "" {
		pw, err := opener(keys).Open(users.BindField(s), body.BindPassword)
		if err != nil {
			problem = passwordProblem + err.Error()
		} else {
			s.BindPassword = pw
		}
	}
	s.Normalize()
	b.open.etag, b.open.kids, b.open.settings, b.open.problem = etag, kids, s.Clone(), problem
	return s, true, problem
}

// seal returns the body of settings s from source, with the password
// sealed for the connection s makes.
func (b *DirectoryBackend) seal(s users.LDAPSettings, source string, old *DirectoryBody) (*DirectoryBody, error) {
	k := b.Docs.key()
	if k == nil {
		return nil, errors.New("this server has no cluster key")
	}
	pw := s.BindPassword
	s = s.Clone()
	s.BindPassword = ""
	sealed := ""
	if pw != "" {
		var err error
		if sealed, err = k.SecretsKey().Seal(users.BindField(s), pw); err != nil {
			return nil, err
		}
	}
	nb := &DirectoryBody{Settings: s, BindPassword: sealed,
		From: &From{Source: source, Node: b.Node, At: b.now().UTC().Format(time.RFC3339Nano)}}
	if old != nil {
		nb.Extra = old.Extra
	}
	return nb, nil
}

// Save stores settings saved on the Users page, read at etag when it is
// set (a *shared.StaleError naming who changed them since).
func (b *DirectoryBackend) Save(ctx context.Context, by, etag string, s users.LDAPSettings) error {
	return b.save(ctx, by, etag, s, FromPage)
}

// SaveFrom stores settings that came from source (FromYAML or
// FromImport), over whatever is there.
func (b *DirectoryBackend) SaveFrom(ctx context.Context, by string, s users.LDAPSettings, source string) error {
	return b.save(ctx, by, "", s, source)
}

func (b *DirectoryBackend) save(ctx context.Context, by, etag string, s users.LDAPSettings, source string) error {
	doc := b.Docs.Directory()
	change := func(cur *DirectoryBody) error {
		nb, err := b.seal(s, source, cur)
		if err != nil {
			return err
		}
		*cur = *nb
		return nil
	}
	var err error
	if etag != "" {
		_, err = doc.MutateIf(ctx, by, etag, change)
	} else {
		_, err = doc.Mutate(ctx, by, change)
	}
	return err
}

// ErrOtherConnection refuses a service account password meant for one
// directory connection while the shared settings name another.
var ErrOtherConnection = errors.New("the shared directory sign-in settings connect to another server or as another account " +
	"than this server's signalith.yaml, so the password is not used with them")

// SetBindPassword seals a new service account password for the shared
// settings as they are, as SIGNALITH_LDAP_BIND_PASSWORD gives when it
// changed. There must be settings, and they must connect as for (the
// server, bind account and TLS settings users.SameConnection compares):
// otherwise ErrOtherConnection, so the password never goes to a
// directory server someone changed the shared settings to.
func (b *DirectoryBackend) SetBindPassword(ctx context.Context, by, password, source string, conn users.LDAPSettings) error {
	_, err := b.Docs.Directory().Mutate(ctx, by, func(cur *DirectoryBody) error {
		if cur.Settings.URL == "" {
			return errors.New("there are no directory sign-in settings to set the password of")
		}
		if !users.SameConnection(conn, cur.Settings) {
			return ErrOtherConnection
		}
		s := cur.Settings.Clone()
		s.BindPassword = password
		nb, err := b.seal(s, source, cur)
		if err != nil {
			return err
		}
		*cur = *nb
		return nil
	})
	return err
}

// Revision is the revision of the shared settings, the same on every
// server, so the Basic credentials every server remembers for directory
// users are forgotten together when the settings change.
func (b *DirectoryBackend) Revision() uint64 {
	_, _, rev := b.Docs.Directory().Updated()
	return uint64(max(rev, 0))
}

// ETag is the version of the shared settings in use.
func (b *DirectoryBackend) ETag() string { return b.Docs.Directory().ETag() }

// From says where the settings in use came from.
func (b *DirectoryBackend) From() users.DirectoryFrom {
	body, ok := b.Docs.Directory().Get()
	if !ok || body.From == nil {
		return users.DirectoryFrom{}
	}
	f := users.DirectoryFrom{Source: body.From.Source, Node: body.From.Node}
	if at, err := time.Parse(time.RFC3339Nano, body.From.At); err == nil {
		f.At = at
	}
	return f
}
