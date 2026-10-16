package vulnscan

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Scan logins let OpenVAS sign in to the hosts it scans, so that it can
// check the installed packages and patches from inside instead of only
// what the network shows: a credentialed scan. A login is SSH (Linux and
// other Unix systems, a private key or a password) or SMB (Windows, a
// password). Networks name the logins to use, by ID.
//
// The private keys and passwords are encrypted (Keys) before they are
// stored, bound to the login they belong to, and are never sent back to
// a browser or written to a log: the API says only whether one is set.
// They are decrypted only on the server that runs an OpenVAS scan, just
// before the scan, and handed to OpenVAS for that scan alone; the copy
// OpenVAS keeps is removed with the scan's target when the scan ends.

// Login kinds.
const (
	LoginSSH = "ssh"
	LoginSMB = "smb"
)

// SSH sign-in methods.
const (
	AuthKey      = "key"
	AuthPassword = "password"
)

const (
	maxLogins      = 50
	maxSecretLen   = 16 << 10
	maxPasswordLen = 256
	credentialsID  = "credentials"
	kindLogins     = "credentials"
)

// loginUserRE is a user name OpenVAS can sign in with: letters, digits
// and . _ - @ $, with a DOMAIN\ in front for Windows.
var loginUserRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,63}\\)?[A-Za-z0-9._@$-]{1,128}$`)

// Keys encrypts the secrets of scan logins so that every server can
// decrypt them: in a cluster, with the cluster key.
type Keys interface {
	Seal(field, plain string) (string, error)
	Open(field, stored string) (string, error)
}

// Credential is a scan login as stored: Secret and Passphrase are
// encrypted.
type Credential struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Username string `json:"username"`
	// Auth is key or password, for SSH; SMB is always a password.
	Auth string `json:"auth"`
	// Port is the SSH port, 22 unless set.
	Port int `json:"port,omitempty"`
	// Secret is the private key (PEM) or the password, encrypted.
	Secret string `json:"secret"`
	// Passphrase is the private key's passphrase, encrypted, if it has
	// one.
	Passphrase string    `json:"passphrase,omitempty"`
	UpdatedBy  string    `json:"updated_by,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitzero"`
}

// LoginInput is a login an admin saves. An empty Secret keeps the saved
// one, as does an empty Passphrase unless ClearPassphrase is set.
type LoginInput struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Username        string `json:"username"`
	Auth            string `json:"auth"`
	Port            int    `json:"port"`
	Secret          string `json:"secret"`
	Passphrase      string `json:"passphrase"`
	ClearPassphrase bool   `json:"clear_passphrase"`
}

// LoginView is a login as the API shows it: never its secrets.
type LoginView struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Username      string    `json:"username"`
	Auth          string    `json:"auth"`
	Port          int       `json:"port,omitempty"`
	HasPassphrase bool      `json:"has_passphrase"`
	UpdatedBy     string    `json:"updated_by,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitzero"`
	// Readable is false when this server cannot decrypt the secret, as
	// after it was saved on a server with another key: enter it again.
	Readable bool `json:"readable"`
}

// Login is a login decrypted for one scan.
type Login struct {
	Kind, Username, Auth string
	Port                 int
	Secret, Passphrase   string
}

// String keeps the secrets out of logs and error messages.
func (l *Login) String() string {
	if l == nil {
		return "<no login>"
	}
	return l.Kind + " login " + l.Username
}

// LogValue keeps the secrets out of structured logs too.
func (l *Login) LogValue() slog.Value { return slog.StringValue(l.String()) }

type loginsDoc struct {
	Kind   string       `json:"kind"`
	Logins []Credential `json:"logins"`
}

func secretField(id, part string) string { return "vulns.credentials[" + id + "]." + part }

// View is c without its secrets; keys, when set, says whether they can
// be decrypted here.
func (c Credential) View(keys Keys) LoginView {
	v := LoginView{ID: c.ID, Name: c.Name, Kind: c.Kind, Username: c.Username, Auth: c.Auth, Port: c.Port,
		HasPassphrase: c.Passphrase != "", UpdatedBy: c.UpdatedBy, UpdatedAt: c.UpdatedAt}
	if keys != nil {
		_, err := keys.Open(secretField(c.ID, "secret"), c.Secret)
		v.Readable = err == nil && secrets.IsSealed(c.Secret)
	}
	return v
}

// Logins lists the scan logins, secrets encrypted.
func (s *Store) Logins(ctx context.Context) ([]Credential, store.Version, error) {
	src, v, found, err := s.Docs.Get(ctx, s.Index, credentialsID)
	if err != nil || !found {
		return nil, v, err
	}
	var d loginsDoc
	if err := json.Unmarshal(src, &d); err != nil {
		return nil, v, fmt.Errorf("the saved scan logins cannot be read: %w", err)
	}
	return d.Logins, v, nil
}

// ErrNoKeys is returned when scan logins cannot be saved because this
// server has no key to encrypt them with.
var ErrNoKeys = errors.New("scan logins cannot be saved: this server has no encryption key for them")

// SaveLogin adds or changes a scan login, encrypting its secrets, and
// returns it as stored.
func (s *Store) SaveLogin(ctx context.Context, in LoginInput, by string) (Credential, error) {
	if s.Keys == nil {
		return Credential{}, ErrNoKeys
	}
	for range 3 {
		list, v, err := s.Logins(ctx)
		if err != nil {
			return Credential{}, err
		}
		i := slices.IndexFunc(list, func(c Credential) bool { return c.ID == in.ID })
		var prev *Credential
		if i >= 0 {
			prev = &list[i]
		}
		c, err := s.buildLogin(in, prev, list)
		if err != nil {
			return Credential{}, err
		}
		c.UpdatedBy, c.UpdatedAt = by, s.now().UTC()
		next := slices.Clone(list)
		if i >= 0 {
			next[i] = c
		} else {
			if len(next) >= maxLogins {
				return Credential{}, inputErrorf("at most %d scan logins", maxLogins)
			}
			next = append(next, c)
		}
		if err := s.putLogins(ctx, next, v); err != nil {
			if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) {
				continue
			}
			return Credential{}, err
		}
		return c, nil
	}
	return Credential{}, errors.New("someone else changed the scan logins at the same time; try again")
}

// DeleteLogin removes a scan login, unless a network uses it.
func (s *Store) DeleteLogin(ctx context.Context, id string) (Credential, error) {
	set, err := s.CachedSettings(ctx)
	if err != nil {
		return Credential{}, err
	}
	for range 3 {
		list, v, err := s.Logins(ctx)
		if err != nil {
			return Credential{}, err
		}
		i := slices.IndexFunc(list, func(c Credential) bool { return c.ID == id })
		if i < 0 {
			return Credential{}, store.ErrNotFound
		}
		if used := LoginUsers(set, id); len(used) > 0 {
			return Credential{}, inputErrorf("%s is used by %s: pick another login for %s first", list[i].Name, strings.Join(used, ", "), plural(len(used), "that network", "those networks"))
		}
		gone := list[i]
		if err := s.putLogins(ctx, slices.Delete(slices.Clone(list), i, i+1), v); err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return Credential{}, err
		}
		return gone, nil
	}
	return Credential{}, errors.New("someone else changed the scan logins at the same time; try again")
}

func (s *Store) putLogins(ctx context.Context, list []Credential, v store.Version) error {
	doc := loginsDoc{Kind: kindLogins, Logins: list}
	if v.IsZero() {
		_, err := s.Docs.Create(ctx, s.Index, credentialsID, doc, true)
		return err
	}
	_, err := s.Docs.PutIf(ctx, s.Index, credentialsID, doc, v, true)
	return err
}

// LoginUsers names the networks that use the login id.
func LoginUsers(set Settings, id string) []string {
	var out []string
	for _, t := range set.Targets {
		if t.SSHLogin == id || t.SMBLogin == id {
			out = append(out, t.Name)
		}
	}
	return out
}

// buildLogin checks in and makes the login to store, keeping prev's
// secrets where in leaves them empty.
func (s *Store) buildLogin(in LoginInput, prev *Credential, list []Credential) (Credential, error) {
	c := Credential{ID: strings.TrimSpace(in.ID), Name: strings.TrimSpace(in.Name), Kind: in.Kind,
		Username: strings.TrimSpace(in.Username), Auth: in.Auth, Port: in.Port}
	if !idRE.MatchString(c.ID) {
		return c, inputErrorf("the login has no valid ID; reload the page and add it again")
	}
	if c.Name == "" || len(c.Name) > maxNameLen || strings.ContainsAny(c.Name, "\x00\r\n") {
		return c, inputErrorf("give the login a name of up to %d characters, such as Linux servers", maxNameLen)
	}
	for _, o := range list {
		if o.ID != c.ID && strings.EqualFold(o.Name, c.Name) {
			return c, inputErrorf("another login is named %q; give each its own name", c.Name)
		}
	}
	if prev != nil && prev.Kind != c.Kind {
		return c, inputErrorf("%s: a login cannot change between SSH and Windows; add a new one instead", c.Name)
	}
	if !loginUserRE.MatchString(c.Username) {
		return c, inputErrorf("%s: the user name may have letters, digits and . _ - @ $, and DOMAIN\\ in front for Windows", c.Name)
	}
	switch c.Kind {
	case LoginSSH:
		if strings.Contains(c.Username, `\`) {
			return c, inputErrorf("%s: an SSH user name has no DOMAIN\\ in front", c.Name)
		}
		if c.Port == 0 {
			c.Port = 22
		}
		if c.Port < 1 || c.Port > 65535 {
			return c, inputErrorf("%s: the SSH port must be from 1 to 65535", c.Name)
		}
		if c.Auth != AuthKey && c.Auth != AuthPassword {
			return c, inputErrorf("%s: sign in with a key or a password", c.Name)
		}
	case LoginSMB:
		c.Auth, c.Port = AuthPassword, 0
	default:
		return c, inputErrorf("%s: a login is SSH (Linux) or SMB (Windows)", c.Name)
	}
	if prev != nil && prev.Auth != c.Auth && in.Secret == "" {
		return c, inputErrorf("%s: enter the %s, as it now signs in with one", c.Name, secretWord(c.Auth))
	}
	field := secretField(c.ID, "secret")
	phraseField := secretField(c.ID, "passphrase")
	if in.Secret == "" && prev == nil {
		return c, inputErrorf("%s: enter the %s", c.Name, secretWord(c.Auth))
	}
	if c.Auth != AuthKey && in.Passphrase != "" {
		return c, inputErrorf("%s: only a private key has a passphrase", c.Name)
	}
	switch {
	case in.Secret != "":
		// A new key comes with its own passphrase, or none.
		if err := checkSecret(c, in.Secret, in.Passphrase); err != nil {
			return c, err
		}
		sealed, err := s.Keys.Seal(field, in.Secret)
		if err != nil {
			return c, err
		}
		c.Secret = sealed
		if in.Passphrase != "" {
			if c.Passphrase, err = s.Keys.Seal(phraseField, in.Passphrase); err != nil {
				return c, err
			}
		}
	default:
		c.Secret, c.Passphrase = prev.Secret, prev.Passphrase
		if c.Auth != AuthKey || (in.Passphrase == "" && !in.ClearPassphrase) {
			break
		}
		// A new passphrase, or none, must still open the saved key.
		key, err := s.Keys.Open(field, prev.Secret)
		if err != nil {
			return c, inputErrorf("%s: the saved key cannot be decrypted on this server; enter it again", c.Name)
		}
		if err := checkSecret(c, key, in.Passphrase); err != nil {
			return c, err
		}
		c.Passphrase = ""
		if in.Passphrase != "" {
			if c.Passphrase, err = s.Keys.Seal(phraseField, in.Passphrase); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

func secretWord(auth string) string {
	if auth == AuthKey {
		return "private key"
	}
	return "password"
}

// checkSecret checks a private key (it must be one SSH reads, opened by
// phrase when it is protected) or a password.
func checkSecret(c Credential, secret, phrase string) error {
	if secrets.IsSealed(secret) {
		return inputErrorf("%s: paste the %s itself, not an encrypted value", c.Name, secretWord(c.Auth))
	}
	if len(secret) > maxSecretLen {
		return inputErrorf("%s: that is too long for a %s", c.Name, secretWord(c.Auth))
	}
	if c.Auth != AuthKey {
		if len(secret) > maxPasswordLen || strings.ContainsFunc(secret, func(r rune) bool { return r == 0 || r == '\n' || r == '\r' }) {
			return inputErrorf("%s: the password is longer than %d characters or has a line break", c.Name, maxPasswordLen)
		}
		return nil
	}
	if strings.Contains(secret, "PUBLIC KEY") || strings.HasPrefix(strings.TrimSpace(secret), "ssh-") {
		return inputErrorf("%s: that is the public key; paste the private key, which starts with -----BEGIN", c.Name)
	}
	var err error
	if phrase != "" {
		if _, plain := ssh.ParseRawPrivateKey([]byte(secret)); plain == nil {
			return inputErrorf("%s: the passphrase does not open the private key: this key has none, so leave the passphrase empty", c.Name)
		}
		_, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(secret), []byte(phrase))
	} else {
		_, err = ssh.ParseRawPrivateKey([]byte(secret))
	}
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &missing):
		return inputErrorf("%s: the private key is protected with a passphrase; enter it too", c.Name)
	case errors.Is(err, x509.IncorrectPasswordError) || strings.Contains(err.Error(), "decryption password incorrect"):
		return inputErrorf("%s: the passphrase does not open the private key", c.Name)
	}
	return inputErrorf("%s: that is not a private key SSH can read; paste the whole file, from -----BEGIN to -----END", c.Name)
}

// OpenLogin decrypts the login id for a scan.
func (s *Store) OpenLogin(ctx context.Context, id string) (*Login, error) {
	list, _, err := s.Logins(ctx)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(list, func(c Credential) bool { return c.ID == id })
	if i < 0 {
		return nil, errors.New("its scan login was removed; edit the network and pick another")
	}
	c := list[i]
	if s.Keys == nil {
		return nil, fmt.Errorf("the scan login %s cannot be decrypted: this server has no key for it", c.Name)
	}
	// A secret is only ever stored encrypted: one in the clear was not
	// written by Signalith, so it is not used.
	secret, err := s.Keys.Open(secretField(c.ID, "secret"), c.Secret)
	if err != nil || !secrets.IsSealed(c.Secret) || (c.Passphrase != "" && !secrets.IsSealed(c.Passphrase)) {
		return nil, fmt.Errorf("the scan login %s cannot be decrypted on this server; enter its %s again in Settings > Scanners", c.Name, secretWord(c.Auth))
	}
	l := &Login{Kind: c.Kind, Username: c.Username, Auth: c.Auth, Port: c.Port, Secret: secret}
	if c.Passphrase != "" {
		if l.Passphrase, err = s.Keys.Open(secretField(c.ID, "passphrase"), c.Passphrase); err != nil {
			return nil, fmt.Errorf("the scan login %s cannot be decrypted on this server; enter its key and passphrase again in Settings > Scanners", c.Name)
		}
	}
	return l, nil
}

// ScanLogins are the logins OpenVAS signs in with for one scan.
type ScanLogins struct {
	SSH, SMB *Login
}

// loginsFor decrypts the logins t names.
func (s *Store) loginsFor(ctx context.Context, t Target) (ScanLogins, error) {
	var out ScanLogins
	var err error
	if t.SSHLogin != "" {
		if out.SSH, err = s.OpenLogin(ctx, t.SSHLogin); err != nil {
			return out, err
		}
	}
	if t.SMBLogin != "" {
		if out.SMB, err = s.OpenLogin(ctx, t.SMBLogin); err != nil {
			return out, err
		}
	}
	return out, nil
}

// checkLoginRefs makes sure the logins the networks name exist and are
// of the right kind, and are only on networks OpenVAS scans.
func checkLoginRefs(set Settings, list []Credential) error {
	kind := map[string]string{}
	for _, c := range list {
		kind[c.ID] = c.Kind
	}
	for _, t := range set.Targets {
		for _, ref := range []struct{ id, want, what string }{{t.SSHLogin, LoginSSH, "SSH login"}, {t.SMBLogin, LoginSMB, "Windows login"}} {
			if ref.id == "" {
				continue
			}
			if !t.OpenVAS {
				return inputErrorf("%s: only OpenVAS scans sign in to hosts; turn OpenVAS on or set %s to None", t.Name, ref.what)
			}
			if k, ok := kind[ref.id]; !ok || k != ref.want {
				return inputErrorf("%s: its %s was removed or is not one; reload the page and pick another", t.Name, ref.what)
			}
		}
	}
	return nil
}

// CheckLogins checks the logins the networks of set name against the
// saved ones.
func (s *Store) CheckLogins(ctx context.Context, set Settings) error {
	need := false
	for _, t := range set.Targets {
		need = need || t.SSHLogin != "" || t.SMBLogin != ""
	}
	if !need {
		return nil
	}
	list, _, err := s.Logins(ctx)
	if err != nil {
		return err
	}
	return checkLoginRefs(set, list)
}

// validLoginRef is a login ID a network may name.
func validLoginRef(id string) bool {
	return id == "" || (idRE.MatchString(id) && !strings.ContainsFunc(id, unicode.IsSpace))
}
