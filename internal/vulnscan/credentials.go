// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
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
// other Unix systems, a private key or a password), SMB (Windows, a
// password), ESXi (VMware hosts, a password) or SNMP (network devices:
// SNMPv3 with SHA authentication and AES privacy, or an SNMPv1/v2c
// community when a device has nothing better). Networks name the logins
// to use, by ID.
//
// The private keys and passwords are encrypted (Keys) before they are
// stored, bound to the login they belong to, and are never sent back to
// a browser or written to a log: the API says only whether one is set.
// They are decrypted only on the server that runs an OpenVAS scan, just
// before the scan, and handed to OpenVAS for that scan alone; the copy
// OpenVAS keeps is removed with the scan's target when the scan ends.

// Login kinds.
const (
	LoginSSH  = "ssh"
	LoginSMB  = "smb"
	LoginESXi = "esxi"
	LoginSNMP = "snmp"
)

// SSH sign-in methods.
const (
	AuthKey      = "key"
	AuthPassword = "password"
)

// SNMP sign-in methods: v3 is a user with an authentication and a privacy
// password (SHA and AES); community is SNMPv1/v2c, sent in the clear.
const (
	AuthSNMPv3    = "v3"
	AuthCommunity = "community"
)

const (
	maxLogins      = 50
	maxSecretLen   = 16 << 10
	maxPasswordLen = 256
	// minSNMPLen is the shortest SNMPv3 password (RFC 3414), also asked of
	// a community so it cannot be guessed in a few tries.
	minSNMPLen    = 8
	credentialsID = "credentials"
	kindLogins    = "credentials"
)

// loginUserRE is a user name OpenVAS can sign in with: letters, digits
// and . _ - @ $, with a DOMAIN\ in front for Windows.
// Neither part starts with a - or other punctuation, so a name is never
// read as an option.
var loginUserRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,63}\\)?[A-Za-z0-9_][A-Za-z0-9._@$-]{0,127}$`)

// maxKeyRounds is the most bcrypt rounds an encrypted OpenSSH key may ask
// for: each round costs about 10 ms, and the key is opened while an admin
// waits. ssh-keygen uses 16 unless told otherwise.
const maxKeyRounds = 64

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
	// Auth is key or password, for SSH; v3 or community, for SNMP; SMB
	// and ESXi are always a password.
	Auth string `json:"auth"`
	// Port is the SSH port, 22 unless set.
	Port int `json:"port,omitempty"`
	// Secret is the private key (PEM), the password, the SNMPv3
	// authentication password or the SNMP community, encrypted.
	Secret string `json:"secret"`
	// Passphrase is the private key's passphrase, encrypted, if it has
	// one.
	Passphrase string `json:"passphrase,omitempty"`
	// Privacy is the SNMPv3 privacy (encryption) password, encrypted.
	Privacy   string    `json:"privacy,omitempty"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// LoginInput is a login an admin saves. An empty Secret keeps the saved
// one, as do an empty Privacy and an empty Passphrase unless
// ClearPassphrase is set.
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
	Privacy         string `json:"privacy"`
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
	Kind, Username, Auth        string
	Port                        int
	Secret, Passphrase, Privacy string
}

// String keeps the secrets out of logs and error messages.
func (l *Login) String() string {
	if l == nil {
		return "<no login>"
	}
	if l.Auth == AuthCommunity {
		return l.Kind + " community login"
	}
	return l.Kind + " login " + l.Username
}

// LogValue keeps the secrets out of structured logs too.
func (l *Login) LogValue() slog.Value { return slog.StringValue(l.String()) }

type loginsDoc struct {
	Kind   string       `json:"kind"`
	Logins []Credential `json:"logins"`
}

// The field also names the login's kind and how it signs in, so a secret
// cannot be read back as another kind of secret.
func secretField(c Credential, part string) string {
	return "vulns.credentials[" + c.ID + "]." + c.Kind + "." + c.Auth + "." + part
}

// View is c without its secrets; keys, when set, says whether they can
// be decrypted here.
func (c Credential) View(keys Keys) LoginView {
	v := LoginView{ID: c.ID, Name: c.Name, Kind: c.Kind, Username: c.Username, Auth: c.Auth, Port: c.Port,
		HasPassphrase: c.Passphrase != "", UpdatedBy: c.UpdatedBy, UpdatedAt: c.UpdatedAt}
	if keys != nil {
		_, err := keys.Open(secretField(c, "secret"), c.Secret)
		v.Readable = err == nil && secrets.IsSealed(c.Secret)
		if c.Auth == AuthSNMPv3 {
			_, err := keys.Open(secretField(c, "privacy"), c.Privacy)
			v.Readable = v.Readable && err == nil && secrets.IsSealed(c.Privacy)
		}
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
	// The saved settings, not a cached copy: a network that just picked
	// this login must keep it.
	set, _, err := s.Settings(ctx)
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
		if slices.ContainsFunc(t.loginRefs(), func(r loginRef) bool { return r.id == id }) {
			out = append(out, t.Name)
		}
	}
	return out
}

// loginRef is a login a network names, the kind it must be, and what the
// page calls it.
type loginRef struct{ id, kind, what string }

// loginRefs are the logins t may name, set or not.
func (t Target) loginRefs() []loginRef {
	return []loginRef{
		{t.SSHLogin, LoginSSH, "SSH login"},
		{t.SMBLogin, LoginSMB, "Windows login"},
		{t.ESXiLogin, LoginESXi, "ESXi login"},
		{t.SNMPLogin, LoginSNMP, "SNMP login"},
	}
}

// hasLogin says whether t names any login.
func (t Target) hasLogin() bool {
	return slices.ContainsFunc(t.loginRefs(), func(r loginRef) bool { return r.id != "" })
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
		return c, inputErrorf("%s: a login cannot change what it signs in to (SSH, Windows, ESXi or SNMP); add a new one instead", c.Name)
	}
	community := c.Kind == LoginSNMP && c.Auth == AuthCommunity
	if community {
		// A community is the whole sign-in: there is no user.
		c.Username = ""
	} else if !loginUserRE.MatchString(c.Username) {
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
	case LoginSMB, LoginESXi:
		c.Auth, c.Port = AuthPassword, 0
	case LoginSNMP:
		c.Port = 0
		if c.Auth != AuthSNMPv3 && c.Auth != AuthCommunity {
			return c, inputErrorf("%s: sign in with SNMPv3 or an SNMPv1/v2c community", c.Name)
		}
		if strings.Contains(c.Username, `\`) {
			return c, inputErrorf("%s: an SNMP user name has no DOMAIN\\ in front", c.Name)
		}
	default:
		return c, inputErrorf("%s: a login is SSH (Linux), SMB (Windows), ESXi or SNMP", c.Name)
	}
	if prev != nil && prev.Auth != c.Auth && in.Secret == "" {
		return c, inputErrorf("%s: enter the %s, as it now signs in with one", c.Name, secretWord(c.Auth))
	}
	field := secretField(c, "secret")
	phraseField := secretField(c, "passphrase")
	if in.Secret == "" && prev == nil {
		return c, inputErrorf("%s: enter the %s", c.Name, secretWord(c.Auth))
	}
	if c.Auth != AuthKey && (in.Passphrase != "" || in.ClearPassphrase) {
		return c, inputErrorf("%s: only a private key has a passphrase", c.Name)
	}
	if c.Auth != AuthSNMPv3 && in.Privacy != "" {
		return c, inputErrorf("%s: only an SNMPv3 login has a privacy password", c.Name)
	}
	if err := s.buildPrivacy(&c, in, prev); err != nil {
		return c, err
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

// buildPrivacy sets an SNMPv3 login's privacy password: a new one, or the
// saved one. It must differ from the authentication password, so that
// one leaked does not give away the other.
func (s *Store) buildPrivacy(c *Credential, in LoginInput, prev *Credential) error {
	if c.Auth != AuthSNMPv3 {
		return nil
	}
	if in.Privacy == "" {
		if prev == nil || prev.Auth != AuthSNMPv3 || prev.Privacy == "" {
			return inputErrorf("%s: enter the privacy password, which encrypts what the device sends", c.Name)
		}
		c.Privacy = prev.Privacy
		if in.Secret == "" {
			return nil
		}
		saved, err := s.Keys.Open(secretField(*c, "privacy"), prev.Privacy)
		if err != nil {
			return inputErrorf("%s: the saved privacy password cannot be decrypted on this server; enter it again", c.Name)
		}
		if saved == in.Secret {
			return inputErrorf("%s: use a privacy password that differs from the authentication password", c.Name)
		}
		return nil
	}
	if err := checkSNMPSecret(c.Name, "privacy password", in.Privacy); err != nil {
		return err
	}
	auth := in.Secret
	if auth == "" && prev != nil && prev.Auth == AuthSNMPv3 {
		saved, err := s.Keys.Open(secretField(*c, "secret"), prev.Secret)
		if err != nil {
			return inputErrorf("%s: the saved authentication password cannot be decrypted on this server; enter it again", c.Name)
		}
		auth = saved
	}
	if auth == in.Privacy {
		return inputErrorf("%s: use a privacy password that differs from the authentication password", c.Name)
	}
	sealed, err := s.Keys.Seal(secretField(*c, "privacy"), in.Privacy)
	if err != nil {
		return err
	}
	c.Privacy = sealed
	return nil
}

// checkSNMPSecret checks an SNMPv3 password or a community: long enough
// not to be guessed, and never a well-known default.
func checkSNMPSecret(name, what, v string) error {
	if len(v) < minSNMPLen {
		return inputErrorf("%s: the %s must be at least %d characters", name, what, minSNMPLen)
	}
	if len(v) > maxPasswordLen || strings.ContainsFunc(v, unicode.IsControl) {
		return inputErrorf("%s: the %s is longer than %d characters or has a line break or other control character", name, what, maxPasswordLen)
	}
	return nil
}

// defaultCommunities are communities devices ship with, which anyone
// can guess.
var defaultCommunities = []string{"public", "private", "community", "password", "secret", "admin", "manager", "monitor", "snmp", "cisco", "default"}

func secretWord(auth string) string {
	switch auth {
	case AuthKey:
		return "private key"
	case AuthSNMPv3:
		return "authentication password"
	case AuthCommunity:
		return "community"
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
	switch c.Auth {
	case AuthSNMPv3:
		return checkSNMPSecret(c.Name, secretWord(c.Auth), secret)
	case AuthCommunity:
		if err := checkSNMPSecret(c.Name, secretWord(c.Auth), secret); err != nil {
			return err
		}
		if slices.ContainsFunc(defaultCommunities, func(d string) bool { return strings.HasPrefix(strings.ToLower(secret), d) && len(secret) < len(d)+4 }) {
			return inputErrorf("%s: that community is a well-known default anyone can guess; set a long random one on the devices", c.Name)
		}
		return nil
	}
	if c.Auth != AuthKey {
		// OpenVAS gets it in XML, which cannot carry control characters.
		if len(secret) > maxPasswordLen || strings.ContainsFunc(secret, unicode.IsControl) {
			return inputErrorf("%s: the password is longer than %d characters or has a line break or other control character", c.Name, maxPasswordLen)
		}
		return nil
	}
	if len(phrase) > maxPasswordLen || strings.ContainsFunc(phrase, unicode.IsControl) {
		return inputErrorf("%s: the passphrase is longer than %d characters or has a line break or other control character", c.Name, maxPasswordLen)
	}
	if strings.ContainsFunc(secret, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) {
		return inputErrorf("%s: that is not a private key SSH can read; paste the whole file, from -----BEGIN to -----END", c.Name)
	}
	if strings.Contains(secret, "PUBLIC KEY") || strings.HasPrefix(strings.TrimSpace(secret), "ssh-") {
		return inputErrorf("%s: that is the public key; paste the private key, which starts with -----BEGIN", c.Name)
	}
	if n, ok := keyRounds(secret); ok && n > maxKeyRounds {
		return inputErrorf("%s: the key's passphrase is protected with %d rounds, more than the %d Signalith opens; "+
			"set it again with ssh-keygen -p -a 16, or remove the passphrase (Signalith keeps the key encrypted)", c.Name, n, maxKeyRounds)
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

// keyRounds reads how many bcrypt rounds an OpenSSH private key's
// passphrase asks for; ok is false for any other key.
func keyRounds(secret string) (uint32, bool) {
	b, _ := pem.Decode([]byte(secret))
	if b == nil || b.Type != "OPENSSH PRIVATE KEY" {
		return 0, false
	}
	const magic = "openssh-key-v1\x00"
	rest, ok := bytes.CutPrefix(b.Bytes, []byte(magic))
	if !ok {
		return 0, false
	}
	str := func() ([]byte, bool) {
		if len(rest) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(rest)
		if uint64(n) > uint64(len(rest)-4) {
			return nil, false
		}
		v := rest[4 : 4+n]
		rest = rest[4+n:]
		return v, true
	}
	if _, ok := str(); !ok { // the cipher
		return 0, false
	}
	kdf, ok := str()
	if !ok || string(kdf) != "bcrypt" {
		return 0, false
	}
	opts, ok := str()
	if !ok {
		return 0, false
	}
	rest = opts
	if _, ok := str(); !ok || len(rest) < 4 { // the salt, then the rounds
		return 0, false
	}
	return binary.BigEndian.Uint32(rest), true
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
	secret, err := s.Keys.Open(secretField(c, "secret"), c.Secret)
	if err != nil || !secrets.IsSealed(c.Secret) || (c.Passphrase != "" && !secrets.IsSealed(c.Passphrase)) {
		return nil, fmt.Errorf("the scan login %s cannot be decrypted on this server; enter its %s again in Settings > Scanners", c.Name, secretWord(c.Auth))
	}
	l := &Login{Kind: c.Kind, Username: c.Username, Auth: c.Auth, Port: c.Port, Secret: secret}
	if c.Auth == AuthSNMPv3 {
		if !secrets.IsSealed(c.Privacy) {
			return nil, fmt.Errorf("the scan login %s cannot be decrypted on this server; enter its passwords again in Settings > Scanners", c.Name)
		}
		if l.Privacy, err = s.Keys.Open(secretField(c, "privacy"), c.Privacy); err != nil {
			return nil, fmt.Errorf("the scan login %s cannot be decrypted on this server; enter its passwords again in Settings > Scanners", c.Name)
		}
	}
	if c.Passphrase != "" {
		if l.Passphrase, err = s.Keys.Open(secretField(c, "passphrase"), c.Passphrase); err != nil {
			return nil, fmt.Errorf("the scan login %s cannot be decrypted on this server; enter its key and passphrase again in Settings > Scanners", c.Name)
		}
	}
	return l, nil
}

// ScanLogins are the logins OpenVAS signs in with for one scan.
type ScanLogins struct {
	SSH, SMB, ESXi, SNMP *Login
}

// all lists the logins set, in a fixed order.
func (l ScanLogins) all() []*Login {
	var out []*Login
	for _, x := range []*Login{l.SSH, l.SMB, l.ESXi, l.SNMP} {
		if x != nil {
			out = append(out, x)
		}
	}
	return out
}

// loginsFor decrypts the logins t names.
func (s *Store) loginsFor(ctx context.Context, t Target) (ScanLogins, error) {
	var out ScanLogins
	slots := map[string]**Login{LoginSSH: &out.SSH, LoginSMB: &out.SMB, LoginESXi: &out.ESXi, LoginSNMP: &out.SNMP}
	for _, ref := range t.loginRefs() {
		if ref.id == "" {
			continue
		}
		l, err := s.OpenLogin(ctx, ref.id)
		if err != nil {
			return ScanLogins{}, err
		}
		if l.Kind != ref.kind {
			return ScanLogins{}, fmt.Errorf("its %s is a login of another kind; edit the network and pick another", ref.what)
		}
		*slots[ref.kind] = l
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
		for _, ref := range t.loginRefs() {
			if ref.id == "" {
				continue
			}
			if !t.OpenVAS {
				return inputErrorf("%s: only OpenVAS scans sign in to hosts; turn OpenVAS on or set %s to None", t.Name, ref.what)
			}
			if k, ok := kind[ref.id]; !ok || k != ref.kind {
				return inputErrorf("%s: its %s was removed or is not one; reload the page and pick another", t.Name, ref.what)
			}
		}
	}
	return nil
}

// CheckLogins checks the logins the networks of set name against the
// saved ones.
func (s *Store) CheckLogins(ctx context.Context, set Settings) error {
	if !slices.ContainsFunc(set.Targets, Target.hasLogin) {
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

// ResealLogins seals the logins' secrets again, after the cluster key
// changes. reseal returns a value as it is when it is not its to seal
// again, such as one sealed with a single server's own key.
func (s *Store) ResealLogins(ctx context.Context, reseal func(field, sealed string) (string, error)) error {
	for range 3 {
		list, v, err := s.Logins(ctx)
		if err != nil || len(list) == 0 {
			return err
		}
		next := slices.Clone(list)
		for i := range next {
			c := &next[i]
			if c.Secret, err = reseal(secretField(*c, "secret"), c.Secret); err != nil {
				return fmt.Errorf("the scan login %s: %w", c.Name, err)
			}
			if c.Passphrase, err = reseal(secretField(*c, "passphrase"), c.Passphrase); err != nil {
				return fmt.Errorf("the scan login %s: %w", c.Name, err)
			}
			if c.Privacy, err = reseal(secretField(*c, "privacy"), c.Privacy); err != nil {
				return fmt.Errorf("the scan login %s: %w", c.Name, err)
			}
		}
		if slices.Equal(next, list) {
			return nil
		}
		if err := s.putLogins(ctx, next, v); err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return err
		}
		return nil
	}
	return errors.New("someone else changed the scan logins at the same time; try again")
}
