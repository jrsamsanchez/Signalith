package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"gopkg.in/yaml.v3"
)

// The settings changed on the Settings page are kept in settings.yaml in
// the lookups folder (SIGNALITH_SETTINGS_FILE moves it), never in
// signalith.yaml, which is often read-only (Docker mounts it so, and the
// systemd unit protects /etc). The file holds only the settings changed
// on the page, with who changed them and when. Signalith rewrites it whole
// on each save, through a temporary file and a rename, readable only by
// its own account. Passwords and API keys saved on the page are kept in it
// encrypted with Signalith's master key (see internal/secrets).
//
// Precedence: environment variable > Settings page > signalith.yaml >
// built-in default.

// PageSettings is the content of settings.yaml.
type PageSettings struct {
	Settings map[string]*PageEntry `yaml:"settings"`
	// explicitMode is set while checking an edit that enters certificate
	// files: they need the HTTPS mode chosen with them (see pageCertMode).
	explicitMode bool
}

// PageEntry is one setting changed on the page.
type PageEntry struct {
	// Value is the setting's value. A secret is kept in Secret instead.
	Value  yaml.Node `yaml:"value,omitempty"`
	Secret *string   `yaml:"secret,omitempty"`
	// SentTo is the only address a secret is sent to: scheme://host:port
	// of the server it was entered for.
	SentTo    string    `yaml:"sent_to,omitempty"`
	ChangedBy string    `yaml:"changed_by,omitempty"`
	ChangedAt time.Time `yaml:"changed_at,omitempty"`
	// Refused says why a restart did not use this change, which is then
	// set aside: Signalith does not use it, not even when it next starts,
	// until it is saved again on the page.
	Refused   string    `yaml:"refused,omitempty"`
	RefusedAt time.Time `yaml:"refused_at,omitempty"`
	// CheckedAt is when Signalith last started with this change after
	// checking it; zero for one saved since, with no restart yet.
	CheckedAt time.Time `yaml:"checked_at,omitempty"`
}

const pageFileHeader = `# Settings changed on the Settings page of Signalith. They override
# signalith.yaml; environment variables override both. Signalith rewrites
# this file when settings are saved on the page. To undo a change, use Reset
# on the page, or on the server: signalith settings reset [key...]
# Passwords and API keys in it are encrypted with Signalith's master key
# (enc:v1:...); keep it private all the same.
`

// pageField is the setting a secret saved on the page is encrypted for:
// "settings." and its key, so the value cannot pass for the same setting
// in signalith.yaml or in another file.
func pageField(key string) string { return "settings." + key }

// sealSecret and openSecret are the one place secrets saved on the page
// are written and read: encrypted with Signalith's master key. A secret
// kept as plain text, as Signalith did before it encrypted them, is read
// as it is; the server encrypts it when it next starts (see
// ResealSettingsFile).
func sealSecret(key, v string) (string, error) { return secrets.Seal(pageField(key), v) }

// openSecret decrypts a secret saved on the page with keys, the master
// key of the configuration it is applied to (found from signalith.yaml and
// the environment, as for the values in signalith.yaml), or else with the
// keyring the server and commands save with (secrets.Default), when that
// is another one.
func openSecret(keys *secrets.Keyring, key, v string) (string, error) {
	plain, err := keys.Open(pageField(key), v)
	if err != nil {
		if d := secrets.Default(); d != keys {
			if p, derr := d.Open(pageField(key), v); derr == nil {
				return p, nil
			}
		}
	}
	return plain, err
}

// Empty reports whether no setting was changed on the page.
func (p *PageSettings) Empty() bool { return p == nil || len(p.Settings) == 0 }

// Keys lists the settings changed on the page, sorted.
func (p *PageSettings) Keys() []string {
	if p == nil {
		return nil
	}
	keys := make([]string, 0, len(p.Settings))
	for k := range p.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Clone returns a copy that can be changed without changing p.
func (p *PageSettings) Clone() *PageSettings {
	out := &PageSettings{Settings: map[string]*PageEntry{}}
	if p == nil {
		return out
	}
	for k, e := range p.Settings {
		c := *e
		if e.Secret != nil {
			s := *e.Secret
			c.Secret = &s
		}
		out.Settings[k] = &c
	}
	return out
}

// Set records a value changed on the page.
func (p *PageSettings) Set(key string, v any, by string, at time.Time) error {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return err
	}
	p.put(key, &PageEntry{Value: n, ChangedBy: by, ChangedAt: at.UTC()})
	return nil
}

// SetSecret records a secret entered on the page, encrypted with the
// master key (secrets.Seal), and the address it may be sent to; an empty
// secret means none.
func (p *PageSettings) SetSecret(key, secret, sentTo string, by string, at time.Time) error {
	sealed, err := sealSecret(key, secret)
	if err != nil {
		return err
	}
	if secret == "" {
		sentTo = ""
	}
	p.put(key, &PageEntry{Secret: &sealed, SentTo: sentTo, ChangedBy: by, ChangedAt: at.UTC()})
	return nil
}

func (p *PageSettings) put(key string, e *PageEntry) {
	if p.Settings == nil {
		p.Settings = map[string]*PageEntry{}
	}
	p.Settings[key] = e
}

// Remove takes a setting off the page, so signalith.yaml or the default
// applies again. It reports whether it was there.
func (p *PageSettings) Remove(key string) bool {
	if p == nil || p.Settings[key] == nil {
		return false
	}
	delete(p.Settings, key)
	return true
}

// refuse sets the changes to keys aside, for reason. It returns the keys
// it set aside: those changed on the page and not set aside already.
func (p *PageSettings) refuse(keys []string, reason string, at time.Time) []string {
	var out []string
	for _, k := range keys {
		if e := p.Settings[k]; e != nil && e.Refused == "" {
			e.Refused, e.RefusedAt = reason, at.UTC()
			out = append(out, k)
		}
	}
	return out
}

// MarkRefused sets the changes made on the Settings page to keys aside in
// the settings file, for reason, so they are not used again, not even at
// the next start, until they are saved again on the page. It returns the
// keys it set aside.
func MarkRefused(path string, keys []string, reason string) ([]string, error) {
	p, err := ReadPageSettings(path)
	if err != nil {
		return nil, err
	}
	marked := p.refuse(keys, reason, time.Now())
	if len(marked) == 0 {
		return nil, nil
	}
	return marked, WritePageSettings(path, p)
}

// MarkChecked records in the settings file that Signalith started with the
// changes to keys after checking them, as a restart does.
func MarkChecked(path string, keys []string) error {
	p, err := ReadPageSettings(path)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	changed := false
	for _, k := range keys {
		if e := p.Settings[k]; e != nil && e.Refused == "" && e.CheckedAt.IsZero() {
			e.CheckedAt, changed = now, true
		}
	}
	if !changed {
		return nil
	}
	return WritePageSettings(path, p)
}

// PageChecked reports whether the change to key made on the Settings page
// was checked by a restart, or Signalith started with it after checking.
func (c *Config) PageChecked(key string) bool {
	if c.layers == nil {
		return false
	}
	e := c.layers.page[key]
	return e != nil && !e.CheckedAt.IsZero()
}

// PageStore keeps the settings changed on the Settings page. PageFile,
// the settings file next to the lookups folder's lists, is the only one
// today; the Settings page uses the interface so servers that share one
// OpenSearch can keep them there instead.
type PageStore interface {
	// Read returns the saved settings; none saved is an empty set.
	Read() (*PageSettings, error)
	// Write replaces the saved settings with p.
	Write(p *PageSettings) error
	// Backup moves saved settings that cannot be read out of the way,
	// before new ones are started, and says where they went.
	Backup() (string, error)
	// CheckEdit applies an edit to the saved settings and checks the whole
	// configuration it gives, as Validate does at startup, without saving
	// anything.
	CheckEdit(e Edit) (*EditResult, error)
}

// PageFile is the PageStore of the config file at Config: its settings
// file (SettingsFile).
type PageFile struct {
	Config string // the path of signalith.yaml
}

func (f PageFile) file() (string, error) { return SettingsFileFor(f.Config) }

// Read reads the settings file.
func (f PageFile) Read() (*PageSettings, error) {
	file, err := f.file()
	if err != nil {
		return nil, err
	}
	return ReadPageSettings(file)
}

// Write replaces the settings file.
func (f PageFile) Write(p *PageSettings) error {
	file, err := f.file()
	if err != nil {
		return err
	}
	return WritePageSettings(file, p)
}

// Backup moves the settings file aside (BackUpPageFile).
func (f PageFile) Backup() (string, error) {
	file, err := f.file()
	if err != nil {
		return "", err
	}
	return BackUpPageFile(file)
}

// CheckEdit is CheckEdit for the config file.
func (f PageFile) CheckEdit(e Edit) (*EditResult, error) { return CheckEdit(f.Config, e) }

// BackUpPageFile moves a settings file that cannot be read out of the way,
// to settings.yaml.broken next to it, before a new one is started, so
// what it held can still be looked at. It returns the backup's path.
func BackUpPageFile(path string) (string, error) {
	backup := path + ".broken"
	if err := os.Rename(path, backup); err != nil {
		return "", err
	}
	return backup, nil
}

// PageFileError is a settings file that cannot be read.
type PageFileError struct {
	Path string
	Err  error
}

func (e *PageFileError) Error() string {
	return fmt.Sprintf("the settings file %s cannot be read (%v)", e.Path, e.Err)
}

func (e *PageFileError) Unwrap() error { return e.Err }

// ReadPageSettings reads the settings file. A missing file is no settings.
func ReadPageSettings(path string) (*PageSettings, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &PageSettings{}, nil
	}
	if err != nil {
		return nil, &PageFileError{Path: path, Err: err}
	}
	p, err := parsePageSettings(data)
	if err != nil {
		return nil, &PageFileError{Path: path, Err: err}
	}
	return p, nil
}

// parsePageSettings reads the settings file's text.
func parsePageSettings(data []byte) (*PageSettings, error) {
	var p PageSettings
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	for k, e := range p.Settings {
		if e == nil {
			delete(p.Settings, k)
		}
	}
	return &p, nil
}

// WritePageSettings replaces the settings file; with no settings left it
// removes it.
func WritePageSettings(path string, p *PageSettings) error {
	if p.Empty() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := encodePageSettings(p)
	if err != nil {
		return err
	}
	// Written whole or not at all, readable only by Signalith's account
	// (see securefile). The new file keeps the owner of the one it
	// replaces, or run as root takes its folder's, so "sudo signalith
	// settings reset" does not leave a file the service cannot read. A
	// link put in its place is replaced, not followed, so the file it
	// points to is left alone.
	return securefile.Replace(path, data)
}

// encodePageSettings returns the settings file's text.
func encodePageSettings(p *PageSettings) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(pageFileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ResealSettingsFile passes every password and key saved on the Settings
// page, in the settings.yaml text data, through fn and returns the file
// with the values fn changed, and how many it changed. Each is passed as
// the setting "settings." and its key. A secret written by hand as a plain
// value: is passed too, and kept as an encrypted secret: once fn changes
// it. Empty ones are not passed.
func ResealSettingsFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	p, err := parsePageSettings(data)
	if err != nil {
		return nil, 0, fmt.Errorf("not a settings file Signalith can read: %w", err)
	}
	n := 0
	for _, key := range p.Keys() {
		e := p.Settings[key]
		var v string
		switch {
		case e.Secret != nil:
			v = *e.Secret
		case e.Value.Kind != 0:
			if s, ok := Lookup(key); !ok || s.Type != TypeSecret || e.Value.Decode(&v) != nil {
				continue
			}
		}
		if v == "" {
			continue
		}
		nv, err := fn(secrets.Stored{Field: pageField(key), Label: key, Value: v})
		if err != nil {
			return nil, 0, err
		}
		if nv == v {
			continue
		}
		e.Secret, e.Value = &nv, yaml.Node{}
		n++
	}
	if n == 0 {
		return data, 0, nil
	}
	out, err := encodePageSettings(p)
	if err != nil {
		return nil, 0, err
	}
	return out, n, nil
}

// secretMismatch is a secret that is not used because the address it
// would be sent to is not the one it was entered for.
type secretMismatch struct {
	Key   string
	Bound string // where it may be sent
	Now   string // where it would go now
}

// applyPage applies the page's settings to c, which already has the
// environment applied: a setting set by an environment variable keeps
// that value. base is c without the page's settings. A value of the wrong
// type is an error; an unknown setting is skipped with a warning.
func (c *Config) applyPage(p *PageSettings, base *Config) error {
	l := c.layers
	// A file without a server.tls section gets one as in effect before
	// the page's HTTPS settings or public address apply, so each changes
	// only itself (see Server.materializeTLS). c is not validated yet;
	// base is.
	for _, key := range p.Keys() {
		if e := p.Settings[key]; tlsKey(key) && l.env[key] == "" && e.Refused == "" {
			c.Server.materializeTLS(pageCertMode(p, base.Server))
			break
		}
	}
	for _, key := range p.Keys() {
		e := p.Settings[key]
		s, ok := Lookup(key)
		if !ok {
			l.warnings = append(l.warnings, fmt.Sprintf("%s has %s, which is not a setting on the Settings page; it is ignored", l.pageFile, key))
			continue
		}
		if l.env[key] != "" {
			continue
		}
		if e.Refused != "" {
			l.refused[key] = e
			continue
		}
		if s.Type == TypeSecret {
			var v string
			switch {
			case e.Secret != nil:
				var err error
				if v, err = openSecret(c.Keyring(), key, *e.Secret); err != nil {
					// Like one in signalith.yaml, a secret that cannot be
					// decrypted does not keep Signalith from starting, nor
					// the page's other settings from being used: it is left
					// out, as if none were set, and reported (see
					// PageUnreadable).
					c.pageCannotOpen(key, err)
					v = ""
				}
			case e.Value.Kind != 0:
				if err := e.Value.Decode(&v); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			}
			if err := c.SetValue(key, v); err != nil {
				return err
			}
			l.page[key] = e
			continue
		}
		if e.Value.Kind == 0 {
			return fmt.Errorf("%s has no value", key)
		}
		f, _ := fieldToSet(c, key)
		nv := reflect.New(f.Type())
		if err := e.Value.Decode(nv.Interface()); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		f.Set(nv.Elem())
		l.page[key] = e
	}
	// A secret is only sent to the address it was entered for: one saved
	// on the page to the address it was saved with, one from signalith.yaml
	// or the environment to the address set there. When the address has
	// moved since, the secret is not used until it is entered again.
	for i := range Registry {
		s := &Registry[i]
		if s.Type != TypeSecret || s.sentTo == nil {
			continue
		}
		v, _ := c.Value(s.Key).(string)
		if v == "" {
			continue
		}
		bound := s.SentTo(base)
		if e, ok := l.page[s.Key]; ok {
			bound = e.SentTo
		}
		if v, ok := l.shared[s.Key]; ok {
			bound = v.SentTo
		} else if r, ok := l.kept[s.Key]; ok {
			kept, _ := keptValue(s.Key, r.Kept)
			bound = kept.SentTo
		}
		// A secret sent nowhere now (the assistant turned off) is kept
		// for when the address it was saved with comes back.
		if now := s.SentTo(c); now != "" && now != bound {
			_ = c.SetValue(s.Key, "")
			l.mismatch = append(l.mismatch, secretMismatch{Key: s.Key, Bound: bound, Now: now})
			l.warnings = append(l.warnings, fmt.Sprintf("%s is not used: it is only sent to %s, and the address is now %s. Enter it again on the Settings page", s.Key, orNone(bound), orNone(now)))
		}
	}
	return nil
}

// pageCertMode returns eff with the certificate file saved on the page,
// when the page sets one but no HTTPS mode. Before the mode existed, a
// certificate set on the page was how HTTPS was turned on, as it is in a
// file without the mode: such settings are read as files mode, not as
// the auto mode of a file that has no certificate itself. Certificate
// files entered now need the mode chosen with them (explicitMode).
func pageCertMode(p *PageSettings, eff Server) Server {
	if e := p.Settings["server.tls.mode"]; p.explicitMode || (e != nil && e.Refused == "") {
		return eff
	}
	e := p.Settings["server.tls_cert"]
	if e == nil || e.Refused != "" || e.Value.Kind == 0 {
		return eff
	}
	var cert string
	if e.Value.Decode(&cert) != nil || strings.TrimSpace(cert) == "" {
		return eff
	}
	eff.TLSCert = cert
	return eff
}

func orNone(origin string) string {
	if origin == "" {
		return "no address"
	}
	return origin
}

// Source says where a setting's value comes from.
type Source struct {
	// Kind is env, page, file, shared, kept or default.
	Kind string `json:"kind"`
	// Env is the environment variable, for env.
	Env string `json:"env,omitempty"`
	// By and At say who changed it on the page, and when; for shared, who
	// changed the shared value, when, and on which server (Node).
	By   string    `json:"by,omitempty"`
	At   time.Time `json:"at,omitzero"`
	Node string    `json:"node,omitempty"`
	// Applied is "yaml" or "env" for a shared value that came from a
	// server's signalith.yaml or environment when it changed there.
	Applied string `json:"applied,omitempty"`
}

// Where a value comes from.
const (
	FromEnv     = "env"
	FromPage    = "page"
	FromFile    = "file"
	FromShared  = "shared"
	FromDefault = "default"
	// FromKept is a shared setting this server keeps its own value of,
	// because it could not use the shared one (see SharedKept).
	FromKept = "kept"
)

// alias is the other name of a setting with two: detections.scheduler is
// the old name of cluster.leader_eligible.
func alias(key string) string {
	switch key {
	case "cluster.leader_eligible":
		return "detections.scheduler"
	case "detections.scheduler":
		return "cluster.leader_eligible"
	}
	return ""
}

// Source says where the value of a setting in c comes from.
func (c *Config) Source(key string) Source {
	l := c.layers
	if l == nil {
		return Source{Kind: FromDefault}
	}
	if v := l.env[key]; v != "" {
		return Source{Kind: FromEnv, Env: v}
	}
	if v, ok := l.shared[key]; ok {
		src := Source{Kind: FromShared, By: v.From.By, At: v.From.At, Node: v.From.Node}
		if k := v.From.Kind; k == "yaml" || k == FromEnv {
			src.Applied = k
		}
		return src
	}
	if r, ok := l.kept[key]; ok {
		return Source{Kind: FromKept, At: r.At}
	}
	if l.sharedOn && slices.Contains(SharedKeys(), key) {
		// Neither the files nor the page set it.
		return Source{Kind: FromDefault}
	}
	for _, k := range []string{key, alias(key)} {
		if e, ok := l.page[k]; ok && k != "" {
			return Source{Kind: FromPage, By: e.ChangedBy, At: e.ChangedAt}
		}
	}
	if l.file[key] || alias(key) != "" && l.file[alias(key)] {
		return Source{Kind: FromFile}
	}
	return Source{Kind: FromDefault}
}

// RefusedSetting is a change saved on the Settings page that a restart
// set aside, and why.
type RefusedSetting struct {
	Key string `json:"key"`
	// Value is the value set aside; nil for a secret.
	Value  any       `json:"value"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
	By     string    `json:"by,omitempty"`
}

// Refused lists the changes made on the Settings page that a restart set
// aside, in page order.
func (c *Config) Refused() []RefusedSetting {
	out := []RefusedSetting{}
	if c.layers == nil {
		return out
	}
	for _, key := range sortedKeys(c.layers.refused) {
		e := c.layers.refused[key]
		r := RefusedSetting{Key: key, Reason: e.Refused, At: e.RefusedAt, By: e.ChangedBy}
		if s, ok := Lookup(key); ok && s.Type != TypeSecret {
			if f, ok := field(&Config{}, key); ok {
				nv := reflect.New(f.Type())
				if e.Value.Decode(nv.Interface()) == nil {
					r.Value = nv.Elem().Interface()
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// PageKeys lists the settings whose value comes from the Settings page.
func (c *Config) PageKeys() []string {
	keys := []string{}
	if c.layers == nil {
		return keys
	}
	for k := range c.layers.page {
		if c.layers.env[k] == "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// Base returns c without the settings changed on the Settings page:
// signalith.yaml, the environment and the defaults. Reset goes back to
// its values.
func (c *Config) Base() *Config {
	if c.layers == nil || c.layers.base == nil {
		return c
	}
	return c.layers.base
}

// SettingsFile returns where the settings changed on the Settings page
// are kept: settings.yaml in the lookups folder, or the file named by
// SIGNALITH_SETTINGS_FILE.
func (c *Config) SettingsFile() string {
	if c.layers != nil && c.layers.pageFile != "" {
		return c.layers.pageFile
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_SETTINGS_FILE")); v != "" {
		return c.resolve(v)
	}
	return filepath.Join(c.LookupsDir(), "settings.yaml")
}

// SettingsFileFor returns the Settings page's file for the config file at
// path, even when the configuration is not valid.
func SettingsFileFor(path string) (string, error) {
	c, err := readAndEnv(path)
	if err != nil {
		return "", err
	}
	return c.SettingsFile(), nil
}

// SettingsFileFromEnv reports whether SIGNALITH_SETTINGS_FILE set where
// the settings file is.
func (c *Config) SettingsFileFromEnv() bool {
	return c.layers != nil && c.layers.pageFileEnv
}

// SettingsProblem says why the settings changed on the Settings page are
// not in use, or "" when they are (or there are none). Signalith then
// runs with signalith.yaml alone.
func (c *Config) SettingsProblem() string {
	if c.layers == nil {
		return ""
	}
	return c.layers.problem
}

// SettingsWarnings lists settings from the page that are skipped, such as
// a password saved for a server that is no longer the one set.
func (c *Config) SettingsWarnings() []string {
	if c.layers == nil {
		return nil
	}
	return c.layers.warnings
}

// LockedReason says why a setting set by an environment variable cannot
// be changed on the page.
func LockedReason(env string) string {
	return fmt.Sprintf("Set by the %s environment variable, which overrides this page. Change it where Signalith's environment is set, such as docker-compose.yml or the service's settings, then restart Signalith.", env)
}
