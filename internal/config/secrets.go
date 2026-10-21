// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/incontainer"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"gopkg.in/yaml.v3"
)

// Passwords and keys in signalith.yaml may be written as plain text or
// encrypted (enc:v1:...; see internal/secrets). Load decrypts them, so the
// rest of Signalith sees plain values; the server never writes the file,
// which is often read-only. "signalith secrets encrypt" encrypts plain
// ones in place, and "signalith secrets set" stores a new one encrypted.
// The secrets in the file are:
//
//	opensearch.password (and a password written into opensearch.url,
//	which "signalith secrets encrypt" moves there)
//	assistant.api_key
//	vulns.nvd_api_key
//	m365.client_secret
//	okta.private_key
//	okta.api_token
//	vulns.openvas_password
//	auth.ldap.bind_password
//	auth.oidc.client_secret
//	ingest.tokens (each one)
//	intel.feeds[].password and .headers (values that use ${ENV_VAR} are
//	left as they are)
//
// A value that cannot be decrypted (the master key was lost or replaced,
// or the value was changed) does not stop the server: it runs without it,
// and Warnings say which values to enter again. The same goes for the
// passwords and keys saved on the Settings page (see pagefile.go), which
// settings.yaml keeps encrypted with the same master key.

// systemdStateDir is the state folder of the systemd unit. Commands run by
// hand do not see the unit's SIGNALITH_STATE_DIR, so on Linux the master
// key is also looked for there.
const systemdStateDir = "/var/lib/signalith"

// systemConfigDir holds the config of a system-wide Linux install
// (/etc/signalith/signalith.yaml).
const systemConfigDir = "/etc/"

// Keyring returns the master key holder for this config. The key is
// looked for (after systemd credentials and the SIGNALITH_MASTER_KEY_FILE
// and SIGNALITH_MASTER_KEY variables) in keys/ in the state folder, then
// next to this file, then on Linux in /var/lib/signalith. A new key is
// made in the first of these.
//
// On Linux, a config in /etc with no SIGNALITH_STATE_DIR set is a system
// install whose service keeps its files in /var/lib/signalith (see
// deploy/systemd), even when "signalith init" runs before the service is
// set up. Its key goes there first, so it is not next to signalith.yaml
// in /etc, where backups of /etc would carry both the key and the values
// it decrypts. For any other config, /var/lib/signalith is only looked in
// last, where a folder this account may not open is that install's and
// not an error (see secrets.Keyring.LookAlsoIn).
func (c *Config) Keyring() *secrets.Keyring {
	keyringMu.Lock()
	defer keyringMu.Unlock()
	if c.keys == nil {
		dirs := []string{c.StateDir()}
		if c.path != "" {
			dirs = append(dirs, filepath.Dir(c.path))
		}
		var also []string
		if runtime.GOOS == "linux" {
			also = append(also, systemdStateDir)
			if os.Getenv("SIGNALITH_STATE_DIR") == "" && c.path != "" && strings.HasPrefix(absPath(c.path), systemConfigDir) {
				dirs = append([]string{systemdStateDir}, dirs...)
			}
		}
		c.keys = secrets.NewKeyring(dirs...)
		c.keys.LookAlsoIn(also...)
	}
	return c.keys
}

// keyringMu makes Keyring safe to call from several goroutines at once,
// such as the Security page's checks. It is not a field of Config, which
// is copied by value.
var keyringMu sync.Mutex

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// secretRef is one password or key in a Config.
type secretRef struct {
	field string // the name it is encrypted for
	label string // the name shown to people
	// envRefs is true where ${ENV_VAR} is filled in from the environment;
	// such values are not encrypted.
	envRefs bool
	// feed is the feed it belongs to; token is set for an ingest token.
	feed  string
	token bool
	get   func() string
	set   func(string)
}

// feedField is the setting a feed's password or header value in
// signalith.yaml is encrypted for: intel.feeds.password, or
// intel.feeds.headers. and the header's name in lower case (header names
// ignore case). The feed's name is not part of it, so a feed can be
// renamed in the file without entering its key again.
func feedField(part string) string { return "intel.feeds." + strings.ToLower(part) }

// feedLabel names a feed's password or header for people.
func feedLabel(name, part string) string { return "intel.feeds[" + name + "]." + part }

// secretRefs lists the passwords and keys in c.
func (c *Config) secretRefs() []secretRef {
	var out []secretRef
	str := func(r secretRef, p *string) {
		r.get, r.set = func() string { return *p }, func(v string) { *p = v }
		out = append(out, r)
	}
	str(secretRef{field: "opensearch.password", label: "opensearch.password"}, &c.OpenSearch.Password)
	str(secretRef{field: "assistant.api_key", label: "assistant.api_key"}, &c.Assistant.APIKey)
	str(secretRef{field: "vulns.nvd_api_key", label: "vulns.nvd_api_key"}, &c.Vulns.NVDAPIKey)
	str(secretRef{field: "vulns.openvas_password", label: "vulns.openvas_password"}, &c.Vulns.OpenVASPassword)
	str(secretRef{field: "m365.client_secret", label: "m365.client_secret"}, &c.M365.ClientSecret)
	str(secretRef{field: "okta.private_key", label: "okta.private_key"}, &c.Okta.PrivateKey)
	str(secretRef{field: "okta.api_token", label: "okta.api_token"}, &c.Okta.APIToken)
	str(secretRef{field: "auth.oidc.client_secret", label: "auth.oidc.client_secret"}, &c.Auth.OIDC.ClientSecret)
	// A bind password from SIGNALITH_LDAP_BIND_PASSWORD replaces the one
	// in the file, which then need not be readable.
	if c.Auth.LDAP != nil && c.ldapBindPassword == "" {
		str(secretRef{field: "auth.ldap.bind_password", label: "auth.ldap.bind_password"}, &c.Auth.LDAP.BindPassword)
	}
	for i := range c.Ingest.Tokens {
		str(secretRef{field: "ingest.tokens", label: fmt.Sprintf("ingest.tokens[%d]", i), token: true}, &c.Ingest.Tokens[i])
	}
	for i := range c.Intel.Feeds {
		f := &c.Intel.Feeds[i]
		str(secretRef{field: feedField("password"), label: feedLabel(f.Name, "password"), envRefs: true, feed: f.Name}, &f.Password)
		names := make([]string, 0, len(f.Headers))
		for h := range f.Headers {
			names = append(names, h)
		}
		sort.Strings(names)
		for _, h := range names {
			m := f.Headers
			out = append(out, secretRef{field: feedField("headers." + h), label: feedLabel(f.Name, "headers."+h), envRefs: true, feed: f.Name,
				get: func() string { return m[h] }, set: func(v string) { m[h] = v }})
		}
	}
	return out
}

// isPlain reports whether a stored secret is plain text that should be
// encrypted: set, not encrypted, and not a ${ENV_VAR} reference.
func isPlain(v string, envRefs bool) bool {
	return v != "" && !secrets.IsSealed(v) && !(envRefs && len(intel.EnvRefs(v)) > 0)
}

// openSecrets decrypts the encrypted passwords and keys in c. One that
// cannot be decrypted does not stop Signalith, so a lost master key never
// takes the whole server down: it is left out, as if it were not set,
// and reported (see Unreadable). An unreadable ingest token is dropped and
// the others kept; a feed with an unreadable password or header is not
// downloaded (see FeedProblem).
func (c *Config) openSecrets() {
	c.unreadable, c.locked, c.feedLocked = nil, map[string]bool{}, map[string][]string{}
	var tokens []string
	for _, r := range c.secretRefs() {
		v := r.get()
		if !secrets.IsSealed(v) {
			if r.token {
				tokens = append(tokens, v)
			}
			continue
		}
		plain, err := c.Keyring().Open(r.field, v)
		if err != nil {
			c.unreadable = append(c.unreadable, strings.Replace(err.Error(), r.field, r.label, 1)+". "+fixHint(r, err))
			c.locked[r.field] = true
			if r.feed != "" {
				// Kept as it is: the feed is not downloaded, so it is
				// never sent.
				c.feedLocked[r.feed] = append(c.feedLocked[r.feed], r.label)
			} else if !r.token {
				r.set("")
			}
			continue
		}
		r.set(plain)
		if r.token {
			tokens = append(tokens, plain)
		}
	}
	c.Ingest.Tokens = tokens
}

// Unreadable lists the passwords and keys in signalith.yaml that cannot
// be decrypted, each with what to do about it. The server runs without
// them; Warnings include them.
func (c *Config) Unreadable() []string { return c.unreadable }

// pageProblem is a secret saved on the Settings page that cannot be
// decrypted: its setting, and what Warnings say about it.
type pageProblem struct{ key, text string }

// pageCannotOpen records that the secret saved on the Settings page for
// key cannot be decrypted (err), so it is left out.
func (c *Config) pageCannotOpen(key string, err error) {
	what := strings.Replace(err.Error(), pageField(key), key, 1)
	c.pageUnreadable = append(c.pageUnreadable, pageProblem{key: key,
		text: what + ". Enter it again on the Settings page, or remove it there or with: signalith settings reset " + key})
	field := "It cannot be decrypted with this server's master key, so it is not used. Enter it again, or reset it."
	var oe *secrets.OpenError
	if errors.As(err, &oe) {
		switch {
		case oe.Reason != "":
			field = "It cannot be decrypted (" + oe.Reason + "), so it is not used. Enter it again, or reset it."
		case oe.Have == "":
			field = "It was saved encrypted with master key " + oe.KeyID + ", and this server has no master key, so it is not used. " +
				"Restore the master key it was saved with, or enter it again."
		default:
			field = "It was saved encrypted with master key " + oe.KeyID + ", but this server's master key is " + oe.Have + ", so it is not used. " +
				"Restore the master key it was saved with, or enter it again."
		}
	}
	if c.pageLocked == nil {
		c.pageLocked = map[string]string{}
	}
	c.pageLocked[key] = field
}

// PageUnreadable lists the passwords and keys saved on the Settings page
// that cannot be decrypted, each with what to do about it. The server runs
// without them; Warnings include them.
func (c *Config) PageUnreadable() []string {
	var out []string
	for _, p := range c.pageUnreadable {
		out = append(out, p.text)
	}
	return out
}

// copyPageProblem makes what c says about the secret saved on the
// Settings page for key, whether it can be decrypted, what from says: a
// value copied from from (CopyValue) brings that with it. The lists are
// replaced, not changed in place, since a copy of c may share them.
func (c *Config) copyPageProblem(key string, from *Config) {
	if c.pageLocked[key] == "" && from.pageLocked[key] == "" {
		return
	}
	var list []pageProblem
	for _, p := range c.pageUnreadable {
		if p.key != key {
			list = append(list, p)
		}
	}
	for _, p := range from.pageUnreadable {
		if p.key == key {
			list = append(list, p)
		}
	}
	locked := maps.Clone(c.pageLocked)
	delete(locked, key)
	if msg := from.pageLocked[key]; msg != "" {
		if locked == nil {
			locked = map[string]string{}
		}
		locked[key] = msg
	}
	c.pageUnreadable, c.pageLocked = list, locked
}

// PageSecretProblem says, for the Settings page's field of key, why the
// secret saved there cannot be used: it cannot be decrypted. "" when it
// can.
func (c *Config) PageSecretProblem(key string) string { return c.pageLocked[key] }

// FeedProblem says why a feed in signalith.yaml cannot be downloaded: its
// password or a header cannot be decrypted. "" when it can.
func (c *Config) FeedProblem(name string) string {
	if l := c.feedLocked[name]; len(l) > 0 {
		return strings.Join(l, " and ") + " cannot be decrypted with this server's master key, so the feed is not downloaded. " +
			"Restore the master key, or replace the value in signalith.yaml with the plain one and run: signalith secrets encrypt"
	}
	return ""
}

// fixHint says how to enter a secret again.
func fixHint(r secretRef, err error) string {
	switch r.field {
	case "opensearch.password", "assistant.api_key", "vulns.nvd_api_key", "vulns.openvas_password", "auth.ldap.bind_password", "auth.oidc.client_secret", "m365.client_secret", "okta.api_token":
		return "Enter it again with: signalith secrets set " + r.field
	case "okta.private_key":
		return "Enter it again on the Settings page, or with: signalith secrets set okta.private_key < key.pem"
	case "ingest.tokens":
		return "Remove it from ingest.tokens and add a token with: signalith secrets set ingest.tokens"
	}
	var oe *secrets.OpenError
	if strings.HasPrefix(r.field, "intel.feeds.headers.") && errors.As(err, &oe) && oe.Reason != "" {
		return "It is tied to the header's name: if the header was renamed, change the name back. " +
			"Otherwise, replace it in signalith.yaml with the plain value, then run: signalith secrets encrypt"
	}
	return "Replace it in signalith.yaml with the plain value, then run: signalith secrets encrypt"
}

// PlainSecrets lists the passwords and keys stored as plain text in the
// file this config was loaded from, such as "opensearch.password".
func (c *Config) PlainSecrets() []string { return c.plain }

func plainLabels(refs []secretRef) []string {
	var out []string
	for _, r := range refs {
		if isPlain(r.get(), r.envRefs) {
			out = append(out, r.label)
		}
	}
	return out
}

// secretWarnings are the Warnings about stored secrets.
func (c *Config) secretWarnings() []string {
	var w []string
	for _, u := range c.unreadable {
		w = append(w, "In signalith.yaml, "+u+". Signalith runs without it until then.")
	}
	for _, u := range c.pageUnreadable {
		w = append(w, "On the Settings page ("+c.SettingsFile()+"), "+u.text+". Signalith runs without it until then.")
	}
	if n := len(c.plain); n > 0 {
		what := "passwords or keys in signalith.yaml are"
		if n == 1 {
			what = "password or key in signalith.yaml is"
		}
		how := "Run: signalith secrets encrypt"
		if inContainer() {
			how += " (in Docker, see docs/encryption.md, \"Docker\")"
		}
		w = append(w, fmt.Sprintf("%d %s stored as plain text (%s). %s", n, what, strings.Join(c.plain, ", "), how))
	}
	w = append(w, c.addressWarnings...)
	if c.path != "" {
		if src, err := c.Keyring().Source(); err == nil {
			if src.Weak() {
				w = append(w, "The master key comes from the SIGNALITH_MASTER_KEY environment variable, which other programs on this computer "+
					"can sometimes read (docker inspect, /proc). Put it in a file readable only by Signalith and set SIGNALITH_MASTER_KEY_FILE instead.")
			}
			if src.Warning != "" {
				w = append(w, src.Warning+".")
			}
		}
	}
	return w
}

// inContainer reports whether Signalith runs in a container.
func inContainer() bool { return incontainer.Here() }

// urlPassword returns the password written into a URL, if any.
func urlPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return ""
	}
	pw, _ := u.User.Password()
	return pw
}

// urlKeyParams returns the names of query parameters in a URL that look
// like they hold a key, such as apikey or token.
func urlKeyParams(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	for name := range u.Query() {
		if redact.SecretName(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// AddressSecret is a password or key written into an address in
// signalith.yaml, where it cannot be encrypted.
type AddressSecret struct {
	// Label names the setting, such as opensearch.url.
	Label string
	// Movable is set when "signalith secrets encrypt" moves it into a
	// setting of its own and encrypts it there (opensearch.url); otherwise
	// Advice says what to do instead.
	Movable bool
	Advice  string
}

// addressSecrets lists the passwords and keys written into addresses in
// c's own settings: a password in opensearch.url or opensearch.proxy, and
// a key in the query of a feed's URL.
func (c *Config) addressSecrets() []AddressSecret {
	var out []AddressSecret
	if urlPassword(c.OpenSearch.URL) != "" {
		out = append(out, AddressSecret{Label: "opensearch.url", Movable: true,
			Advice: "a password in the address; signalith secrets encrypt moves it to opensearch.password"})
	}
	if urlPassword(c.OpenSearch.Proxy) != "" {
		out = append(out, AddressSecret{Label: "opensearch.proxy",
			Advice: "a password in the address, which cannot be encrypted there; set the proxy with the SIGNALITH_OPENSEARCH_PROXY environment variable instead"})
	}
	for _, f := range c.Intel.Feeds {
		if names := urlKeyParams(f.URL); len(names) > 0 {
			out = append(out, AddressSecret{Label: feedLabel(f.Name, "url"),
				Advice: fmt.Sprintf("a key in the address (%s=), which cannot be encrypted there; if the feed accepts it, send it as a header instead (intel.feeds[].headers are encrypted)",
					strings.Join(names, "=, "))})
		}
	}
	return out
}

// AddressSecrets lists the passwords and keys written into addresses in
// the signalith.yaml text data.
func AddressSecrets(data []byte) []AddressSecret {
	c := Default()
	if yaml.Unmarshal(data, c) != nil {
		return nil
	}
	return c.addressSecrets()
}

// addressPlain splits address secrets into plain-text labels, which
// "signalith secrets encrypt" fixes, and warnings for the others.
func addressPlain(list []AddressSecret) (plain, warnings []string) {
	for _, a := range list {
		if a.Movable {
			plain = append(plain, a.Label+" (a password in the address)")
		} else {
			warnings = append(warnings, "In signalith.yaml, "+a.Label+" holds "+a.Advice+".")
		}
	}
	return plain, warnings
}

// MoveURLPassword takes a user name and password written into
// opensearch.url in the signalith.yaml text data out of the address, as
// Signalith does each time it reads the file, and writes them as
// opensearch.username and opensearch.password instead, where the password
// can be encrypted. When those are set already, the address's are not
// used, and are only removed. It reports whether it changed anything.
func MoveURLPassword(data []byte) ([]byte, bool, error) {
	type openSearch struct {
		URL      string `yaml:"url"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	}
	read := func(b []byte) (openSearch, error) {
		var f struct {
			OpenSearch openSearch `yaml:"opensearch"`
		}
		err := yaml.Unmarshal(b, &f)
		return f.OpenSearch, err
	}
	o, err := read(data)
	if err != nil {
		return nil, false, fmt.Errorf("not valid YAML: %w", err)
	}
	if urlPassword(o.URL) == "" {
		return data, false, nil
	}
	stripped, user, pw, _ := redact.Strip(o.URL)
	move := o.Username == "" && o.Password == ""
	out, err := setScalar(data, []string{"opensearch", "url"}, stripped)
	add := func(key, value string) {
		if err != nil {
			return
		}
		// Added as a line under url when there is no such key yet, so
		// nothing else in the file moves.
		if next, ok := addAfter(out, "opensearch", "url", key, value); ok {
			out = next
			return
		}
		out, err = setScalar(out, []string{"opensearch", key}, value)
	}
	// Each goes right under url: password first, so username ends up
	// above it.
	if move {
		add("password", pw)
	}
	if move && user != "" {
		add("username", user)
	}
	if err != nil {
		return nil, false, fmt.Errorf("could not move the password out of opensearch.url: %w", err)
	}
	if back, err := read(out); err != nil || back.URL != stripped || move && (back.Username != user || back.Password != pw) {
		return nil, false, errors.New("could not move the password out of opensearch.url")
	}
	return out, true, nil
}

// addAfter adds "key: value" to the section of the YAML text data, on a
// line of its own after the setting after, which must be on one line, with
// the same indentation. It does nothing (false) when the section has key
// already or the line cannot be placed; the caller then edits the
// document instead.
func addAfter(data []byte, section, after, key, value string) ([]byte, bool) {
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) == 0 {
		return nil, false
	}
	sec := mapValue(doc.Content[0], section)
	if sec == nil || sec.Kind != yaml.MappingNode || sec.Style&yaml.FlowStyle != 0 || mapValue(sec, key) != nil {
		return nil, false
	}
	var k, v *yaml.Node
	for i := 0; i+1 < len(sec.Content); i += 2 {
		if sec.Content[i].Value == after {
			k, v = sec.Content[i], sec.Content[i+1]
		}
	}
	if k == nil || v.Kind != yaml.ScalarNode || v.Line != k.Line || v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return nil, false
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if k.Line < 1 || k.Line > len(lines) {
		return nil, false
	}
	text := value
	if !plainScalar(value) {
		text = strconv.Quote(value)
	}
	var out bytes.Buffer
	for _, l := range lines[:k.Line] {
		out.Write(l)
	}
	if !bytes.HasSuffix(lines[k.Line-1], []byte("\n")) {
		out.WriteByte('\n')
	}
	out.WriteString(strings.Repeat(" ", k.Column-1) + key + ": " + text + "\n")
	for _, l := range lines[k.Line:] {
		out.Write(l)
	}
	if valueAt(out.Bytes(), []string{section, key}) != value {
		return nil, false
	}
	return out.Bytes(), true
}

// secretNode is one password or key in a YAML document of signalith.yaml.
type secretNode struct {
	field, label string
	envRefs      bool
	node         *yaml.Node
}

// mapValue returns the value of key in a YAML mapping, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// secretNodes lists the passwords and keys in a signalith.yaml document,
// in the order they appear in it.
func secretNodes(doc *yaml.Node) []secretNode {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	var out []secretNode
	add := func(field, label string, env bool, n *yaml.Node) {
		if n != nil && n.Kind == yaml.ScalarNode && n.Tag != "!!null" {
			out = append(out, secretNode{field: field, label: label, envRefs: env, node: n})
		}
	}
	add("opensearch.password", "opensearch.password", false, mapValue(mapValue(root, "opensearch"), "password"))
	add("assistant.api_key", "assistant.api_key", false, mapValue(mapValue(root, "assistant"), "api_key"))
	add("vulns.nvd_api_key", "vulns.nvd_api_key", false, mapValue(mapValue(root, "vulns"), "nvd_api_key"))
	add("vulns.openvas_password", "vulns.openvas_password", false, mapValue(mapValue(root, "vulns"), "openvas_password"))
	add("m365.client_secret", "m365.client_secret", false, mapValue(mapValue(root, "m365"), "client_secret"))
	add("okta.private_key", "okta.private_key", false, mapValue(mapValue(root, "okta"), "private_key"))
	add("okta.api_token", "okta.api_token", false, mapValue(mapValue(root, "okta"), "api_token"))
	add("auth.ldap.bind_password", "auth.ldap.bind_password", false, mapValue(mapValue(mapValue(root, "auth"), "ldap"), "bind_password"))
	add("auth.oidc.client_secret", "auth.oidc.client_secret", false, mapValue(mapValue(mapValue(root, "auth"), "oidc"), "client_secret"))
	if toks := mapValue(mapValue(root, "ingest"), "tokens"); toks != nil && toks.Kind == yaml.SequenceNode {
		for i, t := range toks.Content {
			add("ingest.tokens", fmt.Sprintf("ingest.tokens[%d]", i), false, t)
		}
	}
	if feeds := mapValue(mapValue(root, "intel"), "feeds"); feeds != nil && feeds.Kind == yaml.SequenceNode {
		for _, f := range feeds.Content {
			name := ""
			if n := mapValue(f, "name"); n != nil {
				name = n.Value
			}
			add(feedField("password"), feedLabel(name, "password"), true, mapValue(f, "password"))
			if h := mapValue(f, "headers"); h != nil && h.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(h.Content); i += 2 {
					k := h.Content[i].Value
					add(feedField("headers."+k), feedLabel(name, "headers."+k), true, h.Content[i+1])
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].node, out[j].node
		return a.Line < b.Line || a.Line == b.Line && a.Column < b.Column
	})
	return out
}

// ResealFile passes every password and key in the signalith.yaml text data
// through fn and returns the text with the values fn changed, and how many
// it changed. Each value is replaced where it stands, so comments and
// layout stay as they are; only if that is not possible (a value written
// over several lines) is the whole document written out again. Values
// that use ${ENV_VAR}, and empty ones, are not passed to fn. Settings from
// environment variables are never involved: only the text is read.
func ResealFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, 0, fmt.Errorf("not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		return data, 0, nil
	}
	nodes := secretNodes(&doc)
	want := make([]string, len(nodes))
	var changed []int
	for i, n := range nodes {
		v := n.node.Value
		want[i] = v
		if v == "" || n.envRefs && len(intel.EnvRefs(v)) > 0 {
			continue
		}
		nv, err := fn(secrets.Stored{Field: n.field, Label: n.label, Value: v})
		if err != nil {
			return nil, 0, err
		}
		if nv != v {
			want[i] = nv
			changed = append(changed, i)
		}
	}
	if len(changed) == 0 {
		return data, 0, nil
	}
	out, ok := data, true
	for _, i := range changed {
		var d yaml.Node
		if yaml.Unmarshal(out, &d) != nil {
			ok = false
			break
		}
		cur := secretNodes(&d)
		if len(cur) != len(nodes) {
			ok = false
			break
		}
		if out, ok = replaceInLine(out, cur[i].node, want[i]); !ok {
			break
		}
	}
	if ok {
		ok = secretsAre(out, want)
	}
	if !ok {
		for _, i := range changed {
			nodes[i].node.Value, nodes[i].node.Tag, nodes[i].node.Style = want[i], "!!str", 0
		}
		var err error
		if out, err = encode(&doc); err != nil {
			return nil, 0, err
		}
		if !secretsAre(out, want) {
			return nil, 0, errors.New("could not rewrite the passwords and keys in place")
		}
	}
	return out, len(changed), nil
}

// secretsAre checks that the passwords and keys in data are want, in
// order.
func secretsAre(data []byte, want []string) bool {
	var d yaml.Node
	if yaml.Unmarshal(data, &d) != nil {
		return false
	}
	got := secretNodes(&d)
	if len(got) != len(want) {
		return false
	}
	for i, n := range got {
		if n.node.Value != want[i] {
			return false
		}
	}
	return true
}

// SettableSecrets are the settings "signalith secrets set" stores.
var SettableSecrets = []string{"opensearch.password", "assistant.api_key", "vulns.nvd_api_key", "vulns.openvas_password", "auth.ldap.bind_password", "auth.oidc.client_secret", "m365.client_secret", "okta.private_key", "okta.api_token", "ingest.tokens"}

// CheckSecret checks a value "signalith secrets set" is to store as the
// setting field.
func CheckSecret(field, value string) error {
	switch field {
	case "opensearch.password", "assistant.api_key", "vulns.nvd_api_key", "vulns.openvas_password", "auth.ldap.bind_password", "auth.oidc.client_secret", "m365.client_secret", "okta.api_token":
	case "okta.private_key":
		if strings.TrimSpace(value) == "" {
			return errors.New("the private key is empty")
		}
		if err := CheckOktaPrivateKey(value); err != nil {
			return err
		}
	case "ingest.tokens":
		if len(value) < 16 {
			return errors.New("an ingest token must be at least 16 characters")
		}
	default:
		return fmt.Errorf("%s cannot be set this way; the settings are: %s", field, strings.Join(SettableSecrets, ", "))
	}
	if secrets.IsSealed(value) {
		return errors.New("the value cannot start with enc:v and a number and a colon, which is how encrypted values look")
	}
	return nil
}

// ReadForEdit reads a config file to change it, saying how to make one
// when there is none.
func ReadForEdit(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("config file %s not found; create one with: signalith init", path)
	}
	return data, err
}

// SetSecretText returns the signalith.yaml text data with stored, an
// encrypted value, as the setting field (added as another token for
// ingest.tokens), and nothing else changed.
func SetSecretText(data []byte, field, stored string) ([]byte, error) {
	switch field {
	case "opensearch.password", "assistant.api_key", "vulns.nvd_api_key", "vulns.openvas_password", "auth.oidc.client_secret", "m365.client_secret", "okta.private_key", "okta.api_token":
		return setScalar(data, strings.Split(field, "."), stored)
	case "auth.ldap.bind_password":
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("not valid YAML: %w", err)
		}
		root := &doc
		if len(root.Content) == 1 {
			root = root.Content[0]
		}
		if l := mapValue(mapValue(root, "auth"), "ldap"); l == nil || l.Kind != yaml.MappingNode {
			return nil, errors.New("signalith.yaml has no auth.ldap section, so there is no bind password to set here; " +
				"directory sign-in set up on the Users page keeps its own, which you change on that page")
		}
		return setScalar(data, strings.Split(field, "."), stored)
	case "ingest.tokens":
		return appendToken(data, stored)
	}
	return nil, fmt.Errorf("%s cannot be set this way; the settings are: %s", field, strings.Join(SettableSecrets, ", "))
}

// appendToken adds a token at the end of ingest.tokens: as a new line
// after the last token when the list is written one per line, so nothing
// else moves, or else by writing the document out again.
func appendToken(data []byte, token string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("the file is not a YAML mapping of settings")
	}
	before := len(tokenList(data))
	ingest := mapValue(root, "ingest")
	toks := mapValue(ingest, "tokens")
	if toks != nil && toks.Kind == yaml.SequenceNode && toks.Style&yaml.FlowStyle == 0 && len(toks.Content) > 0 {
		last := toks.Content[len(toks.Content)-1]
		lines := bytes.SplitAfter(data, []byte("\n"))
		if last.Kind == yaml.ScalarNode && last.Style&(yaml.LiteralStyle|yaml.FoldedStyle) == 0 && last.Line >= 1 && last.Line <= len(lines) {
			line := lines[last.Line-1]
			prefix := line[:min(len(line), byteOffset(line, last.Column))]
			if strings.TrimSpace(string(prefix)) == "-" {
				var out bytes.Buffer
				for _, l := range lines[:last.Line] {
					out.Write(l)
				}
				if !bytes.HasSuffix(line, []byte("\n")) {
					out.WriteByte('\n')
				}
				out.Write(prefix)
				out.WriteString(strconv.Quote(token) + "\n")
				for _, l := range lines[last.Line:] {
					out.Write(l)
				}
				if got := tokenList(out.Bytes()); len(got) == before+1 && got[before] == token {
					return out.Bytes(), nil
				}
			}
		}
	}
	// Otherwise change the document and write it out again (comments are
	// kept).
	if ingest == nil || ingest.Kind != yaml.MappingNode {
		if ingest != nil {
			return nil, errors.New("ingest is not a section of settings")
		}
		ingest = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ingest"}, ingest)
	}
	if toks == nil || toks.Kind != yaml.SequenceNode {
		if toks != nil && toks.Tag != "!!null" {
			return nil, errors.New("ingest.tokens is not a list")
		}
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if toks != nil {
			*toks = *seq
		} else {
			toks = seq
			ingest.Content = append(ingest.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tokens"}, toks)
		}
	}
	toks.Style &^= yaml.FlowStyle
	toks.Content = append(toks.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: token})
	out, err := encode(&doc)
	if err != nil {
		return nil, err
	}
	if got := tokenList(out); len(got) != before+1 || got[before] != token {
		return nil, errors.New("could not add the token")
	}
	return out, nil
}

// tokenList returns ingest.tokens as written in data.
func tokenList(data []byte) []string {
	var f struct {
		Ingest struct {
			Tokens []string `yaml:"tokens"`
		} `yaml:"ingest"`
	}
	yaml.Unmarshal(data, &f)
	return f.Ingest.Tokens
}
