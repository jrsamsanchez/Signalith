package main

// "signalith secrets" shows where the master key is and how each stored
// password or key is kept, encrypts those still in plain text, stores one
// without showing it, and changes the master key. See docs/encryption.md.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

const secretsUsage = `Usage:
  signalith secrets status         [-c file]   where the master key is, and how each password or key is stored
  signalith secrets encrypt        [-c file]   encrypt the passwords and keys stored as plain text
  signalith secrets set <setting>  [-c file]   store a password or key, encrypted; asks for it without
                                               showing it, or reads one line from a pipe
  signalith secrets rotate-master  [-c file]   make a new master key and encrypt everything again with it
  signalith secrets rotate-master -prune [-c file]   remove the previous master key once nothing uses it
  signalith secrets decrypt        [-c file]   write every stored password and key as plain text again,
                                               before going back to a version older than this one

Settings for "set": opensearch.password, assistant.api_key, auth.ldap.bind_password,
and ingest.tokens (adds a shared agent token; leave it empty to have one made).
New agents get a token of their own instead: signalith tokens create, or the
Add data page.
"encrypt" and "set" make the master key if there is none. If the files hold values
encrypted with a key that cannot be found, they stop instead; add -new-key to make a
new key anyway, when that one is lost (those values must then be entered again).
See docs/encryption.md.
`

// secretEnv are the environment variables that replace a setting "set"
// stores. Their values are used as they are and never written to a file.
var secretEnv = map[string]string{
	"opensearch.password":     "SIGNALITH_OPENSEARCH_PASSWORD",
	"assistant.api_key":       "SIGNALITH_ASSISTANT_API_KEY",
	"auth.ldap.bind_password": "SIGNALITH_LDAP_BIND_PASSWORD",
	"ingest.tokens":           "SIGNALITH_INGEST_TOKEN",
}

func cmdSecrets(args []string) error {
	return runSecrets(args, os.Stdin, os.Stdout)
}

// runSecrets runs a secrets subcommand, reading a value from in and
// writing to out.
func runSecrets(args []string, in *os.File, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, secretsUsage)
		return errors.New("name a secrets command")
	}
	sub, rest := args[0], args[1:]
	if sub == "help" || sub == "-h" || sub == "--help" {
		fmt.Fprint(out, secretsUsage)
		return nil
	}
	if !slices.Contains([]string{"status", "encrypt", "set", "rotate-master", "decrypt"}, sub) {
		fmt.Fprint(out, secretsUsage)
		return fmt.Errorf("unknown secrets command %q", sub)
	}
	fs := flag.NewFlagSet("secrets "+sub, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprint(out, secretsUsage) }
	path := configFlag(fs)
	prune, newKey := false, false
	switch sub {
	case "rotate-master":
		fs.BoolVar(&prune, "prune", false, "remove the previous master key")
	case "encrypt", "set":
		fs.BoolVar(&newKey, "new-key", false, "make a new master key even though the files hold values encrypted with one that cannot be found")
	}
	names, err := parseInterspersed(fs, rest)
	if err != nil {
		return err
	}
	if sub != "set" && len(names) > 0 {
		return fmt.Errorf("signalith secrets %s takes no arguments, only -c file", sub)
	}
	if sub == "set" {
		if len(names) != 1 {
			return fmt.Errorf("name the setting to store, one of: %s", strings.Join(config.SettableSecrets, ", "))
		}
		if !slices.Contains(config.SettableSecrets, names[0]) {
			return fmt.Errorf("%s cannot be set this way; the settings are: %s", names[0], strings.Join(config.SettableSecrets, ", "))
		}
	}
	c, err := secretsConfig(*path, out)
	if err != nil {
		return err
	}
	switch sub {
	case "status":
		return secretsStatus(c, out)
	case "encrypt":
		return secretsEncrypt(c, newKey, out)
	case "set":
		return secretsSet(c, names[0], newKey, in, out)
	case "decrypt":
		return secretsDecrypt(c, out)
	}
	if prune {
		return secretsPrune(c, out)
	}
	return secretsRotate(c, out)
}

// parseInterspersed parses flags that may come before or after the
// arguments, as in "set opensearch.password -c file", and returns the
// arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var names []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return names, nil
		}
		names = append(names, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// secretsConfig loads the config file without decrypting it, so these
// commands work even when some values cannot be decrypted, and makes its
// master key the one the other files use. On Linux the folders the
// signalith service is given in its unit are used too, so the command
// finds the server's files and key (see serviceEnv).
func secretsConfig(path string, out io.Writer) (*config.Config, error) {
	useServiceEnv(path, out)
	c, err := config.LoadUnchecked(path)
	if err != nil {
		return nil, err
	}
	keys := c.Keyring()
	keys.OnCreate = func(src secrets.Source) {
		fmt.Fprintf(out, "Made a new master key: %s.\nBack it up: without it the stored passwords and keys cannot be read (events are not affected).\n\n", src)
	}
	secrets.SetDefault(keys)
	return c, nil
}

// useServiceEnv applies the signalith service's folder, file and master
// key settings (see applyServiceEnv) and says so on out.
func useServiceEnv(path string, out io.Writer) {
	if where, set := applyServiceEnv(path); len(set) > 0 {
		fmt.Fprintf(out, "Using the settings the signalith service is given (%s):\n  %s\n\n", where, strings.Join(set, "\n  "))
	}
}

// useKeys makes the config's master key the one the files the server
// writes are encrypted with, and logs where a new one is made.
func useKeys(c *config.Config, log *slog.Logger) {
	keys := c.Keyring()
	keys.OnCreate = func(src secrets.Source) {
		log.Warn("made a new master key for the passwords and keys Signalith stores; back it up, since without it they cannot be read (events are not affected)",
			"key", src.String(), "key_id", src.KeyID)
	}
	secrets.SetDefault(keys)
}

// secretFile is a file that keeps passwords or keys.
type secretFile struct {
	path string
	// reseal passes each stored value through a secrets.Reseal.
	reseal func([]byte, secrets.Reseal) ([]byte, int, error)
	// server is true for the files the server writes. It also encrypts
	// their plain values when it starts.
	server bool
	// replace is true for a file a link in place of is replaced rather
	// than followed, as the server does (see securefile.Replace).
	replace bool
}

// secretFiles lists the files with passwords or keys (see
// config.Config.SecretFiles, which the Security page also goes by).
func secretFiles(c *config.Config) []secretFile {
	var out []secretFile
	for _, f := range c.SecretFiles() {
		out = append(out, secretFile{path: f.Path, reseal: f.Reseal, server: f.Server, replace: f.Replace})
	}
	return out
}

// writeFile replaces the file f with data, as the server writes it.
func (f secretFile) writeFile(data []byte) error {
	if f.replace {
		return securefile.Replace(f.path, data)
	}
	return securefile.WriteFile(f.path, data)
}

// listSecrets returns the values stored in a file's text.
func listSecrets(f secretFile, data []byte) ([]secrets.Stored, error) {
	return config.ListSecrets(f.reseal, data)
}

// whyUnreadable says briefly why a value cannot be decrypted.
func whyUnreadable(err error) string {
	var oe *secrets.OpenError
	switch {
	case errors.As(err, &oe) && oe.Reason != "":
		return oe.Reason
	case errors.As(err, &oe) && oe.KeyID != "":
		return "encrypted with master key " + oe.KeyID + ", which is not here"
	case err != nil:
		return err.Error()
	}
	return ""
}

func secretsStatus(c *config.Config, out io.Writer) error {
	keys := c.Keyring()
	src, err := keys.Source()
	switch {
	case errors.Is(err, secrets.ErrNoKey):
		fmt.Fprintf(out, "Master key:    none yet. Signalith makes one in %s\n               the first time it stores a password or key.\n", keys.DefaultPath())
	case err != nil:
		fmt.Fprintf(out, "Master key:    cannot be read: %v\n", err)
	default:
		fmt.Fprintf(out, "Master key:    %s, key id %s\n", src, src.KeyID)
		if src.Weak() {
			fmt.Fprintln(out, "               Warning: other programs can sometimes read environment variables;\n               put the key in a file and set SIGNALITH_MASTER_KEY_FILE instead.")
		}
		if src.Warning != "" {
			fmt.Fprintf(out, "               Warning: %s.\n", src.Warning)
		}
		switch {
		case src.OldErr != "":
			fmt.Fprintf(out, "Previous key:  %s cannot be read: %s\n", src.OldPath, src.OldErr)
		case src.OldPath != "":
			fmt.Fprintf(out, "Previous key:  %s, key id %s\n               kept after rotate-master; remove it with: signalith secrets rotate-master -prune\n", src.OldPath, src.OldKeyID)
		}
	}
	for _, p := range keys.Unused() {
		fmt.Fprintf(out, "Note:          %s is another master key, not used\n", p)
	}

	counts := map[secrets.State]int{}
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(out, "\n%s\n  not there yet\n", f.path)
			continue
		}
		if err != nil {
			return err
		}
		list, err := listSecrets(f, data)
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		fmt.Fprintf(out, "\n%s\n", f.path)
		if len(list) == 0 {
			fmt.Fprintln(out, "  no passwords or keys")
		}
		width := 0
		for _, s := range list {
			width = max(width, len(s.Label))
		}
		for _, s := range list {
			st, err := keys.Check(s.Field, s.Value)
			counts[st]++
			line := fmt.Sprintf("  %-*s  %s", width, s.Label, st)
			if st == secrets.Unreadable {
				line = fmt.Sprintf("  %-*s  cannot be decrypted: %s", width, s.Label, whyUnreadable(err))
			}
			fmt.Fprintln(out, line)
		}
		if f.path == c.Path() {
			for _, a := range config.AddressSecrets(data) {
				if a.Movable {
					counts[secrets.Plain]++
					fmt.Fprintf(out, "  %s  plain text: %s\n", a.Label, a.Advice)
				} else {
					fmt.Fprintf(out, "  %s  holds %s\n", a.Label, a.Advice)
				}
			}
		}
	}
	var env []string
	for _, name := range []string{"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_ADMIN_PASSWORD", "SIGNALITH_INGEST_TOKEN", "SIGNALITH_ASSISTANT_API_KEY", "SIGNALITH_LDAP_BIND_PASSWORD"} {
		if os.Getenv(name) != "" {
			env = append(env, name)
		}
	}
	if len(env) > 0 {
		fmt.Fprintf(out, "\nFrom this shell's environment (used as they are, never written to a file):\n  %s\n", strings.Join(env, ", "))
	}

	fmt.Fprintf(out, "\n%d encrypted", counts[secrets.Current])
	if n := counts[secrets.Previous]; n > 0 {
		fmt.Fprintf(out, ", %d with the previous master key", n)
	}
	fmt.Fprintf(out, ", %d plain text", counts[secrets.Plain])
	if n := counts[secrets.Unreadable]; n > 0 {
		fmt.Fprintf(out, ", %d cannot be decrypted", n)
	}
	fmt.Fprintln(out, ".")
	if counts[secrets.Plain]+counts[secrets.Previous] > 0 {
		fmt.Fprintln(out, "Run: signalith secrets encrypt")
	}
	if n := counts[secrets.Unreadable]; n > 0 {
		return fmt.Errorf("%d stored %s cannot be decrypted (see above): restore the master key they were encrypted with, "+
			"or enter them again (signalith secrets set, or the page where they were added)", n, plural(n, "value", "values"))
	}
	return nil
}

// sealedWithout lists the stored values encrypted with a master key, as
// "label in file (master key id)", for when there is no master key here.
func sealedWithout(c *config.Config) []string {
	var out []string
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		list, _ := listSecrets(f, data)
		for _, s := range list {
			if secrets.IsSealed(s.Value) {
				out = append(out, fmt.Sprintf("%s in %s (master key %s)", s.Label, f.path, secrets.KeyID(s.Value)))
			}
		}
	}
	return out
}

// beginFirstKey returns a new master key to encrypt with, not yet in
// place, when there is none (nil when there is one). When the files hold
// values encrypted with a key that is not found, that key is elsewhere,
// such as in a variable the service has and this shell does not, or it
// is lost; a new key is then made only with -new-key, since values would
// otherwise end up split between two keys.
func beginFirstKey(c *config.Config, newKey bool) (*secrets.Rotation, error) {
	keys := c.Keyring()
	_, err := keys.Source()
	if err == nil {
		return nil, nil
	}
	if !errors.Is(err, secrets.ErrNoKey) {
		return nil, err
	}
	if orphans := sealedWithout(c); len(orphans) > 0 && !newKey {
		return nil, fmt.Errorf("%v, but these values are encrypted with one: %s.\n"+
			"If the server gets its key from SIGNALITH_MASTER_KEY_FILE or SIGNALITH_MASTER_KEY, set the same variable here and run this again. "+
			"If that key is lost, run this again with -new-key: a new master key is made, and the values above must be entered again "+
			"(events are not affected). Nothing was changed", err, strings.Join(orphans, ", "))
	}
	return keys.BeginNew()
}

// linkNotes says, for the files of list that change, which other files
// keep their old text when they are written: other names a file has (hard
// links), and the file a link in place of one pointed to, when the link is
// replaced rather than followed (secretFile.replace). It must run before
// they are written.
func linkNotes(list []*rewrite) []string {
	var out []string
	for _, r := range list {
		if !r.changed() {
			continue
		}
		if r.replace {
			if target, ok := linkTarget(r.path); ok {
				out = append(out, replacedLinkNote(r.secretFile, target, r.old))
				continue
			}
		}
		if n := securefile.OtherLinks(r.path); n > 0 {
			out = append(out, fmt.Sprintf("Note: %s has %d other %s (hard links), which still hold its old text, with the values as they were. "+
				"Remove %s, or copy this file over %s.", r.path, n, plural(n, "name", "names"), plural(n, "it", "them"), plural(n, "it", "them")))
		}
	}
	return out
}

// linkTarget returns the file a symbolic link at path points to, when
// path is one.
func linkTarget(path string) (string, bool) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode().Type() != os.ModeSymlink {
		return "", false
	}
	if target, err := filepath.EvalSymlinks(path); err == nil {
		return target, true
	}
	target, _ := os.Readlink(path)
	return target, true
}

// replacedLinkNote says that f, a link to target, is replaced by a file of
// its own, and that target keeps old, its text, with any plain-text
// values in it.
func replacedLinkNote(f secretFile, target string, old []byte) string {
	what := "the values as they were"
	if n := plainIn(f, old); n > 0 {
		what = fmt.Sprintf("%d %s as plain text", n, plural(n, "password or key", "passwords or keys"))
	}
	return fmt.Sprintf("Note: %s was a link to %s, and is now a file of its own; %s still holds the old text, with %s. "+
		"Remove it, or copy %s over it.", f.path, target, target, what, f.path)
}

// plainIn counts the values stored as plain text in a file's text.
func plainIn(f secretFile, data []byte) int {
	list, _ := listSecrets(f, data)
	n := 0
	for _, s := range list {
		if s.Value != "" && !secrets.IsSealed(s.Value) {
			n++
		}
	}
	return n
}

// madeKey says where a new master key was made.
func madeKey(c *config.Config, out io.Writer) {
	if src, err := c.Keyring().Source(); err == nil {
		fmt.Fprintf(out, "Made a new master key: %s (key id %s).\nBack it up: without it the stored passwords and keys cannot be read (events are not affected).\n", src, src.KeyID)
	}
}

// rewrite is a file whose stored values change: n of them, and the text
// from old to new.
type rewrite struct {
	secretFile
	old, new []byte
	n        int
	pending  *securefile.Pending
}

// changed reports whether the file's text changes.
func (r *rewrite) changed() bool { return !bytes.Equal(r.old, r.new) }

// Seams for tests that make a write fail.
var (
	prepareFile    = securefile.Prepare
	prepareReplace = securefile.PrepareReplace
	commitFile     = (*securefile.Pending).Commit
)

// writeAll writes every changed file, or none. Each is first written next
// to its place, and checked not to have changed since it was read (the
// server may save one meanwhile); then key runs, if set (it puts a new
// master key in place), and the files are put in place. If one cannot be,
// those already in place get their old text back and undo runs.
func writeAll(list []*rewrite, key, undo func() error) error {
	var todo []*rewrite
	for _, r := range list {
		if r.changed() {
			todo = append(todo, r)
		}
	}
	discard := func(rs []*rewrite) {
		for _, r := range rs {
			if r.pending != nil {
				r.pending.Discard()
			}
		}
	}
	for _, r := range todo {
		prepare := prepareFile
		if r.replace {
			prepare = prepareReplace
		}
		p, err := prepare(r.path, r.new)
		if err != nil {
			discard(todo)
			if errors.Is(err, syscall.EROFS) {
				// Such as signalith.yaml in a container, mounted on its own.
				return fmt.Errorf("could not write %s: %w. Nothing was changed. Its folder is read-only here; "+
					"in Docker, run the command as docs/encryption.md shows under \"Docker\"", r.path, err)
			}
			return fmt.Errorf("could not write %s: %w. Nothing was changed", r.path, err)
		}
		r.pending = p
	}
	for _, r := range todo {
		if now, err := os.ReadFile(r.path); err != nil || !bytes.Equal(now, r.old) {
			discard(todo)
			return fmt.Errorf("%s changed while this ran (the server may have saved it). Nothing was changed; run the command again", r.path)
		}
	}
	if key != nil {
		if err := key(); err != nil {
			discard(todo)
			return fmt.Errorf("%w. Nothing was changed", err)
		}
	}
	for i, r := range todo {
		err := commitFile(r.pending)
		if err == nil {
			continue
		}
		discard(todo[i+1:])
		var stuck []string
		for _, done := range todo[:i] {
			if werr := done.writeFile(done.old); werr != nil {
				stuck = append(stuck, fmt.Sprintf("%s (%v)", done.path, werr))
			}
		}
		if undo != nil {
			if uerr := undo(); uerr != nil {
				stuck = append(stuck, uerr.Error())
			}
		}
		if len(stuck) > 0 {
			return fmt.Errorf("could not write %s: %w. Putting back what was already changed failed too: %s", r.path, err, strings.Join(stuck, "; "))
		}
		return fmt.Errorf("could not write %s: %w. Nothing was changed", r.path, err)
	}
	return nil
}

func secretsEncrypt(c *config.Config, newKey bool, out io.Writer) error {
	keys := c.Keyring()
	first, err := beginFirstKey(c, newKey)
	if err != nil {
		return err
	}
	committed := false
	seal := keys.Seal
	if first != nil {
		seal = first.Seal
		defer func() {
			if !committed {
				first.Discard()
			}
		}()
	}
	var list []*rewrite
	var unreadable []string
	moved := false
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		text := data
		if f.path == c.Path() {
			// A password in opensearch.url goes to opensearch.password
			// first, where it is encrypted with the others.
			if text, moved, err = config.MoveURLPassword(data); err != nil {
				return fmt.Errorf("%s: %w", f.path, err)
			}
		}
		next, n, err := f.reseal(text, func(s secrets.Stored) (string, error) {
			st, _ := keys.Check(s.Field, s.Value)
			switch st {
			case secrets.Plain:
				return seal(s.Field, s.Value)
			case secrets.Previous:
				plain, err := keys.Open(s.Field, s.Value)
				if err != nil {
					return "", err
				}
				return seal(s.Field, plain)
			case secrets.Unreadable:
				unreadable = append(unreadable, s.Label+" in "+f.path)
			}
			return s.Value, nil
		})
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		list = append(list, &rewrite{secretFile: f, old: data, new: next, n: n})
	}
	var key, undo func() error
	// A new key is kept only when something was encrypted with it.
	if first != nil && len(changedPaths(list)) > 0 {
		key = func() error {
			if err := first.Commit(); err != nil {
				return err
			}
			committed = true
			return nil
		}
		undo = first.Undo
	}
	notes := linkNotes(list)
	if err := writeAll(list, key, undo); err != nil {
		return err
	}
	if committed {
		first.Done()
		madeKey(c, out)
	}
	total := 0
	for _, r := range list {
		if r.n > 0 {
			fmt.Fprintf(out, "Encrypted %d %s in %s\n", r.n, plural(r.n, "value", "values"), r.path)
			total += r.n
		}
	}
	if moved {
		fmt.Fprintln(out, "The password written in opensearch.url is now opensearch.password, encrypted, and the address no longer holds it.")
	}
	if total == 0 && !moved {
		fmt.Fprintln(out, "Nothing to encrypt: every stored password and key is already encrypted with the master key in use.")
	} else if src, err := keys.Source(); err == nil && !committed {
		fmt.Fprintf(out, "Master key: %s, key id %s\n", src, src.KeyID)
	}
	if data, err := os.ReadFile(c.Path()); err == nil {
		for _, a := range config.AddressSecrets(data) {
			if !a.Movable {
				fmt.Fprintf(out, "Not encrypted: %s holds %s.\n", a.Label, a.Advice)
			}
		}
	}
	for _, n := range notes {
		fmt.Fprintln(out, n)
	}
	if len(unreadable) > 0 {
		return leftAsIs(unreadable)
	}
	return nil
}

// changedPaths lists the files of a rewrite that change.
func changedPaths(list []*rewrite) []string {
	var out []string
	for _, r := range list {
		if r.changed() {
			out = append(out, r.path)
		}
	}
	return out
}

// leftAsIs reports stored values that could not be decrypted, and so
// were not changed.
func leftAsIs(list []string) error {
	if len(list) == 1 {
		return fmt.Errorf("1 stored value cannot be decrypted and was left as it was: %s. Restore the master key it was encrypted with, or enter it again", list[0])
	}
	return fmt.Errorf("%d stored values cannot be decrypted and were left as they were: %s. Restore the master key they were encrypted with, or enter them again",
		len(list), strings.Join(list, ", "))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func secretsSet(c *config.Config, field string, newKey bool, in *os.File, out io.Writer) error {
	data, err := config.ReadForEdit(c.Path())
	if err != nil {
		return err
	}
	// The file must be one this can change, before anything is asked.
	if _, err := config.SetSecretText(data, field, "enc:v1:00000000:AAAA"); err != nil {
		return fmt.Errorf("%s: %w", c.Path(), err)
	}
	first, err := beginFirstKey(c, newKey)
	if err != nil {
		return err
	}
	seal := c.Keyring().Seal
	var key, undo func() error
	committed := false
	if first != nil {
		defer func() {
			if !committed {
				first.Discard()
			}
		}()
		seal, undo = first.Seal, first.Undo
		key = func() error {
			if err := first.Commit(); err != nil {
				return err
			}
			committed = true
			return nil
		}
	}
	label := "New value for " + field + ": "
	if field == "ingest.tokens" {
		label = "New shared agent token (press Enter to have one made): "
	}
	value, err := readSecret(in, out, label, field == "ingest.tokens")
	if err != nil {
		return err
	}
	made := value == ""
	if made {
		value = config.RandomToken(24)
	}
	if err := config.CheckSecret(field, value); err != nil {
		return err
	}
	sealed, err := seal(field, value)
	if err != nil {
		return err
	}
	next, err := config.SetSecretText(data, field, sealed)
	if err != nil {
		return fmt.Errorf("%s: %w", c.Path(), err)
	}
	list := []*rewrite{{secretFile: secretFile{path: c.Path(), reseal: config.ResealFile}, old: data, new: next, n: 1}}
	notes := linkNotes(list)
	if err := writeAll(list, key, undo); err != nil {
		return err
	}
	if committed {
		first.Done()
		madeKey(c, out)
	}
	if field == "ingest.tokens" {
		if made {
			fmt.Fprintf(out, "Added this shared agent token, encrypted, to %s:\n\n  %s\n\nIt is shown only now. Every agent that has it can send as all of them; for a token of each agent's own, use signalith tokens create or the Add data page.\n", c.Path(), value)
		} else {
			fmt.Fprintf(out, "Added the shared agent token, encrypted, to %s.\n", c.Path())
		}
	} else {
		fmt.Fprintf(out, "Saved %s, encrypted, in %s.\n", field, c.Path())
	}
	if note := pageOverrides(c, field); note != "" {
		fmt.Fprintln(out, note)
	} else {
		fmt.Fprintln(out, "Restart the server to use it.")
	}
	if note := envOverrides(c.Path(), field); note != "" {
		fmt.Fprintln(out, note)
	}
	for _, n := range notes {
		fmt.Fprintln(out, n)
	}
	return nil
}

// envOverrides says, when an environment variable that replaces field is
// set here or given to the signalith service, that the value "set" just
// saved in signalith.yaml is not used where it is set; "" when none is.
// An ingest token from the environment is accepted besides the file's, so
// it replaces nothing.
func envOverrides(path, field string) string {
	env := secretEnv[field]
	if env == "" || field == "ingest.tokens" {
		return ""
	}
	for _, name := range []string{env, env + "_FILE"} {
		if os.Getenv(name) != "" {
			return fmt.Sprintf("Note: %s is set in this environment; wherever it is set for the server, it is used instead of signalith.yaml's %s.", name, field)
		}
	}
	if name := serviceGives(path, env, env+"_FILE"); name != "" {
		return fmt.Sprintf("Note: the signalith service is given %s, which it uses instead of signalith.yaml's %s. Remove it there to use the value just saved.", name, field)
	}
	return ""
}

// pageOverrides says, when the Settings page has its own value for field,
// that the server uses that one instead of the one "set" just saved in
// signalith.yaml, even when it cannot be decrypted, and how to change
// that; "" when the page has none, or one a restart set aside.
func pageOverrides(c *config.Config, field string) string {
	s, err := config.LoadSaved(c.Path())
	if err != nil || s.Page == nil {
		return ""
	}
	e := s.Page.Settings[field]
	if e == nil || e.Refused != "" {
		return ""
	}
	note := fmt.Sprintf("Note: %s is also set on the Settings page (in %s), and the server uses that one instead of the one in signalith.yaml", field, s.SettingsFile())
	if s.PageSecretProblem(field) != "" {
		note += "; it cannot be decrypted with this master key, so until it is removed the server runs without one"
	}
	return note + ".\nTo use the one just saved, remove it on the Settings page, or run: signalith settings reset " + field + "\nThen restart the server."
}

func secretsRotate(c *config.Config, out io.Writer) error {
	keys := c.Keyring()
	before, err := keys.Source()
	if err != nil && !errors.Is(err, secrets.ErrNoKey) {
		return err
	}
	r, err := keys.BeginRotation()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			r.Discard()
		}
	}()
	var list []*rewrite
	var unreadable []string
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		next, n, err := f.reseal(data, func(s secrets.Stored) (string, error) {
			plain, err := keys.Open(s.Field, s.Value)
			if err != nil {
				unreadable = append(unreadable, s.Label+" in "+f.path)
				return s.Value, nil
			}
			return r.Seal(s.Field, plain)
		})
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		list = append(list, &rewrite{secretFile: f, old: data, new: next, n: n})
	}
	notes := linkNotes(list)
	err = writeAll(list, func() error {
		if err := r.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	}, r.Undo)
	if err != nil {
		return err
	}
	r.Done()
	fmt.Fprintf(out, "New master key %s in %s.\n", r.KeyID(), r.Path())
	for _, w := range list {
		if w.n > 0 {
			fmt.Fprintf(out, "Encrypted %d %s again in %s\n", w.n, plural(w.n, "value", "values"), w.path)
		}
	}
	fmt.Fprintf(out, "The previous key (%s) is kept as %s.old, so files saved before now can still be read.\n", before.KeyID, r.Path())
	if keyIsCredential {
		fmt.Fprintln(out, "The service gets the key as a systemd credential, which it reads only when it starts. Restart it now:\n"+
			"  sudo systemctl restart signalith\n"+
			"then encrypt anything it saved in the meantime with the new key: sudo signalith secrets encrypt")
		fmt.Fprintln(out, "Next: back up the new key; after the restart, remove the previous one with: signalith secrets rotate-master -prune")
	} else {
		fmt.Fprintln(out, "A running server picks up the new key by itself.")
		fmt.Fprintln(out, "Next: back up the new key, then remove the previous one with: signalith secrets rotate-master -prune")
	}
	for _, n := range notes {
		fmt.Fprintln(out, n)
	}
	if len(unreadable) > 0 {
		return leftAsIs(unreadable)
	}
	return nil
}

// serviceRestarted reports whether the service picked up a key file
// changed at t; tests replace it.
var serviceRestarted = serviceStartedAfter

func secretsPrune(c *config.Config, out io.Writer) error {
	keys := c.Keyring()
	src, err := keys.Source()
	if err != nil {
		return err
	}
	if src.OldPath == "" {
		fmt.Fprintln(out, "There is no previous master key to remove.")
		return nil
	}
	if src.OldErr != "" {
		// It cannot be told whether values need it, so it stays.
		return fmt.Errorf("the previous master key %s cannot be read (%s), so it cannot be checked whether stored values still need it; "+
			"it was not removed. Fix that first (signalith secrets status)", src.OldPath, src.OldErr)
	}
	var still, unknown []string
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		list, err := listSecrets(f, data)
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		for _, s := range list {
			switch st, err := keys.Check(s.Field, s.Value); {
			case st == secrets.Previous:
				still = append(still, s.Label+" in "+f.path)
			case st == secrets.Unreadable && secrets.KeyID(s.Value) != src.KeyID:
				unknown = append(unknown, fmt.Sprintf("%s in %s (%s)", s.Label, f.path, whyUnreadable(err)))
			}
		}
	}
	if len(still) > 0 {
		return fmt.Errorf("%d stored %s still %s the previous master key: %s. Run: signalith secrets encrypt, then this again",
			len(still), plural(len(still), "value", "values"), plural(len(still), "needs", "need"), strings.Join(still, ", "))
	}
	if len(unknown) > 0 {
		return fmt.Errorf("the previous master key was not removed, since %d stored %s cannot be decrypted and may need it: %s. "+
			"Enter %s again, or remove %s, then run this again", len(unknown), plural(len(unknown), "value", "values"),
			strings.Join(unknown, ", "), plural(len(unknown), "it", "them"), plural(len(unknown), "it", "them"))
	}
	if keyIsCredential {
		// The running service still has the key it read when it started;
		// until it restarts it encrypts what it saves with that one.
		st, err := os.Stat(src.Path)
		if err != nil {
			return err
		}
		if ok, err := serviceRestarted(st.ModTime()); err != nil || !ok {
			why := "the signalith service has not been restarted since the master key changed"
			if err != nil {
				why = "it cannot be told whether the signalith service was restarted since the master key changed (" + err.Error() + ")"
			}
			return fmt.Errorf("the previous master key was not removed: %s, and until then it encrypts what it saves with the previous key. "+
				"Run: sudo systemctl restart signalith, then sudo signalith secrets encrypt, then this again", why)
		}
	}
	removed, err := keys.RemoveOld()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed the previous master key %s (key id %s).\n", removed, src.OldKeyID)
	fmt.Fprintln(out, "Backups of files from before the rotation now need a backup of that key to be read.")
	return nil
}

// secretsDecrypt writes every stored password and key back as plain text,
// for going back to a version of Signalith older than this one, which
// cannot read encrypted values and would use them as they are (such as
// the directory service account's password, which could lock it out).
func secretsDecrypt(c *config.Config, out io.Writer) error {
	keys := c.Keyring()
	var list []*rewrite
	var unreadable []string
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		next, n, err := f.reseal(data, func(s secrets.Stored) (string, error) {
			if !secrets.IsSealed(s.Value) {
				return s.Value, nil
			}
			plain, err := keys.Open(s.Field, s.Value)
			if err != nil {
				unreadable = append(unreadable, s.Label+" in "+f.path)
				return s.Value, nil
			}
			return plain, nil
		})
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		list = append(list, &rewrite{secretFile: f, old: data, new: next, n: n})
	}
	notes := linkNotes(list)
	if err := writeAll(list, nil, nil); err != nil {
		return err
	}
	total := 0
	for _, r := range list {
		if r.n > 0 {
			fmt.Fprintf(out, "Decrypted %d %s in %s\n", r.n, plural(r.n, "value", "values"), r.path)
			total += r.n
		}
	}
	for _, n := range notes {
		fmt.Fprintln(out, n)
	}
	if total == 0 {
		fmt.Fprintln(out, "Nothing to decrypt.")
	} else {
		fmt.Fprintln(out, "These files now hold passwords and keys as plain text. Put the older version in place before the server starts again: "+
			"this version encrypts its own files again when it starts or saves them.")
	}
	if len(unreadable) > 0 {
		return fmt.Errorf("%d stored %s cannot be decrypted and %s left as %s: %s. Enter %s again after going back",
			len(unreadable), plural(len(unreadable), "value", "values"), plural(len(unreadable), "was", "were"),
			plural(len(unreadable), "it was", "they were"), strings.Join(unreadable, ", "), plural(len(unreadable), "it", "them"))
	}
	return nil
}

// encryptStores encrypts the plain values (and those still under the
// previous master key) in the files the server writes, once at startup.
// signalith.yaml is never changed by the server; Warnings report its plain
// values instead.
func encryptStores(c *config.Config, log *slog.Logger) {
	keys := c.Keyring()
	for _, f := range secretFiles(c) {
		if !f.server {
			continue
		}
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		next, n, err := f.reseal(data, func(s secrets.Stored) (string, error) {
			switch st, _ := keys.Check(s.Field, s.Value); st {
			case secrets.Plain:
				return keys.Seal(s.Field, s.Value)
			case secrets.Previous:
				plain, err := keys.Open(s.Field, s.Value)
				if err != nil {
					return s.Value, nil
				}
				return keys.Seal(s.Field, plain)
			}
			return s.Value, nil
		})
		if err != nil {
			log.Warn("could not encrypt the passwords and keys in a file; they stay as they are", "file", f.path, "err", err)
			continue
		}
		if n == 0 {
			continue
		}
		target, link := "", false
		if f.replace {
			target, link = linkTarget(f.path)
		}
		if err := f.writeFile(next); err != nil {
			log.Warn("could not encrypt the passwords and keys in a file; they stay as they are until it can be written", "file", f.path, "err", err)
			continue
		}
		log.Info("encrypted the passwords and keys stored in a file", "file", f.path, "values", n)
		if link {
			// The link was replaced by the encrypted file; the file it
			// pointed to keeps the values as they were.
			log.Warn("the file was a link, and is now a file of its own; the file it pointed to still holds the old text, "+
				"with the values as they were (plain_values of them as plain text): remove it", "file", f.path, "link_target", target, "plain_values", plainIn(f, data))
		}
	}
}
