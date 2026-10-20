// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/content"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/keytrust"
)

const contentUsage = `usage:
  signalith content status  [-c file]               the content pack version in use and any installed update
  signalith content install [-c file] <bundle>      install an update from a file (its signature is <bundle>.sig),
                                                    such as on a computer without internet access
  signalith content remove  [-c file]               go back to the rules built into Signalith
  signalith content keygen                          make a signing key for the content workflow
  signalith content bundle  -packs DIR -o FILE      make a bundle from a packs folder (internal/detect/packs)
  signalith content sign    FILE                    sign a bundle with the key in SIGNALITH_CONTENT_KEY, writing FILE.sig
  signalith content pubkey                          print the public key of SIGNALITH_CONTENT_KEY
  signalith content revocations [-c file]           the signing keys revoked on this server
  signalith content import-revocations [-c file] <list>
                                                    keep a signed revocation list (its signature is <list>.sig),
                                                    such as on a computer without internet access
  signalith content revoke -o FILE [-from FILE] [-note TEXT] <key ID>...
                                                    write a revocation list signed with the root key in
                                                    SIGNALITH_ROOT_KEY, adding to the list in -from

Content updates bring newer SigmaHQ and Splunk rules, tested and signed by
the Signalith project, without a new Signalith release. The Detections page
checks for them and takes uploads; restart Signalith after install or
remove here for a running server to use the change.

A signing key that leaked is revoked with a list signed by the project's
offline root key; servers download it next to the content updates and hand
it to their agents. See docs/key-management.md.
`

func cmdContent(args []string) error { return runContent(args, os.Stdout) }

func runContent(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, contentUsage)
		return errors.New("a content command is required")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("content "+cmd, flag.ContinueOnError)
	fs.SetOutput(out)
	path := configFlag(fs)
	packs := fs.String("packs", "internal/detect/packs", "packs folder (bundle)")
	output := fs.String("o", "", "file to write (bundle, revoke)")
	from := fs.String("from", "", "revocation list to add to (revoke)")
	note := fs.String("note", "", "why the keys are revoked (revoke)")
	rest := parseInterleaved(fs, args)
	var revocations *keytrust.Store
	dir := func() (string, error) {
		useServiceEnv(*path, out)
		c, err := config.Load(*path)
		if err != nil {
			return "", err
		}
		revocations = &keytrust.Store{Dir: filepath.Join(c.StateDir(), "keytrust")}
		return filepath.Join(c.DetectionsDir(), "content"), nil
	}
	// trusted are the content keys this server trusts: built in, plus the
	// root keys, less the keys revoked.
	trusted := func() ([]ed25519.PublicKey, error) {
		list, _, _, err := revocations.Load()
		return keytrust.Trusted(content.TrustedKeys(), keytrust.RevokedIDs(list)), err
	}
	switch cmd {
	case "keygen":
		priv, pub, err := content.NewKey()
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Private key (the SIGNALITH_CONTENT_KEY secret; keep it secret):\n%s\n\nPublic key (goes in internal/content/trusted.keys):\n%s\n", priv, pub)
		return nil
	case "bundle":
		if *output == "" {
			return errors.New("-o is required")
		}
		data, m, err := content.Build(*packs, time.Now())
		if err != nil {
			return err
		}
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: version %s, %d bytes\n", *output, m.Version, len(data))
		for _, p := range m.Packs {
			fmt.Fprintf(out, "  %s: %d rules (%s)\n", p.Name, p.Rules, p.Version)
		}
		return nil
	case "pubkey":
		priv, err := content.ParsePrivateKey(os.Getenv("SIGNALITH_CONTENT_KEY"))
		if err != nil {
			return err
		}
		fmt.Fprintln(out, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
		return nil
	case "sign":
		if len(rest) != 1 {
			return errors.New("name the bundle to sign")
		}
		key := os.Getenv("SIGNALITH_CONTENT_KEY")
		if key == "" {
			return errors.New("SIGNALITH_CONTENT_KEY is not set")
		}
		priv, err := content.ParsePrivateKey(key)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(rest[0])
		if err != nil {
			return err
		}
		if err := os.WriteFile(rest[0]+".sig", content.Sign(priv, data), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s.sig written with key %s\n", rest[0], content.KeyID(priv.Public().(ed25519.PublicKey)))
		return nil
	case "status":
		d, err := dir()
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Rules built into this Signalith: %s\n", detect.BuiltinContentVersion())
		keys, err := trusted()
		if err != nil {
			fmt.Fprintf(out, "The kept revocation list cannot be read: %v\n", err)
		}
		b, err := content.Installed(d, keys)
		switch {
		case err != nil:
			fmt.Fprintf(out, "Installed update in %s cannot be used: %v\n", d, err)
		case b == nil:
			fmt.Fprintln(out, "No content update installed.")
		default:
			fmt.Fprintf(out, "Installed update: %s (%s)\n", b.Manifest.Version, d)
			for _, p := range b.Manifest.Packs {
				fmt.Fprintf(out, "  %s: %d rules (%s)\n", p.Name, p.Rules, p.Version)
			}
			if b.Manifest.Version < detect.BuiltinContentVersion() {
				fmt.Fprintln(out, "It is older than the rules built into Signalith, which are used.")
			}
		}
		if len(keys) == 0 {
			fmt.Fprintln(out, "This build has no key to check content updates with, so it cannot take any.")
		}
		return nil
	case "install":
		if len(rest) != 1 {
			return errors.New("name the bundle to install; its signature must be next to it, ending in .sig")
		}
		d, err := dir()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(rest[0])
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(rest[0] + ".sig")
		if err != nil {
			return fmt.Errorf("the signature: %w", err)
		}
		u := &content.Updater{Dir: d, Revocations: revocations}
		u.Start()
		st, err := u.Install(data, sig)
		if errors.Is(err, content.ErrNotNewer) {
			fmt.Fprintf(out, "Nothing to do: the rules in use (%s) are as new or newer.\n", st.Version)
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Installed content update %s in %s.", st.Version, d)
		if st.Skipped > 0 {
			fmt.Fprintf(out, " %d rules need a newer Signalith and are left out.", st.Skipped)
		}
		fmt.Fprintln(out, " Restart Signalith to use it, or upload it on the Detections page instead.")
		return nil
	case "revocations":
		if _, err := dir(); err != nil {
			return err
		}
		return printRevocations(out, revocations)
	case "import-revocations":
		if len(rest) != 1 {
			return errors.New("name the revocation list to import; its signature must be next to it, ending in .sig")
		}
		d, err := dir()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(rest[0])
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(rest[0] + ".sig")
		if err != nil {
			return fmt.Errorf("the signature: %w", err)
		}
		kept, err := revocations.Offer(data, sig)
		if err != nil {
			return err
		}
		if !kept {
			fmt.Fprintln(out, "Nothing to do: the list kept here is as new or newer.")
			return nil
		}
		fmt.Fprintln(out, "Revocation list kept.")
		if keys, err := trusted(); err == nil {
			if _, err := content.Installed(d, keys); err != nil {
				if err := content.Remove(d); err != nil {
					return err
				}
				fmt.Fprintln(out, "The installed content update was signed with a revoked key and is removed.")
			}
		}
		fmt.Fprintln(out, "Restart Signalith for a running server to use it; it hands the list to its agents.")
		return printRevocations(out, revocations)
	case "revoke":
		return writeRevocations(out, rest, *output, *from, *note)
	case "remove":
		d, err := dir()
		if err != nil {
			return err
		}
		if err := content.Remove(d); err != nil {
			return err
		}
		fmt.Fprintln(out, "Content update removed. Restart Signalith to use the rules built into it.")
		return nil
	}
	return fmt.Errorf("unknown content command %q\n\n%s", cmd, contentUsage)
}

// printRevocations lists the keys revoked on this server.
func printRevocations(out io.Writer, store *keytrust.Store) error {
	list, _, _, err := store.Load()
	if err != nil {
		return err
	}
	if len(keytrust.Roots) == 0 {
		fmt.Fprintln(out, "This build has no root key, so it cannot take revocation lists.")
	}
	if list != nil {
		fmt.Fprintf(out, "Revocation list issued %s.\n", list.Issued.UTC().Format(time.RFC3339))
	}
	ids := keytrust.RevokedIDs(list)
	if len(ids) == 0 {
		fmt.Fprintln(out, "No signing keys are revoked.")
		return nil
	}
	fmt.Fprintln(out, "Revoked signing keys:")
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		why := "built in"
		if list != nil {
			for _, r := range list.Revoked {
				if r.ID == id {
					why = r.Note
				}
			}
		}
		fmt.Fprintf(out, "  %s  %s\n", id, why)
	}
	return nil
}

var keyIDRE = regexp.MustCompile(`^[0-9a-f]{12}$`)

// writeRevocations writes a revocation list with the keys in ids added to
// the one in from, signed with the root key in SIGNALITH_ROOT_KEY.
func writeRevocations(out io.Writer, ids []string, output, from, note string) error {
	if output == "" {
		return errors.New("-o is required")
	}
	if len(ids) == 0 {
		return errors.New("name the key IDs to revoke (the first word of a .sig file)")
	}
	priv, err := content.ParsePrivateKey(os.Getenv("SIGNALITH_ROOT_KEY"))
	if err != nil {
		return fmt.Errorf("SIGNALITH_ROOT_KEY: %w", err)
	}
	root := priv.Public().(ed25519.PublicKey)
	list := keytrust.List{Format: keytrust.Format}
	if from != "" {
		data, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(from + ".sig")
		if err != nil {
			return fmt.Errorf("the signature of %s: %w", from, err)
		}
		old, err := keytrust.Verify([]ed25519.PublicKey{root}, data, sig)
		if err != nil {
			return fmt.Errorf("%s: %w", from, err)
		}
		list = *old
	}
	for _, id := range ids {
		switch {
		case !keyIDRE.MatchString(id):
			return fmt.Errorf("%q is not a key ID: a key ID is 12 hex digits, the first word of a .sig file", id)
		case id == keytrust.KeyID(root) || slices.ContainsFunc(keytrust.Roots, func(k ed25519.PublicKey) bool { return keytrust.KeyID(k) == id }):
			return fmt.Errorf("%s is a root key, which a list cannot revoke; ship a release without it instead", id)
		case slices.ContainsFunc(list.Revoked, func(r keytrust.RevokedKey) bool { return r.ID == id }):
			continue
		}
		list.Revoked = append(list.Revoked, keytrust.RevokedKey{ID: id, Note: note})
	}
	// Newer than the list it adds to, or servers keep the old one.
	prev := list.Issued
	if list.Issued = time.Now().UTC().Truncate(time.Second); !list.Issued.After(prev) {
		list.Issued = prev.Add(time.Second)
	}
	// A list issued in the future (made -from one) makes every list after
	// it carry that time on, so each must be made -from the one before.
	future := list.Issued.After(time.Now().Add(time.Hour))
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := keytrust.Verify([]ed25519.PublicKey{root}, data, keytrust.Sign(priv, data)); err != nil {
		return err
	}
	if err := os.WriteFile(output, data, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(output+".sig", keytrust.Sign(priv, data), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s and %s.sig written with root key %s: %d keys revoked.\n", output, output, keytrust.KeyID(root), len(list.Revoked))
	if future {
		fmt.Fprintf(out, "Warning: this list is issued %s, in the future; make every later list with -from, or servers keep this one.\n", list.Issued.Format(time.RFC3339))
	}
	if !slices.ContainsFunc(keytrust.Roots, func(k ed25519.PublicKey) bool { return keytrust.KeyID(k) == keytrust.KeyID(root) }) {
		fmt.Fprintln(out, "Warning: this build does not trust that root key; servers will refuse the list.")
	}
	return nil
}
