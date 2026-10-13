package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/content"
	"github.com/jrsamsanchez/signalith/internal/detect"
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

Content updates bring newer SigmaHQ and Splunk rules, tested and signed by
the Signalith project, without a new Signalith release. The Detections page
checks for them and takes uploads; restart Signalith after install or
remove here for a running server to use the change.
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
	output := fs.String("o", "", "bundle file to write (bundle)")
	rest := parseInterleaved(fs, args)
	dir := func() (string, error) {
		useServiceEnv(*path, out)
		c, err := config.Load(*path)
		if err != nil {
			return "", err
		}
		return filepath.Join(c.DetectionsDir(), "content"), nil
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
		b, err := content.Installed(d, content.TrustedKeys())
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
		if len(content.TrustedKeys()) == 0 {
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
		u := &content.Updater{Dir: d}
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
