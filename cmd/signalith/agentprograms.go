// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/clusterinstall"
	"github.com/jrsamsanchez/signalith/internal/content"
)

const agentProgramsUsage = `usage:
  signalith agent-programs status [-dir DIR]                 the Signalith Agent programs this server hands out, and their signed manifest
  signalith agent-programs keygen                            make the release key agents update with
  signalith agent-programs sign -version VERSION [-dir DIR]  sign the programs in DIR with the key in SIGNALITH_AGENT_KEY
  signalith agent-programs pubkey                            print the public key of SIGNALITH_AGENT_KEY

The release build signs the agent programs, so agents update themselves
only to programs from a Signalith release (docs/signalith-agent.md).
`

func cmdAgentPrograms(args []string) error { return runAgentPrograms(args, os.Stdout) }

func runAgentPrograms(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, agentProgramsUsage)
		return errors.New("an agent-programs command is required")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("agent-programs "+cmd, flag.ContinueOnError)
	fs.SetOutput(out)
	dir := fs.String("dir", "", "the folder of agent programs (default: the one this server hands out)")
	ver := fs.String("version", "", "the programs' version (sign)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		*dir = clusterinstall.DefaultProgramsDir()
	}
	// The key is the same kind as the content key, from the environment
	// only: never on the command line, where other users could read it.
	key := func() (ed25519.PrivateKey, error) {
		k := os.Getenv("SIGNALITH_AGENT_KEY")
		if k == "" {
			return nil, errors.New("SIGNALITH_AGENT_KEY is not set")
		}
		return content.ParsePrivateKey(k)
	}
	switch cmd {
	case "keygen":
		priv, pub, err := content.NewKey()
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Private key (the SIGNALITH_AGENT_KEY secret; keep it secret):\n%s\n\nPublic key (goes in internal/agentproto/release.keys):\n%s\n", priv, pub)
		return nil
	case "pubkey":
		priv, err := key()
		if err != nil {
			return err
		}
		fmt.Fprintln(out, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
		return nil
	case "sign":
		if *dir == "" {
			return errors.New("-dir is required")
		}
		priv, err := key()
		if err != nil {
			return err
		}
		// A manifest no agent trusts would only look like updates work.
		pub := priv.Public().(ed25519.PublicKey)
		if !trustedKey(pub) {
			return fmt.Errorf("key %s is not in internal/agentproto/release.keys, so agents would not trust what it signs; add its public key there: %s",
				agentproto.KeyID(pub), base64.StdEncoding.EncodeToString(pub))
		}
		m, err := clusterinstall.SignPrograms(*dir, *ver, priv)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s signed with key %s: version %s\n", agentproto.ManifestFile, agentproto.KeyID(priv.Public().(ed25519.PublicKey)), m.Version)
		printPrograms(out, m)
		return nil
	case "status":
		if *dir == "" {
			fmt.Fprintln(out, "This server has no agent programs (a development build has none).")
			return nil
		}
		p := &clusterinstall.Programs{Dir: *dir}
		fmt.Fprintf(out, "Agent programs in %s: %v\n", *dir, p.Available())
		_, _, m, err := p.Manifest()
		switch {
		case errors.Is(err, clusterinstall.ErrNoManifest) && len(agentproto.ReleaseKeys) == 0:
			fmt.Fprintln(out, "This build has no release key, so agents are offered no updates.")
		case errors.Is(err, clusterinstall.ErrNoManifest):
			fmt.Fprintln(out, "No signed manifest: agents are offered no updates.")
		case err != nil:
			fmt.Fprintf(out, "The signed manifest cannot be used, so agents are offered no updates: %v\n", err)
		default:
			fmt.Fprintf(out, "Signed manifest: version %s\n", m.Version)
			printPrograms(out, m)
		}
		return nil
	}
	fmt.Fprint(out, agentProgramsUsage)
	return fmt.Errorf("unknown agent-programs command %q", cmd)
}

// trustedKey says whether agents built from this source trust k.
func trustedKey(k ed25519.PublicKey) bool {
	for _, r := range agentproto.ReleaseKeys {
		if r.Equal(k) {
			return true
		}
	}
	return false
}

func printPrograms(out io.Writer, m *agentproto.Manifest) {
	names := make([]string, 0, len(m.Programs))
	for p := range m.Programs {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		fmt.Fprintf(out, "  %s %s\n", p, m.Programs[p])
	}
}
