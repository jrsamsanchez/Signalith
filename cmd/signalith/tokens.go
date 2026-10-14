package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const tokensUsage = `usage:
  signalith tokens list   [-c file] [-json] [-all]              list agent tokens (-all: revoked ones too) and shared tokens
  signalith tokens create [-c file] [-purpose linux|windows|otel|osquery] <name>   make a token and print it once
  signalith tokens rename [-c file] <id> <new name>             rename a token; events already stored keep the old name
  signalith tokens revoke [-c file] [-yes] <id or exact name>   refuse a token on every server within a few seconds
  signalith tokens legacy refuse [-c file] <id>                 stop accepting a shared token from signalith.yaml or the environment
  signalith tokens legacy accept [-c file] <id>                 accept it again

Each agent or group of agents sends with a token of its own, so one group
can be revoked without touching the others. Signalith keeps only a
fingerprint of each token, in OpenSearch, so every server that shares it
accepts the same tokens. The Add data page does the same. In Docker:
  docker compose -f deploy/docker/docker-compose.yml exec signalith signalith tokens list
`

// parseInterleaved parses flags that may come before or after the other
// arguments, which it returns.
func parseInterleaved(fs *flag.FlagSet, args []string) []string {
	var rest []string
	for {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return rest
		}
		rest = append(rest, args[0])
		args = args[1:]
	}
}

func cmdTokens(args []string) error { return runTokens(args, os.Stdin, os.Stdout, os.Stderr) }

// runTokens is cmdTokens with its input and output.
func runTokens(args []string, in *os.File, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New(tokensUsage)
	}
	sub := args[0]
	args = args[1:]
	if sub == "legacy" {
		if len(args) == 0 {
			return errors.New(tokensUsage)
		}
		sub, args = "legacy "+args[0], args[1:]
	}
	fs := flag.NewFlagSet("tokens "+sub, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(errOut, tokensUsage) }
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "list as JSON")
	all := fs.Bool("all", false, "list revoked tokens too")
	purpose := fs.String("purpose", "", "the agent the token is for: linux, windows, otel or osquery")
	yes := fs.Bool("yes", false, "revoke without asking")
	pos := parseInterleaved(fs, args)

	switch sub {
	case "list", "create", "rename", "revoke", "legacy refuse", "legacy accept":
	default:
		return fmt.Errorf("unknown tokens command %q\n\n%s", sub, tokensUsage)
	}
	useServiceEnv(*path, errOut)
	log := newLogger(errOut)
	c, err := loadConfig(*path, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	reg, err := cliTokens(ctx, c)
	if err != nil {
		return err
	}
	by := cliUser()
	audit := func(msg string, args ...any) {
		log.Info(msg, append([]any{"audit", true, "by", by}, args...)...)
	}
	switch sub {
	case "list":
		return tokensList(ctx, reg, out, *asJSON, *all)
	case "create":
		name := strings.Join(pos, " ")
		if strings.TrimSpace(name) == "" {
			return errors.New("give the token a name, such as: signalith tokens create \"Linux web servers\"")
		}
		tok, secret, err := reg.Create(ctx, name, *purpose, by)
		if err != nil {
			return err
		}
		audit("agent token created", "token_id", tok.ID, "token_name", tok.Name, "purpose", tok.Purpose)
		// Only the token on stdout, so $(signalith tokens create x) works.
		fmt.Fprintln(out, secret)
		fmt.Fprintf(errOut, "Created agent token %q (ID %s). Signalith keeps only a fingerprint of it, so this is the only time it is shown. Running servers accept it within a few seconds.\n", tok.Name, tok.ID)
		return nil
	case "rename":
		if len(pos) < 2 {
			return errors.New("usage: signalith tokens rename <id> <new name>")
		}
		tok, old, err := reg.Rename(ctx, pos[0], strings.Join(pos[1:], " "), by)
		if err != nil {
			return err
		}
		if old != tok.Name {
			audit("agent token renamed", "token_id", tok.ID, "old_name", old, "token_name", tok.Name)
		}
		fmt.Fprintf(out, "Renamed %q to %q. Events already stored keep the old name.\n", old, tok.Name)
		return nil
	case "revoke":
		if len(pos) == 0 {
			return errors.New("usage: signalith tokens revoke [-yes] <id or exact name>")
		}
		ref := strings.Join(pos, " ")
		id, ok := reg.FindByName(ref)
		if !ok {
			return fmt.Errorf("no active agent token has the ID or name %q; signalith tokens list shows them", ref)
		}
		name := reg.Name(id)
		if !*yes {
			if !term.IsTerminal(int(in.Fd())) {
				return errors.New("add -yes to revoke a token when not at a terminal")
			}
			fmt.Fprintf(errOut, "Revoke %q? Agents using it are refused within a few seconds on every server. [y/N] ", name)
			line, _ := bufio.NewReader(in).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
				return errors.New("nothing was revoked")
			}
		}
		tok, hosts, err := reg.Revoke(ctx, id, by)
		if err != nil {
			return err
		}
		audit("agent token revoked", "token_id", tok.ID, "token_name", tok.Name, "hosts_removed", hosts)
		msg := fmt.Sprintf("Revoked %q. Agents using it are refused within a few seconds on every server.", tok.Name)
		if hosts > 0 {
			msg += fmt.Sprintf(" %d osquery %s removed.", hosts, map[bool]string{true: "host was", false: "hosts were"}[hosts == 1])
		}
		fmt.Fprintln(out, msg)
		return nil
	case "legacy refuse", "legacy accept":
		if len(pos) != 1 {
			return errors.New("usage: signalith tokens " + sub + " <id>")
		}
		if sub == "legacy refuse" {
			lt, hosts, err := reg.Refuse(ctx, pos[0], by)
			if err != nil {
				return err
			}
			audit("shared agent token refused", "token_id", lt.ID, "token_name", lt.Name, "source", lt.Source, "hosts_removed", hosts)
			fmt.Fprintf(out, "%s is no longer accepted; every server refuses it within a few seconds. To remove it for good, also delete it from %s.\n", lt.Name, lt.Source)
			return nil
		}
		lt, err := reg.Accept(ctx, pos[0], by)
		if err != nil {
			return err
		}
		audit("shared agent token accepted again", "token_id", lt.ID, "token_name", lt.Name, "source", lt.Source)
		fmt.Fprintf(out, "%s is accepted again.\n", lt.Name)
		return nil
	}
	return nil
}

// cliTokens reads the agent tokens from OpenSearch, with the shared ones
// of c.
func cliTokens(ctx context.Context, c *config.Config) (*agenttokens.Registry, error) {
	cl := newStore(c)
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, herr := cl.Health(hctx)
	cancel()
	if herr != nil {
		if store.Problem(herr) == "" {
			return nil, fmt.Errorf("OpenSearch is not reachable, so agent tokens cannot be listed or changed: %w", herr)
		}
		return nil, fmt.Errorf("agent tokens cannot be listed or changed: %s", store.Unusable(herr))
	}
	reg := &agenttokens.Registry{Client: cl, Prefix: c.OpenSearch.IndexPrefix, Legacy: func() []agenttokens.Legacy { return api.LegacyTokens(c) }}
	// Revoking removes the osquery hosts enrolled with the token, as on
	// the Add data page.
	reg.OnRevoke(endpoint.NewStore(cl, c.OpenSearch.IndexPrefix).RevokeToken)
	lctx, lcancel := context.WithTimeout(ctx, 30*time.Second)
	defer lcancel()
	if err := reg.Load(lctx); err != nil {
		return nil, fmt.Errorf("the agent tokens could not be read from OpenSearch: %w", err)
	}
	return reg, nil
}

// cliUser is who changes tokens from the command line.
func cliUser() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	return "cli:" + name
}

func tokensList(ctx context.Context, reg *agenttokens.Registry, w io.Writer, asJSON, all bool) error {
	l := reg.List(ctx)
	if !all {
		active := l.Tokens[:0:0]
		for _, t := range l.Tokens {
			if t.Status == agenttokens.StateActive {
				active = append(active, t)
			}
		}
		l.Tokens = active
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(l)
	}
	when := func(t *time.Time) string {
		if t == nil || t.IsZero() {
			return "never"
		}
		return t.Local().Format("2006-01-02 15:04")
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if len(l.Tokens) == 0 {
		fmt.Fprintln(w, "No agent tokens yet. Make one with: signalith tokens create <name>, or copy an agent configuration on the Add data page.")
	} else {
		fmt.Fprintln(tw, "ID\tNAME\tSTATUS\tCREATED\tLAST USED\tEVENTS 1H")
		for _, t := range l.Tokens {
			created := t.CreatedAt
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Status, when(&created), when(t.LastUsedAt), strconv.FormatInt(t.Events1h, 10))
		}
		tw.Flush()
	}
	if len(l.Legacy) > 0 {
		fmt.Fprintln(w, "\nShared tokens (every agent that has one can send as all of them; give agents their own token, then stop accepting these):")
		tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tFROM\tSTATUS\tLAST USED\tEVENTS 1H")
		for _, t := range l.Legacy {
			status := t.Status
			if t.Public {
				status += " (public example token)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", t.ID, t.Name, t.Source, status, when(t.LastUsedAt), t.Events1h)
		}
		tw.Flush()
	}
	return nil
}
