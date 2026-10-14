package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/security"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Exit codes of signalith security: nothing at risk, something at risk.
// An error exits with 1, as every command does.
const (
	exitNothingAtRisk = 0
	exitAtRisk        = 2
)

// cmdSecurity prints the security report of the server that uses the
// config file, from the files and processes on this computer. Run beside
// the service, as root or Administrator, it checks what the service uses.
func cmdSecurity(args []string) error {
	fs := flag.NewFlagSet("security", flag.ExitOnError)
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "print the report as JSON, as GET /api/security gives it")
	fs.Parse(args)
	code, err := runSecurity(*path, *asJSON, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}
	if code != exitNothingAtRisk {
		os.Exit(code)
	}
	return nil
}

// runSecurity writes the report to out, and notes to note, and returns
// the exit code.
func runSecurity(path string, asJSON bool, out, note io.Writer) (int, error) {
	// The service's folders and master key, so this checks what it uses.
	// Notes go to note with -json, so the output stays JSON.
	info := out
	if asJSON {
		info = note
	}
	useServiceEnv(path, info)
	// What saving BitLocker's answer says goes to note, so the output is
	// the report alone.
	rep, err := securityReport(context.Background(), path, note)
	if err != nil {
		return 1, err
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep.Typographic()); err != nil {
			return 1, err
		}
	} else {
		fmt.Fprint(out, security.Text(rep))
	}
	if len(rep.AtRisk()) > 0 {
		return exitAtRisk, nil
	}
	return exitNothingAtRisk, nil
}

// securityReport gathers the facts on this computer and checks them;
// notes go to info.
func securityReport(ctx context.Context, path string, info io.Writer) (*security.Report, error) {
	c, err := config.Load(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("%w. %s", err, needAdmin)
		}
		return nil, err
	}
	h := cliHost(c, path)
	saveBitLocker(ctx, c.StateDir(), info)
	f := security.NewFacts(h, time.Now(), security.ServerInfoFor(h, cliServerName(c), version))
	cliFacts(f, c)
	f.AgentTokens = cliTokenFacts(ctx, c)
	collectors := append(security.HostCollectors(h, archiving(c)), security.OpenSearchCollectors(c, h.InContainer, c.StateDir())...)
	return security.Run(ctx, f, collectors), nil
}

// cliHost describes the server the config file is for, as seen from
// this computer: the service's environment and process when the service
// uses the same config file; in a container, process 1.
func cliHost(c *config.Config, path string) security.Host {
	inContainer := cluster.InContainer()
	svc := readServiceSettings()
	ours := svc.serves(path)
	getenv := func(k string) string {
		if ours {
			if v, ok := svc.env[k]; ok {
				return v
			}
		}
		return os.Getenv(k)
	}
	h := security.Host{Config: c, GOOS: runtime.GOOS, InContainer: inContainer,
		Docker: inContainer && security.DockerQuickStart(getenv), Getenv: getenv}
	switch {
	case inContainer:
		// The server is the container's first process.
		h.PID = "1"
	case ours:
		h.PID = serviceProcess()
		h.Systemd = runtime.GOOS == "linux"
		h.Service = runtime.GOOS == "windows"
	}
	h.Account = security.ServiceAccount(h.PID, c.StateDir())
	return h
}

// cliServerName is the server's name among those that share its
// OpenSearch, else the computer's.
func cliServerName(c *config.Config) string {
	if c.Cluster.NodeName != "" {
		return c.Cluster.NodeName
	}
	name, _ := os.Hostname()
	return name
}

// cliFacts adds what the server keeps in its files: its certificate,
// users, directory sign-in and threat intel feeds. A file this account
// may not read makes the checks that need it "can't tell".
func cliFacts(f *security.Facts, c *config.Config) {
	denied := func(err error, ids ...string) {
		if errors.Is(err, fs.ErrPermission) {
			f.Deny(ids...)
		}
	}
	if o, ok := certOptions(c); ok {
		m, err := tlsauto.Inspect(o)
		switch {
		case err == nil:
			f.TLS = security.TLSFactsFrom(m, c)
		default:
			denied(err, "transit.certificate", "transit.ca_scope")
		}
	}
	people, err := users.Open(c.UsersFile())
	if err != nil {
		denied(err, "accounts.builtin_use", "accounts.temp_passwords")
	}
	f.Users = security.UserFactsFrom(people, c.Auth.AdminUser, f.Now)
	if fromFile, err := c.LDAP(); err == nil {
		dir, err := users.OpenDirectory(c.DirectoryFile(), fromFile)
		if err == nil {
			if s := dir.Settings(); s.IsEnabled() {
				f.Directory = &s
			}
		} else {
			denied(err, "accounts.directory")
		}
	}
	feeds := &intel.Feeds{List: intelFeeds(c), File: c.IntelFeedsFile(), Log: slog.New(slog.DiscardHandler)}
	f.Feeds = security.FeedsFrom(feeds.Status())
}

// archiving reports whether a retention policy archives days.
func archiving(c *config.Config) bool {
	m := &retention.Manager{Config: c.RetentionPolicies(), Store: retention.NewStore(filepath.Join(c.LookupsDir(), "retention.yaml"))}
	s, _ := m.Settings()
	if s.Default.Archive {
		return true
	}
	for _, p := range s.Policies {
		if p.Archive {
			return true
		}
	}
	return false
}

// cliTokenFacts reads the agent tokens from OpenSearch for the check;
// when it can't, the check says so.
func cliTokenFacts(ctx context.Context, c *config.Config) *security.AgentTokenFacts {
	reg := &agenttokens.Registry{Client: newStore(c), Prefix: c.OpenSearch.IndexPrefix, Legacy: func() []agenttokens.Legacy { return api.LegacyTokens(c) }}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = reg.Load(lctx)
	return api.TokenFacts(lctx, reg)
}
