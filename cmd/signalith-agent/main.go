// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Command signalith-agent is the Signalith Agent, the one program a
// computer needs to send its logs to Signalith. The line from Add data >
// Signalith Agent installs it as a service; see docs/signalith-agent.md.
//
//	signalith-agent run       run the agent (what the service runs)
//	signalith-agent status    show how the agent and its collectors are
//	signalith-agent version   show the agent's version
//	signalith-agent osquery-flags <in> <out>
//	                          check osquery's flags and write the checked
//	                          copy (osquery's Linux service runs this)
//	signalith-agent install-update
//	                          install a signed update the agent got
//	                          ready (the updater runs this)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jrsamsanchez/signalith/internal/agentd"
	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// version is set when the program is built (-X main.version=...).
var version = "dev"

func main() {
	// Started by Windows as the SignalithAgent service: the service
	// handler runs the agent instead of the commands.
	if runService() {
		return
	}
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "signalith-agent:", err)
		os.Exit(1)
	}
}

const usage = `usage: signalith-agent run | status | version

  run       run the agent (the service runs this)
  status    show how the agent and its collectors are
  version   show the agent's version
`

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 3 && args[0] == "osquery-flags" {
		return osqueryFlags(agentd.DefaultPaths(), args[1], args[2])
	}
	if len(args) != 1 {
		fmt.Fprint(stderr, usage)
		return errors.New("one command is needed")
	}
	paths := agentd.DefaultPaths()
	switch args[0] {
	case "install-update":
		return installUpdate(paths, stderr)
	case "run":
		a, err := newAgent(paths, agentLog(paths, stderr))
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return a.Run(ctx)
	case "status":
		return status(paths, stdout)
	case "version":
		fmt.Fprintln(stdout, version)
		return nil
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	}
	fmt.Fprint(stderr, usage)
	return fmt.Errorf("unknown command %q", args[0])
}

// newAgent reads the agent's settings and makes the agent, which logs
// to w (and passes on there what its collectors write).
func newAgent(paths agentd.Paths, w io.Writer) (*agentd.Agent, error) {
	// Checked before anything in the folders is read.
	if err := agentd.CheckFolders(paths); err != nil {
		return nil, err
	}
	settings, err := agentd.ReadSettings(paths)
	if err != nil {
		return nil, err
	}
	a := &agentd.Agent{Paths: paths, Settings: settings, Version: version,
		Log: slog.New(slog.NewTextHandler(w, nil)), Out: w}
	a.Log.Info("Signalith Agent starting", "version", version, "server", settings.Server)
	return a, nil
}

// installUpdate installs the update the agent got ready, logging to w
// (the journal on Linux, the updater's log on Windows and macOS).
func installUpdate(paths agentd.Paths, w io.Writer) error {
	if err := agentd.CheckFolders(paths); err != nil {
		return err
	}
	w = updateLog(paths, w)
	u := &agentd.Updater{Paths: paths, Version: version, Service: agentService(paths),
		Log: slog.New(slog.NewTextHandler(w, nil))}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return u.Install(ctx)
}

// osqueryFlags checks the flags file in and writes the checked copy to
// out, which osquery then runs with.
func osqueryFlags(paths agentd.Paths, in, out string) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil {
		return err
	}
	if len(b) > 64<<10 {
		return errors.New("osquery's flags file is larger than the agent writes")
	}
	text, err := agentd.CheckOsqueryFlags(paths, string(b))
	if err != nil {
		return err
	}
	_ = os.Remove(out)
	o, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := o.WriteString(text); err != nil {
		o.Close()
		return err
	}
	return o.Close()
}

// status prints what the running agent last wrote down.
func status(paths agentd.Paths, w io.Writer) error {
	b, err := os.ReadFile(paths.StatusFile())
	if err != nil {
		return fmt.Errorf("the agent has not reported yet (%w); is the Signalith Agent service running?", err)
	}
	var st agentproto.Status
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	fmt.Fprintf(w, "Signalith Agent %s on %s (%s/%s), started %s\n", st.Version, st.System, st.OS, st.Arch, st.Started)
	switch {
	case st.ConfigError != "":
		fmt.Fprintf(w, "configuration: could not get a new one: %s\n", st.ConfigError)
	case st.Revision == "":
		fmt.Fprintln(w, "configuration: none yet")
	default:
		fmt.Fprintf(w, "configuration: %s\n", st.Revision)
	}
	for _, c := range st.Components {
		v := c.Version
		if v == "" {
			v = "version unknown"
		}
		fmt.Fprintf(w, "%s (%s): %s since %s, %d restarts\n", c.Name, v, c.State, c.Since, c.Restarts)
		if c.Error != "" {
			fmt.Fprintf(w, "  %s\n", c.Error)
		}
	}
	if h, err := os.ReadFile(paths.HealthFile()); err == nil {
		fmt.Fprintf(w, "health:\n%s", h)
	}
	return nil
}
