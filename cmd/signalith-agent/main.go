// Command signalith-agent is the Signalith Agent, the one program a
// computer needs to send its logs to Signalith. The line from Add data >
// Signalith Agent installs it as a service; see docs/signalith-agent.md.
//
//	signalith-agent run       run the agent (what the service runs)
//	signalith-agent status    show how the agent and its collectors are
//	signalith-agent version   show the agent's version
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
	if len(args) != 1 {
		fmt.Fprint(stderr, usage)
		return errors.New("one command is needed")
	}
	paths := agentd.DefaultPaths()
	switch args[0] {
	case "run":
		a, err := newAgent(paths, stderr)
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
	settings, err := agentd.ReadSettings(paths)
	if err != nil {
		return nil, err
	}
	a := &agentd.Agent{Paths: paths, Settings: settings, Version: version,
		Log: slog.New(slog.NewTextHandler(w, nil)), Out: w}
	a.Log.Info("Signalith Agent starting", "version", version, "server", settings.Server)
	return a, nil
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
