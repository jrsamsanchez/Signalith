package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/jrsamsanchez/signalith/internal/upgradecheck"
)

// errNotSafe is upgrade-check's answer when a server should not be
// upgraded yet; upgradeExit turns it into exit code 3.
var errNotSafe = errors.New("not safe to upgrade the next server yet")

// exitFunc ends the process; tests replace it.
var exitFunc = os.Exit

// upgradeExit exits with 3 when err is errNotSafe, whose reasons were
// printed already, and returns any other error as it is.
func upgradeExit(err error) error {
	if errors.Is(err, errNotSafe) {
		exitFunc(3)
	}
	return err
}

// upgradeVerdict, upgradeServer and upgradeNote are upgradecheck's.
type (
	upgradeVerdict = upgradecheck.Verdict
	upgradeServer  = upgradecheck.Server
	upgradeNote    = upgradecheck.Note
)

func (x *clusterCLI) upgradeCheck(ctx context.Context, asJSON bool) error {
	in, err := upgradecheck.Read(ctx, x.cl, x.prefix(), x.self.NodeID, x.runtime(true, ""))
	if err != nil {
		return err
	}
	v := upgradecheck.Judge(in)
	if asJSON {
		enc := json.NewEncoder(x.out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
	} else {
		printUpgrade(x, v)
	}
	if !v.Safe {
		return errNotSafe
	}
	return nil
}

func printUpgrade(x *clusterCLI, v upgradeVerdict) {
	w := tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Server\tVersion\tState\tJobs\tCaught up")
	for _, s := range v.Servers {
		jobs := ""
		if s.Jobs {
			jobs = "runs them"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, upgradecheck.VersionText(s.Version), s.State, jobs, s.CaughtUp)
	}
	w.Flush()
	fmt.Fprintln(x.out)
	if v.Single {
		fmt.Fprintln(x.out, v.Next)
		return
	}
	if v.Safe {
		fmt.Fprintln(x.out, "Safe to upgrade the next server.")
	} else {
		fmt.Fprintln(x.out, "Not safe yet:")
		for _, b := range v.Blockers {
			fmt.Fprintf(x.out, "  - %s\n", b.Text)
		}
	}
	if len(v.Warnings) > 0 {
		fmt.Fprintln(x.out, "\nWarnings:")
		for _, n := range v.Warnings {
			fmt.Fprintf(x.out, "  - %s\n", n.Text)
		}
	}
	if v.Next != "" {
		fmt.Fprintf(x.out, "\n%s\n", v.Next)
	}
}
