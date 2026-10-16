package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"text/tabwriter"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const auditUsage = `Usage:
  signalith audit verify [-c file] [-from date] [-to date] [-server name] [-json]

verify checks that the audit records in OpenSearch were not changed or
removed: each server chains the records it writes and signs them with a
key derived from the cluster key (see docs/audit.md#tamper-evidence). It
reads the records of every server, or of -server alone, from -from up to
the end of -to (dates such as 2026-10-01, or RFC 3339 times), and checks
them with every cluster key this server holds.

It exits 0 when nothing was changed or removed, 2 when something was, and
1 when the records cannot be read.`

// errTampered is verify finding records changed or removed; main exits 2
// with it.
var errTampered = errors.New("audit records were changed or removed")

func cmdAudit(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New(auditUsage)
	}
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, auditUsage) }
	path := configFlag(fs)
	from := fs.String("from", "", "first day or time to check (default: the oldest record)")
	to := fs.String("to", "", "last day, or the time before which to check (default: now)")
	server := fs.String("server", "", "check this server's records only")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	fs.Parse(args[1:])
	var q audit.VerifyQuery
	var err error
	if q.From, err = parseAuditDate(*from, false); err != nil {
		return fmt.Errorf("-from: %w", err)
	}
	if q.To, err = parseAuditDate(*to, true); err != nil {
		return fmt.Errorf("-to: %w", err)
	}
	q.Server = *server
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cl := newStore(c)
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = cl.Health(hctx)
	cancel()
	if err != nil {
		return errors.New(store.Unusable(err))
	}
	keys := auditKeys(c, cliClusterKeys(c, cl))
	if keys == nil {
		fmt.Fprintln(os.Stderr, "This server holds no cluster key, so the records' MACs cannot be checked; only their links are.")
	}
	rep, err := audit.Verify(ctx, cl, c.OpenSearch.IndexPrefix, q, keys)
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		printAuditReport(os.Stdout, rep)
	}
	if rep.Tampered() {
		return errTampered
	}
	return nil
}

// cliClusterKeys returns the cluster keys the cluster uses now, as this
// server's shared runtime reads them, or nil on a server that never
// started.
func cliClusterKeys(c *config.Config, cl *store.Client) func() *shared.KeySet {
	self, err := cluster.ReadIdentity(c.StateDir())
	if err != nil {
		return nil
	}
	x := &clusterCLI{c: c, cl: cl, log: newLogger(io.Discard), self: self, out: io.Discard, errOut: io.Discard, by: cliUser()}
	rt := x.runtime(true, "")
	return func() *shared.KeySet { return rt.Hub().Keys() }
}

// parseAuditDate reads a date (2026-10-01) or an RFC 3339 time. A date
// that ends the range (end) means the end of that day.
func parseAuditDate(v string, end bool) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.DateOnly, v)
	if err != nil {
		return time.Time{}, errors.New("give a date such as 2026-10-01, or a time such as 2026-10-01T12:00:00Z")
	}
	if end {
		t = t.AddDate(0, 0, 1)
	}
	return t, nil
}

func printAuditReport(w io.Writer, r *audit.Report) {
	span := "all audit records"
	switch {
	case r.From != "" && r.To != "":
		span = "audit records from " + r.From + " to " + r.To
	case r.From != "":
		span = "audit records from " + r.From
	case r.To != "":
		span = "audit records before " + r.To
	}
	if r.Server != "" {
		span += " of " + r.Server
	}
	fmt.Fprintf(w, "Checked %d %s.\n\n", r.Records, span)
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for _, l := range []struct {
		label string
		n     int64
		what  string
	}{
		{"OK", r.OK, "signed, and linked to the record before"},
		{"Changed", r.Edited, "the MAC does not match, or a checkpoint saw otherwise"},
		{"Signature removed", r.Stripped, "not signed, though its server signed the records before: MAC removed, or put in"},
		{"Not linked", r.Broken, "a record before was changed, or one was put in"},
		{"Removed", r.Missing, "missing from a chain, and no audit.lost record names them"},
		{"Removed at the end", r.Truncated, "a checkpoint saw later records of a server than there are"},
		{"Dropped", r.Dropped, "missing, and a signed audit.lost record names them (spool full, or refused)"},
		{"Unverifiable", r.Unverifiable, "missing where nothing is signed, and only an unsigned audit.lost record names them"},
		{"Unsigned", r.Unsigned, "older, imported, or written while the server had no cluster key"},
		{"Unknown key", r.UnknownKey, "signed with a cluster key this server does not hold"},
		{"Chains started", r.Restarts, "a server's first record, or the first after it lost its spool folder"},
		{"Checkpoints", r.Checkpoints, "hourly records of each server's latest record"},
	} {
		fmt.Fprintf(tw, "  %s\t%d\t%s\n", l.label, l.n, l.what)
	}
	tw.Flush()
	if r.Limited {
		fmt.Fprintf(w, "\nThere were more records than one check reads; it stopped at %s. Check the rest with -from.\n", r.To)
	}
	if len(r.Servers) > 0 {
		fmt.Fprintln(w, "\nServers:")
		tw = tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  SERVER\tNODE\tRECORDS\tOK\tPROBLEMS\tCHAINS")
		for _, s := range r.Servers {
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\t%d\t%d\n", orDash(s.Server), s.NodeID, s.Records, s.OK, s.Problems, s.Chains)
		}
		tw.Flush()
	}
	if len(r.Problems) > 0 {
		fmt.Fprintln(w, "\nProblems:")
		for _, p := range r.Problems {
			id := ""
			if p.ID != "" {
				id = " (record " + p.ID + ")"
			}
			fmt.Fprintf(w, "  %s  %s  %s seq %d: %s%s\n", p.Time.UTC().Format(time.RFC3339), p.Kind, orDash(p.Server), p.Seq, p.Detail, id)
		}
	}
	if r.Tampered() {
		fmt.Fprintln(w, "\nAudit records were changed or removed.")
	} else {
		fmt.Fprintln(w, "\nNo audit record was changed or removed.")
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
