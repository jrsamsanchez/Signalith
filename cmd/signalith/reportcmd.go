// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/jrsamsanchez/signalith/internal/casereport"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

const reportUsage = `Usage:
  signalith report verify [-c file] [-keys keys.json] [-tenant prefix] [-allow-unsigned] file
  signalith report keys [-c file] [-json]
  signalith report revoke-key [-c file] [-reason text] <key ID>

verify checks a case report exported from a case's page, the .html or the
.json file. Its signature is checked first, against the report keys of
this server (on a server on its own) or of keys.json (the list the
Investigations page's Check a report downloads, for checking on any
computer, or on a server of a cluster, whose own list may be out of date);
then the hashes of the report and of each piece of evidence, and, for the
page, that nothing on it was edited. -tenant also requires the report to
be for that tenant (its index prefix). Without a key list, or for a report
that is not signed, it can only check that the report is intact, which
does not prove who made it.

keys lists the report keys of a server on its own; a cluster's are on the
Investigations page (Check a report).

revoke-key marks a report key of a server on its own as possibly leaked,
after its master key leaked: reports it signed then no longer verify, and
it never signs again. On a cluster, an admin of the provider revokes a key
on the Investigations page.

verify exits 0 when the report verifies; 2 when it was changed, or its
signature is missing, wrong or not one of the keys; 3 when it is signed
with a revoked key; 4 when it is intact but its signature was not checked
(no key list) or it is not signed, unless -allow-unsigned is given; and 1
when the file cannot be read.`

// verify's refusals; main exits with each one's code.
var (
	errReportChanged   = errors.New("the report did not verify")
	errReportRevoked   = errors.New("the report is signed with a revoked key")
	errReportUnchecked = errors.New("the report's signature was not checked")
)

// reportExitCode is the exit code of a verify refusal, or 0 for another
// error.
func reportExitCode(err error) int {
	switch {
	case errors.Is(err, errReportRevoked):
		return 3
	case errors.Is(err, errReportUnchecked):
		return 4
	case errors.Is(err, errReportChanged):
		return 2
	}
	return 0
}

func cmdReport(args []string) error {
	if len(args) == 0 {
		return errors.New(reportUsage)
	}
	switch args[0] {
	case "verify":
		return reportVerify(args[1:], os.Stdout)
	case "keys":
		return reportKeys(args[1:], os.Stdout)
	case "revoke-key":
		return reportRevoke(args[1:], os.Stdout)
	}
	return errors.New(reportUsage)
}

// localReportKeys reads the report keys of the server on its own that
// the config at path belongs to; nil when there is no such list.
func localReportKeys(path string) ([]reportkeys.Key, string, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, "", err
	}
	file := filepath.Join(c.StateDir(), reportkeys.FileName)
	ks, err := reportkeys.Read(file)
	return ks, file, err
}

func reportVerify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("report verify", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, reportUsage) }
	path := configFlag(fs)
	keysFile := fs.String("keys", "", "check signatures against this list of report keys (from the Investigations page)")
	tenant := fs.String("tenant", "", "require the report to be for this tenant (its index prefix)")
	allowUnsigned := fs.Bool("allow-unsigned", false, "exit 0 for an intact report whose signature was not checked")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New(reportUsage)
	}
	fh, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(fh, casereport.MaxSize+1))
	fh.Close()
	if err != nil {
		return err
	}
	if len(data) > casereport.MaxSize {
		return fmt.Errorf("the file is larger than %d MiB, more than any case report", casereport.MaxSize>>20)
	}
	var ks []reportkeys.Key
	from := ""
	if *keysFile != "" {
		b, err := os.ReadFile(*keysFile)
		if err != nil {
			return err
		}
		var list struct {
			Keys []reportkeys.Key `json:"keys"`
		}
		if err := json.Unmarshal(b, &list); err != nil {
			return fmt.Errorf("%s is not a list of report keys: %w", *keysFile, err)
		}
		ks, from = list.Keys, *keysFile
	} else if local, file, err := localReportKeys(*path); err == nil && len(local) > 0 {
		ks, from = local, file
	}
	var keys casereport.Keys
	if from != "" {
		keys = reportkeys.Lookup(ks)
	}
	// With a key list, only a signed report with one of its keys verifies.
	res, err := casereport.Verify(data, keys, keys != nil)
	if err == nil && *tenant != "" && res.Report.Tenant != *tenant {
		err = fmt.Errorf("%w: it was made for tenant %q, not %q", casereport.ErrChanged, res.Report.Tenant, *tenant)
	}
	if errors.Is(err, casereport.ErrChanged) {
		fmt.Fprintln(out, "CHANGED:", err)
		return errReportChanged
	}
	if err != nil {
		return err
	}
	r := res.Report
	made := fmt.Sprintf("case %s for tenant %s, made %s by %s", r.Case.ID, r.Tenant, r.Generated.Format("2006-01-02 15:04 UTC"), r.GeneratedBy)
	switch {
	case keys != nil && res.KeyStatus == reportkeys.Revoked:
		fmt.Fprintf(out, "REVOKED: %s, signed with report key %s, which was revoked because it may have leaked: someone who had that key could have made or backdated this report.\n", made, res.KeyID)
		return errReportRevoked
	case keys != nil:
		fmt.Fprintf(out, "Verified: %s, signed with report key %s (%s, from %s).\n", made, res.KeyID, res.KeyStatus, from)
	case res.Signed:
		fmt.Fprintf(out, "Intact, signature not checked: %s. It carries a signature claiming report key %s (not checked): pass -keys with the list of report keys from the Investigations page.\n", made, res.KeyID)
	default:
		fmt.Fprintf(out, "Intact, not signed: %s. This checks the report is intact; it does not prove who made it.\n", made)
	}
	fmt.Fprintf(out, "SHA-256 %s\n", r.SHA256)
	if keys == nil && !*allowUnsigned {
		return errReportUnchecked
	}
	return nil
}

func reportKeys(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("report keys", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, reportUsage) }
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "print the list as JSON, as verify -keys reads it")
	fs.Parse(args)
	ks, file, err := localReportKeys(*path)
	if err != nil {
		return err
	}
	if *asJSON {
		if ks == nil {
			ks = []reportkeys.Key{}
		}
		b, _ := json.MarshalIndent(map[string]any{"keys": ks}, "", "  ")
		fmt.Fprintln(out, string(b))
		return nil
	}
	if len(ks) == 0 {
		fmt.Fprintf(out, "No case report was signed on this server yet (%s). A cluster's report keys are on the Investigations page.\n", file)
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY ID\tSTATUS\tFROM\tFIRST USED\tPUBLIC KEY")
	for _, k := range ks {
		fmt.Fprintf(w, "%s\t%s\t%s key\t%s\t%s\n", k.ID, k.Status(), k.Source, k.FirstUsed.Format("2006-01-02"), k.Public)
	}
	return w.Flush()
}

func reportRevoke(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("report revoke-key", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, reportUsage) }
	path := configFlag(fs)
	reason := fs.String("reason", "", "why, such as \"the master key was in a leaked backup\"")
	fs.Parse(args)
	if fs.NArg() != 1 || !reportkeys.ValidID(fs.Arg(0)) {
		return errors.New(reportUsage)
	}
	ks, file, err := localReportKeys(*path)
	if err != nil {
		return err
	}
	if len(ks) == 0 {
		return fmt.Errorf("this server keeps no report keys in %s; a cluster's are revoked on the Investigations page", file)
	}
	f := &reportkeys.File{Path: file}
	if err := f.Revoke(context.Background(), fs.Arg(0), cliUser(), *reason, time.Now()); err != nil {
		return err
	}
	fmt.Fprintf(out, "Report key %s is revoked: reports it signed no longer verify, and it signs no more. Rotate the master key too (signalith secrets rotate-master), so new reports get a new key.\n", fs.Arg(0))
	return nil
}
