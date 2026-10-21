// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// signalith cluster tls: the cluster's certificate authority, and the
// choice of one when the servers were set up with their own.

// tlsState reads the cluster's certificate authority, the servers'
// certificates and, while none is chosen, the candidates.
func (x *clusterCLI) tlsState(ctx context.Context) (*shared.Runtime, *clustertls.Report, error) {
	rt, st, _, err := x.tlsReport(ctx)
	return rt, st, err
}

// tlsReport is tlsState, and why the agents could not be read ("" when
// they were, or need not be).
func (x *clusterCLI) tlsReport(ctx context.Context) (*shared.Runtime, *clustertls.Report, string, error) {
	rt := x.runtime(true, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return nil, nil, "", fmt.Errorf("this server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text()))
	}
	if !rt.SharedTLS() {
		return nil, nil, "", errors.New("the cluster does not keep one certificate authority yet: every server must first be upgraded to a version that shares one")
	}
	hbs, err := x.heartbeats(ctx)
	if err != nil {
		return nil, nil, "", fmt.Errorf("the servers' heartbeats cannot be read: %w", err)
	}
	cb, _ := rt.Cluster().Get()
	in := clustertls.ReportInput{Heartbeats: hbs, Founder: cb.CreatedByID, Now: time.Now()}
	unread := ""
	b, ok := x.tls.tls.Get()
	if ok {
		in.Body = b
	}
	// The agents count while none is published (which to choose), and
	// while the published one is replaced (who has the new one).
	if !ok || b.Rotation() != clustertls.RotationNone {
		var err error
		in.Agents, _, err = (&agentinv.Inventory{Client: x.cl, Prefix: x.prefix()}).List(ctx)
		if in.Agents == nil {
			in.Agents = []agentinv.Agent{}
		}
		if err != nil {
			unread = err.Error()
		}
	}
	out := clustertls.BuildReport(in)
	return rt, out, unread, nil
}

// tlsStatus prints the cluster's certificate authority.
func (x *clusterCLI) tlsStatus(ctx context.Context, asJSON bool) error {
	_, st, unread, err := x.tlsReport(ctx)
	if err != nil {
		return err
	}
	if unread != "" {
		fmt.Fprintf(x.errOut, "warning: the agents couldn't all be read from OpenSearch, so the counts may be short: %s\n", unread)
	}
	if asJSON {
		enc := json.NewEncoder(x.out)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	w := tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	if ca := st.CA; ca != nil {
		fmt.Fprintf(w, "Certificate authority:\tthe cluster's, published by %s on %s\n", ca.PublishedBy, ca.PublishedAt.Format(time.DateOnly))
		fmt.Fprintf(w, "Fingerprint:\t%s\n", ca.CASHA256)
		if ca.KeyLost {
			fmt.Fprintf(w, "Key:\tlost with the cluster key: no server can renew its certificate until signalith cluster tls import <ca.key> gives it back\n")
		}
		fmt.Fprintf(w, "Names:\t%s\n", cmp.Or(strings.Join(ca.Names, ", "), "(none added)"))
		printRotation(w, st.Rotation)
		for i, old := range st.Retired {
			label := ""
			if i == 0 {
				label = "Retired:"
			}
			fmt.Fprintf(w, "%s\t%s (%s)\n", label, old.CASHA256, cmp.Or(old.Server, "the cluster's"))
		}
	} else {
		fmt.Fprintf(w, "Certificate authority:\tnone chosen yet; each server keeps its own\n")
	}
	w.Flush()
	fmt.Fprintln(x.out, "\nServers:")
	w = tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	for _, s := range st.Servers {
		ca := cmp.Or(s.CASHA256, "-")
		if s.Cluster {
			ca += " (the cluster's)"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", s.Name, cmp.Or(s.Mode, "-"), ca)
		if s.Problem != "" {
			fmt.Fprintf(w, "  \t\t%s\n", s.Problem)
		}
		for _, warn := range s.Warnings {
			fmt.Fprintf(w, "  \t\t%s\n", warn)
		}
	}
	w.Flush()
	if len(st.Candidates) > 0 {
		fmt.Fprintln(x.out, "\nCertificate authorities to choose from (signalith cluster tls choose <server or fingerprint>):")
		for _, c := range st.Candidates {
			mark := " "
			if c.Preselected {
				mark = "*"
			}
			off := ""
			if !c.Up {
				off = " (offline: start it to choose this one)"
			}
			fmt.Fprintf(x.out, " %s %s, used by %s%s: %d agents; %d would need a new configuration\n", mark, c.CASHA256,
				strings.Join(c.Servers, ", "), off, c.AgentCount, c.BreakCount)
			for _, u := range c.CannotCover {
				fmt.Fprintf(x.out, "     cannot sign %s's names: %s\n", u.Server, strings.Join(u.Names, ", "))
			}
		}
	}
	return nil
}

// tlsChoose asks the server holding the certificate authority what names
// (a server's name or node id, or a fingerprint) to publish it as the
// cluster's, and waits for it.
func (x *clusterCLI) tlsChoose(ctx context.Context, what string, yes bool) error {
	rt, st, unread, err := x.tlsReport(ctx)
	if err != nil {
		return err
	}
	if st.Published {
		return fmt.Errorf("the cluster already has a certificate authority (%s); to change it, replace it with signalith cluster tls rotate-ca", st.CA.CASHA256)
	}
	c, ok := st.Find(what)
	if !ok {
		return fmt.Errorf("no server seen in the last day uses a certificate authority %q names; signalith cluster tls lists them", what)
	}
	if !c.Up {
		return fmt.Errorf("%s is offline, and only a server that holds the certificate authority can publish it: start it first", strings.Join(c.Servers, ", "))
	}
	if unread != "" {
		// The counts of agents the choice breaks may be short.
		if !yes {
			return fmt.Errorf("the agents couldn't all be read from OpenSearch, so Signalith can't tell how many need a new configuration (%s). Try again, or add -yes to choose anyway", unread)
		}
		fmt.Fprintf(x.errOut, "warning: the agents couldn't all be read from OpenSearch, so the counts may be short: %s\n", unread)
	}
	q := fmt.Sprintf("Keep %s's certificate authority (%s) for the whole cluster? The other servers take it within seconds", c.Servers[0], c.CASHA256)
	if c.BreakCount > 0 {
		q += fmt.Sprintf(", and %d agents need a new configuration", c.BreakCount)
	}
	if err := x.confirm(q+".", yes); err != nil {
		return err
	}
	req, err := x.tls.tls.SubmitPublish(ctx, rt.Requests(), c.NodeIDs[0], c.CASHA256, x.by)
	if err != nil {
		return err
	}
	x.audit("asked a server to publish its certificate authority as the cluster's", "server", c.Servers[0], "ca_sha256", c.CASHA256, "request", req.ID)
	deadline := time.Now().Add(cliRequestWait)
	for {
		got, ok, err := rt.Requests().Get(ctx, req.ID)
		if err == nil && ok && got.Over() {
			if got.State == shared.RequestFailed {
				return fmt.Errorf("%s did not publish it: %s", c.Servers[0], got.Error)
			}
			fmt.Fprintf(x.out, "The cluster's certificate authority is now %s's (%s). The other servers take it within seconds.\n", c.Servers[0], c.CASHA256)
			return nil
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(x.out, "Asked %s to publish it (request %s); it has not answered yet. signalith cluster tls shows when it has.\n", c.Servers[0], req.ID)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// cliRequestWait is how long a command waits for a request it made.
var cliRequestWait = time.Minute

// errTLSUsage is the usage of signalith cluster tls.
var errTLSUsage = errors.New("usage: signalith cluster tls [-c file] [-json]\n" +
	"       signalith cluster tls choose [-c file] [-yes] <server or fingerprint>\n" +
	"       signalith cluster tls import [-c file] [-cert ca.pem] [-yes] <ca.key>\n" +
	"       signalith cluster tls rotate-ca [-c file] [-yes] prepare|switch|retire|abort")

// tlsCommand runs signalith cluster tls with its arguments.
func (x *clusterCLI) tlsCommand(ctx context.Context, pos []string, certFile string, asJSON, yes bool) error {
	switch {
	case len(pos) == 0:
		return x.tlsStatus(ctx, asJSON)
	case len(pos) == 2 && pos[0] == "choose":
		return x.tlsChoose(ctx, pos[1], yes)
	case len(pos) == 2 && pos[0] == "import":
		return x.tlsImport(ctx, pos[1], certFile, yes)
	case len(pos) == 2 && pos[0] == "rotate-ca":
		return x.tlsRotate(ctx, pos[1], yes)
	}
	return errTLSUsage
}

// rotateQuestions are what tlsRotate asks before each step.
var rotateQuestions = map[string]string{
	clustertls.StepPrepare: "Make a new certificate authority for the cluster? Every server hands it out with the one in use from now on, so agents, browsers and syslog devices can trust it before the switch.",
	clustertls.StepSwitch:  "Switch every server to the new certificate authority (%s)? Each issues itself a new certificate from it; the old one is still trusted until you retire it.",
	clustertls.StepRetire:  "Retire the old certificate authority (%s)? Its key is deleted from the shared settings, and agents that trust only it need a new configuration.",
	clustertls.StepAbort:   "Abort replacing the certificate authority? The prepared one (%s) and its key are deleted from the shared settings, and every server hands out only the one in use again.",
}

// tlsRotate takes step (prepare, switch, retire or abort) of replacing the
// cluster's certificate authority: the server that runs the background
// jobs takes it, after checking the servers again.
func (x *clusterCLI) tlsRotate(ctx context.Context, step string, yes bool) error {
	rt, st, _, err := x.tlsReport(ctx)
	if err != nil {
		return err
	}
	b, ok := x.tls.tls.Get()
	if !st.Published || !ok {
		return errors.New("the cluster has no certificate authority yet, so there is none to replace")
	}
	if err := rt.Writable(); err != nil {
		return err
	}
	var blockers []string
	if st.Rotation != nil {
		blockers = st.Rotation.Blockers
	}
	fp, err := clustertls.CheckStep(b, blockers, step)
	if errors.Is(err, clustertls.ErrBadStep) {
		return errTLSUsage
	}
	if err != nil {
		return err
	}
	q := rotateQuestions[step]
	if strings.Contains(q, "%s") {
		q = fmt.Sprintf(q, fp)
	}
	// Not a blocker: an agent that is offline, or of an older version,
	// can't say, and one that never fetches needs the file by hand anyway.
	if step == clustertls.StepSwitch && st.Rotation != nil && st.Rotation.Agents.Waiting() > 0 {
		fmt.Fprintf(x.errOut, "warning: managed agents: %s. Those without it refuse the servers after the switch until they fetch it, or you give them the file with both CAs.\n",
			agentsText(st.Rotation.Agents))
	}
	if err := x.confirm(q, yes); err != nil {
		return err
	}
	req, err := submitRotateCA(ctx, rt, step, fp, x.by)
	if err != nil {
		return err
	}
	x.audit("asked to replace the cluster's certificate authority", "step", step, "ca_sha256", fp, "request", req.ID)
	deadline := time.Now().Add(cliRequestWait)
	for {
		got, ok, err := rt.Requests().Get(ctx, req.ID)
		if err == nil && ok && got.Over() {
			if got.State == shared.RequestFailed {
				return fmt.Errorf("the %s step was not taken: %s", step, got.Error)
			}
			var res clustertls.RotateResult
			_ = json.Unmarshal(got.Result, &res)
			x.rotateDone(step, res)
			return nil
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(x.out, "Asked the server that runs the background jobs to %s (request %s); it has not answered yet. signalith cluster tls shows when it has.\n", step, req.ID)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// rotateDone says what step did, and what comes next.
func (x *clusterCLI) rotateDone(step string, res clustertls.RotateResult) {
	again := ""
	if res.Already {
		again = " (it was already)"
	}
	switch step {
	case clustertls.StepPrepare:
		fmt.Fprintf(x.out, "The cluster has a new certificate authority, %s%s. Every server hands it out with the one in use within seconds.\n", res.CASHA256, again)
		fmt.Fprintln(x.out, "Managed agents take both by themselves. Give the others, browsers and syslog devices the CA file from Add data again (both CAs), then run signalith cluster tls rotate-ca switch.")
	case clustertls.StepSwitch:
		fmt.Fprintf(x.out, "Every server now issues its certificate from the new certificate authority, %s%s, within seconds. The old one is still trusted.\n", res.CASHA256, again)
		fmt.Fprintln(x.out, "Once signalith cluster tls shows every server's certificate from it, run signalith cluster tls rotate-ca retire.")
	case clustertls.StepRetire:
		fmt.Fprintf(x.out, "The old certificate authority, %s, is retired%s: no server hands it out, and its key is gone from the shared settings.\n", res.CASHA256, again)
		fmt.Fprintln(x.out, "Copies of the old key elsewhere (backups, removed servers) no longer make certificates agents trust, once each agent has the new CA file only.")
	case clustertls.StepAbort:
		fmt.Fprintf(x.out, "Replacing the certificate authority is aborted%s: the prepared one and its key are gone, and every server hands out only the one in use within seconds.\n", again)
		fmt.Fprintln(x.out, "To replace it, run signalith cluster tls rotate-ca prepare again.")
	}
}

// printRotation prints how far replacing the cluster's certificate
// authority came.
func printRotation(w *tabwriter.Writer, r *clustertls.RotationView) {
	if r == nil {
		return
	}
	switch r.State {
	case clustertls.RotationPrepared:
		fmt.Fprintf(w, "Replacing it:\tprepared on %s by %s: %s is handed out with it\n", r.Next.At.Format(time.DateOnly), cmp.Or(r.Next.By, "-"), r.Next.CASHA256)
		if r.Next.KeyLost {
			fmt.Fprintf(w, "\tits key is lost (reset-key emptied it): signalith cluster tls rotate-ca abort, then prepare again\n")
		} else {
			fmt.Fprintf(w, "\tnext: signalith cluster tls rotate-ca switch (or abort)\n")
		}
	case clustertls.RotationSwitched:
		fmt.Fprintf(w, "Replacing it:\tswitched on %s by %s: the old one, %s, is still trusted\n", r.Previous.At.Format(time.DateOnly), cmp.Or(r.Previous.By, "-"), r.Previous.CASHA256)
		fmt.Fprintf(w, "\tnext: signalith cluster tls rotate-ca retire\n")
	default:
		return
	}
	if a := r.Agents; a != nil {
		fmt.Fprintf(w, "\tmanaged agents: %s\n", agentsText(a))
	}
	for _, b := range r.Blockers {
		fmt.Fprintf(w, "\twaiting: %s\n", b)
	}
}

// agentsText says how many managed agents have the new certificate
// authority.
func agentsText(a *clustertls.RotationAgents) string {
	t := fmt.Sprintf("%d of %d have the new certificate authority", a.HaveNew, a.Managed)
	if old := a.Managed - a.Reporting; old > 0 {
		t += fmt.Sprintf(" (%d run a version that doesn't say)", old)
	}
	return t
}
