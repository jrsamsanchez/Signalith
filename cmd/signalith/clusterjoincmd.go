package main

import (
	"cmp"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// signalith cluster token and signalith cluster approve: the Servers
// page's Add a server and Approve, from the command line. Both use the
// same clusterjoin calls as the API.

// joinSecured checks the cluster's secured-OpenSearch requirement on
// this server's settings (clusterjoin.RequireSecured); tests replace it,
// since the fake OpenSearch speaks plain http.
var joinSecured = func(c *config.Config) error { return clusterjoin.ViewOf(c).Secured() }

// tokenOptions are signalith cluster token's flags.
type tokenOptions struct {
	platform, note, nodeURL, url string
	ttl                          time.Duration
}

// memberRuntime returns a read-only runtime once this server is a
// member, with the join tokens ready to be made.
func (x *clusterCLI) memberRuntime() (*shared.Runtime, error) {
	rt := x.runtime(true, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return nil, fmt.Errorf("this server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text()))
	}
	x.join.Writable = rt.Writable
	return rt, nil
}

// joinCADER is the certificate a token pins: the one this server answers
// GET /api/cluster/join/ca with, read from its HTTPS files.
func (x *clusterCLI) joinCADER() ([]byte, error) {
	o, ok := certOptions(x.c)
	if !ok {
		return nil, errors.New("this server does not serve HTTPS, so a new server could not check it: turn HTTPS on, or give the new server the cluster key with signalith cluster export-key")
	}
	m, err := tlsauto.Inspect(o)
	if err != nil {
		return nil, fmt.Errorf("this server's HTTPS certificate cannot be read (start it once with signalith serve): %w", err)
	}
	b, _ := pem.Decode(m.CAPEM())
	if b == nil {
		return nil, errors.New("this server's HTTPS certificate is not from a certificate authority a new server could check it by " +
			"(Signalith's own, or a private one whose root is in the certificate file), so it cannot make a join token. " +
			"Approve the new server by its fingerprint instead (signalith cluster approve), or give it the cluster key with signalith cluster export-key")
	}
	return b.Bytes, nil
}

// tokenHostLocal reports whether host is reached only from this
// computer.
func tokenHostLocal(host string) bool {
	ip := net.ParseIP(host)
	return loopbackHost(host) || ip != nil && ip.IsUnspecified()
}

// tokenAnswer is what signalith cluster token -json prints, the same
// fields as POST /api/cluster/tokens.
type tokenAnswer struct {
	ID        string            `json:"id"`
	Token     string            `json:"token"`
	ExpiresAt time.Time         `json:"expires_at"`
	Commands  map[string]string `json:"commands"`
}

// token makes a join token and prints it with the lines that use it.
func (x *clusterCLI) token(ctx context.Context, o tokenOptions, asJSON bool) error {
	if err := joinSecured(x.c); err != nil {
		return err
	}
	if _, err := x.memberRuntime(); err != nil {
		return err
	}
	ca, err := x.joinCADER()
	if err != nil {
		return err
	}
	u := strings.TrimSpace(o.url)
	if u == "" {
		// The settings' address, unless it is one only this computer
		// reaches.
		u, err = (&joinAPI{c: x.c}).tokenURL("")
		if p, perr := url.Parse(u); err != nil || perr != nil || tokenHostLocal(p.Hostname()) {
			return errors.New("a join token needs this server's https address that the new server reaches: give it with -url https://siem-a.example.com:8080, or set server.node_url (or server.public_url) on the Settings page")
		}
	}
	is, err := x.join.Issue(ctx, clusterjoin.IssueArgs{By: x.by, Node: x.self.Name, URL: u, CADER: ca, TTL: o.ttl,
		Platform: o.platform, Note: o.note, NodeURL: o.nodeURL})
	if err != nil {
		return err
	}
	defer is.Token.Clear()
	x.audit("join token made", "token", is.Token.ID, "platform", o.platform, "expires_at", is.ExpiresAt, "note", o.note)
	text := is.Token.String()
	linux, windows, docker := api.JoinLines(text)
	if asJSON {
		enc := json.NewEncoder(x.out)
		enc.SetIndent("", "  ")
		return enc.Encode(tokenAnswer{ID: is.Token.ID, Token: text, ExpiresAt: is.ExpiresAt,
			Commands: map[string]string{"linux": linux, "windows": windows, "docker": docker}})
	}
	fmt.Fprintf(x.out, "Join token %s, which works once, until %s:\n\n  %s\n\n", is.Token.ID, is.ExpiresAt.Local().Format("2006-01-02 15:04 MST"), text)
	fmt.Fprintf(x.out, "On the new server, once Signalith is installed:\n")
	fmt.Fprintf(x.out, "  Linux:                        %s\n", linux)
	fmt.Fprintf(x.out, "  Windows (elevated PowerShell): %s\n", windows)
	fmt.Fprintf(x.out, "  Docker (in its .env file):     %s\n", docker)
	fmt.Fprintf(x.out, "\nThe token is not shown again. To cancel it, delete it on Servers → Add a server.\n")
	return nil
}

// approve makes a server that waits for approval a member: who is its
// fingerprint, its name or its node id. A name or id asks to compare the
// fingerprint first (-yes skips that). Without who, it lists the waiting
// servers.
func (x *clusterCLI) approve(ctx context.Context, who string, yes bool) error {
	rt, err := x.memberRuntime()
	if err != nil {
		return err
	}
	a := &clusterjoin.Approver{RT: rt, Secured: func() error { return joinSecured(x.c) }, Log: x.log}
	list, err := a.Pending(ctx)
	if err != nil {
		return fmt.Errorf("the servers waiting for approval cannot be read: %w", err)
	}
	who = strings.TrimSpace(who)
	if who == "" {
		if len(list) == 0 {
			fmt.Fprintln(x.out, "No server waits for approval.")
			return nil
		}
		fmt.Fprintln(x.out, "Servers waiting for approval (approve one with signalith cluster approve <fingerprint>):")
		for _, p := range list {
			fmt.Fprintf(x.out, "  %-20s %s  %s %s/%s  %s\n", p.Name, p.Fingerprint, p.Version, p.OS, p.Arch, strings.Join(p.Addresses, ","))
		}
		return nil
	}
	var match []shared.PendingDoc
	byFingerprint := false
	for _, p := range list {
		if clusterjoin.SameFingerprint(p.Fingerprint, who) {
			match, byFingerprint = []shared.PendingDoc{p}, true
			break
		}
		if strings.EqualFold(p.Name, who) || p.NodeID == who {
			match = append(match, p)
		}
	}
	switch len(match) {
	case 0:
		return fmt.Errorf("no server waits for approval as %q: signalith cluster approve, without a server, lists those that do", who)
	case 1:
	default:
		var fps []string
		for _, p := range match {
			fps = append(fps, p.Fingerprint)
		}
		return fmt.Errorf("%d waiting servers are named %q: approve one by the fingerprint it shows (%s)", len(match), who, strings.Join(fps, ", "))
	}
	p := match[0]
	if !byFingerprint {
		q := fmt.Sprintf("Approve %s (%s/%s, %s) to join the cluster? Its fingerprint is %s: it must be the one %s shows on its sign-in page and in its log.",
			p.Name, p.OS, p.Arch, cmp.Or(strings.Join(p.Addresses, ", "), "no address given"), p.Fingerprint, p.Name)
		if err := x.confirm(q, yes); err != nil {
			return err
		}
	}
	got, err := a.Approve(ctx, p.NodeID, p.Fingerprint, x.by)
	if err != nil {
		return err
	}
	x.audit("server approved to join the cluster", "server", got.Name, "node_id", got.NodeID, "fingerprint", got.Fingerprint)
	fmt.Fprintf(x.out, "Approved %s (%s). It takes the cluster key within a minute and joins; signalith cluster status then lists it.\n", got.Name, got.Fingerprint)
	return nil
}
