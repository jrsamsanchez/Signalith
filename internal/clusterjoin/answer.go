// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterjoin

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// The answering side of POST /api/cluster/join: a member checks the
// joining server's proof against a token, uses the token once, and
// answers with a Bundle sealed to the joiner's node key and the token's
// secret.

// View is what the answering server copies into a bundle from its own
// settings.
type View struct {
	// OpenSearch is the answering server's own OpenSearch settings, and
	// URL the address a new server is given (cluster.opensearch_url when
	// set, else opensearch.url); URLs are further addresses
	// (opensearch.urls, once it exists).
	OpenSearch config.OpenSearch
	URL        string
	URLs       []string
	PublicURL  string
	Listen     string
	// AgentListen is server.agent_listen as it was set, "" when it was
	// worked out from the listen address.
	AgentListen string
	Syslog      SyslogDefaults
}

// ViewOf returns the view of the configuration c.
func ViewOf(c *config.Config) View {
	return View{OpenSearch: c.OpenSearch, URL: cmp.Or(strings.TrimSpace(c.Cluster.OpenSearchURL), c.OpenSearch.URL),
		PublicURL: c.Server.PublicURL, Listen: c.Server.Listen, AgentListen: agentListenSet(c),
		Syslog: SyslogDefaults{UDP: c.Syslog.UDP, TCP: c.Syslog.TCP, TLS: c.Syslog.TLS}}
}

// Secured checks the cluster's secured-OpenSearch requirement on the
// view: its own OpenSearch, and the address new servers are given.
func (v View) Secured() error {
	return RequireSecured(v.OpenSearch, append([]string{v.URL}, v.URLs...)...)
}

// OSCredential is how a new server signs in to OpenSearch.
type OSCredential struct {
	CAPEM         string
	Username      string
	Password      string
	ClientCertPEM string
	// ClientKeyPEM is the issuer's own key, sent only when the
	// certificate is the issuer's (not Managed).
	ClientKeyPEM string
	// Managed: the certificate was issued for the key of the new server's
	// own CSR. Shared: the new server uses the issuer's credential.
	Managed bool
	Shared  bool
}

// CredentialFunc gives the new server name, with node id nodeID, its
// OpenSearch credential; csrPEM is its own OpenSearch client CSR, or nil. The OpenSearch
// identity per server (the cluster's osca) replaces DefaultCredential
// through Deps.Credential.
type CredentialFunc func(ctx context.Context, name, nodeID string, csrPEM []byte) (OSCredential, error)

// DefaultCredential gives every new server the answering server's own
// credential: its password, or its client certificate and key, with the
// certificate authority of OpenSearch's certificate. The bundle then says
// the credential is shared.
func DefaultCredential(view func() View) CredentialFunc {
	return func(context.Context, string, string, []byte) (OSCredential, error) {
		o := view().OpenSearch
		cr := OSCredential{Username: o.Username, Password: o.Password, Shared: true}
		read := func(what, path string) (string, error) {
			if path == "" {
				return "", nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("could not read OpenSearch's %s (%s): %w", what, path, err)
			}
			return string(b), nil
		}
		var err error
		if cr.CAPEM, err = read("certificate authority", o.CAFile); err != nil {
			return cr, err
		}
		if o.CertFile != "" && o.KeyFile != "" {
			if cr.ClientCertPEM, err = read("client certificate", o.CertFile); err != nil {
				return cr, err
			}
			if cr.ClientKeyPEM, err = read("client key", o.KeyFile); err != nil {
				return cr, err
			}
		}
		return cr, nil
	}
}

// LeafFunc signs the new server's HTTPS certificate from the cluster's
// certificate authority, for the key of csrPEM and the names given (those
// the certificate authority may sign). It returns the certificate
// authority and the certificate in PEM, or nil, nil, nil when the cluster
// keeps no certificate authority (the new server then makes its own).
type LeafFunc func(csrPEM []byte, names []string) (caPEM, leafPEM []byte, err error)

// Deps is what Answer needs.
type Deps struct {
	RT     *shared.Runtime
	Tokens *Tokens
	// Version is the answering server's version.
	Version string
	View    func() View
	// IssueLeaf signs the new server's HTTPS certificate; nil gives none.
	IssueLeaf LeafFunc
	// Credential gives the new server its OpenSearch credential; nil is
	// DefaultCredential.
	Credential CredentialFunc
	Log        *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (d *Deps) log() *slog.Logger {
	if d.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return d.Log
}

// ErrUnavailable: this server cannot answer joins now (it is not a
// member, or OpenSearch failed). The joining server may try again or try
// another server; nothing about the token is said.
var ErrUnavailable = errors.New("this server cannot answer a join now; try again in a minute, or make the token on another server")

// RefusedError is a refused join whose reason the joining server learns
// only as Refused (an unknown, used or expired token, a wrong proof or a
// request that is not one); Reason is for the server log.
type RefusedError struct{ Reason error }

func (e *RefusedError) Error() string { return Refused }
func (e *RefusedError) Unwrap() error { return e.Reason }

// JoinError is a join refused for a reason the joining server is told,
// once it proved it holds the token's secret (a version that cannot join,
// or an OpenSearch without security). The token stays usable.
type JoinError struct{ Msg string }

func (e *JoinError) Error() string { return e.Msg }

// unavailable wraps err as ErrUnavailable for the caller, keeping err for
// the log.
type unavailable struct{ err error }

func (e *unavailable) Error() string { return ErrUnavailable.Error() }
func (e *unavailable) Unwrap() []error {
	return []error{ErrUnavailable, e.err}
}

// ErrSpent: the token was used, but the answering server could not finish
// the join. The joining server needs a new token.
var ErrSpent = errors.New("The token was used, but this server could not finish the join (its log says why). Make a new token, then run signalith join again.")

// spent wraps err as ErrSpent for the caller, keeping err for the log.
type spent struct{ err error }

func (e *spent) Error() string { return ErrSpent.Error() }
func (e *spent) Unwrap() []error {
	return []error{ErrSpent, e.err}
}

// Reason is the real reason of a refused or failed join, for the server
// log.
func Reason(err error) string {
	var r *RefusedError
	var u *unavailable
	var sp *spent
	switch {
	case errors.As(err, &r) && r.Reason != nil:
		return r.Reason.Error()
	case errors.As(err, &u) && u.err != nil:
		return u.err.Error()
	case errors.As(err, &sp) && sp.err != nil:
		return sp.err.Error()
	case err != nil:
		return err.Error()
	}
	return ""
}

// ClashError is a server that would take another member's place in the
// keyring: its node id is listed with another node key (a copied state
// folder, or someone posing as that member), or another member has its
// name. Error is for an admin who approves it, Joiner for the server that
// joins.
type ClashError struct {
	NodeID, Name string
	// SameName: another member has the name; otherwise the node id is
	// listed with another node key.
	SameName bool
}

func (e *ClashError) Error() string {
	if e.SameName {
		return fmt.Sprintf("Another server in the cluster is named %s already: the waiting server needs another name.", e.Name)
	}
	return fmt.Sprintf("The cluster lists %s (node id %s) with another node key, so this server cannot take its place. "+
		"A server rebuilt with the same identity is removed from the cluster first; a copied state folder needs a new node.id.", cmp.Or(e.Name, "a server"), e.NodeID)
}

// Joiner is the text the joining server gets.
func (e *ClashError) Joiner() string {
	if e.SameName {
		return fmt.Sprintf("Another server in the cluster is named %s already: give this one another name (signalith join --name), then run signalith join again.", e.Name)
	}
	return fmt.Sprintf("The cluster lists a server with this server's identity (node id %s, %s) and another node key. "+
		"Its state folder may have been copied from that server: run signalith cluster new-identity on this server, then run signalith join again. "+
		"If that server was rebuilt, remove it from the cluster first (signalith cluster remove).", e.NodeID, cmp.Or(e.Name, "no name"))
}

// memberClash refuses the server nodeID, named name, with the node key
// nodePub (base64), when it would replace or pose as another member of
// the keyring kb. The same server with the same key again is no clash.
func memberClash(kb *shared.KeyringBody, nodeID, name, nodePub string) error {
	if kb == nil {
		return nil
	}
	if m, ok := kb.Members[nodeID]; ok && m.NodePub != nodePub {
		return &ClashError{NodeID: nodeID, Name: m.Name}
	}
	for id, m := range kb.Members {
		if id != nodeID && m.Name != "" && strings.EqualFold(m.Name, name) {
			return &ClashError{NodeID: id, Name: m.Name, SameName: true}
		}
	}
	return nil
}

// sameMachine reports whether ip is an address of this machine: the
// loopback, or one of its interfaces.
func sameMachine(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// localOnlyHost reports whether host names this machine only: localhost
// or a loopback or unspecified address.
func localOnlyHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// checkIssuer checks, once the proof matched and before the token is
// used, what the answering server needs to give the new server its
// settings: OpenSearch's address must be one the new server can reach
// (not this machine's loopback when it joins from another machine), and
// this server's own OpenSearch certificate files must be readable. A
// failure leaves the token usable.
func (d *Deps) checkIssuer(req *Request, view View) error {
	if !sameMachine(req.RemoteIP) {
		for _, u := range append([]string{view.URL}, view.URLs...) {
			if p, err := url.Parse(u); err == nil && localOnlyHost(p.Hostname()) {
				return &JoinError{Msg: fmt.Sprintf("The cluster gives new servers the OpenSearch address %s, which only the server that answered reaches. "+
					"Set cluster.opensearch_url on its Settings page to the address other servers reach OpenSearch at, then run signalith join again: the token was not used.", u)}
			}
		}
	}
	o := view.OpenSearch
	for _, f := range []struct{ what, path string }{{"certificate authority", o.CAFile}, {"client certificate", o.CertFile}, {"client key", o.KeyFile}} {
		if f.path == "" {
			continue
		}
		if _, err := os.ReadFile(f.path); err != nil {
			d.log().Error("cannot answer a join: this server cannot read its own OpenSearch "+f.what, "file", f.path, "err", err)
			return &JoinError{Msg: "The server that answered cannot read its own OpenSearch " + f.what + " file, so it cannot give this server its OpenSearch settings. " +
				"Fix that on it (its log names the file), then run signalith join again: the token was not used."}
		}
	}
	return nil
}

// checkJoiner checks what the joining server says of itself against
// this cluster: its version must read the cluster's level, and be the
// answering server's own unless it asked to skip that.
func checkJoiner(req *Request, version string, level int) error {
	if req.LevelMax < level {
		return &JoinError{Msg: fmt.Sprintf("Signalith %s cannot join this cluster, which needs a newer version: install Signalith %s on this server first.", req.Version, version)}
	}
	if req.Version != version && !req.AllowVersionSkew {
		return &JoinError{Msg: fmt.Sprintf("This server runs Signalith %s, and the cluster runs %s: install Signalith %s first (or run signalith join with --allow-version-skew).",
			req.Version, version, version)}
	}
	return nil
}

// leafNames are the names the new server's HTTPS certificate is asked
// for: its name, and the host of the address the other servers reach it
// at.
func leafNames(req *Request) []string {
	names := []string{strings.ToLower(req.Name)}
	if req.NodeURL != "" {
		if u, err := url.Parse(req.NodeURL); err == nil && u.Hostname() != "" {
			names = append(names, strings.ToLower(u.Hostname()))
		}
	}
	for _, n := range req.Names {
		names = append(names, strings.ToLower(n))
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// checkCSR checks that s is one PEM certificate request, or empty.
func checkCSR(s string) error {
	if s == "" {
		return nil
	}
	b, rest := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "" {
		return errors.New("a certificate request is not one PEM CERTIFICATE REQUEST")
	}
	return nil
}

// Answer answers a join request: it checks the request's form, then uses
// the token once with the joining server's proof (Tokens.Consume), checks
// the joining version, and returns the bundle sealed to the joining
// server. Its errors are *RefusedError (answer Refused), *JoinError (say
// it), or ErrUnavailable; Reason gives the log the real one. The token's
// secret never leaves this function.
func Answer(ctx context.Context, d Deps, req *Request) (string, error) {
	if err := d.RT.Writable(); err != nil {
		return "", &unavailable{err}
	}
	p, err := req.Check()
	if err == nil {
		err = cmp.Or(checkCSR(req.CSRPEM), checkCSR(req.OSCSRPEM))
	}
	if err != nil {
		return "", &RefusedError{Reason: err}
	}
	if req.NodeID == d.RT.Self().NodeID {
		return "", &RefusedError{Reason: errors.New("the joining server has this server's node id")}
	}
	cb, ok := d.RT.Cluster().Get()
	if !ok || cb == nil {
		return "", &unavailable{errors.New("the cluster document is not read")}
	}
	view := d.View()
	// Checked only once the proof matched, so a caller without the token
	// learns nothing: what else is wrong leaves the token unused.
	var after error
	consumed, err := d.Tokens.Consume(ctx, req.TokenID, UsedBy{NodeID: req.NodeID, Name: req.Name}, func(secret []byte) bool {
		if !CheckProof(secret, req.TokenID, p.Nonce, p.NodePub, p.Proof) {
			return false
		}
		if after = cmp.Or(checkJoiner(req, d.Version, cb.Level), secured(view), d.checkIssuer(req, view), d.clash(req, p), d.rotating()); after != nil {
			return false
		}
		return true
	})
	if after != nil && errors.Is(err, ErrProof) {
		return "", after
	}
	switch {
	case err == nil:
	case errors.Is(err, ErrTokenUnknown), errors.Is(err, ErrTokenExpired), errors.Is(err, ErrTokenUsed), errors.Is(err, ErrProof):
		return "", &RefusedError{Reason: err}
	default:
		return "", &unavailable{err}
	}
	defer consumed.Clear()
	sealed, err := d.bundle(ctx, req, p, cb, view, consumed)
	if err != nil {
		// The token is used: the joining server needs a new one.
		d.log().Error("cluster.join failed after the token was used; the new server needs a new token", "audit", true,
			"token", req.TokenID, "node_id", req.NodeID, "name", req.Name, "err", err)
		return "", &spent{err}
	}
	d.log().Info("cluster.join: a server joined the cluster with a join token", "audit", true,
		"token", req.TokenID, "node_id", req.NodeID, "name", req.Name, "version", req.Version, "os", req.OS, "arch", req.Arch,
		"fingerprint", shared.Fingerprint(p.NodePub), "token_by", consumed.Body.CreatedBy)
	return sealed, nil
}

// clash is memberClash on the keyring this server has read, as a
// JoinError: checked before the token is used, and again when the keyring
// is written.
func (d *Deps) clash(req *Request, p Parsed) error {
	kb, _ := d.RT.Keyring().Get()
	var ce *ClashError
	if err := memberClash(kb, req.NodeID, req.Name, base64.StdEncoding.EncodeToString(p.NodePub)); errors.As(err, &ce) {
		return &JoinError{Msg: ce.Joiner()}
	}
	return nil
}

// ErrRotating: a key rotation is in progress. A server that joined now
// would get the key being replaced and no copy of the new one.
var ErrRotating = errors.New("the cluster key is being rotated: add the server once the rotation ends (signalith cluster rotate-key shows it)")

// rotating refuses a join while the cluster key is being rotated.
func rotating(kb *shared.KeyringBody) error {
	if kb == nil {
		return nil
	}
	if n, err := kb.Rotation(); err != nil || n != nil {
		return ErrRotating
	}
	return nil
}

// rotating is rotating as a JoinError: the token stays unused.
func (d *Deps) rotating() error {
	kb, _ := d.RT.Keyring().Get()
	if err := rotating(kb); err != nil {
		return &JoinError{Msg: err.Error()}
	}
	return nil
}

// secured is the view's secured-OpenSearch check as a JoinError.
func secured(v View) error {
	if err := v.Secured(); err != nil {
		return &JoinError{Msg: err.Error()}
	}
	return nil
}

// bundle lists the new server in the keyring and seals its bundle.
func (d *Deps) bundle(ctx context.Context, req *Request, p Parsed, cb *shared.ClusterBody, view View, c *Consumed) (string, error) {
	k := d.RT.Hub().Keys().Active()
	if k == nil {
		return "", errors.New("this server has no cluster key")
	}
	raw, err := base64.StdEncoding.DecodeString(k.Text())
	if err != nil {
		return "", err
	}
	defer clear(raw)
	credential := d.Credential
	if credential == nil {
		credential = DefaultCredential(d.View)
	}
	var osCSR []byte
	if req.OSCSRPEM != "" {
		osCSR = []byte(req.OSCSRPEM)
	}
	cr, err := credential(ctx, req.Name, req.NodeID, osCSR)
	if err != nil {
		return "", fmt.Errorf("the new server's OpenSearch credential: %w", err)
	}
	b := &Bundle{ClusterID: cb.ClusterID, ClusterName: cb.Name, IndexPrefix: cmp.Or(cb.IndexPrefix, view.OpenSearch.IndexPrefix),
		OpenSearch: OpenSearch{URL: view.URL, URLs: view.URLs, CAPEM: cr.CAPEM, Username: cr.Username, Password: cr.Password,
			ClientCertPEM: cr.ClientCertPEM, ClientKeyPEM: cr.ClientKeyPEM, Managed: cr.Managed, Shared: cr.Shared},
		KID: k.ID(), ClusterKey: raw, PublicURL: view.PublicURL, NodeName: req.Name, Listen: view.Listen, AgentListen: view.AgentListen,
		IssuerVersion: d.Version, Level: cb.Level, Role: c.Body.Role}
	if req.CopySyslog {
		s := view.Syslog
		b.Syslog = &s
	}
	if d.IssueLeaf != nil && req.CSRPEM != "" {
		ca, leaf, err := d.IssueLeaf([]byte(req.CSRPEM), leafNames(req))
		if err != nil {
			// The new server makes its own certificate authority then,
			// and takes the cluster's at its first start.
			d.log().Warn("could not issue the joining server's HTTPS certificate from the cluster's certificate authority; it makes its own until it takes the cluster's",
				"name", req.Name, "err", err)
		} else if len(ca) > 0 && len(leaf) > 0 {
			b.ClusterCAPEM, b.LeafPEM = string(ca), string(leaf)
		}
	}
	nodePub := base64.StdEncoding.EncodeToString(p.NodePub)
	m := shared.KeyringMember{Name: req.Name, NodePub: nodePub, Fingerprint: shared.Fingerprint(p.NodePub),
		AddedAt: d.now().Format(time.RFC3339Nano), AddedBy: shared.AddedByJoin}
	// The keyring is written again on a passing OpenSearch failure: the
	// token is used already.
	var err2 error
	for try := range 3 {
		if try > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(try) * time.Second):
			}
		}
		_, err2 = d.RT.Keyring().Mutate(ctx, systemUser, func(kb *shared.KeyringBody) error {
			if err := cmp.Or(memberClash(kb, req.NodeID, req.Name, nodePub), rotating(kb)); err != nil {
				return err
			}
			if kb.Members == nil {
				kb.Members = map[string]shared.KeyringMember{}
			}
			if old, there := kb.Members[req.NodeID]; !there || old.NodePub != nodePub {
				kb.Members[req.NodeID] = m
			}
			b.Servers = len(kb.Members)
			return nil
		})
		var ce *ClashError
		if err2 == nil || errors.As(err2, &ce) || errors.Is(err2, ErrRotating) {
			break
		}
	}
	if err2 != nil {
		return "", fmt.Errorf("could not list the new server in the keyring: %w", err2)
	}
	return Seal(b, p.NodePub, req.NodeID, req.TokenID, c.Secret)
}

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

// agentListenSet is server.agent_listen as it was set, "" when it was
// worked out from the listen address.
func agentListenSet(c *config.Config) string {
	if c.AgentListenDerived() {
		return ""
	}
	return c.Server.AgentListen
}
