// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustertls

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// Replacing the cluster's certificate authority takes the steps a server
// of its own takes on its Security page (internal/tlsauto, rotate.go),
// for every server at once, in the tls document:
//
//  1. prepare: a next certificate authority, made like the one in use
//     (same template and name constraints), is added with its key sealed
//     like the other's. Every server hands it out with the one in use:
//     Add data, the CA file, and the configuration managed agents fetch,
//     which keep it over the connection they already trust.
//  2. switch: once every server running hands it out, the next one
//     becomes the one in use. Each server issues itself a certificate from
//     it; the one before is still handed out, and its key kept.
//  3. retire: once every server running serves a certificate from the new
//     one, the old one is dropped with its key and listed as retired.
//
// Each step is a request the server that runs the background jobs runs
// (RequestRotateCA), which checks again that the servers are ready.

// RequestRotateCA asks the server that runs the background jobs to take
// a step of replacing the cluster's certificate authority.
const RequestRotateCA = "tls_rotate_ca"

// Steps of replacing the cluster's certificate authority.
const (
	StepPrepare = "prepare"
	StepSwitch  = "switch"
	StepRetire  = "retire"
)

// States of replacing the cluster's certificate authority.
const (
	RotationNone     = "none"
	RotationPrepared = "prepared"
	RotationSwitched = "switched"
)

// RotateArgs are the arguments of a tls_rotate_ca request.
type RotateArgs struct {
	Step string `json:"step"`
	// CASHA256 is the certificate authority the step was asked for: the
	// next one for switch, the previous one for retire, the one in use
	// for prepare. A step whose certificate authority changed since is
	// refused.
	CASHA256 string `json:"ca_sha256,omitempty"`
}

// RotateResult is what a tls_rotate_ca request did.
type RotateResult struct {
	Step     string `json:"step"`
	CASHA256 string `json:"ca_sha256"`
	// Already is true when the step was taken before.
	Already bool `json:"already,omitempty"`
}

// ErrRetireFirst: a new certificate authority cannot be prepared while
// the one a switch replaced is still kept.
var ErrRetireFirst = errors.New("the certificate authority the last switch replaced is still trusted: retire it first (signalith cluster tls rotate-ca retire)")

// errNoCA: the cluster has no certificate authority to replace.
var errNoCA = errors.New("the cluster has no certificate authority yet, so there is none to replace")

// Rotation returns the state of replacing the cluster's certificate
// authority.
func (b *Body) Rotation() string {
	switch {
	case b.Next != nil:
		return RotationPrepared
	case b.Previous != nil:
		return RotationSwitched
	}
	return RotationNone
}

// clusterCA is o for tlsauto, nil for none.
func (o *OtherCA) clusterCA() *tlsauto.ClusterCA {
	if o == nil {
		return nil
	}
	c, err := o.Cert()
	if err != nil {
		return nil
	}
	return &tlsauto.ClusterCA{Cert: c, At: o.At}
}

// Others returns the cluster's next and previous certificate authorities
// for tlsauto (Manager.SetClusterCAs), nil for none.
func (t *TLS) Others() (next, previous *tlsauto.ClusterCA) {
	b, ok := t.Get()
	if !ok {
		return nil, nil
	}
	return b.Next.clusterCA(), b.Previous.clusterCA()
}

// caName is the name of a certificate authority made for the cluster.
func caName(now time.Time) string {
	return "Signalith Cluster CA (" + now.UTC().Format(time.DateOnly) + ")"
}

// PrepareNext makes the certificate authority that will replace the
// cluster's, as the user by asked, and adds it to the
// tls document as the next one with its key sealed with the cluster key,
// bound to its fingerprint. cur, when not "", is the fingerprint of the
// certificate authority in use the admin saw. When one is prepared
// already it changes nothing and reports already.
func (t *TLS) PrepareNext(ctx context.Context, by, cur string) (fp string, already bool, err error) {
	h, d, err := t.parts()
	if err != nil {
		return "", false, err
	}
	b, ok := d.Get()
	if !ok || b.CASHA256 == "" {
		return "", false, errNoCA
	}
	if cur != "" && !SameFingerprint(cur, b.CASHA256) {
		return "", false, fmt.Errorf("the cluster's certificate authority changed (it is now %s); look again", b.CASHA256)
	}
	if b.Next != nil {
		return b.Next.CASHA256, true, nil
	}
	if b.Previous != nil {
		return "", false, ErrRetireFirst
	}
	ca, err := b.Cert()
	if err != nil {
		return "", false, err
	}
	now := time.Now()
	next, key, err := tlsauto.NewCALike(ca, caName(now), now)
	if err != nil {
		return "", false, err
	}
	fp = tlsauto.Fingerprint(next.Raw)
	k := h.Keys().Active()
	if k == nil {
		return "", false, errors.New("this server has no cluster key")
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return "", false, err
	}
	sealed, err := k.SecretsKey().Seal(keyField(fp), keyPEM)
	if err != nil {
		return "", false, err
	}
	o := &OtherCA{CACertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: next.Raw})), CAKey: sealed, CASHA256: fp,
		By: by, At: now.UTC()}
	_, err = d.Mutate(ctx, by, func(c *Body) error {
		switch {
		case !SameFingerprint(c.CASHA256, b.CASHA256):
			return ErrOtherCA
		case c.Next != nil:
			return errUnchanged
		case c.Previous != nil:
			return ErrRetireFirst
		}
		c.Next = o
		return nil
	})
	if errors.Is(err, errUnchanged) {
		b, _ := d.Get()
		if b.Next != nil {
			return b.Next.CASHA256, true, nil
		}
		return "", false, errors.New("another server changed the cluster's certificate authority meanwhile; look again")
	}
	if err != nil {
		return "", false, err
	}
	return fp, false, nil
}

// SwitchNext makes the next certificate authority, whose fingerprint is
// fp, the cluster's, as the user by on the server node asked. The one it
// replaces becomes the previous one, still handed out with its key kept
// until RetirePrevious, and is listed among the retired. When fp is in use
// already it changes nothing and reports already.
func (t *TLS) SwitchNext(ctx context.Context, by, node, fp string) (already bool, err error) {
	_, d, err := t.parts()
	if err != nil {
		return false, err
	}
	b, ok := d.Get()
	if !ok || b.CASHA256 == "" {
		return false, errNoCA
	}
	if fp != "" && SameFingerprint(b.CASHA256, fp) && b.Next == nil {
		return true, nil
	}
	if b.Next == nil {
		return false, errors.New("no new certificate authority is prepared: run signalith cluster tls rotate-ca prepare first")
	}
	if fp != "" && !SameFingerprint(b.Next.CASHA256, fp) {
		return false, fmt.Errorf("the prepared certificate authority is %s, not %s; look again", b.Next.CASHA256, fp)
	}
	nc, err := b.Next.Cert()
	if err != nil {
		return false, err
	}
	// Its key must open here, or no server could issue from it.
	if _, _, err := t.openSealed(nc, b.Next.CASHA256, b.Next.CAKey); err != nil {
		return false, fmt.Errorf("the prepared certificate authority's key cannot be used, so the switch would leave every server unable to renew: %w", err)
	}
	want := b.Next.CASHA256
	now := time.Now().UTC()
	_, err = d.Mutate(ctx, by, func(c *Body) error {
		if c.Next == nil || !SameFingerprint(c.Next.CASHA256, want) {
			if c.Next == nil && SameFingerprint(c.CASHA256, want) {
				return errUnchanged
			}
			return errors.New("the prepared certificate authority changed meanwhile; look again")
		}
		old := &OtherCA{CACertPEM: c.CACertPEM, CAKey: c.CAKey, CASHA256: c.CASHA256, By: by, At: now}
		next := c.Next
		newCA, err := next.Cert()
		if err != nil {
			return err
		}
		c.CACertPEM, c.CAKey, c.CASHA256 = next.CACertPEM, next.CAKey, next.CASHA256
		c.Names = cleanNames(newCA, c.Names)
		c.PublishedBy, c.PublishedAt = node, now
		c.Next, c.Previous = nil, old
		if oldCA, err := old.Cert(); err == nil {
			addRetired(c, oldCA, "", now)
		}
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return true, nil
	}
	return false, err
}

// RetirePrevious stops handing out the certificate authority the last
// switch replaced, whose fingerprint is fp, and deletes its sealed key
// from the tls document. When none is kept it changes nothing and reports
// already.
func (t *TLS) RetirePrevious(ctx context.Context, by, fp string) (already bool, err error) {
	_, d, err := t.parts()
	if err != nil {
		return false, err
	}
	b, ok := d.Get()
	if !ok || b.CASHA256 == "" {
		return false, errNoCA
	}
	if b.Previous == nil {
		if b.Next != nil {
			return false, errors.New("a new certificate authority is prepared but not switched to yet: switch first (signalith cluster tls rotate-ca switch)")
		}
		return true, nil
	}
	if fp != "" && !SameFingerprint(b.Previous.CASHA256, fp) {
		return false, fmt.Errorf("the certificate authority to retire is %s, not %s; look again", b.Previous.CASHA256, fp)
	}
	want := b.Previous.CASHA256
	_, err = d.Mutate(ctx, by, func(c *Body) error {
		if c.Previous == nil {
			return errUnchanged
		}
		if !SameFingerprint(c.Previous.CASHA256, want) {
			return errors.New("the certificate authority to retire changed meanwhile; look again")
		}
		if old, err := c.Previous.Cert(); err == nil {
			addRetired(c, old, "", time.Now().UTC())
		}
		c.Previous = nil
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return true, nil
	}
	return false, err
}

// addRetired lists ca among b's retired certificate authorities, once.
func addRetired(b *Body, ca *x509.Certificate, server string, at time.Time) {
	fp := tlsauto.Fingerprint(ca.Raw)
	if slices.ContainsFunc(b.RetiredFingerprints(), func(r string) bool { return SameFingerprint(r, fp) }) {
		return
	}
	b.Retired = append(b.Retired, RetiredCA{CACertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		RetiredAt: at, Server: server})
	if len(b.Retired) > MaxRetired {
		b.Retired = b.Retired[len(b.Retired)-MaxRetired:]
	}
}

// ErrBadStep: a step that is not prepare, switch or retire.
var ErrBadStep = errors.New("the step must be prepare, switch or retire")

// CheckStep checks that step of replacing b, the cluster's certificate
// authority, can be asked for now, with blockers the servers not ready
// for it (Blockers), and returns the fingerprint of the certificate
// authority the step is for: the one in use for prepare, the next one for
// switch, the previous one for retire.
func CheckStep(b *Body, blockers []string, step string) (string, error) {
	switch step {
	case StepPrepare:
		if b.Previous != nil {
			return "", ErrRetireFirst
		}
		if b.Next == nil && len(blockers) > 0 {
			return "", fmt.Errorf("not every server is ready to replace the cluster's certificate authority: %s", strings.Join(blockers, "; "))
		}
		return b.CASHA256, nil
	case StepSwitch:
		if b.Next == nil {
			return "", errors.New("no new certificate authority is prepared to switch to: run the prepare step first")
		}
		if len(blockers) > 0 {
			return "", fmt.Errorf("not every server is ready to switch: %s", strings.Join(blockers, "; "))
		}
		return b.Next.CASHA256, nil
	case StepRetire:
		if b.Previous == nil {
			return "", errors.New("no certificate authority is waiting to be retired")
		}
		if len(blockers) > 0 {
			return "", fmt.Errorf("not every server is ready to retire the old one: %s", strings.Join(blockers, "; "))
		}
		return b.Previous.CASHA256, nil
	}
	return "", ErrBadStep
}

// Blockers lists, for the step after b's state (prepare while none is
// under way, switch once prepared, retire once switched), the servers
// running now that are not ready for it, with why; empty when they all
// are. A server is running when its heartbeat (hbs) says so and is at
// most UpWithin old at now.
//
// Prepare waits for every running server to run a version that keeps the
// next and previous certificate authorities (TLSStatus.CARotation): an
// older one running the background jobs would rotate the cluster key
// without resealing their keys. Switch and retire wait only for servers
// that use the cluster's certificate authority: servers with their own
// certificate files, or that do not serve HTTPS, never use it, and a
// server that keeps its own for now takes the new one directly.
func Blockers(b *Body, hbs []cluster.Heartbeat, now time.Time) []string {
	if b == nil {
		return nil
	}
	var step, fp string
	switch {
	case b.Next != nil:
		step, fp = StepSwitch, b.Next.CASHA256
	case b.Previous != nil:
		step, fp = StepRetire, b.CASHA256
	default:
		step = StepPrepare
	}
	var out, older []string
	sorted := slices.Clone(hbs)
	slices.SortFunc(sorted, func(a, b cluster.Heartbeat) int { return cmp.Compare(a.Name, b.Name) })
	for _, hb := range sorted {
		if hb.State == cluster.StateStopped || hb.State == cluster.StateOffline || now.Sub(hb.HeartbeatAt) > UpWithin {
			continue
		}
		t := hb.TLS
		if t == nil || !t.CARotation {
			older = append(older, hb.Name)
			continue
		}
		if t.Mode != ModeAuto || !t.Cluster {
			// Its own certificate files, no HTTPS, or a certificate
			// authority of its own for now: it takes the cluster's later,
			// the new one by then.
			continue
		}
		switch {
		case step == StepSwitch && !SameFingerprint(t.NextCASHA256, fp):
			out = append(out, hb.Name+" doesn't hand out the new certificate authority yet")
		case step == StepRetire && (!SameFingerprint(t.CASHA256, fp) || !SameFingerprint(t.LeafCASHA256, fp)):
			out = append(out, hb.Name+"'s certificate doesn't come from the new certificate authority yet")
		}
	}
	if len(older) > 0 {
		verb := "runs a version"
		if len(older) > 1 {
			verb = "run a version"
		}
		out = append([]string{strings.Join(older, ", ") + " " + verb + " that can't replace the cluster's certificate authority: upgrade " +
			plural(len(older), "it", "them") + ", or stop " + plural(len(older), "it", "them")}, out...)
	}
	return out
}

// RotateHandler runs tls_rotate_ca requests on the server that runs the
// background jobs: it checks the step again against the servers'
// heartbeats (servers reads them), then takes it. node is this server's
// name.
func RotateHandler(t *TLS, servers func(context.Context) ([]cluster.Heartbeat, error), node string, log *slog.Logger) shared.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return func(ctx context.Context, req *shared.Request) error {
		var a RotateArgs
		if err := json.Unmarshal(req.Args, &a); err != nil {
			return errors.New("the request's arguments cannot be read")
		}
		_, d, err := t.parts()
		if err != nil {
			return err
		}
		// The latest copy, not one this server may be behind on.
		if err := d.Load(ctx); err != nil {
			return err
		}
		by := req.RequestedBy
		res := RotateResult{Step: a.Step}
		switch a.Step {
		case StepPrepare:
			if b, _ := t.Get(); b.Next == nil && b.Previous == nil {
				// Checked here again: a server on an older version may
				// have started since the admin looked.
				hbs, err := servers(ctx)
				if err != nil {
					return fmt.Errorf("the servers' heartbeats cannot be read, so it is not safe to prepare now: %w", err)
				}
				if bl := Blockers(b, hbs, time.Now()); len(bl) > 0 {
					return fmt.Errorf("not every server is ready to replace the cluster's certificate authority: %s", strings.Join(bl, "; "))
				}
			}
			fp, already, err := t.PrepareNext(ctx, by, a.CASHA256)
			if err != nil {
				return err
			}
			res.CASHA256, res.Already = fp, already
		case StepSwitch, StepRetire:
			b, _ := t.Get()
			if a.Step == StepSwitch && b.Next != nil || a.Step == StepRetire && b.Previous != nil {
				// Checked here again: the admin looked a while ago.
				hbs, err := servers(ctx)
				if err != nil {
					return fmt.Errorf("the servers' heartbeats cannot be read, so it is not safe to %s now: %w", a.Step, err)
				}
				if bl := Blockers(b, hbs, time.Now()); len(bl) > 0 {
					return fmt.Errorf("not every server is ready to %s: %s", a.Step, strings.Join(bl, "; "))
				}
			}
			var already bool
			if a.Step == StepSwitch {
				already, err = t.SwitchNext(ctx, by, node, a.CASHA256)
			} else {
				already, err = t.RetirePrevious(ctx, by, a.CASHA256)
			}
			if err != nil {
				return err
			}
			res.CASHA256, res.Already = a.CASHA256, already
		default:
			return fmt.Errorf("unknown step %q: it is prepare, switch or retire", a.Step)
		}
		_ = req.SetResult(res)
		if !res.Already {
			log.Info("took a step of replacing the cluster's certificate authority", "audit", true,
				"step", a.Step, "by", by, "request", req.ID, "ca_sha256", res.CASHA256)
		}
		return nil
	}
}
