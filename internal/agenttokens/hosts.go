// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agenttokens

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Host keys: a Signalith Agent trades its install line's token for a key
// of its own the first time it talks to the server (Enroll), and sends
// with that key from then on. A key holds for one computer name only, and
// one name has one key at a time: a host that holds its line's token
// cannot report as a computer that enrolled, and one computer can be cut
// off without cutting off its line. Revoking the line cuts off its keys
// too.
//
// A key is "sgh_" and 52 characters of lowercase base32, like a token,
// and kept the same way: only its SHA-256. Its document is
// agenthost:<hostDocKey(name)>, made with create-only, so two servers
// asked at once for the same name enroll it once.
const (
	// HostPrefix starts every host key.
	HostPrefix = "sgh_"
	// HostScannerPattern finds host keys in text, for secret scanners.
	HostScannerPattern = `\bsgh_[a-z2-7]{52}\b`
	// MaxHosts is how many host documents there may be, revoked ones
	// included.
	MaxHosts = 20000
	// MaxHostLen is the longest computer name.
	MaxHostLen = 253
)

const kindHost = "agent_host"

// Host key states: active, revoked (the name stays taken until an admin
// releases it), as for tokens.
const (
	CodeHostEnrolled = "host_enrolled"
	CodeHostRevoked  = "host_revoked"
	CodeHostMismatch = "host_mismatch"
)

// hostDoc is agenthost:<key>.
type hostDoc struct {
	Kind string `json:"kind"`
	// ID is the key's ID: the first 12 hex characters of its fingerprint.
	ID    string `json:"id"`
	State string `json:"state"`
	// Host is the computer's name, cleaned and in lower case.
	Host string `json:"name"`
	// Line is the ID of the token the computer enrolled with.
	Line      string     `json:"line"`
	Hash      string     `json:"hash"`
	At        time.Time  `json:"at"`
	Address   string     `json:"address"`
	RevokedAt *time.Time `json:"revoked_at"`
	RevokedBy string     `json:"revoked_by"`
}

func hostDocKey(host string) string {
	h := sha256.Sum256([]byte("signalith agent host\x00" + strings.ToLower(host)))
	return hex.EncodeToString(h[:])[:24]
}

func hostDocID(host string) string { return "agenthost:" + hostDocKey(host) }

// IsHostKey reports whether s has the shape of a host key.
func IsHostKey(s string) bool {
	return len(s) == Length && strings.HasPrefix(s, HostPrefix) && IsToken(Prefix+s[len(HostPrefix):])
}

func newHostKey() (string, error) {
	s, err := NewSecret()
	if err != nil {
		return "", err
	}
	return HostPrefix + s[len(Prefix):], nil
}

// HostKey is a host key as listed: never the key itself.
type HostKey struct {
	ID           string     `json:"id"`
	Host         string     `json:"host"`
	TokenID      string     `json:"token_id"`
	TokenName    string     `json:"token_name"`
	Status       string     `json:"status"`
	EnrolledAt   time.Time  `json:"enrolled_at"`
	EnrolledFrom string     `json:"enrolled_from"`
	RevokedAt    *time.Time `json:"revoked_at"`
	RevokedBy    string     `json:"revoked_by"`
}

func (s *snapshot) hostKey(d *hostDoc) HostKey {
	k := HostKey{ID: d.ID, Host: d.Host, TokenID: d.Line, Status: d.State, EnrolledAt: d.At, EnrolledFrom: d.Address,
		RevokedAt: d.RevokedAt, RevokedBy: d.RevokedBy}
	if t := s.tokens[d.Line]; t != nil {
		k.TokenName = t.Name
		if !isActive(t) && d.State == StateActive {
			// Revoking the line cut it off.
			k.Status = StateRevoked
		}
	}
	return k
}

func hostActive(s *snapshot, d *hostDoc) bool {
	t := s.tokens[d.Line]
	return d.State == StateActive && t != nil && isActive(t)
}

func (r *Registry) checkHost(secret string) (Identity, Result) {
	if !IsHostKey(secret) {
		return Identity{}, Unknown
	}
	snap := r.current()
	if !snap.loaded {
		return Identity{}, NotLoaded
	}
	sum := sha256.Sum256([]byte(secret))
	h := hex.EncodeToString(sum[:])
	d := snap.keys[h[:12]]
	if d == nil || subtle.ConstantTimeCompare([]byte(h), []byte(d.Hash)) != 1 {
		return Identity{}, Unknown
	}
	t := snap.tokens[d.Line]
	if t == nil {
		return Identity{}, Unknown
	}
	id := Identity{ID: t.ID, Name: t.Name, Purpose: t.Purpose, Host: d.Host, HostKey: d.ID}
	if !hostActive(snap, d) {
		return id, Revoked
	}
	return id, Valid
}

// Enrolled reports whether the computer called host has a host key,
// active or revoked: requests about it must then come with that key.
func (r *Registry) Enrolled(host string) bool {
	_, ok := r.current().hosts[hostDocKey(host)]
	return ok
}

func errHostEnrolled(host string) *Error {
	return &Error{Status: http.StatusConflict, Code: CodeHostEnrolled,
		Msg: fmt.Sprintf("A computer called %s already has its own key. If this is a new install of that computer, release the name on the Agents page (or signalith tokens hosts release %s), then it enrolls by itself.", host, host)}
}

func errHostRevoked(host string) *Error {
	return &Error{Status: http.StatusConflict, Code: CodeHostRevoked,
		Msg: fmt.Sprintf("The key of the computer called %s was revoked. An admin can release the name on the Agents page (or signalith tokens hosts release %s) to let it enroll again.", host, host)}
}

func errHostNotFound() *Error {
	return &Error{Status: http.StatusNotFound, Code: CodeNotFound, Msg: "No computer with this name has a key."}
}

func errTooManyHosts() *Error {
	return &Error{Status: http.StatusConflict, Code: CodeTooMany,
		Msg: "There are already 20,000 computers with keys, revoked ones included. Release the ones you no longer use."}
}

// Enroll gives the computer called host, which sent with the agent token
// lineID from addr, a key of its own. host must be cleaned (lower case);
// the caller checked that lineID is an active token for the agent. old is
// the key the computer had, when it was installed again with another
// line: holding it proves it is the same computer, so its key is
// replaced, under the new line. The key is never shown again.
func (r *Registry) Enroll(ctx context.Context, lineID, host, addr, old string) (HostKey, string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(host) > MaxHostLen {
		return HostKey{}, "", &Error{Status: http.StatusBadRequest, Code: CodeNameInvalid, Field: "name", Msg: "The agent sent no valid computer name."}
	}
	if err := r.fresh(ctx); err != nil {
		return HostKey{}, "", err
	}
	snap := r.current()
	t := snap.tokens[lineID]
	if t == nil {
		return HostKey{}, "", errNotFound()
	}
	if !isActive(t) {
		return HostKey{}, "", errRevoked()
	}
	var replace *hostDoc
	if d := snap.hosts[hostDocKey(host)]; d != nil {
		switch {
		case d.State != StateActive:
			return HostKey{}, "", errHostRevoked(host)
		case IsHostKey(old) && subtle.ConstantTimeCompare([]byte(Fingerprint(old)), []byte(d.Hash)) == 1:
			replace = d
		default:
			return HostKey{}, "", errHostEnrolled(host)
		}
	} else if len(snap.hosts) >= MaxHosts {
		return HostKey{}, "", errTooManyHosts()
	}
	secret, err := newHostKey()
	if err != nil {
		return HostKey{}, "", err
	}
	h := Fingerprint(secret)
	d := &hostDoc{Kind: kindHost, ID: h[:12], State: StateActive, Host: host, Line: lineID, Hash: h,
		At: r.now().UTC().Truncate(time.Second), Address: addr}
	if replace != nil {
		if err := r.replaceHost(ctx, replace, d); err != nil {
			return HostKey{}, "", err
		}
	} else if _, err := r.Client.Create(ctx, r.index(), hostDocID(host), d, true); errors.Is(err, store.ErrExists) {
		return HostKey{}, "", errHostEnrolled(host)
	} else if err != nil {
		return HostKey{}, "", errStore(err)
	}
	r.apply(func(s *snapshot) { s.putHost(d) })
	r.touch(ctx)
	if replace != nil {
		// Its osquery host enrolls again with the new key.
		r.revoked(ctx, replace.ID)
	}
	return r.current().hostKey(d), secret, nil
}

// replaceHost writes d over old, only if old is still what is stored.
func (r *Registry) replaceHost(ctx context.Context, old, d *hostDoc) error {
	src, v, found, err := r.Client.Get(ctx, r.index(), hostDocID(d.Host))
	if err != nil {
		return errStore(err)
	}
	var now hostDoc
	if !found || json.Unmarshal(src, &now) != nil || now.Hash != old.Hash || now.State != StateActive {
		return errHostEnrolled(d.Host)
	}
	if _, err := r.Client.PutIf(ctx, r.index(), hostDocID(d.Host), d, v, true); err != nil {
		if store.IsConflict(err) {
			return errHostEnrolled(d.Host)
		}
		return errStore(err)
	}
	return nil
}

// putHost sets the host document d, and dropHost removes the one of
// host.
func (s *snapshot) putHost(d *hostDoc) {
	k := hostDocKey(d.Host)
	if old := s.hosts[k]; old != nil {
		delete(s.keys, old.ID)
	}
	s.hosts[k] = d
	s.keys[d.ID] = d
}

func (s *snapshot) dropHost(host string) {
	k := hostDocKey(host)
	if old := s.hosts[k]; old != nil {
		delete(s.keys, old.ID)
	}
	delete(s.hosts, k)
}

// Hosts lists the computers with keys, by name.
func (r *Registry) Hosts() []HostKey {
	snap := r.current()
	out := make([]HostKey, 0, len(snap.hosts))
	for _, d := range snap.hosts {
		out = append(out, snap.hostKey(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Host returns the listing of the computer called host.
func (r *Registry) Host(host string) (HostKey, bool) {
	snap := r.current()
	d := snap.hosts[hostDocKey(host)]
	if d == nil {
		return HostKey{}, false
	}
	return snap.hostKey(d), true
}

// RevokeHost revokes the key of the computer called host: every server
// refuses it within a few seconds, this one at once, and the name stays
// taken, so nothing can enroll as it until an admin releases it. It
// returns how many osquery hosts enrolled with the key were removed.
func (r *Registry) RevokeHost(ctx context.Context, host, by string) (HostKey, int, error) {
	if r.Client == nil {
		return HostKey{}, 0, errStore(errors.New("no OpenSearch"))
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(host) > MaxHostLen {
		return HostKey{}, 0, errHostNotFound()
	}
	if err := r.ensureIndex(ctx); err != nil {
		return HostKey{}, 0, errStore(err)
	}
	for try := 0; ; try++ {
		src, v, found, err := r.Client.Get(ctx, r.index(), hostDocID(host))
		if err != nil {
			return HostKey{}, 0, errStore(err)
		}
		var d hostDoc
		if !found || json.Unmarshal(src, &d) != nil || d.Host != host {
			return HostKey{}, 0, errHostNotFound()
		}
		if d.State == StateActive {
			d.State, d.RevokedAt, d.RevokedBy = StateRevoked, timePtr(r.now().UTC().Truncate(time.Second)), by
			if _, err = r.Client.PutIf(ctx, r.index(), hostDocID(host), &d, v, true); err != nil {
				if !store.IsConflict(err) || try >= 9 {
					return HostKey{}, 0, errStore(err)
				}
				if err := sleep(ctx, jitter(10*time.Millisecond, 250*time.Millisecond)); err != nil {
					return HostKey{}, 0, errStore(err)
				}
				continue
			}
			r.touch(ctx)
		}
		// Even when it was revoked already, so hosts a failed removal left
		// behind go now.
		r.apply(func(s *snapshot) { s.putHost(&d) })
		return r.current().hostKey(&d), r.revoked(ctx, d.ID), nil
	}
}

// ReleaseHost revokes the key of the computer called host, if it is
// still active, and frees the name, so the next computer with that name
// enrolls again with its line's token: for a computer that was installed
// again, or renamed.
func (r *Registry) ReleaseHost(ctx context.Context, host, by string) (HostKey, int, error) {
	k, n, err := r.RevokeHost(ctx, host, by)
	if err != nil {
		return k, n, err
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for try := 0; ; try++ {
		_, v, found, err := r.Client.Get(ctx, r.index(), hostDocID(host))
		if err != nil {
			return k, n, errStore(err)
		}
		if found {
			err = r.Client.DeleteIf(ctx, r.index(), hostDocID(host), v, true)
		}
		switch {
		case err == nil, errors.Is(err, store.ErrNotFound):
			r.apply(func(s *snapshot) { s.dropHost(host) })
			r.touch(ctx)
			return k, n, nil
		case !store.IsConflict(err) || try >= 9:
			return k, n, errStore(err)
		}
		if err := sleep(ctx, jitter(10*time.Millisecond, 250*time.Millisecond)); err != nil {
			return k, n, errStore(err)
		}
	}
}

// loadHost reads a host document into s.
func (s *snapshot) loadHost(id string, src json.RawMessage) {
	var d hostDoc
	if json.Unmarshal(src, &d) != nil || !validID(d.ID) || len(d.Hash) != 64 || d.Hash[:12] != d.ID ||
		d.Host == "" || id != hostDocID(d.Host) {
		return
	}
	s.putHost(&d)
}
