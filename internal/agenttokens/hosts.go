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
	"net/url"
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
	if d == nil {
		// Another server may have made it since this one last read the
		// keys: look whether anything changed since, and read them again
		// if so.
		var res Result
		if snap, res = r.reloadForMiss(); res != Valid {
			return Identity{}, res
		}
		d = snap.keys[h[:12]]
	}
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

// missCheck is the least time between two looks at the watched document
// for keys this server does not know. Anyone can send a key that looks
// right, so this, and one look at a time, bound what they cost
// OpenSearch; Run looks every few seconds anyway.
var missCheck = 500 * time.Millisecond

// reloadForMiss is for a key Check does not know.
// It reads the version of the watched document, which every new key
// rewrites, and reads the keys again only when it changed since the last
// full read: a key made on another server is found, and random keys cost
// one small request. Valid means the snapshot returned holds every key
// made before this call, so a key not in it is unknown. Otherwise it answers
// NotLoaded (try again): while another Check looks, within missCheck of
// the last look, or when OpenSearch does not answer. A key is never
// called unknown without a look that began after it was sent, so one
// made a moment ago on another server is not refused for good.
func (r *Registry) reloadForMiss() (*snapshot, Result) {
	if r.Client == nil {
		return r.current(), Valid
	}
	if !r.missMu.TryLock() {
		return nil, NotLoaded
	}
	defer r.missMu.Unlock()
	if time.Since(r.missAt) < missCheck {
		return nil, NotLoaded
	}
	// Counted before the look, so an OpenSearch that does not answer is
	// asked at most once every missCheck.
	r.missAt = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := r.readWatch(ctx)
	if err != nil {
		return nil, NotLoaded
	}
	if r.watchChanged(w) {
		if err := r.loadSince(ctx, w); err != nil {
			// The key may be one made since.
			return nil, NotLoaded
		}
	}
	return r.current(), Valid
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

// warnHosts logs, at most once an hour, that n computers have keys,
// which is near MaxHosts.
func (r *Registry) warnHosts(n int) {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	if r.Log == nil || time.Since(r.lastFull) < time.Hour {
		return
	}
	r.lastFull = time.Now()
	r.Log.Warn("almost every computer key is taken: at 20,000, revoked ones included, new computers get none and keep sending with their line's token. Release the names you no longer use, or revoke a line that leaked", "hosts", n, "max", MaxHosts)
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
	} else if len(snap.hosts) >= MaxHosts*8/10 {
		r.warnHosts(len(snap.hosts))
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

// dropLineHosts deletes the keys of the computers of the revoked line
// id, so their names are free and no longer count towards MaxHosts: a
// line token that leaked cannot keep thousands of names taken after it
// is revoked. The keys were refused already, with the line. When it
// fails, it is logged, and revoking the line again deletes what is left.
func (r *Registry) dropLineHosts(ctx context.Context, id string) {
	// Read again first, for keys made on other servers a moment ago.
	if err := r.Load(ctx); err != nil && r.Log != nil {
		r.Log.Warn("the agent tokens could not be read again before removing a revoked line's computer keys", "token_id", id, "err", err)
	}
	var hosts []string
	for _, h := range r.current().hosts {
		if h.Line == id && h.State == StateActive {
			hosts = append(hosts, h.Host)
		}
	}
	if len(hosts) == 0 {
		return
	}
	deleted := true
	for start := 0; start < len(hosts); start += 1000 {
		part := hosts[start:min(start+1000, len(hosts))]
		ids := make([]string, len(part))
		for i, h := range part {
			ids[i] = hostDocID(h)
		}
		// Only the line's active keys: a key an admin revoked by itself
		// keeps its name taken until an admin releases it, and a key
		// replaced meanwhile (its computer moved to another line) no
		// longer names this line.
		err := r.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(r.index())+"/_delete_by_query?conflicts=proceed&refresh=true", map[string]any{
			"query": map[string]any{"bool": map[string]any{"filter": []any{
				map[string]any{"ids": map[string]any{"values": ids}},
				map[string]any{"term": map[string]any{"kind": kindHost}},
				map[string]any{"term": map[string]any{"line": id}},
				map[string]any{"term": map[string]any{"state": StateActive}},
			}}},
		}, nil)
		if err != nil {
			if r.Log != nil {
				r.Log.Warn("the computer keys of a revoked agent line could not all be removed; they are refused anyway. Revoke the line again to remove the rest", "token_id", id, "err", err)
			}
			deleted = false
			break
		}
	}
	// What was deleted, and what a failure left, is what OpenSearch says.
	if err := r.Load(ctx); err != nil && deleted {
		r.apply(func(s *snapshot) {
			for _, h := range hosts {
				if d := s.hosts[hostDocKey(h)]; d != nil && d.Line == id && d.State == StateActive {
					s.dropHost(h)
				}
			}
		})
	}
	r.touch(ctx)
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
