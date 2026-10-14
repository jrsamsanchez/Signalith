package clusterauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The sessions of a cluster are documents in <prefix>_sessions, one per
// signed-in browser, with the id SessionID of its cookie. Every server
// accepts every session: a cookie made on one server works on another at
// once, as a realtime GET reads the document without waiting for a
// refresh. Each document carries a MAC under the cluster key over what
// grants access (the user, the user's session epoch, when it was made and
// whether it is remembered), so someone who can write to OpenSearch
// cannot make one up.
//
// A session ends when its user's session epoch moves on (a new password,
// disabled, refused by the directory), when it is signed out (its
// document deleted, and watch:sessions bumped with its id so every server
// drops it from its cache), after 7 days, or after the idle time without
// a request, which each server checks against the later of its own last
// request and the stored last_seen.

// Session timing.
const (
	// MaxAge ends any session this long after sign-in.
	MaxAge = 7 * 24 * time.Hour
	// CacheFor is how long a session read from OpenSearch is used without
	// reading it again, and how long a cookie found to have no session is
	// refused without asking.
	CacheFor = 15 * time.Second
	// StaleFor is how long past its last confirmation a session read
	// before is still used while OpenSearch cannot be read.
	StaleFor = 5 * time.Minute
	// LastSeenEvery is how often, at most, a server writes when a session
	// was last used.
	LastSeenEvery = time.Minute
	// MaxPerUser bounds the sessions of one user; the oldest go first.
	MaxPerUser = 50
)

// sessionMAC starts the text a session's MAC covers.
const sessionMAC = "sgl-session-v1"

// sessionDoc is a session document as stored.
type sessionDoc struct {
	User  string `json:"user"`
	Epoch int64  `json:"epoch"`
	// Created is kept as the text it was written as, for the MAC.
	Created  string `json:"created"`
	LastSeen string `json:"last_seen"`
	Remember bool   `json:"remember"`
	Node     string `json:"node"`
	Client   string `json:"client,omitempty"`
	Method   string `json:"method"`
	Degraded bool   `json:"degraded"`
	// Born is the creation time of the user document the session was
	// made for, as that document's server wrote it: a user made again
	// under the same name has another.
	Born string `json:"born,omitempty"`
	MAC  string `json:"mac"`
}

func sessionText(id string, d *sessionDoc) []byte {
	var b bytes.Buffer
	for _, f := range []string{sessionMAC, id, d.User, strconv.FormatInt(d.Epoch, 10), d.Created, strconv.FormatBool(d.Remember), d.Born} {
		b.WriteString(f)
		b.WriteByte(0)
	}
	return b.Bytes()
}

func sessionSum(k *shared.ClusterKey, id string, d *sessionDoc) []byte {
	m := hmac.New(sha256.New, k.MACKey())
	m.Write(sessionText(id, d))
	return m.Sum(nil)
}

// sign sets the MAC of the session document id with k.
func (d *sessionDoc) sign(k *shared.ClusterKey, id string) {
	d.MAC = "m1:" + k.ID() + ":" + b64.EncodeToString(sessionSum(k, id, d))
}

// verify checks the MAC of the session document id against keys.
func (d *sessionDoc) verify(keys *shared.KeySet, id string) bool {
	rest, ok := strings.CutPrefix(d.MAC, "m1:")
	if !ok || strings.IndexByte(d.User, 0) >= 0 || strings.IndexByte(d.Created, 0) >= 0 || strings.IndexByte(d.Born, 0) >= 0 {
		return false
	}
	kid, sum, ok := strings.Cut(rest, ":")
	k := keys.Get(kid)
	if !ok || k == nil {
		return false
	}
	got, err := b64.DecodeString(sum)
	return err == nil && hmac.Equal(got, sessionSum(k, id, d))
}

// entry is a session as this server knows it.
type entry struct {
	user     string
	epoch    int64
	created  time.Time
	remember bool
	method   string
	degraded bool
	// born is the session document's Born.
	born string
	// stored is the last_seen stored, local this server's last request,
	// and confirmed when the session was last read from OpenSearch (or
	// written).
	stored, local, confirmed time.Time
}

// bornText is the creation time of user u as a session records it.
func bornText(u *UserBody) string {
	if u.Created.IsZero() {
		return ""
	}
	return u.Created.UTC().Format(time.RFC3339Nano)
}

// bornOf reports whether the session was made for user u as they are
// now. A session made while this server had no document of its user (the
// built-in admin's, while OpenSearch could not be used) was made no
// earlier than the user.
func (e *entry) bornOf(u *UserBody) bool {
	if e.born == "" {
		return !e.created.Before(u.Created)
	}
	return e.born == bornText(u)
}

// SessionCache is what a server keeps of the sessions in memory: those
// read lately, the cookies found to have none, the sessions made while
// OpenSearch could not be written, and the sign-outs to write once it
// can. An in-process restart keeps it.
type SessionCache struct {
	mu       sync.Mutex
	pos      map[string]*entry
	neg      map[string]time.Time
	degraded map[string]*entry
	pending  []string
	// carried holds the ids of the sessions Carry brought over from this
	// server's own sessions, whose cookies keep their old form.
	carried map[string]bool
	// watch is the version of watch:sessions last seen.
	watch store.Version
}

// NewSessionCache returns an empty cache.
func NewSessionCache() *SessionCache {
	return &SessionCache{pos: map[string]*entry{}, neg: map[string]time.Time{}, degraded: map[string]*entry{}, carried: map[string]bool{}}
}

// Sessions keeps the sign-in sessions of a cluster in OpenSearch. It has
// the methods of api.SessionStore.
type Sessions struct {
	Docs *Docs
	// Client returns the OpenSearch client and index prefix in use now.
	Client func() (*store.Client, string)
	// Node is this server's node id, written in the sessions it makes.
	Node  string
	Cache *SessionCache
	// DirectoryOn reports whether directory sign-in is on: directory
	// users' sessions only work while it is.
	DirectoryOn func() bool
	// Degraded reports whether this server cannot use OpenSearch now
	// (shared.ModeDegraded); sessions are then made in memory only, for
	// the users MayDegrade allows.
	Degraded func() bool
	// Confirmed is when the shared settings were last read in full
	// (Hub.Confirmed): only a copy at most DegradedCopyAge old lets a
	// local admin sign in while OpenSearch cannot be used.
	Confirmed func() time.Time
	Log       *slog.Logger
	Now       func() time.Time

	idleMu sync.Mutex
	idle   time.Duration
}

// Listen follows watch:sessions, so a sign-out on another server ends
// the session here within one poll. Call it once per start.
func (s *Sessions) Listen() { s.Docs.onSessions(s.watched) }

func (s *Sessions) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sessions) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (s *Sessions) index() (*store.Client, string) {
	cl, prefix := s.Client()
	return cl, shared.SessionsIndex(prefix)
}

func (s *Sessions) degradedNow() bool { return s.Degraded != nil && s.Degraded() }

// SetIdle changes how long a session lasts without a request.
func (s *Sessions) SetIdle(d time.Duration) {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	s.idle = d
}

func (s *Sessions) idleFor() time.Duration {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.idle <= 0 {
		return 12 * time.Hour
	}
	return s.idle
}

// MaxAge is how long any session lasts after sign-in.
func (s *Sessions) MaxAge() time.Duration { return MaxAge }

// SetVersion does nothing: a shared session ends through its user's
// session epoch when the password changes, not through a password stamp.
func (s *Sessions) SetVersion(context.Context, string, string) {}

// unusable reports whether a write failed because OpenSearch cannot be
// used now (unreachable, overloaded, or refusing writes), rather than
// because of what was written.
func unusable(err error) bool {
	var e *store.Error
	if store.IsClusterBlock(err) || !errors.As(err, &e) {
		return true
	}
	return e.Status >= 500
}

// Create starts a session for n and returns its cookie. While OpenSearch
// cannot be written, the session is kept in memory on this server only,
// for the users MayDegrade allows.
func (s *Sessions) Create(ctx context.Context, n auth.NewSession) (string, error) {
	k, cid := s.Docs.key(), s.Docs.ClusterID()
	if k == nil || cid == "" {
		return "", errors.New("this server is not a member of the cluster now")
	}
	cookie := NewCookie(k, cid)
	id := SessionID(cookie)
	now := s.now().UTC()
	user := users.NormalizeUsername(n.User)
	e := &entry{user: user, epoch: n.Epoch, created: now, remember: n.Remember, method: n.Method, stored: now, local: now, confirmed: now}
	if u, _, ok := s.Docs.Users().Get(user); ok {
		e.born = bornText(u)
	}
	if s.degradedNow() {
		return cookie, s.createDegraded(id, e, n.Client)
	}
	doc := &sessionDoc{User: user, Epoch: n.Epoch, Created: now.Format(time.RFC3339Nano), LastSeen: now.Format(time.RFC3339Nano),
		Remember: n.Remember, Node: s.Node, Client: n.Client, Method: n.Method, Born: e.born}
	doc.sign(k, id)
	cl, index := s.index()
	if _, err := cl.Create(ctx, index, id, doc, false); err != nil {
		if unusable(err) {
			return cookie, s.createDegraded(id, e, n.Client)
		}
		return "", err
	}
	s.Cache.mu.Lock()
	s.Cache.pos[id] = e
	delete(s.Cache.neg, id)
	waiting := len(s.Cache.degraded) > 0 || len(s.Cache.pending) > 0
	s.Cache.mu.Unlock()
	s.trim(ctx, user)
	if waiting {
		// OpenSearch takes writes again.
		s.Recover(ctx)
	}
	return cookie, nil
}

// createDegraded keeps a session made while OpenSearch cannot be
// written in memory, for at most DegradedSession.
func (s *Sessions) createDegraded(id string, e *entry, client string) error {
	if err := s.MayDegrade(e.user, e.method); err != nil {
		return err
	}
	e.degraded = true
	s.Cache.mu.Lock()
	s.Cache.degraded[id] = e
	s.Cache.mu.Unlock()
	s.log().Warn("signed in while OpenSearch cannot be written; the session works on this server only, for at most an hour",
		"audit", true, "user", e.user, "method", e.method, "client", client)
	return nil
}

// trim deletes the oldest sessions of user beyond MaxPerUser. It is best
// effort: a session made at the same moment on another server may be
// counted after a refresh.
func (s *Sessions) trim(ctx context.Context, user string) {
	cl, index := s.index()
	docs, err := cl.SearchDocs(ctx, index, map[string]any{"term": map[string]any{"user": user}})
	if err != nil || len(docs) <= MaxPerUser {
		return
	}
	type aged struct {
		id      string
		created time.Time
	}
	var all []aged
	for _, d := range docs {
		var sd sessionDoc
		if json.Unmarshal(d.Source, &sd) != nil {
			continue
		}
		at, _ := time.Parse(time.RFC3339Nano, sd.Created)
		all = append(all, aged{d.ID, at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].created.Before(all[j].created) })
	for _, a := range all[:max(len(all)-MaxPerUser, 0)] {
		if err := s.deleteDoc(ctx, a.id); err == nil {
			s.forget(a.id)
		}
	}
}

// deleteDoc deletes a session document; one that is gone is no error.
func (s *Sessions) deleteDoc(ctx context.Context, id string) error {
	cl, index := s.index()
	err := cl.Do(ctx, http.MethodDelete, "/"+url.PathEscape(index)+"/_doc/"+url.PathEscape(id), nil, nil)
	var e *store.Error
	if errors.As(err, &e) && e.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// forget drops a session from the cache and refuses its cookie for a
// while without asking.
func (s *Sessions) forget(id string) {
	s.Cache.mu.Lock()
	defer s.Cache.mu.Unlock()
	delete(s.Cache.pos, id)
	s.Cache.neg[id] = s.now().Add(CacheFor)
}

// Lookup returns the session of a cookie, checked against its user as
// they are now. used marks it used, so it does not end for being idle; a
// request a page makes on its own passes false.
func (s *Sessions) Lookup(ctx context.Context, cookie string, used bool) (auth.Session, bool) {
	if !s.known(cookie) {
		return auth.Session{}, false
	}
	id := SessionID(cookie)
	now := s.now()
	c := s.Cache
	c.mu.Lock()
	if until, ok := c.neg[id]; ok {
		if now.Before(until) {
			c.mu.Unlock()
			return auth.Session{}, false
		}
		delete(c.neg, id)
	}
	if e := c.degraded[id]; e != nil {
		ok := now.Sub(e.created) < DegradedSession && s.allows(e, now, true)
		if !ok {
			delete(c.degraded, id)
		} else if used {
			e.local = now
		}
		out := e.session()
		c.mu.Unlock()
		return out, ok
	}
	e := c.pos[id]
	var cur entry
	if e != nil {
		cur = *e
	}
	c.mu.Unlock()
	if e == nil || now.Sub(cur.confirmed) >= CacheFor {
		read, ok := s.read(ctx, id, e, now)
		if !ok {
			return auth.Session{}, false
		}
		cur = read
	}
	if !s.allows(&cur, now, false) {
		return auth.Session{}, false
	}
	if used {
		cur.local = now
		if !cur.degraded && now.Sub(cur.stored) >= LastSeenEvery && !s.degradedNow() {
			cl, index := s.index()
			_, err := cl.Update(ctx, index, id, map[string]any{"last_seen": now.UTC().Format(time.RFC3339Nano)}, false)
			switch {
			case errors.Is(err, store.ErrNotFound):
				s.forget(id)
				return auth.Session{}, false
			case err == nil:
				cur.stored = now
			}
		}
	}
	c.mu.Lock()
	if e := c.pos[id]; e != nil {
		// Keep what moved meanwhile.
		cur.local = maxTime(cur.local, e.local)
		cur.stored = maxTime(cur.stored, e.stored)
		cur.confirmed = maxTime(cur.confirmed, e.confirmed)
		*e = cur
	}
	c.mu.Unlock()
	return cur.session(), true
}

// known reports whether a cookie may have a session, without reading
// OpenSearch: a cookie this cluster made, or one of a session Carry
// brought over on this server.
func (s *Sessions) known(cookie string) bool {
	if cookie == "" {
		return false
	}
	if ParseCookie(s.Docs.keys(), s.Docs.ClusterID(), cookie) == nil {
		return true
	}
	s.Cache.mu.Lock()
	defer s.Cache.mu.Unlock()
	return s.Cache.carried[SessionID(cookie)]
}

// Carried is a sign-in session a server made while it kept its users in
// its own files, with what its user was there.
type Carried struct {
	auth.Held
	// Role is the user's role, and PasswordHash their password hash (the
	// built-in admin's for its sessions; "" for a directory user).
	Role         users.Role
	PasswordHash string
}

// Carry writes the sessions this server made while it kept its users in
// its own files into the shared sessions, when it starts using the shared
// users, so the browsers signed in stay signed in. A session is carried
// only when the shared settings have its user as they were here: the same
// source, role and password hash, enabled and not refused; it then joins
// the user's current session epoch, so a new password or disabling the
// user on any server ends it as it ends any other. The cookies keep
// their old form, so they work on this server only (where they were
// made), until the session ends or the process stops. It returns how many
// sessions were carried and how many were not.
func (s *Sessions) Carry(ctx context.Context, list []Carried) (carried, dropped int) {
	k := s.Docs.key()
	if k == nil || s.Docs.ClusterID() == "" || s.degradedNow() {
		return 0, len(list)
	}
	now := s.now()
	cl, index := s.index()
	for _, c := range list {
		user := users.NormalizeUsername(c.User)
		u, _, ok := s.Docs.Users().Get(user)
		if !ok || u.Disabled || u.Refused != "" || u.Source != c.Method || u.Role != c.Role || u.PasswordHash != c.PasswordHash ||
			u.Source == users.SourceDirectory && (s.DirectoryOn == nil || !s.DirectoryOn()) || now.Sub(c.Created) >= MaxAge {
			dropped++
			continue
		}
		id := b64.EncodeToString(c.Hash[:])
		at := c.Created.UTC().Format(time.RFC3339Nano)
		doc := &sessionDoc{User: user, Epoch: u.SessionEpoch, Created: at, LastSeen: c.LastSeen.UTC().Format(time.RFC3339Nano),
			Remember: c.Remember, Node: s.Node, Method: c.Method, Born: bornText(u)}
		doc.sign(k, id)
		if _, err := cl.Create(ctx, index, id, doc, false); err != nil {
			dropped++
			continue
		}
		created, _ := time.Parse(time.RFC3339Nano, at)
		e := &entry{user: user, epoch: u.SessionEpoch, created: created, remember: c.Remember, method: c.Method, born: doc.Born,
			stored: c.LastSeen, local: c.LastSeen, confirmed: now}
		s.Cache.mu.Lock()
		s.Cache.carried[id] = true
		s.Cache.pos[id] = e
		delete(s.Cache.neg, id)
		s.Cache.mu.Unlock()
		carried++
	}
	return carried, dropped
}

// read reads the session id from OpenSearch and caches it. When
// OpenSearch cannot be read, or this server cannot use it now, a copy
// confirmed less than StaleFor ago (old) is used instead.
func (s *Sessions) read(ctx context.Context, id string, old *entry, now time.Time) (entry, bool) {
	var oldCopy entry
	if old != nil {
		s.Cache.mu.Lock()
		oldCopy = *old
		s.Cache.mu.Unlock()
	}
	stale := func() (entry, bool) {
		if old != nil && now.Sub(oldCopy.confirmed) < StaleFor {
			return oldCopy, true
		}
		return entry{}, false
	}
	if s.degradedNow() {
		return stale()
	}
	cl, index := s.index()
	src, _, found, err := cl.Get(ctx, index, id)
	if err != nil {
		return stale()
	}
	if !found {
		s.forget(id)
		return entry{}, false
	}
	var d sessionDoc
	if err := json.Unmarshal(src, &d); err != nil || !d.verify(s.Docs.keys(), id) {
		s.forget(id)
		s.log().Error("session.tamper: a sign-in session in OpenSearch was changed or made outside Signalith; it is refused",
			"audit", true, "session", id, "user", d.User, "node", d.Node)
		return entry{}, false
	}
	created, err := time.Parse(time.RFC3339Nano, d.Created)
	if err != nil {
		s.forget(id)
		return entry{}, false
	}
	stored, _ := time.Parse(time.RFC3339Nano, d.LastSeen)
	e := entry{user: d.User, epoch: d.Epoch, created: created, remember: d.Remember, method: d.Method, degraded: d.Degraded, born: d.Born,
		stored: stored, local: oldCopy.local, confirmed: now}
	s.Cache.mu.Lock()
	if cur := s.Cache.pos[id]; cur != nil {
		e.local = maxTime(e.local, cur.local)
	}
	s.Cache.pos[id] = &e
	cp := e
	s.Cache.mu.Unlock()
	return cp, true
}

// allows checks a session against its user as they are now: there, not
// disabled or refused, a directory user only while directory sign-in is
// on, in the user's current session epoch, made for the user as they
// are now (born: a user deleted and made again under the same name does
// not get the old sessions; servers' clocks are never compared), younger than MaxAge, and not idle too long unless
// remembered. inMemory is a session made while OpenSearch could not be
// written; the built-in admin may have one without a user document.
func (s *Sessions) allows(e *entry, now time.Time, inMemory bool) bool {
	if now.Sub(e.created) >= MaxAge {
		return false
	}
	if !e.remember && now.Sub(maxTime(e.local, e.stored)) >= s.idleFor() {
		return false
	}
	u, _, ok := s.Docs.Users().Get(e.user)
	if !ok {
		return inMemory && e.method == users.SourceBuiltin && e.epoch == 0 && strings.EqualFold(e.user, s.Docs.builtinName())
	}
	if u.Disabled || u.Refused != "" || e.epoch != u.SessionEpoch || !e.bornOf(u) {
		return false
	}
	if u.Source == users.SourceDirectory && (s.DirectoryOn == nil || !s.DirectoryOn()) {
		return false
	}
	return true
}

func (e *entry) session() auth.Session {
	return auth.Session{User: e.user, Created: e.created, LastSeen: maxTime(e.local, e.stored), Remember: e.remember,
		Epoch: e.epoch, Method: e.method, Degraded: e.degraded}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Delete ends the session of a cookie: its document is deleted and
// watch:sessions is bumped with its id, so every server drops it within
// one poll. While OpenSearch cannot be written, the document is deleted
// once it can.
func (s *Sessions) Delete(ctx context.Context, cookie string) {
	if !s.known(cookie) {
		return
	}
	id := SessionID(cookie)
	s.Cache.mu.Lock()
	delete(s.Cache.carried, id)
	_, inMemory := s.Cache.degraded[id]
	delete(s.Cache.degraded, id)
	delete(s.Cache.pos, id)
	s.Cache.neg[id] = s.now().Add(CacheFor)
	s.Cache.mu.Unlock()
	if inMemory {
		return
	}
	if s.degradedNow() {
		s.later(id)
		return
	}
	if err := s.deleteDoc(ctx, id); err != nil {
		s.later(id)
		return
	}
	if h := s.Docs.Hub(); h != nil {
		if _, err := h.BumpWith(ctx, SessionsWatch, map[string]any{"last": id}); err != nil {
			s.log().Warn("signed out, but the other servers may accept the session for up to 15 seconds", "err", err)
		}
	}
}

// later keeps a sign-out to write once OpenSearch takes writes.
func (s *Sessions) later(id string) {
	s.Cache.mu.Lock()
	defer s.Cache.mu.Unlock()
	if !slices.Contains(s.Cache.pending, id) {
		s.Cache.pending = append(s.Cache.pending, id)
	}
}

// watched is called with watch:sessions whenever it moved: a version one
// above the last seen is one sign-out, whose session is dropped; any
// other move may hide several, so every session read is read again.
func (s *Sessions) watched(_ context.Context, raw json.RawMessage, v store.Version) {
	var body struct {
		Last string `json:"last"`
	}
	_ = json.Unmarshal(raw, &body)
	s.Cache.mu.Lock()
	defer s.Cache.mu.Unlock()
	last := s.Cache.watch
	if v.Same(last) && v.Version == last.Version {
		return
	}
	s.Cache.watch = v
	if !last.IsZero() && v.PrimaryTerm == last.PrimaryTerm && v.Version == last.Version+1 && body.Last != "" {
		delete(s.Cache.pos, body.Last)
		s.Cache.neg[body.Last] = s.now().Add(CacheFor)
		return
	}
	clear(s.Cache.pos)
}

// EndUser forgets the sessions of user this server holds, but the one of
// the cookie keep, and reports how many of their sessions are in
// OpenSearch: they end through the user's session epoch, which the change
// that ends them moves on in the same write.
func (s *Sessions) EndUser(ctx context.Context, user, keep string) int {
	user = users.NormalizeUsername(user)
	keepID := ""
	if keep != "" {
		keepID = SessionID(keep)
	}
	n := 0
	s.Cache.mu.Lock()
	for id, e := range s.Cache.pos {
		if e.user == user && id != keepID {
			delete(s.Cache.pos, id)
		}
	}
	for id, e := range s.Cache.degraded {
		if e.user == user && id != keepID {
			delete(s.Cache.degraded, id)
			n++
		}
	}
	s.Cache.mu.Unlock()
	cl, index := s.index()
	docs, err := cl.SearchDocs(ctx, index, map[string]any{"term": map[string]any{"user": user}})
	if err != nil {
		return n
	}
	keys := s.Docs.keys()
	now := s.now()
	for _, d := range docs {
		var sd sessionDoc
		if d.ID == keepID || json.Unmarshal(d.Source, &sd) != nil || !sd.verify(keys, d.ID) {
			continue
		}
		if at, err := time.Parse(time.RFC3339Nano, sd.Created); err == nil && now.Sub(at) < MaxAge {
			n++
		}
	}
	return n
}

// Users lists the users with a session that has not ended, each once, in
// lower case. Sessions whose MAC does not verify are left out.
func (s *Sessions) Users(ctx context.Context) []string {
	now := s.now()
	seen := map[string]bool{}
	s.Cache.mu.Lock()
	for _, e := range s.Cache.degraded {
		if now.Sub(e.created) < DegradedSession && s.allows(e, now, true) {
			seen[e.user] = true
		}
	}
	s.Cache.mu.Unlock()
	cl, index := s.index()
	docs, err := cl.SearchDocs(ctx, index, nil)
	if err == nil {
		keys := s.Docs.keys()
		for _, d := range docs {
			var sd sessionDoc
			if json.Unmarshal(d.Source, &sd) != nil || !sd.verify(keys, d.ID) || seen[sd.User] {
				continue
			}
			created, err := time.Parse(time.RFC3339Nano, sd.Created)
			if err != nil {
				continue
			}
			stored, _ := time.Parse(time.RFC3339Nano, sd.LastSeen)
			e := entry{user: sd.User, epoch: sd.Epoch, created: created, remember: sd.Remember, method: sd.Method, born: sd.Born, stored: stored}
			if s.allows(&e, now, false) {
				seen[sd.User] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, strings.ToLower(u))
	}
	sort.Strings(out)
	return out
}

// Recover writes through the sessions made while OpenSearch could not be
// written, once it can: each only while its user is still an enabled
// admin in the same session epoch; the others end. It also deletes the
// documents of sign-outs made meanwhile.
func (s *Sessions) Recover(ctx context.Context) {
	if s.degradedNow() {
		return
	}
	k := s.Docs.key()
	if k == nil {
		return
	}
	now := s.now()
	s.Cache.mu.Lock()
	held := make(map[string]entry, len(s.Cache.degraded))
	for id, e := range s.Cache.degraded {
		held[id] = *e
	}
	pending := slices.Clone(s.Cache.pending)
	s.Cache.mu.Unlock()
	cl, index := s.index()
	for id, e := range held {
		u, _, ok := s.Docs.Users().Get(e.user)
		keep := ok && !u.Disabled && u.Refused == "" && u.SessionEpoch == e.epoch && now.Sub(e.created) < DegradedSession &&
			(u.Role == users.Admin || u.Source == users.SourceBuiltin)
		if !keep {
			s.Cache.mu.Lock()
			delete(s.Cache.degraded, id)
			s.Cache.mu.Unlock()
			s.log().Warn("a session made while OpenSearch could not be written ended: its user changed meanwhile", "audit", true, "user", e.user)
			continue
		}
		at := e.created.UTC().Format(time.RFC3339Nano)
		doc := &sessionDoc{User: e.user, Epoch: e.epoch, Created: at, LastSeen: maxTime(e.local, e.stored).UTC().Format(time.RFC3339Nano),
			Remember: e.remember, Node: s.Node, Method: e.method, Degraded: true, Born: bornText(u)}
		doc.sign(k, id)
		if _, err := cl.Create(ctx, index, id, doc, false); err != nil {
			continue
		}
		e.degraded, e.confirmed, e.born = false, now, doc.Born
		e.created, _ = time.Parse(time.RFC3339Nano, at)
		s.Cache.mu.Lock()
		delete(s.Cache.degraded, id)
		s.Cache.pos[id] = &e
		s.Cache.mu.Unlock()
		s.log().Info("wrote through a session made while OpenSearch could not be written", "audit", true, "user", e.user)
	}
	var done []string
	for _, id := range pending {
		if s.deleteDoc(ctx, id) == nil {
			done = append(done, id)
		}
	}
	if len(done) > 0 {
		s.Cache.mu.Lock()
		s.Cache.pending = slices.DeleteFunc(s.Cache.pending, func(id string) bool { return slices.Contains(done, id) })
		s.Cache.mu.Unlock()
		if h := s.Docs.Hub(); h != nil {
			_, _ = h.Bump(ctx, SessionsWatch)
		}
	}
}

// housekeepUsers is how many users one query of Housekeep names.
const housekeepUsers = 500

// Housekeep deletes the sessions that ended for good: made more than
// MaxAge ago, unused for that long and not remembered, or of an older
// session epoch of their user. It also writes through what Recover
// writes. Nothing depends on it: Lookup refuses those sessions anyway.
// It returns how many it deleted.
func (s *Sessions) Housekeep(ctx context.Context) (int, error) {
	if s.degradedNow() {
		return 0, nil
	}
	s.Recover(ctx)
	old := s.now().Add(-MaxAge).UTC().Format(time.RFC3339Nano)
	queries := []map[string]any{{"bool": map[string]any{"should": []any{
		map[string]any{"range": map[string]any{"created": map[string]any{"lt": old}}},
		map[string]any{"bool": map[string]any{"must": []any{
			map[string]any{"range": map[string]any{"last_seen": map[string]any{"lt": old}}},
			map[string]any{"term": map[string]any{"remember": false}},
		}}},
	}}}}
	var epochs []any
	for _, it := range s.Docs.Users().List() {
		if it.Value != nil && it.Value.SessionEpoch > 1 {
			epochs = append(epochs, map[string]any{"bool": map[string]any{"must": []any{
				map[string]any{"term": map[string]any{"user": it.Name}},
				map[string]any{"range": map[string]any{"epoch": map[string]any{"lt": it.Value.SessionEpoch}}},
			}}})
		}
	}
	for len(epochs) > 0 {
		n := min(len(epochs), housekeepUsers)
		queries = append(queries, map[string]any{"bool": map[string]any{"should": epochs[:n]}})
		epochs = epochs[n:]
	}
	cl, index := s.index()
	total := 0
	var errs []error
	for _, q := range queries {
		var out struct {
			Deleted int `json:"deleted"`
		}
		err := cl.Do(ctx, http.MethodPost, "/"+url.PathEscape(index)+"/_delete_by_query?conflicts=proceed&ignore_unavailable=true", map[string]any{"query": q}, &out)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		total += out.Deleted
	}
	if err := errors.Join(errs...); err != nil {
		return total, fmt.Errorf("could not delete old sessions: %w", err)
	}
	return total, nil
}
