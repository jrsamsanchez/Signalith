// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The users, the directory sign-in settings and the sign-in sessions of a
// member of a cluster, once every server reads them from the shared
// settings (cluster level 2) and the founder's were imported
// (shared.Runtime.SharedUsers): a person then signs in once and is known
// on every server, and sign-in lockouts count across them
// (internal/clusterauth). Until then, and on any server that is not a
// member, they stay in this server's files and memory, as before. Which
// one is decided at each start of the components; a change restarts them
// in place; the sessions made before carry over (carry).

// sharedUsers links the shared users' documents to the components of each
// start. Like the runtime, it belongs to the process: its session cache
// (sessions read lately, and those made while OpenSearch could not be
// written) is kept across restarts in place.
type sharedUsers struct {
	docs  *clusterauth.Docs
	cache *clusterauth.SessionCache
	log   *slog.Logger
	// on is true while the components running now keep the users in the
	// shared settings, and cur holds them then.
	on  atomic.Bool
	cur atomic.Pointer[usersParts]

	// servers is how many servers take sign-ins, worked out from the
	// node's status at most every serversFor.
	serversMu sync.Mutex
	servers   int
	serversAt time.Time
}

// usersParts are the shared users' components of one start.
type usersParts struct {
	store    *users.Store
	dir      *users.Directory
	sessions *clusterauth.Sessions
	locks    *clusterauth.Locks
	seen     *clusterauth.LastSeen
	recheck  *clusterauth.Recheck
	spent    *clusterauth.Spent
	browsers *auth.BrowserKey
	node     *cluster.Node
}

// newSharedUsers returns the link for the process.
func newSharedUsers(log *slog.Logger) *sharedUsers {
	return &sharedUsers{docs: clusterauth.NewDocs(), cache: clusterauth.NewSessionCache(), log: log}
}

// follow ties the shared users to the runtime of the process: the
// documents check built-in admins against its cluster document, and once
// OpenSearch takes writes again the sessions made meanwhile are written
// through.
func (ua *sharedUsers) follow(rt *shared.Runtime) {
	ua.docs.Cluster = rt.Cluster
	ua.docs.Tenants = rt.Tenants
	rt.OnMode(func(_, m shared.Mode) {
		if m != shared.ModeMember {
			return
		}
		if p := ua.cur.Load(); p != nil {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				p.sessions.Recover(ctx)
			}()
		}
	})
}

// start builds the shared users' components of a start on cl. They work
// until ctx ends; what runs on every server runs in jobs.
func (ua *sharedUsers) start(ctx context.Context, rt *shared.Runtime, node *cluster.Node, c *config.Config, cl *store.Client,
	limiter *auth.Limiter, legacyBrowsers *auth.BrowserKey, jobs *sync.WaitGroup) (*usersParts, error) {
	prefix := c.OpenSearch.IndexPrefix
	client := func() (*store.Client, string) { return cl, prefix }
	writable := func() bool { return rt.Writable() == nil }
	log := ua.log
	ub := &clusterauth.UsersBackend{Docs: ua.docs}
	st, err := users.New(ub)
	if err != nil {
		return nil, err
	}
	seen := &clusterauth.LastSeen{Client: client, Node: node.Name(), Writable: writable}
	st.Builtin, st.SignIns = ua.docs.Builtin, seen.Hook(log)
	dir := users.NewDirectory(&clusterauth.DirectoryBackend{Docs: ua.docs, Node: node.Name()})
	sess := &clusterauth.Sessions{Docs: ua.docs, Client: client, Node: node.ID(), Cache: ua.cache, DirectoryOn: dir.Enabled,
		Degraded: func() bool {
			m, _ := rt.Mode()
			return m != shared.ModeMember
		},
		Confirmed: func() time.Time { return rt.Hub().Confirmed() }, Log: log}
	sess.SetIdle(c.SessionIdle())
	sess.SetMaxAge(c.SessionMaxAge())
	sess.Listen()
	// The limiter reports its locks through the runner (reportLock), which
	// it was given once for the process.
	locks := &clusterauth.Locks{Docs: ua.docs, Client: client, Node: node.ID(), Limiter: limiter, Writable: writable, Log: log}
	locks.Follow()
	jobs.Go(func() { locks.Run(ctx) })
	p := &usersParts{store: st, dir: dir, sessions: sess, locks: locks, seen: seen, node: node, browsers: legacyBrowsers,
		spent:   &clusterauth.Spent{Docs: ua.docs, Client: client, Node: node.ID()},
		recheck: &clusterauth.Recheck{Docs: ua.docs, Store: st, Users: ub, Directory: dir, Sessions: sess, Log: log}}
	// A browser known on one server is known on every one.
	if k := rt.Hub().Keys().Active(); k != nil {
		p.browsers = auth.NewBrowserKeyFrom(k.KnownBrowserKey())
	}
	if name := ua.docs.BuiltinName(); config.KeptLegacyAdmin(name, c.Auth.AdminUser) {
		log.Info("the built-in admin keeps the name it had before this version; new installs name it "+config.DefaultAdminUser,
			"builtin", name, "admin_user", c.Auth.AdminUser)
	} else if name != "" && !strings.EqualFold(name, c.Auth.AdminUser) {
		log.Warn("the cluster's built-in admin has another name than auth.admin_user on this server; the cluster's name is used",
			"builtin", name, "admin_user", c.Auth.AdminUser)
	}
	return p, nil
}

// use makes p the shared users' components running now; nil when the
// users are kept in this server's files.
func (ua *sharedUsers) use(p *usersParts) {
	ua.cur.Store(p)
	ua.on.Store(p != nil)
}

// carry moves the sign-in sessions this server made while it kept its
// users in its own files (legacy, for the users of people and the
// built-in admin of c) into the shared sessions when it starts using the
// shared users, so the switch signs out only those whom the shared
// settings do not have as they were here (clusterauth.Sessions.Carry).
func (p *usersParts) carry(ctx context.Context, legacy *auth.Sessions, people *users.Store, c *config.Config, log *slog.Logger) {
	// A sign-in the old components were still finishing when the restart
	// stopped waiting for them ends after the sessions moved: its session
	// is carried on its own, or its browser would be signed out at once.
	late := context.WithoutCancel(ctx) // ctx itself is replaced below
	legacy.Forward(func(h auth.Held) {
		ctx, cancel := context.WithTimeout(late, time.Minute)
		defer cancel()
		if n, _ := p.sessions.Carry(ctx, carried([]auth.Held{h}, people, c)); n == 0 {
			log.Warn("a sign-in that finished while this server moved to the shared users could not be kept; that browser signs in again",
				"audit", true, "user", h.User)
		}
	})
	held := legacy.Take()
	if len(held) == 0 {
		return
	}
	list := carried(held, people, c)
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	n, dropped := p.sessions.Carry(ctx, list)
	dropped += len(held) - len(list)
	log.Info("kept the sign-in sessions made before the users were shared", "audit", true, "kept", n, "ended", dropped)
}

// carried returns the sessions of held whose users this server has as
// they are (the built-in admin of c, or a user of people), for Carry.
func carried(held []auth.Held, people *users.Store, c *config.Config) []clusterauth.Carried {
	list := make([]clusterauth.Carried, 0, len(held))
	for _, h := range held {
		cr := clusterauth.Carried{Held: h}
		switch {
		case h.Method == users.SourceBuiltin:
			if !strings.EqualFold(h.User, c.Auth.AdminUser) {
				continue
			}
			cr.Role, cr.PasswordHash = users.Admin, c.Auth.AdminPasswordHash
		case people != nil:
			u, ok := people.Get(h.User)
			if !ok || u.Disabled || u.Source != h.Method {
				continue
			}
			cr.Role = u.Role
			if u.Source == users.SourceLocal {
				cr.PasswordHash = people.PasswordVersion(u.Username)
				if h.Version != "" && h.Version != api.PasswordStamp(cr.PasswordHash) {
					continue
				}
			}
		default:
			continue
		}
		list = append(list, cr)
	}
	return list
}

// firstPasswordMu keeps keepFirstPasswordChange from running twice at
// once (at the switch and from a late change on the page).
var firstPasswordMu sync.Mutex

// keepFirstPasswordChange carries into the shared settings a change of
// the first password Signalith made that this server kept in its own
// files while its users moved into the shared settings: the change on
// the page lands there when it reaches the server between the import and
// the switch, and the cluster's built-in admin would keep the first
// password. It does so only while the cluster's built-in admin still has
// this server's first password and was never changed since the import
// (session epoch 1), so a password set on the cluster is never replaced
// with an older one. It returns the hash it set, or "".
func keepFirstPasswordChange(ctx context.Context, docs *clusterauth.Docs, c *config.Config, log *slog.Logger) string {
	firstPasswordMu.Lock()
	defer firstPasswordMu.Unlock()
	b, err := os.ReadFile(c.AdminHashFile())
	if err != nil {
		return ""
	}
	h := strings.TrimSpace(string(b))
	if _, err := bcrypt.Cost([]byte(h)); err != nil {
		return ""
	}
	u, _, ok := docs.BuiltinUser()
	if !ok || u.SessionEpoch != 1 || u.PasswordHash == h || !isFirstPassword(c, u.PasswordHash) {
		return ""
	}
	if err := docs.SetBuiltinHash(ctx, u.Username, h); err != nil {
		log.Warn("the built-in admin's new password reached this server while its users moved into the shared settings and could not be kept there; "+
			"change it again on the page or with signalith passwd", "user", u.Username, "err", err)
		return ""
	}
	log.Info("kept the built-in admin's new password, changed while the users moved into the shared settings", "audit", true, "user", u.Username)
	return h
}

// isFirstPassword reports whether hash is that of the first password
// Signalith made for the built-in admin of this server (see
// config.FirstPassword).
func isFirstPassword(c *config.Config, hash string) bool {
	if fh := c.FirstPasswordHash(); fh != "" && subtle.ConstantTimeCompare([]byte(fh), []byte(hash)) == 1 {
		return true
	}
	file, _ := c.InitialPasswordFile()
	if file == "" {
		return false
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	pw := strings.TrimSpace(string(b))
	return pw != "" && users.ComparePassword(hash, pw)
}

// builtinSetHere is api.Server.BuiltinSetHere for a server whose API keeps
// the users in its own files: once the users are shared (the change
// finished after the switch), the change is carried there.
func (ua *sharedUsers) builtinSetHere(c *config.Config) func(context.Context) {
	return func(ctx context.Context) {
		if p := ua.cur.Load(); p != nil {
			keepFirstPasswordChange(ctx, p.sessions.Docs, c, ua.log)
		}
	}
}

// api is what the API needs of p.
func (p *usersParts) api(c *config.Config) *api.SharedUsers {
	local := &localHash{dir: c.StateDir()}
	return &api.SharedUsers{Docs: p.sessions.Docs, Seen: p.seen, LocalHash: local.get,
		WritesRefused: p.node.WritesRefused, MayDegrade: p.sessions.MayDegrade, Spent: p.spent}
}

// localHashFor is how long the hash signalith passwd -local wrote is used
// before its file is read again.
const localHashFor = 2 * time.Second

// localHash reads the built-in admin's password hash that signalith
// passwd -local wrote, at most every localHashFor, so a new one works
// without a restart. A file that cannot be read now (on Windows, while
// passwd replaces it) keeps the hash read before.
type localHash struct {
	dir string
	mu  sync.Mutex
	at  time.Time
	h   string
}

func (l *localHash) get() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.at.IsZero() && time.Since(l.at) < localHashFor {
		return l.h
	}
	if h, err := config.ReadAdminLocalHash(l.dir); err == nil {
		l.h, l.at = h, time.Now()
	}
	return l.h
}

// job is the background job that checks signed-in directory users again,
// for every server.
func (p *usersParts) job() cluster.Job {
	return cluster.Job{Name: "directory", Run: p.recheck.Loop}
}

// housekeep deletes the sessions and lockouts that ended, and the last
// sign-ins of deleted users; the server that runs the background jobs
// calls it with the shared settings' housekeeping.
func (p *usersParts) housekeep(ctx context.Context, log *slog.Logger) {
	if n, err := p.sessions.Housekeep(ctx); err != nil {
		log.Debug("could not delete old sign-in sessions", "err", err)
	} else if n > 0 {
		log.Info("deleted sign-in sessions that ended", "sessions", n)
	}
	if _, err := p.locks.Housekeep(ctx); err != nil {
		log.Debug("could not delete sign-in lockouts that ended", "err", err)
	}
	if _, err := p.spent.Housekeep(ctx); err != nil {
		log.Debug("could not delete the records of used sign-ins that ended", "err", err)
	}
	// The last sign-ins of deleted users; the built-in admin is a user
	// document too.
	var names []string
	for _, it := range p.sessions.Docs.Users().List() {
		names = append(names, it.Name)
	}
	if len(names) > 0 {
		if _, err := p.seen.Housekeep(ctx, names); err != nil {
			log.Debug("could not delete the last sign-ins of deleted users", "err", err)
		}
	}
}

// serversFor is how long the count of servers that take sign-ins is used
// before it is worked out again.
const serversFor = 15 * time.Second

// signInServers is how many servers take sign-ins now, for the
// limiter's Divisor: the servers ready in the node's view while the users
// are shared, else 1 (each server counts on its own).
func (ua *sharedUsers) signInServers() int {
	p := ua.cur.Load()
	if p == nil || p.node == nil {
		return 1
	}
	ua.serversMu.Lock()
	defer ua.serversMu.Unlock()
	if !ua.serversAt.IsZero() && time.Since(ua.serversAt) < serversFor {
		return ua.servers
	}
	n := 0
	for _, s := range p.node.Status().Servers {
		if s.State == cluster.StateReady {
			n++
		}
	}
	ua.servers, ua.serversAt = max(n, 1), time.Now()
	return ua.servers
}

// reportLock tells the other servers about a lock the limiter tripped,
// while the users are shared.
func (ua *sharedUsers) reportLock(scope, key string, until time.Time) {
	if p := ua.cur.Load(); p != nil {
		p.locks.Report(scope, key, until)
	}
}

// sharedCachePath is this server's copy of the shared settings, which a
// server has once it was a member of a cluster.
func sharedCachePath(c *config.Config) string { return shared.CachePath(c.StateDir()) }

// passwdShared gives the built-in admin of the cluster the password hash
// h, when the server of the config at path is a member whose users are
// shared and OpenSearch answers: every server uses it within a few
// seconds. It reports whether it did; when it did not, it says why if the
// server was ever a member, and signalith passwd changes this server's
// files as before.
func passwdShared(path, stateDir, h string) (bool, error) {
	if _, err := os.Stat(shared.CachePath(stateDir)); err != nil {
		// Never a member of a cluster.
		return false, nil
	}
	fallback := func(why string) (bool, error) {
		fmt.Printf("%s, so the password is changed in this server's files only.\n", why)
		return false, nil
	}
	log := newLogger(os.Stderr)
	c, err := loadConfig(path, log)
	if err != nil {
		return fallback(fmt.Sprintf("The configuration could not be read (%v)", err))
	}
	self, err := cluster.ReadIdentity(c.StateDir())
	if err != nil {
		return fallback("This server has no identity yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cl, err := cliOpenSearch(ctx, c, "the password the servers of the cluster share cannot be changed")
	if err != nil {
		return fallback(strings.TrimSuffix(err.Error(), "."))
	}
	defer cl.CloseIdleConnections()
	x := &clusterCLI{c: c, cl: cl, log: log, self: self, errOut: os.Stderr, out: os.Stdout, by: cliUser()}
	rt := x.runtime(true, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return fallback(fmt.Sprintf("This server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text())))
	}
	if !rt.SharedUsers() {
		return fallback("The servers of this cluster do not share their users yet")
	}
	if err := x.auth.SetBuiltinHash(ctx, x.by, h); err != nil {
		return true, fmt.Errorf("could not change the built-in admin's password in the shared settings: %w", err)
	}
	x.audit("changed the built-in admin's password for every server of the cluster", "user", x.auth.BuiltinName())
	fmt.Println("Password updated for every server of the cluster. It applies on every server within a few seconds; no restart needed.")
	return true, nil
}
