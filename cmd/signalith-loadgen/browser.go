package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Browsers are simulated people with the web pages open: they sign in,
// keep the findings queue and a search fresh, and, with triage, comment
// on the same findings and the same case as each other, which is where
// servers that share state can trip over each other.
type Browsers struct {
	run     string
	load    UserLoad
	targets []string
	tr      http.RoundTripper
	users   [][2]string
	// caseID is the case every analyst writes to, when triage is on.
	caseID string
	m      *Metrics
}

// Run uses the pages until ctx ends, then signs every user out.
func (b *Browsers) Run(ctx context.Context) {
	if len(b.users) == 0 {
		b.m.Add("users_without_account", int64(b.load.N))
		return
	}
	var wg sync.WaitGroup
	for i := range b.load.N {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Spread the users' first page loads over one think time.
			think := b.think()
			select {
			case <-ctx.Done():
				return
			case <-time.After(think * time.Duration(i) / time.Duration(max(b.load.N, 1))):
			}
			u := b.users[i%len(b.users)]
			s := newSession(b.targets[i%len(b.targets)], b.tr, u[0], u[1])
			b.user(ctx, s)
		}(i)
	}
	wg.Wait()
}

func (b *Browsers) think() time.Duration {
	if b.load.Think > 0 {
		return b.load.Think.D()
	}
	return 5 * time.Second
}

func (b *Browsers) user(ctx context.Context, s *Session) {
	start := time.Now()
	if err := s.SignIn(ctx); err != nil {
		b.m.Add("signin_errors", 1)
		b.m.Add("signin_status_"+strconv.Itoa(statusOf(err)), 1)
		return
	}
	b.m.Observe("signin", time.Since(start))
	defer func() {
		out, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.SignOut(out)
	}()
	tick := time.NewTicker(b.think())
	defer tick.Stop()
	for {
		b.visit(ctx, s)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// visit is one round of page loads.
func (b *Browsers) visit(ctx context.Context, s *Session) {
	var list struct {
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if !b.call(ctx, s, "page", http.MethodGet, "/api/findings?limit=50&status=new,in_progress", nil, &list) {
		return
	}
	b.call(ctx, s, "page", http.MethodGet, "/api/health", nil, nil)
	q := b.load.Search
	if q == "" {
		q = "loadgen_run=" + b.run + " | stats count by host"
	}
	b.call(ctx, s, "search", http.MethodPost, "/api/search", map[string]string{"query": q, "earliest": "-15m"}, nil)
	if !b.load.Triage {
		return
	}
	// Everyone triages the same few findings, the worst case for writes.
	for _, f := range list.Findings[:min(3, len(list.Findings))] {
		b.call(ctx, s, "write", http.MethodPatch, "/api/findings/"+url.PathEscape(f.ID),
			map[string]string{"comment": fmt.Sprintf("loadgen %s: looked at by %s", b.run, s.User)}, nil)
	}
	if b.caseID != "" {
		b.call(ctx, s, "write", http.MethodPost, "/api/cases/"+url.PathEscape(b.caseID)+"/entries",
			map[string]string{"kind": "note", "text": fmt.Sprintf("loadgen %s: note from %s", b.run, s.User)}, nil)
	}
}

// call makes one request and records it; false means stop this round.
func (b *Browsers) call(ctx context.Context, s *Session, kind, method, path string, in, out any) bool {
	start := time.Now()
	err := s.Do(ctx, method, path, in, out)
	if ctx.Err() != nil {
		return false
	}
	b.m.Observe(kind, time.Since(start))
	b.m.Add("user_requests", 1)
	switch st := statusOf(err); {
	case err == nil:
		return true
	case st == http.StatusUnauthorized:
		// A signed-in user sent back to the sign-in page: the session
		// was lost, as when another server does not know it.
		b.m.Add("unexpected_signouts", 1)
		return false
	case st == http.StatusConflict:
		b.m.Add("write_conflicts", 1)
		return true
	default:
		b.m.Add("user_errors", 1)
		b.m.Add("user_status_"+strconv.Itoa(st), 1)
		return st != 0
	}
}
