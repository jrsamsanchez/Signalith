package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// attempt is one sign-in through the sign-in page's API.
type attempt struct {
	user, pass string
	// xff is sent as X-Forwarded-For when set.
	xff     string
	cookies []*http.Cookie
}

type attemptResult struct {
	code    int
	body    map[string]any
	cookies []*http.Cookie
	retry   string
}

func signInWith(t *testing.T, cl *http.Client, base string, a attempt) attemptResult {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": a.user, "password": a.pass})
	req, _ := http.NewRequest("POST", base+"/api/login", strings.NewReader(string(b)))
	if a.xff != "" {
		req.Header.Set("X-Forwarded-For", a.xff)
	}
	for _, c := range a.cookies {
		req.AddCookie(c)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r attemptResult
	r.code, r.cookies, r.retry = resp.StatusCode, resp.Cookies(), resp.Header.Get("Retry-After")
	_ = json.NewDecoder(resp.Body).Decode(&r.body)
	return r
}

// newLockoutServer is a server with vera and walt as local users, its log
// in logs, reached over HTTPS (so the known-browser cookie is set) at the
// returned URL with the returned client. The sign-in limits' clock stands
// still, so a slow-down lasts until the test ends.
func newLockoutServer(t *testing.T, change func(*Server)) (*Server, string, *http.Client, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	_, s := newUsersServer(t, func(s *Server) {
		s.Log = slog.New(slog.NewTextHandler(logs, nil))
		s.Limiter = auth.NewLimiter()
		now := time.Now()
		s.Limiter.Now = func() time.Time { return now }
		for _, u := range []string{"vera", "walt"} {
			if _, err := s.Users.Create(users.NewUser{Username: u, Role: users.Analyst, Password: u + "-password"}); err != nil {
				t.Fatal(err)
			}
		}
		if change != nil {
			change(s)
		}
	})
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	cl := ts.Client()
	cl.CheckRedirect = noRedirect.CheckRedirect
	return s, ts.URL, cl, logs
}

func knownCookies(cs []*http.Cookie) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range cs {
		if strings.HasPrefix(c.Name, knownCookiePrefix) && c.Value != "" {
			out = append(out, c)
		}
	}
	return out
}

// Two people behind one address listed in server.shared_addresses (a
// proxy or NAT) cannot lock each other out, whatever one of them types.
func TestSharedAddressUsersDoNotLockEachOtherOut(t *testing.T) {
	t.Parallel()
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprint("shared=", shared), func(t *testing.T) {
			t.Parallel()
			_, base, cl, logs := newLockoutServer(t, func(s *Server) {
				if shared {
					s.Config.Server.SharedAddresses = []string{"127.0.0.1", "::1"}
				}
				// Smaller limits, for fewer password checks.
				s.Limiter.Max, s.Limiter.MaxPerAddress, s.Limiter.MaxPerAccount = 5, 10, 8
			})
			// Someone behind the address tries 11 made-up accounts, then
			// 6 guesses at vera's password.
			for i := 0; i < 11; i++ {
				signInWith(t, cl, base, attempt{user: fmt.Sprint("nobody", i), pass: "guess"})
			}
			for i := 0; i < 6; i++ {
				signInWith(t, cl, base, attempt{user: "vera", pass: "guess"})
			}
			r := signInWith(t, cl, base, attempt{user: "walt", pass: "walt-password"})
			if !shared {
				// Without the setting the address is one client, and locked.
				if r.code != http.StatusTooManyRequests || !strings.Contains(logs.String(), "server.shared_addresses") {
					t.Errorf("walt from an address not listed as shared = %d %v", r.code, r.body)
				}
				return
			}
			if r.code != http.StatusOK {
				t.Errorf("walt behind a shared address = %d %v", r.code, r.body)
			}
			if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password"}); r.code != http.StatusOK {
				t.Errorf("vera after 6 wrong guesses at her password behind a shared address = %d %v", r.code, r.body)
			}
			if strings.Contains(logs.String(), "locked_out=true") {
				t.Error("a sign-in behind a shared address was locked out")
			}
		})
	}
}

// Behind a trusted reverse proxy each person is counted by the address
// the proxy forwarded for: an attacker is locked out at their own address,
// and an address they put in the header themselves changes nothing.
func TestAttackerBehindTrustedProxyIsKeyedOnForwardedAddress(t *testing.T) {
	t.Parallel()
	_, base, cl, logs := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
	})
	for i := 0; i < 10; i++ {
		// The proxy appends the address it got the request from; anything
		// to its left is the attacker's own.
		r := signInWith(t, cl, base, attempt{user: "vera", pass: "guess", xff: fmt.Sprintf("10.66.0.%d, 198.51.100.7", i)})
		if r.code != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d %v", i+1, r.code, r.body)
		}
	}
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "198.51.100.7"}); r.code != http.StatusTooManyRequests {
		t.Errorf("the attacker's address after 10 guesses = %d", r.code)
	}
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "203.0.113.20"}); r.code != http.StatusOK {
		t.Errorf("vera from her own address behind the proxy = %d %v", r.code, r.body)
	}
	want := `user=vera client=198.51.100.7 peer=127.0.0.1 method=session reason="wrong password"`
	if !strings.Contains(logs.String(), want) {
		t.Errorf("the log does not name the attacker and the proxy (%s):\n%s", want, logs.String())
	}
	if !strings.Contains(logs.String(), `msg="signed in" audit=true user=vera role=analyst source=local client=203.0.113.20 peer=127.0.0.1`) {
		t.Errorf("the sign-in is not logged with the forwarded address:\n%s", logs.String())
	}
}

// X-Forwarded-For from a peer that is not a trusted proxy is ignored:
// anyone can send it.
func TestForwardedHeadersFromUntrustedPeerAreIgnored(t *testing.T) {
	t.Parallel()
	_, base, cl, logs := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"192.0.2.1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
	})
	for i := 0; i < 10; i++ {
		signInWith(t, cl, base, attempt{user: "vera", pass: "guess", xff: fmt.Sprintf("198.51.100.%d", i)})
	}
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "203.0.113.99"}); r.code != http.StatusTooManyRequests {
		t.Errorf("a new X-Forwarded-For from an untrusted peer got a fresh allowance: %d", r.code)
	}
	if strings.Contains(logs.String(), "198.51.100.") || strings.Contains(logs.String(), "peer=") {
		t.Errorf("the log believed X-Forwarded-For from an untrusted peer:\n%s", logs.String())
	}
}

// A browser that signed in to an account before keeps signing in while
// someone elsewhere guesses its password; strangers are slowed down.
func TestKnownBrowserSignsInDuringAnAttack(t *testing.T) {
	t.Parallel()
	s, base, cl, logs := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
	})
	first := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "192.0.2.50"})
	known := knownCookies(first.cookies)
	if first.code != 200 || len(known) != 1 {
		t.Fatalf("first sign-in = %d, known-browser cookies %v", first.code, first.cookies)
	}
	// The attacker: 30 guesses from 30 addresses, then more as fast as
	// they are allowed.
	checked := 0
	for i := 0; i < 60; i++ {
		r := signInWith(t, cl, base, attempt{user: "vera", pass: "guess", xff: fmt.Sprintf("10.1.%d.%d", i/250, i%250)})
		switch r.code {
		case http.StatusUnauthorized:
			checked++
		case http.StatusTooManyRequests:
		default:
			t.Fatalf("guess %d = %d", i+1, r.code)
		}
	}
	if checked > s.limiter().MaxPerAccount+2 {
		t.Errorf("%d of 60 guesses from many addresses were checked", checked)
	}
	// A stranger with the right password is slowed down and told why.
	r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "192.0.2.99"})
	msg, _ := r.body["error"].(string)
	if r.code != http.StatusTooManyRequests || r.body["code"] != "locked_out" || r.retry == "" ||
		!strings.Contains(msg, "use a browser you have signed in to this account with before") {
		t.Errorf("a stranger during the attack = %d %v (Retry-After %q)", r.code, r.body, r.retry)
	}
	// vera's browser, from a new address, is let in.
	r = signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "192.0.2.77", cookies: known})
	if r.code != http.StatusOK {
		t.Fatalf("vera's known browser during the attack = %d %v", r.code, r.body)
	}
	// Its mistakes are its own: a typo does not lock it.
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "typo", xff: "192.0.2.77", cookies: known}); r.code != http.StatusUnauthorized {
		t.Errorf("a typo from the known browser = %d", r.code)
	}
	// The cookie is for vera only.
	walt := signInWith(t, cl, base, attempt{user: "walt", pass: "walt-password", xff: "192.0.2.51"})
	for i := 0; i < 31; i++ {
		signInWith(t, cl, base, attempt{user: "walt", pass: "guess", xff: fmt.Sprintf("10.2.0.%d", i)})
	}
	if r := signInWith(t, cl, base, attempt{user: "walt", pass: "walt-password", xff: "192.0.2.78", cookies: known}); r.code != http.StatusTooManyRequests {
		t.Errorf("vera's cookie let a stranger past walt's slow-down: %d", r.code)
	}
	if r := signInWith(t, cl, base, attempt{user: "walt", pass: "walt-password", xff: "192.0.2.78", cookies: knownCookies(walt.cookies)}); r.code != http.StatusOK {
		t.Errorf("walt's own browser = %d %v", r.code, r.body)
	}
	// A forged or changed cookie is a stranger's.
	forged := []*http.Cookie{{Name: known[0].Name, Value: known[0].Value[:20] + strings.Repeat("A", len(known[0].Value)-20)}}
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "192.0.2.79", cookies: forged}); r.code != http.StatusTooManyRequests {
		t.Errorf("a changed cookie got past the slow-down: %d", r.code)
	}
	if _, ok := s.knownBrowser(cookieRequest(known), "vera"); !ok {
		t.Error("vera's cookie is not recognized")
	}
	if !strings.Contains(logs.String(), "locked_out=true") {
		t.Error("the slow-down is not in the log")
	}
}

// The address someone signed in from before stays theirs for the account:
// an HTTP Basic script there keeps working while the account is attacked
// from elsewhere. It has no cookie to show.
func TestBasicAuthFromAKnownAddressDuringAnAttack(t *testing.T) {
	t.Parallel()
	s, base, cl, _ := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
		s.Limiter.MaxPerAccount = 8 // fewer password checks
	})
	basic := func(xff, pass string) int {
		req, _ := http.NewRequest("GET", base+"/api/me", nil)
		req.SetBasicAuth("walt", pass)
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := basic("192.0.2.60", "walt-password"); code != 200 {
		t.Fatalf("the script's first request = %d", code)
	}
	s.creds = credCache{} // its next request checks the password again
	for i := 0; i < 10; i++ {
		basic(fmt.Sprintf("10.3.0.%d", i), "guess")
	}
	if code := basic("192.0.2.61", "walt-password"); code != http.StatusTooManyRequests {
		t.Errorf("a stranger with the right password = %d", code)
	}
	if code := basic("192.0.2.60", "walt-password"); code != 200 {
		t.Errorf("the script at its known address = %d", code)
	}
}

// A password change makes every other browser a stranger again: a cookie
// from before is only good with the password it was signed in with. The
// browser that changed it gets a new one.
func TestKnownBrowserCookieEndsWithThePassword(t *testing.T) {
	t.Parallel()
	s, base, cl, _ := newLockoutServer(t, nil)
	first := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password"})
	old := knownCookies(first.cookies)
	session := sessionCookieOf(first.cookies)
	if len(old) != 1 || session == nil {
		t.Fatalf("sign-in cookies %v", first.cookies)
	}
	if id, ok := s.knownBrowser(cookieRequest(old), "vera"); !ok || id == "" {
		t.Fatal("the fresh cookie is not recognized")
	}
	req, _ := http.NewRequest("POST", base+"/api/me/password", strings.NewReader(`{"current_password":"vera-password","new_password":"vera-new-password"}`))
	req.AddCookie(session)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("change password = %d", resp.StatusCode)
	}
	if _, ok := s.knownBrowser(cookieRequest(old), "vera"); ok {
		t.Error("a cookie from before the password change is still recognized")
	}
	renewed := knownCookies(resp.Cookies())
	if len(renewed) != 1 || renewed[0].Name != old[0].Name {
		t.Fatalf("the browser that changed the password got %v", resp.Cookies())
	}
	if _, ok := s.knownBrowser(cookieRequest(renewed), "vera"); !ok {
		t.Error("the renewed cookie is not recognized")
	}
	// An admin's reset ends it too.
	if _, err := s.Users.SetPassword("vera", "vera-reset-password", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.knownBrowser(cookieRequest(renewed), "vera"); ok {
		t.Error("a cookie from before a reset is still recognized")
	}
}

// Changing your own password while signed in is not held up by guesses
// at your account from elsewhere: the session counts as a known browser.
func TestChangePasswordDuringAnAttack(t *testing.T) {
	t.Parallel()
	_, base, cl, _ := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
		s.Limiter.MaxPerAccount = 8 // fewer password checks
	})
	first := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "192.0.2.10"})
	session := sessionCookieOf(first.cookies)
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "guess", xff: "10.4.1.1"}); r.code != http.StatusUnauthorized {
		t.Fatalf("first guess = %d", r.code)
	}
	for i := 0; i < 10; i++ {
		signInWith(t, cl, base, attempt{user: "vera", pass: "guess", xff: fmt.Sprintf("10.4.0.%d", i)})
	}
	req, _ := http.NewRequest("POST", base+"/api/me/password", strings.NewReader(`{"current_password":"vera-password","new_password":"vera-new-password"}`))
	req.Header.Set("X-Forwarded-For", "192.0.2.11")
	req.AddCookie(session)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("change password while the account is attacked = %d", resp.StatusCode)
	}
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-new-password", xff: "192.0.2.12"}); r.code != http.StatusTooManyRequests {
		t.Errorf("the account was not slowed down for strangers: %d", r.code)
	}
}

// A trusted proxy that only passes on the X-Forwarded-For a client sent
// (nginx without a proxy_set_header X-Forwarded-For line, as older docs
// showed) must not let the client pick the address it is counted under.
// Without server.client_header no such header is read: everyone behind
// the proxy counts as one shared address, so a made-up colleague's
// address in front of 35 wrong passwords locks nobody out.
func TestTrustedProxyWithoutClientHeaderIgnoresForwardedFor(t *testing.T) {
	t.Parallel()
	_, base, cl, logs := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Limiter.Max, s.Limiter.MaxPerAddress, s.Limiter.MaxPerAccount = 5, 10, 8
	})
	for i := 0; i < 12; i++ {
		if r := signInWith(t, cl, base, attempt{user: fmt.Sprint("nobody", i), pass: "guess", xff: "10.0.0.12"}); r.code != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d", i+1, r.code)
		}
	}
	if r := signInWith(t, cl, base, attempt{user: "walt", pass: "walt-password", xff: "10.0.0.12"}); r.code != http.StatusOK {
		t.Errorf("walt at the address the attacker named = %d %v", r.code, r.body)
	}
	if strings.Contains(logs.String(), "10.0.0.12") || strings.Contains(logs.String(), "peer=") {
		t.Errorf("X-Forwarded-For was believed without server.client_header:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "locked_out=true") {
		t.Error("a sign-in through the proxy was locked out")
	}
}

// With X-Forwarded-For chosen, a Forwarded header the client adds (which
// the proxy passes on unchanged) is not read: it cannot make the client
// shared and escape the per-address limit.
func TestForwardedHeaderFromTheClientChangesNothing(t *testing.T) {
	t.Parallel()
	_, base, cl, _ := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
		s.Limiter.Max, s.Limiter.MaxPerAddress, s.Limiter.MaxPerAccount = 5, 10, 50
	})
	send := func(user, pass string) int {
		b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
		req, _ := http.NewRequest("POST", base+"/api/login", strings.NewReader(string(b)))
		req.Header.Set("Forwarded", "for=unknown")
		req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.7")
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 10; i++ {
		if code := send(fmt.Sprint("nobody", i), "guess"); code != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d", i+1, code)
		}
	}
	if code := send("walt", "walt-password"); code != http.StatusTooManyRequests {
		t.Errorf("after 10 made-up accounts from one address with Forwarded: for=unknown = %d, want the address paused", code)
	}
}

// Someone who puts another person's address in front of their guesses can
// pause sign-ins from that address, but not from a browser that signed in
// to its account there before.
func TestKnownBrowserAtAPausedAddress(t *testing.T) {
	t.Parallel()
	_, base, cl, _ := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
		s.Limiter.Max, s.Limiter.MaxPerAddress = 5, 10
	})
	first := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "10.0.0.12"})
	known := knownCookies(first.cookies)
	if first.code != 200 || len(known) != 1 {
		t.Fatalf("first sign-in = %d %v", first.code, first.cookies)
	}
	for i := 0; i < 10; i++ {
		signInWith(t, cl, base, attempt{user: fmt.Sprint("nobody", i), pass: "guess", xff: "10.0.0.12"})
	}
	if r := signInWith(t, cl, base, attempt{user: "walt", pass: "walt-password", xff: "10.0.0.12"}); r.code != http.StatusTooManyRequests {
		t.Errorf("walt at the paused address = %d", r.code)
	}
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "10.0.0.12", cookies: known}); r.code != http.StatusOK {
		t.Errorf("vera's known browser at the paused address = %d %v", r.code, r.body)
	}
}

// Someone at an address vera once signed in from (an office NAT) uses up
// what known addresses may guess; vera's own browser still signs in.
func TestKnownAddressCannotTurnTheBrowserIntoAStranger(t *testing.T) {
	t.Parallel()
	s, base, cl, _ := newLockoutServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
		s.Limiter.Max, s.Limiter.MaxPerAccount = 20, 8 // fewer password checks
	})
	home := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "192.0.2.50"})
	known := knownCookies(home.cookies)
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "203.0.113.5"}); r.code != 200 || len(known) != 1 {
		t.Fatalf("sign-ins = %d, %d %v", home.code, r.code, home.cookies)
	}
	// The office address, then strangers, guess.
	for i := 0; i < s.limiter().MaxPerAccount+2; i++ {
		signInWith(t, cl, base, attempt{user: "vera", pass: "guess", xff: "203.0.113.5"})
	}
	for i := 0; i < s.limiter().MaxPerAccount; i++ {
		signInWith(t, cl, base, attempt{user: "vera", pass: "guess", xff: fmt.Sprintf("10.6.0.%d", i)})
	}
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "203.0.113.5"}); r.code != http.StatusTooManyRequests {
		t.Errorf("the office address past its budget = %d, want slowed", r.code)
	}
	if r := signInWith(t, cl, base, attempt{user: "vera", pass: "vera-password", xff: "198.51.100.30", cookies: known}); r.code != http.StatusOK {
		t.Errorf("vera's own browser = %d %v", r.code, r.body)
	}
}

// The built-in admin's known-browser cookie lasts across restarts when the
// password comes from SIGNALITH_ADMIN_PASSWORD, which each process hashes
// with a new salt; it ends when the password changes.
func TestBuiltinAdminCookieFromAnEnvironmentPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := os.WriteFile(path, []byte("auth:\n  admin_user: admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func(pw string) *config.Config {
		t.Helper()
		t.Setenv("SIGNALITH_ADMIN_PASSWORD", pw)
		c, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := load("first-password-1")
	s := &Server{Config: first, KnownBrowsers: auth.NewBrowserKey()}
	account := strings.ToLower(first.Auth.AdminUser)
	value := s.KnownBrowsers.Issue(account, s.passwordVersion(account), time.Now())
	cookie := []*http.Cookie{{Name: knownCookiePrefix + s.KnownBrowsers.CookieSuffix(account), Value: value}}
	// Only the last password's hash is kept for the process, so loading
	// another first hashes this one again with a new salt, as a restart
	// does.
	load("other-password-3")
	again := load("first-password-1")
	if again.Auth.AdminPasswordHash == first.Auth.AdminPasswordHash {
		t.Fatal("the test needs a new hash for the same password, as after a restart")
	}
	s.Config = again
	if _, ok := s.knownBrowser(cookieRequest(cookie), account); !ok {
		t.Error("the admin's cookie stopped working after a restart with the same password")
	}
	s.Config = load("second-password-2")
	if _, ok := s.knownBrowser(cookieRequest(cookie), account); ok {
		t.Error("the admin's cookie still works after the password changed")
	}
}

func sessionCookieOf(cs []*http.Cookie) *http.Cookie {
	for _, c := range cs {
		if (c.Name == secureSessionCookie || c.Name == sessionCookie) && c.Value != "" {
			return c
		}
	}
	return nil
}

func cookieRequest(cs []*http.Cookie) *http.Request {
	r := httptest.NewRequest("POST", "/api/login", nil)
	for _, c := range cs {
		r.AddCookie(c)
	}
	return r
}

func TestClientAddress(t *testing.T) {
	type tc struct {
		name, peer string
		hdr        map[string][]string
		client     string
		proxied    bool
		shared     bool
		unnamed    bool
	}
	run := func(t *testing.T, header string, cases []tc) {
		t.Helper()
		cfg := config.Default()
		cfg.Server.TrustedProxies = []string{"10.0.0.5", "10.0.0.6", "2001:db8:ff::/48"}
		cfg.Server.SharedAddresses = []string{"192.0.2.0/24"}
		cfg.Server.ClientHeader = header
		s := &Server{Config: cfg}
		for _, c := range cases {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.peer
			for k, v := range c.hdr {
				r.Header[k] = v
			}
			got := s.client(r)
			if got.String() != c.client || got.Proxied != c.proxied || got.Shared != c.shared || (got.Unnamed != "") != c.unnamed {
				t.Errorf("%s: got %+v", c.name, got)
			}
			if c.proxied && got.Peer != netip.MustParseAddrPort(c.peer).Addr() {
				t.Errorf("%s: peer %v", c.name, got.Peer)
			}
		}
	}
	xff := func(v ...string) map[string][]string { return map[string][]string{"X-Forwarded-For": v} }
	fwd := func(v ...string) map[string][]string { return map[string][]string{"Forwarded": v} }
	// Without server.client_header no header is read, and a trusted proxy
	// counts as one shared address: whatever a client sends through it.
	run(t, "", []tc{
		{"direct", "198.51.100.1:5000", nil, "198.51.100.1", false, false, false},
		{"shared address", "192.0.2.7:5000", nil, "192.0.2.7", false, true, false},
		{"trusted proxy", "10.0.0.5:5000", xff("203.0.113.1"), "10.0.0.5", false, true, false},
		{"trusted proxy, Forwarded", "10.0.0.5:5000", fwd("for=203.0.113.1"), "10.0.0.5", false, true, false},
	})
	run(t, config.ClientHeaderXFF, []tc{
		{"direct", "198.51.100.1:5000", nil, "198.51.100.1", false, false, false},
		{"untrusted peer, header ignored", "198.51.100.1:5000", xff("203.0.113.1"), "198.51.100.1", false, false, false},
		{"shared address", "192.0.2.7:5000", nil, "192.0.2.7", false, true, false},
		{"trusted proxy", "10.0.0.5:5000", xff("203.0.113.1"), "203.0.113.1", true, false, false},
		{"client-sent entries on the left", "10.0.0.5:5000", xff("1.1.1.1, 2.2.2.2, 203.0.113.1"), "203.0.113.1", true, false, false},
		{"two trusted proxies", "10.0.0.5:5000", xff("203.0.113.1, 10.0.0.6"), "203.0.113.1", true, false, false},
		{"several header lines", "10.0.0.5:5000", xff("9.9.9.9", "203.0.113.1"), "203.0.113.1", true, false, false},
		{"with a port", "10.0.0.5:5000", xff("203.0.113.1:4711"), "203.0.113.1", true, false, false},
		{"IPv6 in brackets", "[2001:db8:ff::1]:443", xff("[2001:db8:1::9]:4711"), "2001:db8:1::9", true, false, false},
		{"forwarded for a shared address", "10.0.0.5:5000", xff("192.0.2.9"), "192.0.2.9", true, true, false},
		// A request the proxy did not forward, such as one from the proxy's
		// own machine.
		{"trusted proxy naming nobody", "10.0.0.5:5000", nil, "10.0.0.5", false, true, false},
		{"only trusted proxies", "10.0.0.5:5000", xff("10.0.0.6"), "10.0.0.6", true, false, true},
		{"not an address", "10.0.0.5:5000", xff("unknown"), "10.0.0.5", false, false, true},
		{"not an address left of a trusted proxy", "10.0.0.5:5000", xff("unknown, 10.0.0.6"), "10.0.0.6", true, false, true},
		// The proxy writes X-Forwarded-For and passes Forwarded on from the
		// client: Forwarded is not read, so it cannot make the client
		// shared or pick its address.
		{"Forwarded from the client", "10.0.0.5:5000",
			map[string][]string{"Forwarded": {"for=unknown"}, "X-Forwarded-For": {"203.0.113.1"}}, "203.0.113.1", true, false, false},
		{"Forwarded only", "10.0.0.5:5000", fwd("for=203.0.113.66"), "10.0.0.5", false, true, false},
	})
	run(t, config.ClientHeaderForwarded, []tc{
		{"Forwarded", "10.0.0.5:5000", fwd(`for=1.1.1.1, for="[2001:db8:2::7]:80";proto=https;by=10.0.0.5`), "2001:db8:2::7", true, false, false},
		{"X-Forwarded-For from the client", "10.0.0.5:5000",
			map[string][]string{"Forwarded": {"for=203.0.113.1"}, "X-Forwarded-For": {"203.0.113.66"}}, "203.0.113.1", true, false, false},
		{"unknown", "10.0.0.5:5000", fwd("for=unknown"), "10.0.0.5", false, false, true},
	})
	// IPv6 clients are counted by their /64.
	s := &Server{Config: config.Default()}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8:5:6:aaaa::1]:443"
	if k := s.client(r).key(); k != "2001:db8:5:6::" {
		t.Errorf("IPv6 key %s", k)
	}
}

func TestLockedOutMessages(t *testing.T) {
	for d, want := range map[time.Duration]string{
		300 * time.Millisecond: "a second", 8 * time.Second: "8 seconds", 59500 * time.Millisecond: "a minute",
		time.Minute: "a minute", 61 * time.Second: "2 minutes", 15 * time.Minute: "15 minutes",
	} {
		if got := waitText(d); got != want {
			t.Errorf("waitText(%v) = %q, want %q", d, got, want)
		}
	}
	for _, c := range []struct {
		rf   auth.Refusal
		want string
	}{
		{auth.Refusal{Wait: auth.Busy, Reason: auth.ReasonBusy}, "Too many sign-in attempts at the same time. Wait a few seconds, then try again."},
		{auth.Refusal{Wait: 15 * time.Minute, Reason: auth.ReasonLocked}, "Too many failed sign-ins. Try again in 15 minutes."},
		{auth.Refusal{Wait: 4 * time.Second, Reason: auth.ReasonSlowed}, "Many wrong passwords were tried for this account, so sign-ins to it from new browsers are slowed down. " +
			"Try again in 4 seconds, or use a browser you have signed in to this account with before."},
	} {
		rf := c.rf
		var se *signInError
		if err := lockedOut(&rf); !errors.As(err, &se) || se.msg != c.want || se.status != http.StatusTooManyRequests || se.retryAfter != rf.Wait {
			t.Errorf("%+v: %+v", rf, se)
		}
	}
}
