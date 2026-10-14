package api

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The cookie that holds the sign-in session token for the web UI. Over
// HTTPS it has the __Host- prefix, so browsers keep it only when it is
// Secure, for this exact host and every path: another site or a plain
// HTTP page on this host cannot set or replace it.
const (
	sessionCookie       = "signalith_session"
	secureSessionCookie = "__Host-signalith_session"
)

// publicRoutes work without signing in. Ingest checks its own token; the
// CA certificate is public.
var publicRoutes = append([]string{"POST /api/ingest", otlpLogsRoute, "POST /api/login", "POST /api/logout", "GET /api/tls/ca.pem"}, osqueryRoutes...)

// routeLogin adds the routes that work without signing in: the sign-in
// page, its static assets, and sign-in and sign-out.
func (s *Server) routeLogin(mux *http.ServeMux) {
	// A successful sign-in says how far this server has read the shared
	// settings, as a signed-in answer does.
	mux.Handle("POST /api/login", s.configToken(true, http.HandlerFunc(s.handleLogin)))
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/tls/ca.pem", s.handleCAPEM)
	if s.UI != nil {
		mux.HandleFunc("GET /login", s.handleLoginPage)
		// Stylesheets, fonts, the logo and the sign-in script are public so
		// the sign-in page can use them.
		// Only the assets folder, never the app's own pages and scripts.
		if assets, err := fs.Sub(s.UI, "assets"); err == nil {
			mux.Handle("GET /assets/", http.StripPrefix("/assets", staticFiles(assets, false)))
			if v := versionSegment(s.Version); v != "" {
				prefix := "/v/" + v + "/assets"
				mux.Handle("GET "+prefix+"/", versionedFiles(s.Version, false, http.StripPrefix(prefix, staticFiles(assets, false))))
			}
		}
		mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/assets/favicon.svg", http.StatusMovedPermanently)
		})
	}
}

// sessions sets up everything sign-in needs on first use: sessions, the
// failed sign-in limit, and in-memory users and directory settings when
// none were given.
func (s *Server) sessions() SessionStore {
	s.authOnce.Do(func() {
		if s.SessionStore == nil {
			if s.Sessions == nil {
				s.Sessions = auth.NewSessions(s.conf().SessionIdle())
			}
			s.SessionStore = MemorySessions(s.Sessions)
		}
		if s.Limiter == nil {
			s.Limiter = auth.NewLimiter()
		}
		if s.KnownBrowsers == nil {
			s.KnownBrowsers = auth.NewBrowserKey()
		}
		if s.Users == nil {
			s.Users = users.NewMemory()
		}
		if s.Users.BuiltinAdmin == "" {
			s.Users.BuiltinAdmin = s.conf().Auth.AdminUser
		}
		if s.Directory == nil {
			s.Directory, _ = users.OpenDirectory("", nil)
		}
	})
	return s.SessionStore
}

func (s *Server) limiter() *auth.Limiter {
	s.sessions()
	return s.Limiter
}

func (s *Server) userStore() *users.Store {
	s.sessions()
	return s.Users
}

func (s *Server) dir() *users.Directory {
	s.sessions()
	return s.Directory
}

func (s *Server) unauthorized(w http.ResponseWriter, r *http.Request) {
	browser := r.Header.Get("Sec-Fetch-Mode") != ""
	if !strings.HasPrefix(r.URL.Path, "/api/") && (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		(r.Header.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(r.Header.Get("Accept"), "text/html")) {
		next := r.URL.RequestURI()
		target := "/login"
		if next != "/" {
			target += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	if !browser {
		// Only non-browser clients get the Basic challenge; in a browser it
		// would pop up the native password dialog instead of the sign-in page.
		w.Header().Set("WWW-Authenticate", `Basic realm="Signalith", charset="UTF-8"`)
	}
	writeError(w, http.StatusUnauthorized, errors.New("sign in required"))
}

// sameOrigin rejects state-changing requests a browser sent from another
// site. Requests without browser headers (API clients) pass.
func sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	}
	return true
}

// secureCookie reports whether the session cookie is sent over HTTPS
// only: when this very request reached Signalith over HTTPS, itself or
// through a trusted reverse proxy that says so with X-Forwarded-Proto.
// It does not go by server.public_url, which can say https:// while the
// request came over plain HTTP (HTTPS off, and the address saved on the
// Settings page, which applies at once): a Secure cookie would then never
// come back, and nobody could sign in. Behind a proxy that adds HTTPS,
// list the proxy under server.trusted_proxies.
func (s *Server) secureCookie(r *http.Request) bool {
	return s.overHTTPS(r)
}

// cookieName is the session cookie's name for a request.
func (s *Server) cookieName(r *http.Request) string {
	if s.secureCookie(r) {
		return secureSessionCookie
	}
	return sessionCookie
}

// handleLogin signs in from the sign-in page. A user who must change
// their password gets a session that only allows that (see allow), and
// the reply says so.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	p, err := s.signIn(r, req.Username, req.Password, "session")
	if err != nil {
		writeSignInError(w, err)
		return
	}
	token, err := s.startSession(r, p, req.Remember)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	s.setSessionCookie(w, r, token, req.Remember)
	// From now on this browser can sign in to the account even while
	// someone elsewhere is guessing its password.
	s.rememberBrowser(w, r, req.Username, p.Username)
	p.Method = "session"
	writeJSON(w, http.StatusOK, meView(p))
}

// startSession starts a session for p, signing in from r: with shared
// users, in the user's session epoch as it is now, so a password changed
// or an account disabled since ends it.
func (s *Server) startSession(r *http.Request, p *principal, remember bool) (string, error) {
	n := auth.NewSession{User: p.Username, Remember: remember, Method: p.Source, Epoch: p.epoch}
	if a := s.client(r).Addr; a.IsValid() {
		n.Client = a.String()
	}
	if p.Source == users.SourceLocal && s.SharedUsers == nil {
		n.Version = s.passwordStamp(p.Username)
	}
	return s.sessions().Create(r.Context(), n)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
		return
	}
	if c, err := r.Cookie(s.cookieName(r)); err == nil {
		if ss, ok := s.sessions().Lookup(r.Context(), c.Value, true); ok {
			s.Log.Info("signed out", append([]any{"audit", true, "user", ss.User}, s.client(r).logAttrs()...)...)
		}
		s.sessions().Delete(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(r), Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: s.secureCookie(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

// handleLoginPage serves the sign-in page, or sends a signed-in browser
// to the app. A user who must choose a new password stays here, where the
// page asks for it.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.cookieName(r)); err == nil {
		if ss, ok := s.sessions().Lookup(r.Context(), c.Value, true); ok {
			if p := s.principalFor(ss.User); p != nil && !p.MustChangePassword {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}
	}
	page, err := s.page("login.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if s.TLS.CAPEM() != nil {
		// The link to the CA certificate, hidden unless there is one to
		// download (Signalith's own, or a private CA's).
		page = bytes.Replace(page, []byte(`id="ca-help" hidden`), []byte(`id="ca-help"`), 1)
	}
	if s.TLS.Next() != nil {
		// Signalith is switching certificate authority: the line that
		// offers the new one, hidden otherwise.
		page = bytes.Replace(page, []byte(`id="ca-next" hidden`), []byte(`id="ca-next"`), 1)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

// handleCAPEM serves the certificate authority that Signalith's HTTPS
// certificate comes from, for browsers and agents to trust. It is a
// public certificate, so it needs no sign-in; check its fingerprint
// against the one in the server log before trusting it.
//
// While Signalith is switching certificate authority, which=next serves
// the new one, and which=both the one in use and the new one together.
func (s *Server) handleCAPEM(w http.ResponseWriter, r *http.Request) {
	ca, file := s.TLS.CAPEM(), "signalith-ca.crt"
	switch which := r.URL.Query().Get("which"); which {
	case "", "current":
	case "next", "both":
		if s.TLS.Next() == nil {
			writeError(w, http.StatusNotFound, errors.New("Signalith isn't switching certificate authority, so there is no new one to download."))
			return
		}
		if which == "next" {
			ca, file = s.TLS.NextPEM(), "signalith-ca-new.crt"
		} else {
			ca, file = s.TLS.AgentCAPEM(), "signalith-ca.pem"
		}
	default:
		writeError(w, http.StatusBadRequest, errors.New("which must be next or both"))
		return
	}
	if ca == nil {
		msg := "Signalith does not serve HTTPS itself (server.tls.mode is off), so there is no certificate to download."
		switch {
		case s.TLS.PublicCA():
			msg = "This server's certificate is from a certificate authority your computer already trusts, so there is nothing to download."
		case s.TLS != nil:
			msg = "This server's certificate file does not include the certificate authority that issued it. Ask whoever issued the certificate for it."
		}
		writeError(w, http.StatusNotFound, errors.New(msg))
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(ca)
}
