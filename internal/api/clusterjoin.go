package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"math"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// ClusterJoin adds servers to the cluster (internal/clusterjoin): join
// tokens an admin makes on the Servers page, the public join a new
// server makes with one, and the approval of a server that waits with
// its fingerprint.
type ClusterJoin interface {
	// Issue makes a join token for the user by. The token, secret
	// included, is in the answer only.
	Issue(ctx context.Context, by string, req JoinTokenRequest) (*clusterjoin.Issued, error)
	// Revoke deletes a token.
	Revoke(ctx context.Context, by, id string) error
	// Tokens lists the tokens, without secrets.
	Tokens() []clusterjoin.TokenInfo
	// Pending lists the servers that wait for approval.
	Pending(ctx context.Context) ([]shared.PendingDoc, error)
	// Approve makes the waiting server nodeID a member once fingerprint
	// matches its node key.
	Approve(ctx context.Context, nodeID, fingerprint, by string) (*shared.PendingDoc, error)
	// Answer answers a new server's join (clusterjoin.Answer).
	Answer(ctx context.Context, req *clusterjoin.Request) (string, error)
	// Install returns the install script for os ("sh" or "ps1") and its
	// SHA-256, and Binary the path of this program for goos and arch and
	// its SHA-256; both are empty where the server has none to hand out.
	Install(os string) (script []byte, sha256 string)
	Binary(goos, arch string) (path, sha256 string)
	// Waiting is what the sign-in page of a server waiting for approval
	// says, "" otherwise.
	Waiting() string
}

// JoinTokenRequest is the body of POST /api/cluster/tokens.
type JoinTokenRequest struct {
	Platform   string `json:"platform"`
	TTLMinutes int    `json:"ttl_minutes"`
	Note       string `json:"note"`
	NodeURL    string `json:"node_url"`
	// Origin is the https address the admin's browser reached this server
	// at, used when the server has no node_url or public_url; CADER is
	// the certificate authority the new server finds at GET
	// /api/cluster/join/ca. The API fills both.
	Origin string `json:"-"`
	CADER  []byte `json:"-"`
}

// joinPublicRoutes are the join routes that work without signing in: a
// new server has no account. Each is size- and rate-limited and says
// nothing about why it refused.
var joinPublicRoutes = []string{"GET /api/cluster/join/ca", "POST /api/cluster/join"}

// routeJoinPublic adds the public join routes to the outer mux.
func (s *Server) routeJoinPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/cluster/join/ca", s.handleJoinCA)
	mux.HandleFunc("POST /api/cluster/join", s.handleJoin)
}

// routeClusterJoin adds the admin's join routes.
func (s *Server) routeClusterJoin(api *router) {
	// Who may join the cluster is the admin's to decide.
	api.admin("GET /api/cluster/join/tokens", s.handleJoinTokens)
	api.admin("POST /api/cluster/tokens", s.handleJoinTokenNew)
	api.admin("DELETE /api/cluster/tokens/{id}", s.handleJoinTokenRevoke)
	api.admin("GET /api/cluster/pending", s.handleJoinPending)
	api.admin("POST /api/cluster/servers/{id}/approve", s.handleJoinApprove)
}

var errNoJoin = errors.New("this server cannot add servers to a cluster: it does not keep shared settings")

// joinCAPEM is the certificate a join token pins: the certificate
// authority this server's HTTPS certificate comes from (the cluster's
// once it took it), or the root of the admin's chain. nil when there is
// none: a certificate from a public authority, or no HTTPS here.
func (s *Server) joinCAPEM() []byte { return s.TLS.CAPEM() }

// handleJoinCA answers GET /api/cluster/join/ca: the certificate whose
// SHA-256 a join token names, which the new server compares before it
// trusts this server. 404 when there is none.
func (s *Server) handleJoinCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ca := s.joinCAPEM()
	if ca == nil {
		writeError(w, http.StatusNotFound, errors.New("this server has no certificate authority a new server could check it by"))
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(ca)
}

// handleJoin answers POST /api/cluster/join, a new server's join with a
// token: 200 {sealed}, or 403 with the one refusal text. It counts
// against the sign-in limits, per token and per client address, before
// anything reads OpenSearch.
func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Join == nil {
		writeError(w, http.StatusServiceUnavailable, clusterjoin.ErrUnavailable)
		return
	}
	from := s.client(r)
	logRefused := func(reason string) {
		s.Log.Warn("cluster.join refused", slices.Concat([]any{"audit", true}, from.logAttrs(), []any{"reason", reason})...)
	}
	var req clusterjoin.Request
	body := http.MaxBytesReader(w, r.Body, clusterjoin.MaxRequest)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		logRefused("the request is not one: " + err.Error())
		writeError(w, http.StatusForbidden, errors.New(clusterjoin.Refused))
		return
	}
	account := "join:" + req.TokenID
	if !clusterjoin.ValidID(req.TokenID) {
		account = "join:?"
	}
	attempt, err := s.limiter().Begin(auth.Client{Address: from.key(), Shared: from.Shared}, account)
	var rf *auth.Refusal
	if errors.As(err, &rf) {
		logRefused("too many join attempts")
		w.Header().Set("Retry-After", fmt.Sprint(int(math.Ceil(rf.Wait.Seconds()))))
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("Too many join attempts. Try again in %s.", waitText(rf.Wait)))
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, clusterjoin.ErrUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	// The machine it comes from: the TCP peer, never a proxy header.
	req.RemoteIP = nil
	if from.Peer.IsValid() {
		req.RemoteIP = net.IP(from.Peer.Unmap().AsSlice())
	}
	sealed, err := s.Join.Answer(ctx, &req)
	var refused *clusterjoin.RefusedError
	var joinErr *clusterjoin.JoinError
	switch {
	case err == nil:
		attempt.Succeed()
		writeJSON(w, http.StatusOK, clusterjoin.Reply{Sealed: sealed})
	case errors.As(err, &refused):
		f := attempt.Fail()
		logRefused(clusterjoin.Reason(err))
		if f.AddressLocked {
			s.noteFailure(from, f)
		}
		writeError(w, http.StatusForbidden, errors.New(clusterjoin.Refused))
	case errors.As(err, &joinErr):
		attempt.Done()
		logRefused(joinErr.Msg)
		writeError(w, http.StatusForbidden, joinErr)
	case errors.Is(err, clusterjoin.ErrSpent):
		// The token is used: the new server needs a new one, and is told
		// so rather than to try again.
		attempt.Done()
		s.Log.Warn("cluster.join failed after the token was used", slices.Concat(from.logAttrs(), []any{"err", clusterjoin.Reason(err)})...)
		writeError(w, http.StatusInternalServerError, clusterjoin.ErrSpent)
	default:
		attempt.Done()
		s.Log.Warn("cluster.join could not be answered", slices.Concat(from.logAttrs(), []any{"err", clusterjoin.Reason(err)})...)
		writeError(w, http.StatusServiceUnavailable, clusterjoin.ErrUnavailable)
	}
}

// joinTokens lists the tokens for the page, none without a Join.
func (s *Server) joinTokens() []clusterjoin.TokenInfo {
	if s.Join == nil {
		return []clusterjoin.TokenInfo{}
	}
	if l := s.Join.Tokens(); l != nil {
		return l
	}
	return []clusterjoin.TokenInfo{}
}

// handleJoinTokens answers GET /api/cluster/join/tokens: the tokens,
// never their secrets.
func (s *Server) handleJoinTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"tokens": s.joinTokens()})
}

// joinTokenAnswer is the answer to POST /api/cluster/tokens: the only
// place the token is ever shown.
type joinTokenAnswer struct {
	ID            string            `json:"id"`
	Token         string            `json:"token"`
	ExpiresAt     time.Time         `json:"expires_at"`
	Commands      joinCommands      `json:"commands"`
	InstallSHA256 map[string]string `json:"install_sha256"`
}

// joinCommands are the lines an admin pastes on the new server.
type joinCommands struct {
	Linux   string `json:"linux"`
	Windows string `json:"windows"`
	Docker  string `json:"docker"`
}

// commandsFor returns the lines that join a server with the token tok:
// Signalith installed from a package (Linux) or the .msi (Windows), and
// the variable of Docker's .env file.
func commandsFor(tok string) joinCommands {
	q := "'" + tok + "'"
	return joinCommands{
		Linux:   "sudo signalith join " + q,
		Windows: `& "$env:ProgramFiles\Signalith\signalith.exe" join ` + q,
		Docker:  "SIGNALITH_JOIN=" + tok,
	}
}

// JoinLines returns the Linux, Windows and Docker lines that join a
// server with the token tok, as POST /api/cluster/tokens gives them, for
// signalith cluster token.
func JoinLines(tok string) (linux, windows, docker string) {
	c := commandsFor(tok)
	return c.Linux, c.Windows, c.Docker
}

// handleJoinTokenNew answers POST /api/cluster/tokens {platform,
// ttl_minutes, note, node_url}: a new join token, shown once.
func (s *Server) handleJoinTokenNew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Join == nil {
		writeError(w, http.StatusServiceUnavailable, errNoJoin)
		return
	}
	var req JoinTokenRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.TTLMinutes < 0 {
		writeError(w, http.StatusBadRequest, errors.New("ttl_minutes must be positive"))
		return
	}
	ca := s.joinCAPEM()
	if b, _ := pem.Decode(ca); b != nil {
		req.CADER = b.Bytes
	} else {
		writeError(w, http.StatusConflict, errors.New("this server's HTTPS certificate is not from a certificate authority a new server could check it by "+
			"(Signalith's own, or a private one whose root is in the certificate file), so it cannot make a join token. "+
			"Approve the new server by its fingerprint instead, or give it the cluster key with signalith cluster export-key"))
		return
	}
	if r.TLS != nil && r.Host != "" {
		req.Origin = "https://" + r.Host
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	is, err := s.Join.Issue(ctx, userOf(r), req)
	if err != nil {
		switch {
		case sharedError(w, err):
		case errors.Is(err, clusterjoin.ErrNotSecured):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusBadRequest, err)
		}
		return
	}
	defer is.Token.Clear()
	s.audit(r, "join token made", "token", is.Token.ID, "platform", req.Platform, "expires_at", is.ExpiresAt, "note", req.Note)
	text := is.Token.String()
	out := joinTokenAnswer{ID: is.Token.ID, Token: text, ExpiresAt: is.ExpiresAt, Commands: commandsFor(text), InstallSHA256: map[string]string{}}
	for _, os := range []string{"sh", "ps1"} {
		if _, sum := s.Join.Install(os); sum != "" {
			out.InstallSHA256[os] = sum
		}
	}
	writeJSON(w, http.StatusCreated, out)
}

// handleJoinTokenRevoke answers DELETE /api/cluster/tokens/{id}.
func (s *Server) handleJoinTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if s.Join == nil {
		writeError(w, http.StatusServiceUnavailable, errNoJoin)
		return
	}
	id := r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Join.Revoke(ctx, userOf(r), id); err != nil {
		switch {
		case sharedError(w, err):
		case errors.Is(err, clusterjoin.ErrTokenUnknown):
			writeError(w, http.StatusNotFound, errors.New("there is no join token "+id))
		default:
			writeError(w, http.StatusServiceUnavailable, err)
		}
		return
	}
	s.audit(r, "join token revoked", "token", id)
	w.WriteHeader(http.StatusNoContent)
}

// waitingServer is a server that waits for approval, as the page shows
// it.
type waitingServer struct {
	NodeID      string    `json:"node_id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	Version     string    `json:"version,omitempty"`
	OS          string    `json:"os,omitempty"`
	Arch        string    `json:"arch,omitempty"`
	Addresses   []string  `json:"addresses,omitempty"`
	NodeURL     string    `json:"node_url,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
	SeenAt      time.Time `json:"seen_at"`
}

// joinPending lists the waiting servers.
func (s *Server) joinPending(ctx context.Context) ([]waitingServer, error) {
	out := []waitingServer{}
	if s.Join == nil {
		return out, nil
	}
	list, err := s.Join.Pending(ctx)
	for _, p := range list {
		out = append(out, waitingServer{NodeID: p.NodeID, Name: p.Name, Fingerprint: p.Fingerprint, Version: p.Version, OS: p.OS,
			Arch: p.Arch, Addresses: p.Addresses, NodeURL: p.NodeURL, RequestedAt: p.RequestedAt, SeenAt: p.At})
	}
	return out, err
}

// handleJoinPending answers GET /api/cluster/pending.
func (s *Server) handleJoinPending(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	list, err := s.joinPending(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": list})
}

// handleJoinApprove answers POST /api/cluster/servers/{id}/approve
// {fingerprint}: the fingerprint the admin read on the new server must
// match the one of its node key (409 otherwise).
func (s *Server) handleJoinApprove(w http.ResponseWriter, r *http.Request) {
	if s.Join == nil {
		writeError(w, http.StatusServiceUnavailable, errNoJoin)
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Fingerprint) == "" {
		writeError(w, http.StatusBadRequest, errors.New("type or confirm the fingerprint the new server shows (fingerprint)"))
		return
	}
	id := r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	p, err := s.Join.Approve(ctx, id, req.Fingerprint, userOf(r))
	if err != nil {
		switch {
		case sharedError(w, err):
		case errors.Is(err, clusterjoin.ErrNoPending):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, clusterjoin.ErrFingerprint), errors.Is(err, clusterjoin.ErrNotSecured), errors.Is(err, clusterjoin.ErrRotating),
			errors.As(err, new(*clusterjoin.ClashError)):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusServiceUnavailable, err)
		}
		return
	}
	s.audit(r, "server approved to join the cluster", "server", p.Name, "node_id", p.NodeID, "fingerprint", p.Fingerprint)
	writeJSON(w, http.StatusOK, map[string]any{"node_id": p.NodeID, "name": p.Name, "fingerprint": p.Fingerprint})
}

// clusterJoinView is what GET /api/cluster adds about joins: the open
// tokens and the waiting servers.
func (s *Server) clusterJoinView(ctx context.Context) map[string]any {
	if s.Join == nil {
		return nil
	}
	pending, err := s.joinPending(ctx)
	if err != nil {
		s.Log.Debug("could not list the servers waiting for approval", "err", err)
	}
	return map[string]any{"tokens": s.joinTokens(), "pending": pending}
}

// joinWaiting puts a waiting server's line on the sign-in page.
func (s *Server) joinWaiting(page []byte) []byte {
	if s.Join == nil {
		return page
	}
	msg := s.Join.Waiting()
	if msg == "" {
		return page
	}
	return []byte(strings.Replace(string(page), `id="join-wait" hidden></p>`, `id="join-wait">`+html.EscapeString(msg)+`</p>`, 1))
}
