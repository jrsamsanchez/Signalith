package api

import (
	"net/http"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// The agents that send events (Fluent Bit and OpenTelemetry Collectors),
// heard by every server that shares this OpenSearch. The Endpoints page
// shows them next to the osquery hosts, matched by computer name; there is
// no page of their own. A new configuration needs a new agent token, which
// the Add data page makes and shows once, so the page sends admins there.
func (s *Server) routeAgents(api *router) {
	api.analyst("GET /api/agents", s.handleAgents)
}

// Reasons an agent needs a new configuration, as the page words them.
const (
	// needsCA: it trusts a certificate authority the servers do not use,
	// so its connections fail.
	needsCA = "ca"
	// needsPlain: it sends without encryption.
	needsPlain = "plain"
	// needsRevoked: its agent token was revoked.
	needsRevoked = "revoked"
	// needsOld: it was set up before agents said their computer's name.
	// Only information: it still works.
	needsOld = "old"
)

// agentView is an agent as the Endpoints page shows it.
type agentView struct {
	agentinv.Agent
	Silent bool `json:"silent"`
	// NeedsConfig lists why it needs a new configuration (needsCA,
	// needsPlain, needsRevoked), and Notes what is worth knowing but
	// needs nothing done now (needsOld).
	NeedsConfig []string `json:"needs_config"`
	Notes       []string `json:"notes"`
}

// agents returns the agent inventory; nil when there is none (tests),
// whose methods do nothing.
func (s *Server) agents() *agentinv.Inventory { return s.Agents }

// noteAgent counts a batch an agent sent in the agent inventory, next to
// its token's use. hosts are the host names in an OpenTelemetry batch
// (ingest.Result.Hosts): a Collector does not send X-Signalith-Agent, but
// its resourcedetection processor puts its computer's name on every
// event, so a batch with one host name is named by it. A Collector that
// forwards other computers' events is told apart by address and token.
func (s *Server) noteAgent(r *http.Request, intake, tag string, who agenttokens.Identity, events int, hosts []string) {
	name := r.Header.Get(agentinv.AgentHeader)
	if name == "" && intake == ingest.IntakeOTLP {
		if len(hosts) != 1 && events == 0 {
			return // nothing to tell it by, and nothing stored
		}
		if len(hosts) == 1 {
			name = hosts[0]
		}
	}
	from := clientaddr.Parse(r.RemoteAddr)
	s.agents().Note(agentinv.Contact{
		Name:    name,
		Address: from.String(),
		Tag:     tag, Intake: intake,
		TLS:     r.TLS != nil || s.viaTrustedProxy(r),
		Local:   from.IsValid() && from.Unmap().IsLoopback(),
		TokenID: who.ID, TokenName: who.Name,
		Config: r.Header.Get(agentinv.ConfigHeader),
		Events: events,
	})
}

// caPins returns the pins of the certificate authority this server's
// certificate comes from now and of the one prepared to replace it.
func (s *Server) caPins() (current, next string) {
	if s.TLS == nil {
		return "", ""
	}
	current = agentinv.Pin(s.TLS.Fingerprint())
	if n := s.TLS.Next(); n != nil {
		next = agentinv.Pin(n.Fingerprint)
	}
	return current, next
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	list, overflow, err := s.agents().List(r.Context())
	if err != nil {
		// This server's own agents are still listed; the page says the
		// others could not be read.
		s.Log.Warn("the agents other servers heard from could not be read", "err", err)
	}
	current, next := s.caPins()
	now := time.Now()
	out := make([]agentView, 0, len(list))
	silent, needs := 0, 0
	for _, a := range list {
		v := s.agentFlags(a, current, next, now)
		if v.Silent {
			silent++
		}
		if len(v.NeedsConfig) > 0 {
			needs++
		}
		out = append(out, v)
	}
	body := map[string]any{
		"agents":  out,
		"summary": map[string]int{"total": len(out), "silent": silent, "needs_config": needs},
		"ca":      map[string]string{"current": current, "next": next},
		// Agents this server heard from over the 10,000 it lists.
		"overflow":         overflow,
		"silent_after_sec": int(agentinv.SilentAfter / time.Second),
	}
	if err != nil {
		body["partial"] = true
	}
	writeJSON(w, http.StatusOK, body)
}

// agentFlags says whether an agent is silent and why it needs a new
// configuration, against the certificate authorities this server uses
// (current and next pins) and the agent tokens.
func (s *Server) agentFlags(a agentinv.Agent, current, next string, now time.Time) agentView {
	v := agentView{Agent: a, NeedsConfig: []string{}, Notes: []string{}}
	v.Silent = now.Sub(a.LastSeen) > agentinv.SilentAfter
	// Each entry of a.CA is one configuration's pins: it is fine when it
	// trusts the current certificate authority or the one prepared to
	// replace it (a configuration made while a switch was prepared
	// trusts both).
	wrongCA := a.CAMismatch || a.Refused1h > 0
	if current != "" {
		for _, pins := range a.CA {
			if !agentinv.TrustsCA(pins, current) && !agentinv.TrustsCA(pins, next) {
				wrongCA = true
			}
		}
	}
	if wrongCA {
		v.NeedsConfig = append(v.NeedsConfig, needsCA)
	}
	// Plain HTTP from the server's own computer never crosses the
	// network, as on the Health and Security pages.
	if a.Transport == agentinv.TransportPlain && !a.Local {
		v.NeedsConfig = append(v.NeedsConfig, needsPlain)
	}
	if a.TokenID != "" {
		if _, known := s.tokens().Lookup(a.TokenID); known && !s.tokens().Active(a.TokenID) {
			v.NeedsConfig = append(v.NeedsConfig, needsRevoked)
		}
	}
	// OpenTelemetry Collectors send no name of their own: one without a
	// name forwards other computers' events, and a new configuration
	// would not change that.
	if a.Name == "" && !a.Refusing && a.Intake != ingest.IntakeOTLP {
		v.Notes = append(v.Notes, needsOld)
	}
	slices.Sort(v.NeedsConfig)
	return v
}
