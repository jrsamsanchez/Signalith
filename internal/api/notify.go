package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/notify"
)

// Notify is what the Notifications page works with.
type Notify struct {
	// Settings keeps the channels and rules.
	Settings *notify.Manager
	// Deliveries keeps what was sent; nil shows none.
	Deliveries notify.Deliveries
	// Sender sends test messages.
	Sender notify.Sender
	// Server names this server in the test deliveries it records.
	Server string

	testMu sync.Mutex // one test at a time

	healthMu   sync.Mutex
	healthAt   time.Time
	healthWarn []string
}

// routeNotify registers the notification routes. They are all admin
// work: channels hold webhook addresses and mail passwords, and a test
// makes this server send to an address the request names.
func (s *Server) routeNotify(api *router) {
	api.admin("GET /api/notify", s.handleNotify)
	api.admin("PUT /api/notify", s.handleNotifySave)
	api.admin("POST /api/notify/test", s.handleNotifyTest)
	api.admin("GET /api/notify/deliveries", s.handleNotifyDeliveries)
}

var errNotifyOff = errors.New("notifications are not available on this server")

func (s *Server) notifyOK(w http.ResponseWriter) bool {
	if s.Notify == nil || s.Notify.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, errNotifyOff)
		return false
	}
	return true
}

// errNotifyNoJobs refuses changes on a server that does not send
// notifications: its notifications file is not the one the sending
// server reads.
var errNotifyNoJobs = errors.New("this server does not send notifications (detections.scheduler is off here), so channels and rules are set on the Signalith server that runs the background jobs")

// notifyElsewhere says why channels and rules are not set on this server
// now, or nil. Of the servers that share one OpenSearch, only the one
// that runs the background jobs sends, with its own channels and rules.
func (s *Server) notifyElsewhere() error {
	if s.conf() == nil || !s.conf().Detections.Scheduler {
		return errNotifyNoJobs
	}
	if s.Cluster == nil || s.Cluster.RunsJobs() {
		return nil
	}
	if holder := s.Cluster.JobHolder(); holder != "" {
		return fmt.Errorf("this server does not send notifications right now: %s does, with its own channels and rules; set them there", holder)
	}
	return errors.New("this server does not send notifications right now, and no server runs the background jobs at the moment; the Servers page says why")
}

// channelView is a channel as the page shows it: its secrets only say
// whether they are set, and a webhook URL only shows its server.
type channelView struct {
	notify.Channel
	Label            string                `json:"label"`
	URLSet           bool                  `json:"url_set"`
	URLServer        string                `json:"url_server,omitempty"`
	Headers          []headerView          `json:"headers"`
	SigningSecretSet bool                  `json:"signing_secret_set"`
	PasswordSet      bool                  `json:"password_set"`
	Problem          string                `json:"problem,omitempty"`
	Last             *notify.ChannelStatus `json:"last,omitempty"`
	// Rules names the rules that send to it.
	Rules []string `json:"rules"`
}

type headerView struct {
	Name string `json:"name"`
	Set  bool   `json:"set"`
}

type ruleView struct {
	notify.Rule
	Summary string `json:"summary"`
}

// urlServer returns the scheme and host of a URL, which say where it
// posts without its path or query, which may hold a token.
func urlServer(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// notifyView is the page's data.
func (s *Server) notifyView(ctx context.Context, set notify.Settings, fileErr error) map[string]any {
	var last map[string]notify.ChannelStatus
	out := map[string]any{}
	if s.Notify.Deliveries != nil {
		list, err := s.Notify.Deliveries.Recent(ctx, 300)
		if err != nil {
			out["deliveries_error"] = "Recent deliveries could not be read from OpenSearch: " + err.Error()
		} else {
			last = notify.LastStatus(list)
		}
	}
	channels := make([]channelView, 0, len(set.Channels))
	for _, c := range set.Channels {
		v := channelView{Channel: c, Label: c.Label(), URLSet: c.URL != "", SigningSecretSet: c.SigningSecret != "",
			PasswordSet: c.Password != "", Headers: []headerView{}, Rules: []string{}}
		if !strings.HasPrefix(c.URL, "enc:") {
			v.URLServer = urlServer(c.URL)
		}
		names := make([]string, 0, len(c.Headers))
		for k := range c.Headers {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			v.Headers = append(v.Headers, headerView{Name: k, Set: c.Headers[k] != ""})
		}
		if bad := c.Undecrypted(); len(bad) > 0 {
			v.Problem = "The saved " + strings.Join(bad, " and ") + " cannot be decrypted, because the master key changed. Edit the channel and enter it again."
		}
		if st, ok := last[c.ID]; ok {
			st := st
			v.Last = &st
		}
		for _, r := range set.Rules {
			for _, id := range r.Channels {
				if id == c.ID {
					v.Rules = append(v.Rules, r.Name)
				}
			}
		}
		channels = append(channels, v)
	}
	rules := make([]ruleView, 0, len(set.Rules))
	for _, r := range set.Rules {
		if r.Detections == nil {
			r.Detections = []string{}
		}
		rules = append(rules, ruleView{Rule: r, Summary: r.Summary(set)})
	}
	out["channels"] = channels
	out["rules"] = rules
	out["revision"] = s.Notify.Settings.Revision()
	out["file"] = s.Notify.Settings.File
	out["types"] = notify.Types
	out["urgencies"] = notify.Urgencies
	out["flood_limit"] = notify.FloodLimit
	pub := strings.TrimSpace(s.conf().Server.PublicURL)
	out["public_url"] = pub
	out["link"] = notify.FindingsLink(pub)
	if fileErr != nil {
		out["file_error"] = fileErr.Error()
	}
	out["manage"] = fileErr == nil && s.notifyElsewhere() == nil
	if err := s.notifyElsewhere(); err != nil {
		out["manage_why"] = sentence(err.Error())
		if s.Cluster != nil && !errors.Is(err, errNotifyNoJobs) {
			out["runs_on"] = s.Cluster.JobHolder()
		}
	}
	return out
}

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	if !s.notifyOK(w) {
		return
	}
	set, err := s.Notify.Settings.Settings()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.notifyView(ctx, set, err))
}

func (s *Server) handleNotifySave(w http.ResponseWriter, r *http.Request) {
	if !s.notifyOK(w) {
		return
	}
	if err := s.notifyElsewhere(); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	var in notify.Input
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	set, err := s.Notify.Settings.Save(in)
	var ie *notify.InputError
	var fe *notify.FileError
	switch {
	case errors.As(err, &ie):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ie.Error(), "problems": ie.Problems})
		return
	case errors.Is(err, notify.ErrChanged), errors.As(err, &fe):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		s.Log.Error("could not save the notification settings", "err", err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	on := 0
	for _, rl := range set.Rules {
		if rl.Enabled {
			on++
		}
	}
	s.Log.Info("notification settings changed", "by", userOf(r), "channels", len(set.Channels), "rules", len(set.Rules), "rules_on", on)
	s.Notify.clearHealth()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.notifyView(ctx, set, nil))
}

// handleNotifyTest sends a test message through a saved channel ({"id"})
// or through a channel being edited ({"channel"}, whose empty secrets
// are the saved channel's with the same ID).
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if !s.notifyOK(w) {
		return
	}
	if err := s.notifyElsewhere(); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	var req struct {
		ID      string               `json:"id"`
		Channel *notify.ChannelInput `json:"channel"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var c notify.Channel
	switch {
	case req.Channel != nil:
		ch, err := s.Notify.Settings.Check(*req.Channel)
		var ie *notify.InputError
		if errors.As(err, &ie) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": ie.Error(), "problems": ie.Problems})
			return
		}
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		c = ch
		if _, saved := s.notifySaved(c.ID); !saved {
			// An unsaved channel is not recorded among the deliveries.
			c.ID = "test"
		}
	default:
		ch, ok := s.notifySaved(strings.TrimSpace(req.ID))
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("there is no channel with this ID; reload the page"))
			return
		}
		c = ch
	}
	if !s.Notify.testMu.TryLock() {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, errors.New("another test message is being sent; try again in a moment"))
		return
	}
	defer s.Notify.testMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), notify.MailTimeout+5*time.Second)
	defer cancel()
	d, err := notify.SendTest(ctx, s.Notify.Sender, s.Notify.Deliveries, c, notify.FindingsLink(s.conf().Server.PublicURL), s.Notify.Server, nil)
	out := map[string]any{"ok": err == nil, "duration_ms": d.DurationMS, "channel": c.Name}
	if err != nil {
		out["error"] = err.Error()
		s.Log.Info("notification test failed", "channel", c.Name, "type", c.Type, "by", userOf(r), "err", err.Error())
	} else {
		s.Log.Info("notification test sent", "channel", c.Name, "type", c.Type, "by", userOf(r))
	}
	s.Notify.clearHealth()
	writeJSON(w, http.StatusOK, out)
}

// notifySaved returns a saved channel.
func (s *Server) notifySaved(id string) (notify.Channel, bool) {
	set, err := s.Notify.Settings.Settings()
	if err != nil || id == "" {
		return notify.Channel{}, false
	}
	return set.Channel(id)
}

// deliveryView is a delivery as the page lists it.
type deliveryView struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	FindingID   string     `json:"finding_id,omitempty"`
	Title       string     `json:"title"`
	Urgency     string     `json:"urgency,omitempty"`
	Channel     string     `json:"channel"`
	ChannelName string     `json:"channel_name"`
	ChannelType string     `json:"channel_type"`
	RuleName    string     `json:"rule_name,omitempty"`
	Playbook    string     `json:"playbook,omitempty"`
	Status      string     `json:"status"`
	Final       bool       `json:"final,omitempty"`
	Attempts    int        `json:"attempts"`
	Error       string     `json:"error,omitempty"`
	DurationMS  int64      `json:"duration_ms,omitempty"`
	Summary     int        `json:"summary,omitempty"`
	Server      string     `json:"server,omitempty"`
	Created     time.Time  `json:"created"`
	Updated     time.Time  `json:"updated"`
	NextTry     *time.Time `json:"next_try,omitempty"`
}

func (s *Server) handleNotifyDeliveries(w http.ResponseWriter, r *http.Request) {
	if !s.notifyOK(w) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	list := []deliveryView{}
	if s.Notify.Deliveries != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		got, err := s.Notify.Deliveries.Recent(ctx, limit)
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Errorf("recent deliveries could not be read: %w", err))
			return
		}
		for _, d := range got {
			list = append(list, deliveryView{ID: d.ID, Kind: d.Kind, FindingID: d.FindingID, Title: d.Message.Title, Urgency: d.Message.Urgency,
				Channel: d.Channel, ChannelName: d.ChannelName, ChannelType: d.ChannelType, RuleName: d.RuleName, Playbook: d.Playbook, Status: d.Status,
				Final: d.Final, Attempts: d.Attempts, Error: d.Error, DurationMS: d.DurationMS, Summary: d.Summary, Server: d.Server,
				Created: d.Created, Updated: d.Updated, NextTry: d.NextTry})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": list})
}

// notifyHealthEvery is how long the Health page's notification warnings
// are kept before the deliveries are read again.
const notifyHealthEvery = 30 * time.Second

// notifyWarnings names the channels whose latest message failed in the
// last day, for the Health page.
func (s *Server) notifyWarnings(ctx context.Context) []string {
	n := s.Notify
	if n == nil || n.Settings == nil || n.Deliveries == nil {
		return nil
	}
	n.healthMu.Lock()
	defer n.healthMu.Unlock()
	now := time.Now()
	if !n.healthAt.IsZero() && now.Sub(n.healthAt) < notifyHealthEvery {
		return n.healthWarn
	}
	n.healthAt, n.healthWarn = now, nil
	set, err := n.Settings.Settings()
	if err != nil {
		if s.notifyElsewhere() == nil {
			n.healthWarn = []string{sentence(err.Error()) + " Until then no notifications are sent."}
		}
		return n.healthWarn
	}
	if len(set.Channels) == 0 {
		return nil
	}
	list, err := n.Deliveries.Recent(ctx, 300)
	if err != nil {
		return nil
	}
	last := notify.LastStatus(list)
	for i, c := range notify.Failing(set, list, now.Add(-24*time.Hour)) {
		if i == 3 {
			n.healthWarn = append(n.healthWarn, "Other notification channels are failing too; the Notifications page lists them.")
			break
		}
		n.healthWarn = append(n.healthWarn, fmt.Sprintf("Notifications to %s are failing. %s Check the channel on the Notifications page.", c.Label(), sentence(last[c.ID].Error)))
	}
	return n.healthWarn
}

// clearHealth makes the next Health page read the deliveries again.
func (n *Notify) clearHealth() {
	n.healthMu.Lock()
	n.healthAt = time.Time{}
	n.healthMu.Unlock()
}
