package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// User is a Signalith user as they are now, for a click.
type User struct {
	Username string
	Name     string
	Role     users.Role
	Created  time.Time
	// Blocked says why they may not act now, such as a password they
	// must change first, or "" when they may.
	Blocked string
}

// Display names a user for people, as in "Jordan Lee (jlee)".
func (u User) Display() string {
	if u.Name != "" && u.Name != u.Username {
		return u.Name + " (" + u.Username + ")"
	}
	return u.Username
}

// Ack is what acknowledging a finding did.
type Ack struct {
	Title string
	// Owner is who owned the finding already, when someone else did: it
	// was only noted that the user saw it.
	Owner string
}

// Desk is what a click changes and looks up; the API server provides it.
type Desk interface {
	// User returns a Signalith user's state now, and false when they can
	// no longer sign in (removed or disabled).
	User(name string) (User, bool)
	// Decide approves or rejects the waiting step of a playbook run, as
	// playbooks.DecideStep does.
	Decide(ctx context.Context, runID string, step int, user, note string, approve bool) (playbooks.Run, error)
	// Acknowledge makes user the owner of a finding nobody owns and
	// marks it in progress, or notes that they saw it.
	Acknowledge(ctx context.Context, findingID, user, note string) (Ack, error)
}

// Service answers the chat apps' requests.
type Service struct {
	Store Store
	// Channels returns the notification channels.
	Channels func() (notify.Settings, error)
	Desk     Desk
	// Teams posts replies through Teams app channels.
	Teams *notify.Senders
	// Verifier checks Teams' tokens; nil is a BotVerifier with the Bot
	// Framework's keys.
	Verifier *BotVerifier
	// PublicURL returns server.public_url, for the links to Signalith.
	PublicURL func() string
	// HTTP posts Slack answers to their response_url; nil is a client with
	// a timeout that follows the proxy settings and no redirects.
	HTTP *http.Client
	// SlackURLOK reports whether Slack answers may go to a response_url;
	// nil is SlackResponseURLAllowed. Tests allow others.
	SlackURLOK func(*url.URL) bool
	// ServiceURLOK reports whether a Teams activity's Bot Connector
	// address is allowed; nil is notify.ServiceURLAllowed.
	ServiceURLOK func(*url.URL) bool
	Log          *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	initOnce  sync.Once
	wg        sync.WaitGroup
	mu        sync.Mutex
	refused   map[string]time.Time // address → last refusal logged
	refusedN  map[string]int
	codeTries map[string][]time.Time // Teams user → recent wrong codes
	lastPurge time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) init() {
	s.initOnce.Do(func() {
		if s.Verifier == nil {
			s.Verifier = &BotVerifier{}
		}
		s.refused, s.refusedN, s.codeTries = map[string]time.Time{}, map[string]int{}, map[string][]time.Time{}
	})
}

// Wait waits for the Slack answers still being sent, for tests and a
// clean stop.
func (s *Service) Wait() { s.wg.Wait() }

// Limits on requests.
const (
	maxSlackBody = 64 << 10
	maxTeamsBody = 256 << 10
	// actTimeout bounds acting on a click.
	actTimeout = 20 * time.Second
	// maxCodeTries is how many wrong codes one Teams user may send in
	// codeWindow.
	maxCodeTries = 5
	codeWindow   = 10 * time.Minute
)

// ChatUser is who clicked: their chat account.
type ChatUser struct {
	System   string
	Team     string
	TeamName string
	ID       string
	Name     string
}

func (c ChatUser) logAttrs() []any {
	return []any{"chat", c.System, "chat_team", c.Team, "chat_user", c.ID, "chat_name", c.Name}
}

// outcome is what a click did, for the answer in the chat.
type outcome struct {
	// done is a decision the message now shows for everyone: its buttons
	// go, and text says what happened.
	done bool
	text string
	// private is said to the person who clicked only.
	private string
	// link is a link for them to follow, with linkLabel.
	link, linkLabel string
}

// channel returns an interactive channel of a type, or false.
func (s *Service) channel(id, typ string) (notify.Channel, bool) {
	if s.Channels == nil || id == "" {
		return notify.Channel{}, false
	}
	set, err := s.Channels()
	if err != nil {
		return notify.Channel{}, false
	}
	c, ok := set.Channel(id)
	if !ok || c.Type != typ || !c.Interactive() || len(c.Undecrypted()) > 0 {
		return notify.Channel{}, false
	}
	return c, true
}

// act does what a button asks, as the Signalith user the chat account is
// linked to, and says how it went.
func (s *Service) act(ctx context.Context, c notify.Channel, who ChatUser, b notify.Button) outcome {
	audit := func(result string, extra ...any) {
		attrs := append([]any{"audit", true, "channel", c.Name, "action", b.Action, "object", b.ID, "result", result}, who.logAttrs()...)
		s.log().Info("chat button", append(attrs, extra...)...)
	}
	via := SystemLabel(who.System)
	link, linked, err := s.Store.Link(ctx, who.System, who.Team, who.ID)
	if err != nil {
		audit("error", "err", err)
		return outcome{private: "Signalith could not check who you are right now. Try again in a minute, or use Signalith itself."}
	}
	if !linked {
		audit("not linked")
		return s.linkFirst(ctx, c, who)
	}
	u, ok := s.Desk.User(link.Username)
	if !ok {
		audit("refused", "user", link.Username, "why", "user cannot sign in")
		return outcome{private: fmt.Sprintf("Your %s account is linked to the Signalith user %s, who can no longer sign in, so nothing was done.", via, link.Username)}
	}
	if !link.UserCreated.IsZero() && !u.Created.IsZero() && !u.Created.Equal(link.UserCreated) {
		// The user was removed and someone else was given the name: the
		// link was for the old one.
		_, _ = s.Store.DeleteLink(ctx, link.ID)
		audit("refused", "user", link.Username, "why", "link was for a removed user of the same name")
		return outcome{private: fmt.Sprintf("Your %s account was linked to an earlier Signalith user named %s, so the link was removed. Click again to link your account.", via, link.Username)}
	}
	if u.Blocked != "" {
		audit("refused", "user", u.Username, "why", u.Blocked)
		return outcome{private: u.Blocked + " Nothing was done."}
	}
	if !u.Role.AtLeast(users.Analyst) {
		audit("refused", "user", u.Username, "why", "role "+string(u.Role))
		return outcome{private: fmt.Sprintf("This needs the Analyst role in Signalith, and %s has the %s role. Nothing was done.", u.Username, u.Role.Label())}
	}
	note := fmt.Sprintf("Decided in %s as %s.", via, who.Name)
	switch b.Action {
	case notify.ButtonApprove, notify.ButtonReject:
		approve := b.Action == notify.ButtonApprove
		if approve && !c.ApproveInChat {
			audit("refused", "user", u.Username, "why", "approving from this channel is off")
			return outcome{private: "Approving from " + c.Label() + " is turned off. Approve it on the Approvals page in Signalith.",
				link: notify.ApprovalsLink(s.publicURL()), linkLabel: "Open Approvals"}
		}
		run, err := s.Desk.Decide(ctx, b.ID, b.Step, u.Username, note, approve)
		var de *playbooks.DecidedError
		switch {
		case errors.As(err, &de):
			audit("already decided", "user", u.Username)
			return outcome{done: true, text: capital(de.Error()) + "."}
		case errors.Is(err, playbooks.ErrOtherStep):
			audit("already decided", "user", u.Username)
			return outcome{private: capital(err.Error()) + ".", link: notify.ApprovalsLink(s.publicURL()), linkLabel: "Open Approvals"}
		case errors.Is(err, playbooks.ErrNotFound):
			audit("not found", "user", u.Username)
			return outcome{done: true, text: "This playbook run no longer exists in Signalith."}
		case err != nil:
			audit("error", "user", u.Username, "err", err)
			return outcome{private: "Signalith could not record that: " + err.Error()}
		}
		what := ""
		if run.Approval != nil {
			what = run.Approval.What
		}
		audit("done", "user", u.Username, "playbook", run.PlaybookName, "finding", run.FindingID, "what", what)
		s.log().Info("playbook step "+map[bool]string{true: "approved", false: "rejected"}[approve], "audit", true, "by", u.Username,
			"playbook", run.PlaybookName, "run", run.ID, "finding", run.FindingID, "what", what, "via", who.System)
		if approve {
			return outcome{done: true, text: fmt.Sprintf("✅ Approved by %s in %s. Signalith runs it next: %s", u.Display(), via, what)}
		}
		return outcome{done: true, text: fmt.Sprintf("⛔ Rejected by %s in %s. The playbook stopped.", u.Display(), via)}
	case notify.ButtonAck:
		ack, err := s.Desk.Acknowledge(ctx, b.ID, u.Username, fmt.Sprintf("Acknowledged in %s as %s.", via, who.Name))
		if err != nil {
			audit("error", "user", u.Username, "err", err)
			return outcome{private: "Signalith could not acknowledge the finding: " + err.Error()}
		}
		audit("done", "user", u.Username)
		if ack.Owner != "" && ack.Owner != u.Username {
			return outcome{done: true, text: fmt.Sprintf("👀 Seen by %s in %s. %s already owns this finding.", u.Display(), via, ack.Owner)}
		}
		return outcome{done: true, text: fmt.Sprintf("👀 Acknowledged by %s in %s, who now owns this finding.", u.Display(), via)}
	}
	audit("refused", "why", "unknown action")
	return outcome{private: "Signalith does not know this button."}
}

// linkFirst answers a click from a chat account with no link.
func (s *Service) linkFirst(ctx context.Context, c notify.Channel, who ChatUser) outcome {
	via := SystemLabel(who.System)
	if who.System == Teams {
		// Teams has no message only the clicker sees, so the link goes the
		// other way: they make a code in Signalith and send it here.
		return outcome{private: "Link your Teams account to Signalith first: in Signalith, open your account menu, choose Chat accounts and make a code, " +
			"then send \"link\" and the code to the Signalith app here, as in @Signalith link ABCDE-12345."}
	}
	if s.publicURL() == "" {
		return outcome{private: "Your " + via + " account is not linked to a Signalith user yet, so nothing was done. " +
			"Signalith cannot send you a link to do that, because it does not know its own address: ask an admin to set Public URL (server.public_url) on the Server settings tab."}
	}
	secret := NewSecret()
	now := s.now()
	t := Token{ID: TokenID(secret), System: who.System, Team: who.Team, TeamName: who.TeamName, ChatUser: who.ID, ChatName: who.Name,
		Channel: c.ID, Expires: now.Add(TokenLife), Created: now}
	if err := s.Store.SaveToken(ctx, t); err != nil {
		s.log().Warn("could not make a chat link", "err", err)
		return outcome{private: "Signalith could not make a link for your account right now. Try again in a minute."}
	}
	return outcome{private: fmt.Sprintf("Your %s account is not linked to a Signalith user yet, so nothing was done. "+
		"Open the link, sign in to Signalith as yourself, and confirm. It works once, for the next %d minutes. "+
		"Do not share it: whoever confirms it makes your clicks count as theirs.", via, int(TokenLife.Minutes())),
		link: s.publicURL() + "/#chat-link/" + secret, linkLabel: "Link my account"}
}

func (s *Service) publicURL() string {
	if s.PublicURL == nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(s.PublicURL()), "/")
}

// refuse logs a request that failed its check, at most once a minute for
// each address, with how many were refused since.
func (s *Service) refuse(r *http.Request, system, channel string, why error) {
	addr := clientAddr(r)
	s.mu.Lock()
	s.refusedN[addr]++
	n := s.refusedN[addr]
	log := s.now().Sub(s.refused[addr]) >= time.Minute
	if log {
		s.refused[addr] = s.now()
		s.refusedN[addr] = 0
	}
	if len(s.refused) > 10000 {
		// A flood from many addresses: forget them rather than grow.
		s.refused, s.refusedN = map[string]time.Time{}, map[string]int{}
	}
	s.mu.Unlock()
	if log {
		s.log().Warn("chat request refused", "audit", true, "chat", system, "channel", channel, "addr", addr, "refusals", n, "why", why.Error())
	}
}

// clientAddr is the address a request came from, without its port.
func clientAddr(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().String()
	}
	return r.RemoteAddr
}

// readBody reads a request body of at most max bytes.
func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return body, true
}

// purge deletes old tokens and click IDs, at most once an hour.
func (s *Service) purge() {
	s.mu.Lock()
	due := s.now().Sub(s.lastPurge) >= time.Hour
	if due {
		s.lastPurge = s.now()
	}
	s.mu.Unlock()
	if !due {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.Store.Purge(ctx, s.now()); err != nil {
			s.log().Debug("could not delete old chat tokens", "err", err)
		}
	}()
}

// ServeSlack answers a Slack app's button clicks, at
// /api/chat/slack/{channel}.
func (s *Service) ServeSlack(w http.ResponseWriter, r *http.Request) {
	s.init()
	id := r.PathValue("channel")
	body, ok := readBody(w, r, maxSlackBody)
	if !ok {
		return
	}
	c, ok := s.channel(id, notify.TypeSlack)
	if !ok {
		s.refuse(r, Slack, id, errors.New("no Slack channel with a signing secret has this ID on this server"))
		http.Error(w, "There is no Slack channel with buttons at this address on this Signalith server.", http.StatusNotFound)
		return
	}
	if err := VerifySlack(c.SigningSecret, r.Header, body, s.now()); err != nil {
		s.refuse(r, Slack, c.Name, err)
		http.Error(w, "The request is not signed by Slack.", http.StatusUnauthorized)
		return
	}
	p, err := parseSlack(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.purge()
	if p.Type != "block_actions" || len(p.Actions) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	a := p.Actions[0]
	if !strings.HasPrefix(a.ActionID, slackButtonPrefix) || a.ActionID == slackButtonPrefix+"open" {
		// The link button: Slack tells the app about its clicks too.
		w.WriteHeader(http.StatusOK)
		return
	}
	team := p.Team.ID
	if team == "" {
		team = p.User.TeamID
	}
	name := p.User.Username
	if name == "" {
		name = p.User.Name
	}
	who := ChatUser{System: Slack, Team: team, TeamName: p.Team.Domain, ID: p.User.ID, Name: name}
	if who.Team == "" || who.ID == "" {
		http.Error(w, "the payload names no user", http.StatusBadRequest)
		return
	}
	ru, err := url.Parse(p.ResponseURL)
	if err != nil || !s.slackURLOK(ru) {
		s.refuse(r, Slack, c.Name, errors.New("the response_url is not Slack's"))
		http.Error(w, "the response_url is not Slack's", http.StatusBadRequest)
		return
	}
	b, err := notify.ParseButton(c, a.Value)
	if err != nil {
		s.log().Warn("chat button refused", append([]any{"audit", true, "channel", c.Name, "result", "bad button", "action_id", a.ActionID}, who.logAttrs()...)...)
		s.answerSlack(ru, outcome{private: capital(err.Error()) + "."}, p)
		w.WriteHeader(http.StatusOK)
		return
	}
	click := p.TriggerID
	if click == "" {
		click = who.Team + "|" + who.ID + "|" + a.ActionTS
	}
	seenCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	seen, err := s.Store.Seen(seenCtx, Slack, click, s.now())
	cancel()
	if err != nil {
		s.log().Warn("could not record a chat click; it is not acted on", "err", err)
		http.Error(w, "Signalith could not record the click; try again.", http.StatusServiceUnavailable)
		return
	}
	if seen {
		w.WriteHeader(http.StatusOK)
		return
	}
	// Slack waits three seconds for the answer to the request; what the
	// click did goes to the response_url.
	w.WriteHeader(http.StatusOK)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), actTimeout)
		defer cancel()
		s.answerSlack(ru, s.act(ctx, c, who, b), p)
	}()
}

func (s *Service) slackURLOK(u *url.URL) bool {
	if s.SlackURLOK != nil {
		return s.SlackURLOK(u)
	}
	return SlackResponseURLAllowed(u)
}

func (s *Service) httpClient() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// answerSlack posts what a click did to its response_url: the message
// without its buttons and with the outcome, or a reply only the clicker
// sees.
func (s *Service) answerSlack(ru *url.URL, o outcome, p slackPayload) {
	var body map[string]any
	switch {
	case o.done && p.Message != nil:
		body = map[string]any{"replace_original": true, "text": p.Message.Text, "blocks": slackReplace(p.Message.Blocks, o.text)}
	case o.done:
		body = map[string]any{"replace_original": true, "text": slackEscape(o.text)}
	default:
		text := slackEscape(o.private)
		if o.link != "" {
			text += " <" + o.link + "|" + slackEscape(o.linkLabel) + ">"
		}
		body = map[string]any{"response_type": "ephemeral", "replace_original": false, "text": text}
	}
	raw, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ru.String(), bytes.NewReader(raw))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		s.log().Warn("could not answer a Slack button click", "err", err)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.log().Warn("Slack refused the answer to a button click", "status", resp.Status)
	}
}

// ServeTeams answers what Teams sends a Teams app channel's bot, at
// /api/chat/teams/{channel}: clicks, mentions, and the app being added
// to or removed from a team.
func (s *Service) ServeTeams(w http.ResponseWriter, r *http.Request) {
	s.init()
	id := r.PathValue("channel")
	body, ok := readBody(w, r, maxTeamsBody)
	if !ok {
		return
	}
	c, ok := s.channel(id, notify.TypeTeamsApp)
	if !ok {
		s.refuse(r, Teams, id, errors.New("no Teams app channel has this ID on this server"))
		http.Error(w, "There is no Teams app channel at this address on this Signalith server.", http.StatusNotFound)
		return
	}
	var a activity
	if err := json.Unmarshal(body, &a); err != nil {
		http.Error(w, "the activity is not JSON", http.StatusBadRequest)
		return
	}
	vctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	err := s.Verifier.Verify(vctx, r.Header.Get("Authorization"), c.AppID, a.ServiceURL)
	cancel()
	if err != nil {
		s.refuse(r, Teams, c.Name, err)
		http.Error(w, "The request does not carry a valid Bot Framework token.", http.StatusUnauthorized)
		return
	}
	su, err := url.Parse(a.ServiceURL)
	switch {
	case a.ChannelID != "msteams":
		s.refuse(r, Teams, c.Name, fmt.Errorf("the activity is from %q, not Teams", a.ChannelID))
		http.Error(w, "Only Microsoft Teams is supported.", http.StatusForbidden)
		return
	case a.tenant() != c.TenantID:
		s.refuse(r, Teams, c.Name, fmt.Errorf("the activity is from tenant %q, not the channel's", a.tenant()))
		http.Error(w, "The activity is from another Microsoft Entra tenant.", http.StatusForbidden)
		return
	case err != nil || !s.serviceURLOK(su):
		s.refuse(r, Teams, c.Name, errors.New("the Bot Connector address is not Microsoft's"))
		http.Error(w, "The Bot Connector address is not Microsoft's.", http.StatusForbidden)
		return
	}
	s.purge()
	ctx, cancel := context.WithTimeout(r.Context(), actTimeout)
	defer cancel()
	switch {
	case a.Type == "invoke" && a.Name == "adaptiveCard/action":
		s.teamsClick(ctx, w, c, a)
	case a.botAdded():
		s.teamsHere(ctx, c, a, "added")
		w.WriteHeader(http.StatusOK)
	case a.botRemoved():
		if conv, ok, _ := s.Store.Conversation(ctx, c.ID); ok && (conv.ConversationID == a.Conversation.ID ||
			a.ChannelData.Team.ID != "" && conv.TeamID == a.ChannelData.Team.ID) {
			_ = s.Store.DeleteConversation(ctx, c.ID)
			s.log().Info("Teams app removed from the Teams channel it posted to", "audit", true, "channel", c.Name, "teams_channel", conv.Place())
		}
		w.WriteHeader(http.StatusOK)
	case a.Type == "message":
		s.teamsMessage(ctx, c, a)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Service) serviceURLOK(u *url.URL) bool {
	if s.ServiceURLOK != nil {
		return s.ServiceURLOK(u)
	}
	return notify.ServiceURLAllowed(u)
}

// teamsWho is who sent an activity.
func teamsWho(a activity) ChatUser {
	return ChatUser{System: Teams, Team: a.tenant(), TeamName: a.ChannelData.Team.Name, ID: strings.ToLower(a.From.AADObjectID), Name: a.From.Name}
}

// teamsHere records the conversation of an activity as where the channel
// posts.
func (s *Service) teamsHere(ctx context.Context, c notify.Channel, a activity, how string) bool {
	switch a.Conversation.ConversationType {
	case "channel", "groupChat":
	default:
		// A one-to-one chat with the app is not where the team looks.
		return false
	}
	conv := notify.Conversation{Channel: c.ID, ConversationID: a.Conversation.ID, ServiceURL: a.ServiceURL, TenantID: a.tenant(),
		TeamID: a.ChannelData.Team.ID, TeamName: a.ChannelData.Team.Name, ChannelName: a.ChannelData.Channel.Name, AddedBy: a.From.Name, Added: s.now().UTC()}
	if conv.ChannelName == "" {
		conv.ChannelName = a.Conversation.Name
	}
	if err := s.Store.SaveConversation(ctx, conv); err != nil {
		s.log().Warn("could not record where the Teams app posts", "channel", c.Name, "err", err)
		return false
	}
	s.log().Info("Teams app channel now posts to a Teams conversation", "audit", true, "channel", c.Name, "teams_channel", conv.Place(),
		"how", how, "by", a.From.Name)
	return true
}

// teamsMessage answers a message to the app: "link <code>" links the
// sender's account; "post here" makes this conversation where the channel
// posts; anything else gets help.
func (s *Service) teamsMessage(ctx context.Context, c notify.Channel, a activity) {
	text := mentionText(a.Text)
	fields := strings.Fields(strings.ToLower(text))
	var reply string
	switch {
	case len(fields) >= 2 && fields[0] == "link":
		reply = s.teamsLink(ctx, teamsWho(a), strings.Join(strings.Fields(text)[1:], ""))
	case len(fields) >= 2 && fields[0] == "post" && fields[1] == "here":
		if s.teamsHere(ctx, c, a, "asked") {
			reply = "Signalith posts " + c.Label() + " messages here from now on."
		} else {
			reply = "Signalith posts to team channels and group chats only. Mention the app in one of those."
		}
	default:
		reply = "I post Signalith findings and approval requests. Send \"post here\" to have them posted in this channel, or \"link\" and a code from Signalith (your account menu, Chat accounts) to link your Teams account."
	}
	if s.Teams == nil {
		return
	}
	conv := notify.Conversation{Channel: c.ID, ConversationID: a.Conversation.ID, ServiceURL: a.ServiceURL, TenantID: a.tenant()}
	msg := map[string]any{"type": "message", "text": reply, "textFormat": "plain"}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		rctx, cancel := context.WithTimeout(context.Background(), actTimeout)
		defer cancel()
		if _, err := s.Teams.TeamsPost(rctx, c, conv, a.ID, msg); err != nil {
			s.log().Warn("could not answer a message to the Teams app", "channel", c.Name, "err", err)
		}
	}()
}

// teamsLink links the sender's Teams account with a code a Signalith user
// made.
func (s *Service) teamsLink(ctx context.Context, who ChatUser, code string) string {
	if who.ID == "" || who.Team == "" {
		return "Teams did not say who you are, so your account cannot be linked."
	}
	now := s.now()
	key := who.Team + "|" + who.ID
	s.mu.Lock()
	recent := s.codeTries[key][:0]
	for _, t := range s.codeTries[key] {
		if now.Sub(t) < codeWindow {
			recent = append(recent, t)
		}
	}
	s.codeTries[key] = recent
	blocked := len(recent) >= maxCodeTries
	s.mu.Unlock()
	if blocked {
		return "Too many wrong codes. Wait ten minutes, then make a new code in Signalith."
	}
	t, err := s.Store.TakeToken(ctx, TokenID(code), now)
	if err == nil && (t.System != Teams || t.Username == "") {
		err = ErrNotFound
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrTokenUsed) {
			s.mu.Lock()
			s.codeTries[key] = append(s.codeTries[key], now)
			s.mu.Unlock()
			s.log().Warn("chat account not linked", append([]any{"audit", true, "why", "wrong or used code"}, who.logAttrs()...)...)
			return "That code is not right, was used already, or expired. Make a new one in Signalith (your account menu, Chat accounts)."
		}
		return "Signalith could not check the code right now. Try again in a minute."
	}
	l := Link{ID: LinkID(Teams, who.Team, who.ID), System: Teams, Team: who.Team, TeamName: who.TeamName, ChatUser: who.ID, ChatName: who.Name,
		Username: t.Username, UserCreated: t.UserCreated, Created: now.UTC()}
	if err := s.Store.SaveLink(ctx, l); err != nil {
		return "Signalith could not save the link right now. Make a new code and try again."
	}
	s.log().Info("chat account linked", append([]any{"audit", true, "user", t.Username}, who.logAttrs()...)...)
	return fmt.Sprintf("Done: your Teams account is linked to the Signalith user %s. Your clicks on Signalith buttons now count as theirs.", t.Username)
}

// teamsClick answers a click on a card's button.
func (s *Service) teamsClick(ctx context.Context, w http.ResponseWriter, c notify.Channel, a activity) {
	answer := func(o outcome) {
		if o.done {
			writeInvoke(w, map[string]any{"statusCode": 200, "type": "application/vnd.microsoft.card.adaptive", "value": outcomeCard(o)})
			return
		}
		text := o.private
		if o.link != "" {
			text += " " + o.link
		}
		writeInvoke(w, map[string]any{"statusCode": 200, "type": "application/vnd.microsoft.activity.message", "value": text})
	}
	raw, _ := a.Value.Action.Data[notify.TeamsButtonField].(string)
	b, err := notify.ParseButton(c, raw)
	if err != nil || a.Value.Action.Verb != notify.TeamsVerb(b.Action) {
		s.log().Warn("chat button refused", append([]any{"audit", true, "channel", c.Name, "result", "bad button"}, teamsWho(a).logAttrs()...)...)
		answer(outcome{private: capital(notify.ErrBadButton.Error()) + "."})
		return
	}
	who := teamsWho(a)
	if who.ID == "" {
		answer(outcome{private: "Teams did not say who you are, so nothing was done."})
		return
	}
	if a.ID != "" {
		seen, err := s.Store.Seen(ctx, Teams, a.ID, s.now())
		if err != nil {
			answer(outcome{private: "Signalith could not record the click; try again."})
			return
		}
		if seen {
			answer(outcome{private: "That click was already handled."})
			return
		}
	}
	answer(s.act(ctx, c, who, b))
}

// outcomeCard is the card that replaces one whose button was clicked.
func outcomeCard(o outcome) map[string]any {
	return map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    []any{map[string]any{"type": "TextBlock", "text": teamsEscape(o.text), "wrap": true}},
	}
}

// teamsEscape keeps text from being read as markdown in an Adaptive Card.
func teamsEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "`", "\\`", "~", `\~`, "<", "&lt;", ">", "&gt;").Replace(s)
}

func writeInvoke(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// capital starts s with a capital letter.
func capital(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
