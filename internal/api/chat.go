package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/chatops"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
)

// Chat is the buttons in Slack and Teams messages (see package chatops
// and docs/notifications.md): the store of linked chat accounts, and the
// service that answers the chat apps, made on first use.
type Chat struct {
	Store chatops.Store
	// Verifier checks Teams' tokens; nil uses the Bot Framework's keys.
	// Tests set it.
	Verifier *chatops.BotVerifier
	// Service, when set, answers the chat apps instead of one made from
	// the server's parts. Tests set it.
	Service *chatops.Service
}

// The chat apps' routes check their own signatures instead of a sign-in.
const (
	chatSlackRoute = "POST /api/chat/slack/{channel}"
	chatTeamsRoute = "POST /api/chat/teams/{channel}"
)

var chatPublicRoutes = []string{chatSlackRoute, chatTeamsRoute}

// routeChat registers the chat routes. Slack and Teams post clicks to the
// public ones. Linking an account to yourself asks for your password
// again: a link lets the chat account act as you.
func (s *Server) routeChat(mux *http.ServeMux, api *router) {
	mux.HandleFunc(chatSlackRoute, s.handleChatSlack)
	mux.HandleFunc(chatTeamsRoute, s.handleChatTeams)
	api.viewer("POST /api/chat/link/check", s.handleChatLinkCheck)
	api.viewerSensitive("POST /api/chat/link", s.handleChatLink)
	api.viewerSensitive("POST /api/chat/code", s.handleChatCode)
	api.viewer("GET /api/chat/accounts", s.handleChatAccounts)
	api.viewer("DELETE /api/chat/accounts/{id}", s.handleChatAccountDelete)
	// Admins see and remove every link, on the Notifications page.
	api.admin("GET /api/chat/links", s.handleChatLinks)
	api.admin("DELETE /api/chat/links/{id}", s.handleChatLinkDelete)
	api.admin("GET /api/notify/channels/{id}/teams-app", s.handleTeamsApp)
	api.sensitive("POST /api/notify/channels/{id}/teams-move", s.handleTeamsMove)
	api.admin("DELETE /api/notify/channels/{id}/teams-move", s.handleTeamsMove)
}

var errChatOff = errors.New("chat buttons are not available on this server")

func (s *Server) chatOK(w http.ResponseWriter) bool {
	if s.Chat == nil || s.Chat.Store == nil {
		writeError(w, http.StatusServiceUnavailable, errChatOff)
		return false
	}
	return true
}

// chat returns the service that answers the chat apps.
func (s *Server) chat() *chatops.Service {
	s.chatOnce.Do(func() {
		if s.Chat.Service != nil {
			s.chatSvc = s.Chat.Service
			return
		}
		svc := &chatops.Service{
			Store: s.Chat.Store, Desk: chatDesk{s}, Verifier: s.Chat.Verifier, Log: s.Log,
			PublicURL: func() string { return s.conf().Server.PublicURL },
		}
		if s.Notify != nil && s.Notify.Settings != nil {
			svc.Channels = s.Notify.Settings.Settings
			svc.Teams, _ = s.Notify.Sender.(*notify.Senders)
		}
		s.chatSvc = svc
	})
	return s.chatSvc
}

func (s *Server) handleChatSlack(w http.ResponseWriter, r *http.Request) {
	if s.Chat == nil || s.Chat.Store == nil {
		http.Error(w, errChatOff.Error(), http.StatusServiceUnavailable)
		return
	}
	s.chat().ServeSlack(w, r)
}

func (s *Server) handleChatTeams(w http.ResponseWriter, r *http.Request) {
	if s.Chat == nil || s.Chat.Store == nil {
		http.Error(w, errChatOff.Error(), http.StatusServiceUnavailable)
		return
	}
	s.chat().ServeTeams(w, r)
}

// chatDesk is what a click changes, through this server.
type chatDesk struct{ s *Server }

func (d chatDesk) User(name string) (chatops.User, bool) {
	p := d.s.principalFor(name)
	if p == nil {
		return chatops.User{}, false
	}
	u := chatops.User{Username: p.Username, Name: p.Name, Role: p.Role, Epoch: p.epoch}
	if stored, ok := d.s.userStore().Get(name); ok {
		u.Created = stored.Created
	}
	switch {
	case p.MustChangePassword:
		u.Blocked = "Your Signalith user must choose a new password first: sign in to Signalith to do that."
	case p.MustSetupMFA:
		u.Blocked = "Your Signalith user must set up two-step sign-in first: sign in to Signalith to do that."
	}
	return u, true
}

func (d chatDesk) Decide(ctx context.Context, runID string, step int, user, note string, approve bool) (playbooks.Run, error) {
	if d.s.Playbooks == nil || d.s.Playbooks.Runs == nil {
		return playbooks.Run{}, errPlaybooksOff
	}
	return playbooks.DecideStep(ctx, d.s.Playbooks.Runs, d.s.PlaybookDesk(), runID, step, user, note, approve, time.Now())
}

func (d chatDesk) Acknowledge(ctx context.Context, findingID, user, note string) (chatops.Ack, error) {
	if d.s.Findings == nil {
		return chatops.Ack{}, errDetectionsOff
	}
	var ack chatops.Ack
	f, err := d.s.Findings.Modify(ctx, findingID, func(f *findings.Finding) (bool, error) {
		ack = chatops.Ack{Title: f.Title}
		u := findings.Update{Comment: note}
		switch f.Owner {
		case "":
			owner := user
			u.Owner = &owner
		case user:
		default:
			ack.Owner = f.Owner
		}
		if ack.Owner == "" && f.Status == findings.StatusNew {
			st := findings.StatusInProgress
			u.Status = &st
		}
		return f.Apply(u, user, time.Now().UTC()), nil
	})
	if errors.Is(err, findings.ErrNotFound) {
		return ack, errors.New("the finding no longer exists")
	}
	if err != nil {
		return ack, err
	}
	d.s.Log.Info("finding acknowledged from chat", "audit", true, "by", user, "finding", f.ID, "owner", f.Owner, "status", f.Status)
	return ack, nil
}

// chatAccountView is a link as the pages show it.
type chatAccountView struct {
	chatops.Link
	SystemLabel string `json:"system_label"`
	Account     string `json:"account"`
}

func chatViews(list []chatops.Link) []chatAccountView {
	out := make([]chatAccountView, 0, len(list))
	for _, l := range list {
		out = append(out, chatAccountView{Link: l, SystemLabel: chatops.SystemLabel(l.System), Account: l.Account()})
	}
	return out
}

type chatTokenRequest struct {
	Token string `json:"token"`
}

// readChatToken reads a link token, which is 64 hex characters.
func readChatToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req chatTokenRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return "", false
	}
	t := strings.TrimSpace(req.Token)
	if len(t) != 64 || strings.Trim(strings.ToLower(t), "0123456789abcdef") != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "This link is not complete. Click the button in the chat again to get a new one.", "code": "bad_token"})
		return "", false
	}
	return t, true
}

// chatTokenError answers a token that does not work.
func chatTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, chatops.ErrNotFound), errors.Is(err, chatops.ErrTokenUsed):
		writeJSON(w, http.StatusGone, map[string]any{"error": "This link was already used, or it expired. Click the button in the chat again to get a new one.", "code": "token_used"})
	default:
		writeError(w, http.StatusBadGateway, fmt.Errorf("could not read the link: %w", err))
	}
}

// handleChatLinkCheck says which chat account a link would link, before
// the user confirms.
func (s *Server) handleChatLinkCheck(w http.ResponseWriter, r *http.Request) {
	if !s.chatOK(w) {
		return
	}
	tok, ok := readChatToken(w, r)
	if !ok {
		return
	}
	t, err := s.Chat.Store.PeekToken(r.Context(), chatops.TokenID(tok), time.Now())
	if err == nil && t.ChatUser == "" {
		err = chatops.ErrNotFound
	}
	if err != nil {
		chatTokenError(w, err)
		return
	}
	l := chatops.Link{System: t.System, Team: t.Team, TeamName: t.TeamName, ChatUser: t.ChatUser, ChatName: t.ChatName}
	out := map[string]any{"system": t.System, "system_label": chatops.SystemLabel(t.System), "account": l.Account(),
		"chat_name": t.ChatName, "team_name": t.TeamName, "expires": t.Expires}
	if cur, found, err := s.Chat.Store.Link(r.Context(), t.System, t.Team, t.ChatUser); err == nil && found {
		out["linked_to"] = cur.Username
	}
	writeJSON(w, http.StatusOK, out)
}

// handleChatLink links the chat account of a link to the signed-in user.
func (s *Server) handleChatLink(w http.ResponseWriter, r *http.Request) {
	if !s.chatOK(w) {
		return
	}
	tok, ok := readChatToken(w, r)
	if !ok {
		return
	}
	p := principalOf(r)
	if p.Method == "token" {
		writeError(w, http.StatusForbidden, errors.New("sign in as yourself to link a chat account"))
		return
	}
	now := time.Now()
	t, err := s.Chat.Store.TakeToken(r.Context(), chatops.TokenID(tok), now)
	if err == nil && t.ChatUser == "" {
		err = chatops.ErrNotFound
	}
	if err != nil {
		chatTokenError(w, err)
		return
	}
	l := chatops.Link{ID: chatops.LinkID(t.System, t.Team, t.ChatUser), System: t.System, Team: t.Team, TeamName: t.TeamName,
		ChatUser: t.ChatUser, ChatName: t.ChatName, Username: p.Username, Created: now.UTC()}
	if u, ok := s.userStore().Get(p.Username); ok {
		l.UserCreated = u.Created
	}
	if cur := s.principalFor(p.Username); cur != nil {
		l.UserEpoch = cur.epoch
	}
	prev, had, _ := s.Chat.Store.Link(r.Context(), t.System, t.Team, t.ChatUser)
	if err := s.Chat.Store.SaveLink(r.Context(), l); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("could not save the link: %w", err))
		return
	}
	attrs := []any{"audit", true, "user", p.Username, "chat", t.System, "chat_team", t.Team, "chat_user", t.ChatUser, "chat_name", t.ChatName}
	if had && prev.Username != p.Username {
		attrs = append(attrs, "replaced_user", prev.Username)
	}
	s.Log.Info("chat account linked", attrs...)
	writeJSON(w, http.StatusOK, chatViews([]chatops.Link{l})[0])
}

// handleChatCode makes a code the signed-in user sends to the Signalith
// app in Teams, to link their Teams account.
func (s *Server) handleChatCode(w http.ResponseWriter, r *http.Request) {
	if !s.chatOK(w) {
		return
	}
	p := principalOf(r)
	if p.Method == "token" {
		writeError(w, http.StatusForbidden, errors.New("sign in as yourself to link a chat account"))
		return
	}
	code := chatops.NewCode()
	now := time.Now()
	t := chatops.Token{ID: chatops.TokenID(code), System: chatops.Teams, Username: p.Username, Expires: now.Add(chatops.TokenLife), Created: now}
	if u, ok := s.userStore().Get(p.Username); ok {
		t.UserCreated = u.Created
	}
	if cur := s.principalFor(p.Username); cur != nil {
		t.UserEpoch = cur.epoch
	}
	if err := s.Chat.Store.SaveToken(r.Context(), t); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("could not make a code: %w", err))
		return
	}
	s.Log.Info("chat link code made", "audit", true, "user", p.Username, "chat", chatops.Teams)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "expires": t.Expires, "minutes": int(chatops.TokenLife.Minutes())})
}

func (s *Server) handleChatAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.chatOK(w) {
		return
	}
	list, err := s.Chat.Store.Links(r.Context(), userOf(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("could not read your chat accounts: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": chatViews(list)})
}

func (s *Server) handleChatAccountDelete(w http.ResponseWriter, r *http.Request) {
	s.deleteChatLink(w, r, false)
}

func (s *Server) handleChatLinks(w http.ResponseWriter, r *http.Request) {
	if !s.chatOK(w) {
		return
	}
	list, err := s.Chat.Store.Links(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("could not read the linked chat accounts: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": chatViews(list)})
}

func (s *Server) handleChatLinkDelete(w http.ResponseWriter, r *http.Request) {
	s.deleteChatLink(w, r, true)
}

// deleteChatLink removes a link: any, for an admin, or the user's own.
func (s *Server) deleteChatLink(w http.ResponseWriter, r *http.Request, anyone bool) {
	if !s.chatOK(w) {
		return
	}
	id := r.PathValue("id")
	user := userOf(r)
	if !anyone {
		// Only one's own: someone else's link is answered as missing.
		list, err := s.Chat.Store.Links(r.Context(), user)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		mine := false
		for _, l := range list {
			if l.ID == id {
				mine = true
			}
		}
		if !mine {
			writeError(w, http.StatusNotFound, errors.New("there is no such chat account linked to you"))
			return
		}
	}
	l, err := s.Chat.Store.DeleteLink(r.Context(), id)
	if errors.Is(err, chatops.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("there is no such linked chat account"))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.Log.Info("chat account unlinked", "audit", true, "by", user, "user", l.Username, "chat", l.System, "chat_team", l.Team,
		"chat_user", l.ChatUser, "chat_name", l.ChatName)
	writeJSON(w, http.StatusOK, map[string]any{"removed": l.ID})
}

// handleTeamsApp downloads the Teams app of a Teams app channel.
func (s *Server) handleTeamsApp(w http.ResponseWriter, r *http.Request) {
	if !s.notifyOK(w) {
		return
	}
	set, err := s.Notify.Settings.Settings()
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	c, ok := set.Channel(r.PathValue("id"))
	if !ok || c.Type != notify.TypeTeamsApp {
		writeError(w, http.StatusNotFound, errors.New("there is no Teams app channel with this ID; save the channel first"))
		return
	}
	zip, err := chatops.TeamsAppPackage(c, s.conf().Server.PublicURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="signalith-teams-app.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(zip)
}

// handleTeamsMove confirms (POST, with the "move_id" the page showed) or
// declines (DELETE) a move of a Teams app channel to the conversation a
// Signalith admin named in Teams with "post here".
func (s *Server) handleTeamsMove(w http.ResponseWriter, r *http.Request) {
	if !s.chatOK(w) {
		return
	}
	id := r.PathValue("id")
	conv, found, err := s.Chat.Store.Conversation(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("could not read where the channel posts: %w", err))
		return
	}
	if !found || conv.Next == nil {
		writeError(w, http.StatusNotFound, errors.New("no move waits for this channel"))
		return
	}
	next := *conv.Next
	if r.Method == http.MethodDelete {
		conv.Next = nil
		if err := s.Chat.Store.SaveConversation(r.Context(), conv); err != nil {
			writeError(w, http.StatusBadGateway, fmt.Errorf("could not save: %w", err))
			return
		}
		s.Log.Info("Teams app channel move declined", "audit", true, "user", userOf(r), "channel", id, "teams_channel", conv.Place(), "declined", next.Place())
		writeJSON(w, http.StatusOK, map[string]any{"posts_to": conv.Place()})
		return
	}
	var req struct {
		MoveID string `json:"move_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.MoveID != next.ConversationID {
		writeError(w, http.StatusConflict, errors.New("the move asked for in Teams changed; reload the page"))
		return
	}
	if err := s.Chat.Store.SaveConversation(r.Context(), next); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("could not save: %w", err))
		return
	}
	s.Log.Info("Teams app channel now posts to a Teams conversation", "audit", true, "user", userOf(r), "channel", id,
		"from", conv.Place(), "teams_channel", next.Place(), "asked_by", next.AddedBy)
	writeJSON(w, http.StatusOK, map[string]any{"posts_to": next.Place()})
}
