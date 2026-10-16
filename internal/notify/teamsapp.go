package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A Teams app channel posts through an Azure bot, so that Teams sends the
// clicks on its buttons back to Signalith (Workflows webhooks cannot).
// The admin registers the bot in Microsoft Entra (single tenant), points
// its messaging endpoint at Signalith, and adds the app Signalith makes
// for it to a team. Teams then tells Signalith which channel it was added
// to (package chatops records it as a Conversation), and messages go
// there: Signalith gets a token for the bot from Microsoft Entra with the
// client secret and posts the card to the Bot Connector service Teams
// named.

// Conversation is the Teams channel or chat a Teams app channel posts to,
// recorded when the app is added or mentioned there.
type Conversation struct {
	// Channel is the notification channel's ID.
	Channel string `json:"channel"`
	// ConversationID and ServiceURL are where Teams takes messages for it.
	ConversationID string `json:"conversation_id"`
	ServiceURL     string `json:"service_url"`
	TenantID       string `json:"tenant_id"`
	// TeamID is the team's ID, so removing the app from the team forgets
	// the conversation.
	TeamID string `json:"team_id,omitempty"`
	// Where it is, for people: the team and channel names, when Teams
	// says them.
	TeamName    string    `json:"team_name,omitempty"`
	ChannelName string    `json:"channel_name,omitempty"`
	AddedBy     string    `json:"added_by,omitempty"`
	Added       time.Time `json:"added"`
}

// Place names a conversation for people, as in "SOC > Alerts".
func (c Conversation) Place() string {
	switch {
	case c.TeamName != "" && c.ChannelName != "":
		return c.TeamName + " > " + c.ChannelName
	case c.TeamName != "":
		return c.TeamName
	case c.ChannelName != "":
		return c.ChannelName
	}
	return "a Teams conversation"
}

// Conversations finds where Teams app channels post.
type Conversations interface {
	// Conversation returns where a channel posts, and false when the app
	// was not added anywhere yet.
	Conversation(ctx context.Context, channelID string) (Conversation, bool, error)
}

// MicrosoftLogin is where Teams app channels get their tokens.
const MicrosoftLogin = "https://login.microsoftonline.com"

// botScope is what a bot's token is for: the Bot Connector service.
const botScope = "https://api.botframework.com/.default"

// ServiceURLAllowed reports whether a Bot Connector address Teams named is
// one of Microsoft's, so a bot token is never sent anywhere else. The
// chat requests are checked too (package chatops), so this is a second
// line.
func ServiceURLAllowed(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if h == "smba.trafficmanager.net" {
		return true
	}
	for _, suffix := range []string{".botframework.com", ".teams.microsoft.com", ".teams.microsoft.us", ".botframework.azure.us"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// botToken is a token for a bot, kept until shortly before it expires.
type botToken struct {
	value   string
	expires time.Time
}

// botTokens keeps one token per bot and secret.
type botTokens struct {
	mu sync.Mutex
	m  map[string]botToken
}

func tokenKey(c Channel) string {
	sum := sha256.Sum256([]byte(c.TenantID + "|" + c.AppID + "|" + c.AppPassword))
	return hex.EncodeToString(sum[:])
}

func (t *botTokens) get(c Channel, now time.Time) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	tok, ok := t.m[tokenKey(c)]
	if !ok || !now.Before(tok.expires) {
		return ""
	}
	return tok.value
}

func (t *botTokens) put(c Channel, tok botToken) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]botToken{}
	}
	// A bot whose secret changed leaves an old entry; there are few.
	t.m[tokenKey(c)] = tok
}

func (t *botTokens) drop(c Channel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, tokenKey(c))
}

// TokenError is Microsoft Entra refusing a bot's credentials.
type TokenError struct {
	Code   int
	Status string
	// Kind and Said are the OAuth error and its description, when sent.
	Kind, Said string
}

func (e *TokenError) Error() string {
	msg := "Microsoft Entra refused the bot's credentials (" + e.Status
	if e.Kind != "" {
		msg += ", " + e.Kind
	}
	msg += "). Check the app ID, the tenant ID and the client secret, and that the secret has not expired."
	if e.Said != "" {
		msg += fmt.Sprintf(" It said: %q", e.Said)
	}
	return msg
}

// botToken returns a token for the channel's bot, from the cache or from
// Microsoft Entra.
func (s *Senders) botToken(ctx context.Context, c Channel) (string, error) {
	if tok := s.tokens.get(c, s.now()); tok != "" {
		return tok, nil
	}
	login := strings.TrimRight(s.TeamsLogin, "/")
	if login == "" {
		login = MicrosoftLogin
	}
	u, err := url.Parse(login + "/" + url.PathEscape(c.TenantID) + "/oauth2/v2.0/token")
	if err != nil {
		return "", err
	}
	if err := s.Protected.check(u, c.AllowLoopback); err != nil {
		return "", err
	}
	client, err := httpClient(c, s.Protected)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.AppID}, "client_secret": {c.AppPassword}, "scope": {botScope}}
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Signalith")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return "", &AnswerError{Code: resp.StatusCode, Status: resp.Status, Said: said(raw)}
		}
		// The first line of Entra's description says what is wrong; the
		// rest is trace and correlation IDs.
		desc, _, _ := strings.Cut(out.Description, "\r\n")
		return "", &TokenError{Code: resp.StatusCode, Status: resp.Status, Kind: clean(out.Error, 60), Said: clean(desc, 200)}
	}
	life := time.Duration(out.ExpiresIn) * time.Second
	if life <= 0 || life > 24*time.Hour {
		life = time.Hour
	}
	// Renewed five minutes early, so a token never expires on its way.
	s.tokens.put(c, botToken{value: out.AccessToken, expires: s.now().Add(life - 5*time.Minute)})
	return out.AccessToken, nil
}

// errNoConversation is a Teams app channel the app was not added to yet.
var errNoConversation = &SendError{Msg: "The Signalith app is not in a Teams channel yet. Download the app on the Notifications page, add it to a team in Teams, then send the test again.", Retry: true}

// sendTeamsApp sends m as a card to where channel c posts.
func (s *Senders) sendTeamsApp(ctx context.Context, c Channel, m Message) error {
	if s.Conversations == nil {
		return &SendError{Msg: "Teams app channels are not available on this server."}
	}
	conv, ok, err := s.Conversations.Conversation(ctx, c.ID)
	if err != nil {
		return fmt.Errorf("could not read where the Teams app posts: %w", err)
	}
	if !ok {
		return errNoConversation
	}
	activity := map[string]any{
		"type":    "message",
		"summary": clean(m.headline(), 200),
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     m.teamsCard(c),
		}},
	}
	_, err = s.TeamsPost(ctx, c, conv, "", activity)
	return err
}

// TeamsPost posts an activity to a conversation of a Teams app channel,
// as a reply to replyTo when it is set, and returns the new activity's
// ID. Its error is like Send's: in words for people, with no secret.
func (s *Senders) TeamsPost(ctx context.Context, c Channel, conv Conversation, replyTo string, activity any) (string, error) {
	id, err := s.teamsPost(ctx, c, conv, replyTo, activity)
	if err == nil {
		return id, nil
	}
	var se *SendError
	if errors.As(err, &se) {
		return "", err
	}
	return "", &SendError{Msg: scrub(describe(err, c), c), Retry: retryable(err)}
}

func (s *Senders) teamsPost(ctx context.Context, c Channel, conv Conversation, replyTo string, activity any) (string, error) {
	su, err := url.Parse(conv.ServiceURL)
	if err != nil || !s.serviceURLOK(su) {
		return "", &SendError{Msg: "Teams named a Bot Connector address that is not Microsoft's, so Signalith does not post there. Remove the app from the Teams channel and add it again."}
	}
	path := "v3/conversations/" + url.PathEscape(conv.ConversationID) + "/activities"
	if replyTo != "" {
		path += "/" + url.PathEscape(replyTo)
	}
	target, err := url.Parse(strings.TrimRight(conv.ServiceURL, "/") + "/" + path)
	if err != nil {
		return "", errBadURL
	}
	if err := s.Protected.check(target, c.AllowLoopback); err != nil {
		return "", err
	}
	raw, err := json.Marshal(activity)
	if err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		tok, err := s.botToken(ctx, c)
		if err != nil {
			return "", err
		}
		client, err := httpClient(c, s.Protected)
		if err != nil {
			return "", err
		}
		rctx, cancel := context.WithTimeout(ctx, SendTimeout)
		req, err := http.NewRequestWithContext(rctx, http.MethodPost, target.String(), bytes.NewReader(raw))
		if err != nil {
			cancel()
			return "", errBadURL
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Signalith")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			return "", err
		}
		answer, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
		resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			// The token may have been revoked early: get a new one, once.
			s.tokens.drop(c)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", &AnswerError{Code: resp.StatusCode, Status: resp.Status, Said: said(answer)}
		}
		var out struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(answer, &out)
		return out.ID, nil
	}
}

func (s *Senders) serviceURLOK(u *url.URL) bool {
	if s.ServiceURLOK != nil {
		return s.ServiceURLOK(u)
	}
	return ServiceURLAllowed(u)
}
