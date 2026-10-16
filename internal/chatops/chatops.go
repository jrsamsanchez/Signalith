// Package chatops answers the buttons in Slack and Microsoft Teams
// messages: an analyst approves or rejects a playbook step, or
// acknowledges a finding, from the chat, without opening Signalith.
//
// Every click is checked before anything happens:
//
//   - The request must come from Slack or Teams: a Slack request is
//     signed with the Slack app's signing secret and is at most five
//     minutes old; a Teams request carries a token Microsoft's Bot
//     Framework signed for the channel's bot, about the Microsoft Entra
//     tenant the channel names.
//   - The button must be one Signalith sent on that channel: its value is
//     signed with the channel's own secret (see notify.SignButton).
//   - Each click counts once: its ID is claimed in OpenSearch, so a
//     request sent again is ignored.
//   - The chat account must be linked to a Signalith user, who proved it
//     by signing in to Signalith (see Link), and that user must still be
//     able to sign in, with at least the Analyst role, now.
//   - Approve works only where the channel allows it
//     (notify.Channel.ApproveInChat), and only for the step the message
//     was about.
//
// Every click, accepted or refused, and every link made or removed, goes
// to the audit log.
package chatops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Chat systems.
const (
	Slack = "slack"
	Teams = "teams"
)

// SystemLabel names a chat system for people.
func SystemLabel(system string) string {
	switch system {
	case Slack:
		return "Slack"
	case Teams:
		return "Teams"
	}
	return system
}

// Link says which Signalith user a chat account acts as.
type Link struct {
	// ID is LinkID(system, team, chat user).
	ID     string `json:"id"`
	System string `json:"system"`
	// Team is the Slack workspace (team) ID or the Microsoft Entra tenant
	// ID; TeamName names it for people, when known.
	Team     string `json:"team"`
	TeamName string `json:"team_name,omitempty"`
	// ChatUser is the Slack user ID or the Microsoft Entra object ID;
	// ChatName names them for people.
	ChatUser string `json:"chat_user"`
	ChatName string `json:"chat_name,omitempty"`
	Username string `json:"username"`
	// UserCreated is when the Signalith user was added, so a link never
	// carries over to a new user who gets a removed user's name.
	UserCreated time.Time `json:"user_created,omitzero"`
	// UserEpoch is the user's session epoch when the link was made. It
	// moves on when their password changes or is reset, when they sign
	// out everywhere, and when their two-step sign-in is reset or turned
	// off; a link from before that no longer counts, like their sessions.
	UserEpoch int64     `json:"user_epoch,omitempty"`
	Created   time.Time `json:"created"`
}

// Account names a link's chat account for people, as in "Slack user
// jlee in Acme".
func (l Link) Account() string {
	who := l.ChatName
	if who == "" {
		who = l.ChatUser
	}
	s := SystemLabel(l.System) + " user " + who
	if l.TeamName != "" {
		s += " in " + l.TeamName
	}
	return s
}

// LinkID is the ID of a chat account's link.
func LinkID(system, team, chatUser string) string {
	return hashID("link|" + system + "|" + team + "|" + chatUser)
}

// Token is a one-time secret that links a chat account to a Signalith
// user. For Slack, a click from an account with no link makes one with
// the chat account, sent to that person only, as a link to Signalith:
// signing in there and confirming says which user it is. For Teams, which
// has no message only one person sees, it goes the other way: a signed-in
// user makes one as a code, and sends it to the Signalith app in Teams.
// Either way, the chat account is shown before anything is linked.
type Token struct {
	// ID is TokenID of the secret; the secret itself is never kept.
	ID       string `json:"id"`
	System   string `json:"system"`
	Team     string `json:"team,omitempty"`
	TeamName string `json:"team_name,omitempty"`
	ChatUser string `json:"chat_user,omitempty"`
	ChatName string `json:"chat_name,omitempty"`
	// Username, UserCreated and UserEpoch are set on a token a Signalith
	// user made.
	Username    string    `json:"username,omitempty"`
	UserCreated time.Time `json:"user_created,omitzero"`
	UserEpoch   int64     `json:"user_epoch,omitempty"`
	// Channel is the notification channel it was made for.
	Channel string    `json:"channel,omitempty"`
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used,omitempty"`
	Created time.Time `json:"created"`
}

// TokenLife is how long a token works.
const TokenLife = 10 * time.Minute

// TokenID is the ID a token's secret is kept under.
func TokenID(secret string) string { return hashID("token|" + normalizeCode(secret)) }

func hashID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// NewSecret returns a random link secret for a URL: 32 bytes, as hex.
func NewSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// codeAlphabet has no letters that read alike (0/O, 1/I/L).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NewCode returns a code to type: ten characters from codeAlphabet, about
// 49 bits, shown as XXXXX-XXXXX. It works once, for TokenLife.
func NewCode() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, 0, 11)
	for i, x := range b {
		if i == 5 {
			out = append(out, '-')
		}
		// 256 is not a multiple of 31, so the first few letters are a
		// little likelier; a code is used once, within minutes.
		out = append(out, codeAlphabet[int(x)%len(codeAlphabet)])
	}
	return string(out)
}

// normalizeCode puts a typed code in the form it was made in: upper
// case, without spaces or dashes. A URL secret is unchanged but for case.
func normalizeCode(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, strings.TrimSpace(s))
}

// Errors of the store.
var (
	ErrNotFound = errors.New("not found")
	// ErrTokenUsed is a token that was used, or expired.
	ErrTokenUsed = errors.New("this link or code was already used, or it expired; make a new one")
)

// Store keeps links, tokens, where Teams app channels post, and which
// clicks were handled.
type Store interface {
	// Link returns a chat account's link.
	Link(ctx context.Context, system, team, chatUser string) (Link, bool, error)
	// SaveLink writes a link, replacing one for the same chat account.
	SaveLink(ctx context.Context, l Link) error
	// DeleteLink removes a link and returns it, or ErrNotFound.
	DeleteLink(ctx context.Context, id string) (Link, error)
	// Links lists the links of a Signalith user, or every link for "".
	Links(ctx context.Context, username string) ([]Link, error)
	// SaveToken writes a new token.
	SaveToken(ctx context.Context, t Token) error
	// PeekToken returns a token that still works, without using it:
	// ErrNotFound, or ErrTokenUsed when it was used or expired.
	PeekToken(ctx context.Context, id string, now time.Time) (Token, error)
	// TakeToken uses a token once: of two at the same time, one gets it
	// and the other ErrTokenUsed.
	TakeToken(ctx context.Context, id string, now time.Time) (Token, error)
	// SaveConversation records where a Teams app channel posts.
	SaveConversation(ctx context.Context, c notify.Conversation) error
	// DeleteConversation forgets it.
	DeleteConversation(ctx context.Context, channelID string) error
	notify.Conversations
	// Seen claims a click by its ID, and reports true when it was claimed
	// before: the request came again.
	Seen(ctx context.Context, system, id string, now time.Time) (bool, error)
	// Purge deletes used and expired tokens and old click IDs.
	Purge(ctx context.Context, now time.Time) error
}

// seenFor is how long a click's ID is kept: longer than Slack accepts a
// request (five minutes) and a Teams token lives.
const seenFor = 2 * time.Hour

// Memory keeps everything in memory, for tests and a server without
// OpenSearch.
type Memory struct {
	mu     sync.Mutex
	links  map[string]Link
	tokens map[string]Token
	convs  map[string]notify.Conversation
	seen   map[string]time.Time
}

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{links: map[string]Link{}, tokens: map[string]Token{}, convs: map[string]notify.Conversation{}, seen: map[string]time.Time{}}
}

func (m *Memory) Link(_ context.Context, system, team, chatUser string) (Link, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.links[LinkID(system, team, chatUser)]
	return l, ok, nil
}

func (m *Memory) SaveLink(_ context.Context, l Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links[l.ID] = l
	return nil
}

func (m *Memory) DeleteLink(_ context.Context, id string) (Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.links[id]
	if !ok {
		return Link{}, ErrNotFound
	}
	delete(m.links, id)
	return l, nil
}

func (m *Memory) Links(_ context.Context, username string) ([]Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Link{}
	for _, l := range m.links {
		if username == "" || l.Username == username {
			out = append(out, l)
		}
	}
	sortLinks(out)
	return out, nil
}

func sortLinks(list []Link) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Username != list[j].Username {
			return list[i].Username < list[j].Username
		}
		return list[i].Created.Before(list[j].Created)
	})
}

func (m *Memory) SaveToken(_ context.Context, t Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[t.ID]; ok {
		return store.ErrExists
	}
	m.tokens[t.ID] = t
	return nil
}

func (m *Memory) PeekToken(_ context.Context, id string, now time.Time) (Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return usable(m.tokens[id], m.tokens[id].ID != "", now)
}

func (m *Memory) TakeToken(_ context.Context, id string, now time.Time) (Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, err := usable(m.tokens[id], m.tokens[id].ID != "", now)
	if err != nil {
		return Token{}, err
	}
	t.Used = true
	m.tokens[id] = t
	return t, nil
}

// usable returns a token that works now, or why not.
func usable(t Token, found bool, now time.Time) (Token, error) {
	switch {
	case !found:
		return Token{}, ErrNotFound
	case t.Used || !now.Before(t.Expires):
		return Token{}, ErrTokenUsed
	}
	return t, nil
}

func (m *Memory) SaveConversation(_ context.Context, c notify.Conversation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.convs[c.Channel] = c
	return nil
}

func (m *Memory) DeleteConversation(_ context.Context, channelID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.convs, channelID)
	return nil
}

func (m *Memory) Conversation(_ context.Context, channelID string) (notify.Conversation, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.convs[channelID]
	return c, ok, nil
}

func (m *Memory) Seen(_ context.Context, system, id string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := seenID(system, id)
	if exp, ok := m.seen[key]; ok && now.Before(exp) {
		return true, nil
	}
	m.seen[key] = now.Add(seenFor)
	return false, nil
}

func seenID(system, id string) string { return hashID("seen|" + system + "|" + id) }

func (m *Memory) Purge(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, t := range m.tokens {
		if t.Used || !now.Before(t.Expires) {
			delete(m.tokens, id)
		}
	}
	for id, exp := range m.seen {
		if !now.Before(exp) {
			delete(m.seen, id)
		}
	}
	return nil
}

// LinksOf returns the links of the given users, for tests.
func (m *Memory) LinksOf(names ...string) []Link {
	all, _ := m.Links(context.Background(), "")
	var out []Link
	for _, l := range all {
		if len(names) == 0 || slices.Contains(names, l.Username) {
			out = append(out, l)
		}
	}
	return out
}
