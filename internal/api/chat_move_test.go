package api

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/chatops"
	"github.com/jrsamsanchez/signalith/internal/notify"
)

// convStore is a chat store whose conversation reads or saves fail as
// the test says.
type convStore struct {
	*chatops.Memory
	mu               sync.Mutex
	readErr, saveErr error
}

func (c *convStore) fail(read, save error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readErr, c.saveErr = read, save
}

func (c *convStore) Conversation(ctx context.Context, id string) (notify.Conversation, bool, error) {
	c.mu.Lock()
	err := c.readErr
	c.mu.Unlock()
	if err != nil {
		return notify.Conversation{}, false, err
	}
	return c.Memory.Conversation(ctx, id)
}

func (c *convStore) SaveConversation(ctx context.Context, conv notify.Conversation) error {
	c.mu.Lock()
	err := c.saveErr
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return c.Memory.SaveConversation(ctx, conv)
}

// A Teams move needs one waiting and a body that reads; a store that
// cannot read or save the conversation is a 502, and nothing moves.
func TestTeamsMoveRefusals(t *testing.T) {
	ts, srv, mem, _, _ := chatServer(t)
	cs := &convStore{Memory: mem}
	srv.Chat.Store = cs
	move := func(method, body string) int {
		t.Helper()
		code, _ := do(t, ts, method, "/api/notify/channels/teams/teams-move", body, true)
		return code
	}
	if code := move("POST", `{"move_id":"19:new"}`); code != http.StatusNotFound {
		t.Errorf("no move waiting: %d", code)
	}
	cur := notify.Conversation{Channel: "teams", ConversationID: "19:soc", TeamName: "SOC", ChannelName: "Alerts",
		Next: &notify.Conversation{Channel: "teams", ConversationID: "19:new", TeamName: "SOC", ChannelName: "Triage"}}
	if err := mem.SaveConversation(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	if code := move("POST", `{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	cs.fail(errDown, nil)
	if code := move("POST", `{"move_id":"19:new"}`); code != http.StatusBadGateway {
		t.Errorf("read fails: %d", code)
	}
	cs.fail(nil, errDown)
	for _, m := range []string{"POST", "DELETE"} {
		if code := move(m, `{"move_id":"19:new"}`); code != http.StatusBadGateway {
			t.Errorf("%s save fails: %d", m, code)
		}
	}
	cs.fail(nil, nil)
	if got, _, _ := mem.Conversation(context.Background(), "teams"); got.ConversationID != "19:soc" || got.Next == nil {
		t.Errorf("moved after failures: %+v", got)
	}
}
