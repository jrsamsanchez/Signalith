package chatops

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeDocs keeps documents in memory with OpenSearch's versioning, records
// the raw requests, and fails the calls a test asks it to.
type fakeDocs struct {
	*endpoint.MemoryDocs
	mu        sync.Mutex
	calls     []string
	bodies    []any
	doErr     error
	doAnswer  string // JSON written into out by Do
	getErr    error
	createErr error
	putErrs   []error // returned in turn by PutIf, before the real one
	deleteErr error
	searchErr error
	rawSearch []store.Doc
}

func newFakeDocs() *fakeDocs { return &fakeDocs{MemoryDocs: endpoint.NewMemoryDocs()} }

func (f *fakeDocs) Do(_ context.Context, method, path string, body, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method+" "+path)
	f.bodies = append(f.bodies, body)
	if f.doErr != nil {
		return f.doErr
	}
	if out != nil && f.doAnswer != "" {
		return json.Unmarshal([]byte(f.doAnswer), out)
	}
	return nil
}

func (f *fakeDocs) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if f.getErr != nil {
		return nil, store.Version{}, false, f.getErr
	}
	return f.MemoryDocs.Get(ctx, index, id)
}

func (f *fakeDocs) Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error) {
	if f.createErr != nil {
		return store.Version{}, f.createErr
	}
	return f.MemoryDocs.Create(ctx, index, id, body, refresh)
}

func (f *fakeDocs) PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error) {
	f.mu.Lock()
	if len(f.putErrs) > 0 {
		err := f.putErrs[0]
		f.putErrs = f.putErrs[1:]
		f.mu.Unlock()
		return store.Version{}, err
	}
	f.mu.Unlock()
	return f.MemoryDocs.PutIf(ctx, index, id, body, v, refresh)
}

func (f *fakeDocs) DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.MemoryDocs.DeleteIf(ctx, index, id, v, refresh)
}

func (f *fakeDocs) SearchDocs(ctx context.Context, index string, q map[string]any) ([]store.Doc, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	docs, err := f.MemoryDocs.SearchDocs(ctx, index, q)
	return append(docs, f.rawSearch...), err
}

// testStore checks the behaviour every Store must have.
func testStore(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()

	if _, ok, err := s.Link(ctx, Slack, "T1", "U1"); ok || err != nil {
		t.Fatalf("empty Link = %v, %v", ok, err)
	}
	a := Link{ID: LinkID(Slack, "T1", "U1"), System: Slack, Team: "T1", ChatUser: "U1", Username: "vera", Created: now}
	b := Link{ID: LinkID(Teams, "ten", "obj"), System: Teams, Team: "ten", ChatUser: "obj", Username: "abe", Created: now.Add(time.Minute)}
	c := Link{ID: LinkID(Slack, "T1", "U2"), System: Slack, Team: "T1", ChatUser: "U2", Username: "vera", Created: now.Add(-time.Minute)}
	for _, l := range []Link{a, b, c} {
		if err := s.SaveLink(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	a.ChatName = "jlee"
	if err := s.SaveLink(ctx, a); err != nil { // replaces
		t.Fatal(err)
	}
	got, ok, err := s.Link(ctx, Slack, "T1", "U1")
	if err != nil || !ok || got.ChatName != "jlee" {
		t.Errorf("Link = %+v %v %v", got, ok, err)
	}
	all, err := s.Links(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, l := range all {
		order = append(order, l.Username+"/"+l.ChatUser)
	}
	if strings.Join(order, ",") != "abe/obj,vera/U2,vera/U1" {
		t.Errorf("Links order = %v", order)
	}
	if vs, _ := s.Links(ctx, "vera"); len(vs) != 2 {
		t.Errorf("Links(vera) = %v", vs)
	}
	if none, err := s.Links(ctx, "nobody"); err != nil || none == nil || len(none) != 0 {
		t.Errorf("Links(nobody) = %#v, %v", none, err)
	}
	if del, err := s.DeleteLink(ctx, b.ID); err != nil || del.Username != "abe" {
		t.Errorf("DeleteLink = %+v, %v", del, err)
	}
	if _, err := s.DeleteLink(ctx, b.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteLink again = %v", err)
	}

	tok := Token{ID: TokenID("abcde-fghij"), System: Teams, Username: "vera", Expires: now.Add(TokenLife), Created: now}
	if err := s.SaveToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveToken(ctx, tok); !store.IsConflict(err) {
		t.Errorf("SaveToken twice = %v", err)
	}
	if _, err := s.PeekToken(ctx, TokenID("nope"), now); !errors.Is(err, ErrNotFound) {
		t.Errorf("PeekToken missing = %v", err)
	}
	if _, err := s.TakeToken(ctx, TokenID("nope"), now); !errors.Is(err, ErrNotFound) {
		t.Errorf("TakeToken missing = %v", err)
	}
	if p, err := s.PeekToken(ctx, TokenID("ABCDE FGHIJ"), now); err != nil || p.Username != "vera" {
		t.Errorf("PeekToken = %+v, %v", p, err)
	}
	if _, err := s.PeekToken(ctx, tok.ID, now.Add(TokenLife)); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("PeekToken expired = %v", err)
	}
	if _, err := s.TakeToken(ctx, tok.ID, now.Add(TokenLife)); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("TakeToken expired = %v", err)
	}
	if tk, err := s.TakeToken(ctx, tok.ID, now); err != nil || !tk.Used {
		t.Errorf("TakeToken = %+v, %v", tk, err)
	}
	if _, err := s.TakeToken(ctx, tok.ID, now); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("TakeToken twice = %v", err)
	}
	if _, err := s.PeekToken(ctx, tok.ID, now); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("PeekToken used = %v", err)
	}

	if _, ok, err := s.Conversation(ctx, "ch1"); ok || err != nil {
		t.Errorf("empty Conversation = %v %v", ok, err)
	}
	conv := notify.Conversation{Channel: "ch1", ServiceURL: "https://smba.example/", ConversationID: "19:x"}
	if err := s.SaveConversation(ctx, conv); err != nil {
		t.Fatal(err)
	}
	conv.ConversationID = "19:y"
	if err := s.SaveConversation(ctx, conv); err != nil {
		t.Fatal(err)
	}
	if gc, ok, err := s.Conversation(ctx, "ch1"); err != nil || !ok || gc.ConversationID != "19:y" {
		t.Errorf("Conversation = %+v %v %v", gc, ok, err)
	}
	if err := s.DeleteConversation(ctx, "ch1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteConversation(ctx, "ch1"); err != nil {
		t.Errorf("DeleteConversation of nothing = %v", err)
	}
	if _, ok, _ := s.Conversation(ctx, "ch1"); ok {
		t.Error("conversation still there")
	}

	if seen, err := s.Seen(ctx, Slack, "click1", now); seen || err != nil {
		t.Errorf("Seen first = %v %v", seen, err)
	}
	if seen, err := s.Seen(ctx, Slack, "click1", now); !seen || err != nil {
		t.Errorf("Seen again = %v %v", seen, err)
	}
	if seen, _ := s.Seen(ctx, Teams, "click1", now); seen {
		t.Error("a click on another system counted as seen")
	}
	if err := s.Purge(ctx, now.Add(seenFor+time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryStore(t *testing.T) {
	m := NewMemory()
	testStore(t, m)
	if _, err := m.PeekToken(context.Background(), TokenID("abcde-fghij"), time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("used token not purged: %v", err)
	}
	if seen, _ := m.Seen(context.Background(), Slack, "click1", time.Now()); seen {
		t.Error("old click not purged")
	}
	if got := m.LinksOf("vera"); len(got) != 2 {
		t.Errorf("LinksOf(vera) = %v", got)
	}
	if got := m.LinksOf(); len(got) != 2 {
		t.Errorf("LinksOf() = %v", got)
	}
	if got := m.LinksOf("abe"); len(got) != 0 {
		t.Errorf("LinksOf(abe) = %v", got)
	}
}

func TestOpenSearchStore(t *testing.T) {
	f := newFakeDocs()
	o := NewOpenSearch(f, "sig")
	if o.Index != "sig_chat" {
		t.Errorf("index = %q", o.Index)
	}
	testStore(t, o)
	if len(f.calls) != 1 || !strings.HasPrefix(f.calls[0], "POST /sig_chat/_delete_by_query?") {
		t.Errorf("purge calls = %v", f.calls)
	}
	q := f.bodies[0].(map[string]any)["query"].(map[string]any)["bool"].(map[string]any)
	types := q["filter"].([]any)[0].(map[string]any)["terms"].(map[string]any)["type"].([]string)
	if strings.Join(types, ",") != "token,seen" {
		t.Errorf("purge types = %v", types)
	}
}

func TestOpenSearchEnsureIndex(t *testing.T) {
	ctx := context.Background()
	f := newFakeDocs()
	o := NewOpenSearch(f, "sig")
	if err := o.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if f.calls[0] != "PUT /sig_chat" {
		t.Errorf("calls = %v", f.calls)
	}
	body := f.bodies[0].(map[string]any)
	props := body["mappings"].(map[string]any)["properties"].(map[string]any)
	if props["type"].(map[string]any)["type"] != "keyword" || props["link"].(map[string]any)["enabled"] != false {
		t.Errorf("mappings = %v", props)
	}
	if body["settings"].(map[string]any)["auto_expand_replicas"] != store.AutoReplicas {
		t.Errorf("settings = %v", body["settings"])
	}
	f.doErr = &store.Error{Status: 400, Body: `{"error":{"type":"resource_already_exists_exception"}}`}
	if err := o.EnsureIndex(ctx); err != nil {
		t.Errorf("existing index = %v", err)
	}
	f.doErr = &store.Error{Status: 400, Body: "mapper_parsing_exception"}
	if err := o.EnsureIndex(ctx); err == nil {
		t.Error("bad request not returned")
	}

	// Replicate reads the settings and raises a 0-replica index.
	f.doErr = nil
	f.calls = nil
	f.doAnswer = `{"sig_chat":{"settings":{"index":{"number_of_replicas":"0"}}}}`
	if err := o.Replicate(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[1] != "PUT /sig_chat/_settings" {
		t.Errorf("replicate calls = %v", f.calls)
	}
}

func TestOpenSearchErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	boom := errors.New("boom")
	f := newFakeDocs()
	o := NewOpenSearch(f, "sig")
	l := Link{ID: LinkID(Slack, "T", "U"), System: Slack, Team: "T", ChatUser: "U", Username: "vera"}
	if err := o.SaveLink(ctx, l); err != nil {
		t.Fatal(err)
	}

	// put tries three times on a conflict, then gives up.
	f.putErrs = []error{store.ErrConflict, store.ErrConflict, store.ErrConflict}
	if err := o.SaveLink(ctx, l); !errors.Is(err, store.ErrConflict) {
		t.Errorf("SaveLink conflicts = %v", err)
	}
	f.putErrs = []error{store.ErrConflict}
	if err := o.SaveLink(ctx, l); err != nil {
		t.Errorf("SaveLink after one conflict = %v", err)
	}
	f.putErrs = []error{boom}
	if err := o.SaveLink(ctx, l); !errors.Is(err, boom) {
		t.Errorf("SaveLink error = %v", err)
	}

	f.deleteErr = store.ErrNotFound
	if _, err := o.DeleteLink(ctx, l.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteLink race = %v", err)
	}
	f.deleteErr = boom
	if _, err := o.DeleteLink(ctx, l.ID); !errors.Is(err, boom) {
		t.Errorf("DeleteLink error = %v", err)
	}
	f.deleteErr = nil

	tok := Token{ID: TokenID("x"), System: Teams, Expires: now.Add(time.Minute)}
	if err := o.SaveToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	f.putErrs = []error{store.ErrConflict}
	if _, err := o.TakeToken(ctx, tok.ID, now); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("TakeToken race = %v", err)
	}
	f.putErrs = []error{boom}
	if _, err := o.TakeToken(ctx, tok.ID, now); !errors.Is(err, boom) {
		t.Errorf("TakeToken error = %v", err)
	}
	// A document of another type is not a token or a link.
	if _, err := o.PeekToken(ctx, l.ID, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("PeekToken of a link = %v", err)
	}
	if _, err := o.TakeToken(ctx, l.ID, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("TakeToken of a link = %v", err)
	}
	if _, err := o.DeleteLink(ctx, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteLink of a token = %v", err)
	}

	if err := o.SaveConversation(ctx, notify.Conversation{Channel: "c"}); err != nil {
		t.Fatal(err)
	}
	f.deleteErr = store.ErrConflict
	if err := o.DeleteConversation(ctx, "c"); err != nil {
		t.Errorf("DeleteConversation conflict = %v", err)
	}
	f.deleteErr = boom
	if err := o.DeleteConversation(ctx, "c"); !errors.Is(err, boom) {
		t.Errorf("DeleteConversation error = %v", err)
	}
	f.deleteErr = nil

	f.createErr = boom
	if _, err := o.Seen(ctx, Slack, "c1", now); !errors.Is(err, boom) {
		t.Errorf("Seen error = %v", err)
	}
	if err := o.SaveToken(ctx, Token{ID: "t2"}); !errors.Is(err, boom) {
		t.Errorf("SaveToken error = %v", err)
	}
	f.createErr = nil

	// A document that does not parse is an error, not a missing one.
	if _, err := f.MemoryDocs.Create(ctx, "sig_chat", LinkID(Slack, "T", "bad"), json.RawMessage(`{"type":5}`), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Link(ctx, Slack, "T", "bad"); err == nil {
		t.Error("bad document read without an error")
	}

	// Links skips what does not parse.
	f.rawSearch = []store.Doc{{Source: json.RawMessage(`not json`)}, {Source: json.RawMessage(`{"type":"link"}`)}}
	if ls, err := o.Links(ctx, "vera"); err != nil || len(ls) != 1 {
		t.Errorf("Links = %v, %v", ls, err)
	}
	f.searchErr = boom
	if _, err := o.Links(ctx, ""); !errors.Is(err, boom) {
		t.Errorf("Links error = %v", err)
	}

	f.getErr = boom
	if _, _, err := o.Link(ctx, Slack, "T", "U"); !errors.Is(err, boom) {
		t.Errorf("Link error = %v", err)
	}
	if err := o.SaveLink(ctx, l); !errors.Is(err, boom) {
		t.Errorf("SaveLink get error = %v", err)
	}
	if _, err := o.DeleteLink(ctx, l.ID); !errors.Is(err, boom) {
		t.Errorf("DeleteLink get error = %v", err)
	}
	if _, err := o.PeekToken(ctx, tok.ID, now); !errors.Is(err, boom) {
		t.Errorf("PeekToken error = %v", err)
	}
	if _, err := o.TakeToken(ctx, tok.ID, now); !errors.Is(err, boom) {
		t.Errorf("TakeToken get error = %v", err)
	}
	if err := o.DeleteConversation(ctx, "c"); !errors.Is(err, boom) {
		t.Errorf("DeleteConversation get error = %v", err)
	}
	if _, _, err := o.Conversation(ctx, "c"); !errors.Is(err, boom) {
		t.Errorf("Conversation error = %v", err)
	}
}

func TestLinkAccountAndLabels(t *testing.T) {
	l := Link{System: Slack, ChatUser: "U1"}
	if got := l.Account(); got != "Slack user U1" {
		t.Errorf("Account = %q", got)
	}
	l = Link{System: Teams, ChatUser: "obj", ChatName: "Jo Lee", TeamName: "Acme"}
	if got := l.Account(); got != "Teams user Jo Lee in Acme" {
		t.Errorf("Account = %q", got)
	}
	if SystemLabel("matrix") != "matrix" {
		t.Error("unknown system relabelled")
	}
	a, b := NewSecret(), NewSecret()
	if len(a) != 64 || a == b || strings.Trim(a, "0123456789abcdef") != "" {
		t.Errorf("secrets %q %q", a, b)
	}
}
