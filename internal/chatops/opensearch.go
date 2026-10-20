// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package chatops

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Docs is what OpenSearch keeps chat state with; *store.Client is one.
type Docs interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// OpenSearch keeps chat state in one index, "<prefix>_chat", so every
// server that shares the OpenSearch sees the same links: a click may
// reach any of them. Each document has a "type": link, token,
// conversation or seen. Its name uses "_" rather than "-" so event
// searches over "<prefix>-*" never include it.
type OpenSearch struct {
	Client Docs
	Index  string
	// Replicas are the index's replicas settings (opensearch.replicas);
	// nil is auto.
	Replicas map[string]any
}

// NewOpenSearch returns the chat index of prefix.
func NewOpenSearch(c Docs, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_chat"}
}

// Document types.
const (
	docLink         = "link"
	docToken        = "token"
	docConversation = "conversation"
	docSeen         = "seen"
)

// doc is one document: its type, when it expires (tokens and click IDs),
// and the record of its type.
type doc struct {
	Type         string               `json:"type"`
	Username     string               `json:"username,omitempty"`
	Expires      *time.Time           `json:"expires,omitempty"`
	Link         *Link                `json:"link,omitempty"`
	Token        *Token               `json:"token,omitempty"`
	Conversation *notify.Conversation `json:"conversation,omitempty"`
}

func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	off := map[string]any{"type": "object", "enabled": false}
	return map[string]any{
		"type": kw, "username": kw, "expires": map[string]any{"type": "date"},
		"link": off, "token": off, "conversation": off,
	}
}

// EnsureIndex creates the index if it does not exist. Any server may.
func (o *OpenSearch) EnsureIndex(ctx context.Context) error {
	body := map[string]any{
		"settings": store.SmallIndexSettings(o.Replicas),
		"mappings": map[string]any{"dynamic": "false", "properties": properties()},
	}
	err := o.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(o.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 400 && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// Replicate gives the index, when it was made with no copy on another
// node, the replicas settings new indices get (see store.Replicate).
func (o *OpenSearch) Replicate(ctx context.Context) error {
	return store.Replicate(ctx, o.Client, o.Index, o.Replicas)
}

func (o *OpenSearch) get(ctx context.Context, id string) (doc, store.Version, bool, error) {
	raw, v, found, err := o.Client.Get(ctx, o.Index, id)
	if err != nil || !found {
		return doc{}, v, false, err
	}
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return doc{}, v, false, err
	}
	return d, v, true, nil
}

// put writes a document whatever is there: replaced if it exists.
func (o *OpenSearch) put(ctx context.Context, id string, d doc) error {
	for range 3 {
		_, v, found, err := o.get(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			_, err = o.Client.Create(ctx, o.Index, id, d, true)
		} else {
			_, err = o.Client.PutIf(ctx, o.Index, id, d, v, true)
		}
		if !store.IsConflict(err) {
			return err
		}
	}
	return store.ErrConflict
}

func (o *OpenSearch) Link(ctx context.Context, system, team, chatUser string) (Link, bool, error) {
	d, _, found, err := o.get(ctx, LinkID(system, team, chatUser))
	if err != nil || !found || d.Type != docLink || d.Link == nil {
		return Link{}, false, err
	}
	return *d.Link, true, nil
}

func (o *OpenSearch) SaveLink(ctx context.Context, l Link) error {
	return o.put(ctx, l.ID, doc{Type: docLink, Username: l.Username, Link: &l})
}

func (o *OpenSearch) DeleteLink(ctx context.Context, id string) (Link, error) {
	d, v, found, err := o.get(ctx, id)
	if err != nil {
		return Link{}, err
	}
	if !found || d.Type != docLink || d.Link == nil {
		return Link{}, ErrNotFound
	}
	if err := o.Client.DeleteIf(ctx, o.Index, id, v, true); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Link{}, ErrNotFound
		}
		return Link{}, err
	}
	return *d.Link, nil
}

func (o *OpenSearch) Links(ctx context.Context, username string) ([]Link, error) {
	filter := []any{map[string]any{"term": map[string]any{"type": docLink}}}
	if username != "" {
		filter = append(filter, map[string]any{"term": map[string]any{"username": username}})
	}
	docs, err := o.Client.SearchDocs(ctx, o.Index, map[string]any{"bool": map[string]any{"filter": filter}})
	if err != nil {
		return nil, err
	}
	out := []Link{}
	for _, raw := range docs {
		var d doc
		if json.Unmarshal(raw.Source, &d) == nil && d.Link != nil {
			out = append(out, *d.Link)
		}
	}
	sortLinks(out)
	return out, nil
}

func (o *OpenSearch) SaveToken(ctx context.Context, t Token) error {
	exp := t.Expires
	_, err := o.Client.Create(ctx, o.Index, t.ID, doc{Type: docToken, Username: t.Username, Expires: &exp, Token: &t}, true)
	return err
}

func (o *OpenSearch) PeekToken(ctx context.Context, id string, now time.Time) (Token, error) {
	d, _, found, err := o.get(ctx, id)
	if err != nil {
		return Token{}, err
	}
	if !found || d.Type != docToken || d.Token == nil {
		return Token{}, ErrNotFound
	}
	return usable(*d.Token, true, now)
}

func (o *OpenSearch) TakeToken(ctx context.Context, id string, now time.Time) (Token, error) {
	d, v, found, err := o.get(ctx, id)
	if err != nil {
		return Token{}, err
	}
	if !found || d.Type != docToken || d.Token == nil {
		return Token{}, ErrNotFound
	}
	t, err := usable(*d.Token, true, now)
	if err != nil {
		return Token{}, err
	}
	t.Used = true
	d.Token = &t
	// Written only if nobody used it meanwhile.
	if _, err := o.Client.PutIf(ctx, o.Index, id, d, v, true); err != nil {
		if store.IsConflict(err) {
			return Token{}, ErrTokenUsed
		}
		return Token{}, err
	}
	return t, nil
}

func conversationID(channelID string) string { return hashID("conversation|" + channelID) }

func (o *OpenSearch) SaveConversation(ctx context.Context, c notify.Conversation) error {
	return o.put(ctx, conversationID(c.Channel), doc{Type: docConversation, Conversation: &c})
}

func (o *OpenSearch) DeleteConversation(ctx context.Context, channelID string) error {
	id := conversationID(channelID)
	_, v, found, err := o.get(ctx, id)
	if err != nil || !found {
		return err
	}
	err = o.Client.DeleteIf(ctx, o.Index, id, v, true)
	if errors.Is(err, store.ErrNotFound) || store.IsConflict(err) {
		return nil
	}
	return err
}

func (o *OpenSearch) Conversation(ctx context.Context, channelID string) (notify.Conversation, bool, error) {
	d, _, found, err := o.get(ctx, conversationID(channelID))
	if err != nil || !found || d.Type != docConversation || d.Conversation == nil {
		return notify.Conversation{}, false, err
	}
	return *d.Conversation, true, nil
}

func (o *OpenSearch) Seen(ctx context.Context, system, id string, now time.Time) (bool, error) {
	exp := now.Add(seenFor)
	_, err := o.Client.Create(ctx, o.Index, seenID(system, id), doc{Type: docSeen, Expires: &exp}, false)
	if errors.Is(err, store.ErrExists) {
		return true, nil
	}
	return false, err
}

func (o *OpenSearch) Purge(ctx context.Context, now time.Time) error {
	q := map[string]any{"bool": map[string]any{
		"filter": []any{map[string]any{"terms": map[string]any{"type": []string{docToken, docSeen}}}},
		"must":   []any{map[string]any{"range": map[string]any{"expires": map[string]any{"lt": now.UTC().Format(time.RFC3339Nano)}}}},
	}}
	return o.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(o.Index)+"/_delete_by_query?conflicts=proceed&ignore_unavailable=true",
		map[string]any{"query": q}, nil)
}
