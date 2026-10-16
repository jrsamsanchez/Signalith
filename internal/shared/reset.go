package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// When every copy of the cluster key is lost, nobody can check or sign
// the shared settings any more. "signalith cluster reset-key" makes a new
// key and signs every document again with it, after an admin looked at
// them: they cannot be checked, so the admin vouches for them. Values
// sealed with the lost key cannot be opened again; they are emptied, and
// listed for entering again.

// StoredDoc is a document of the config index as it is stored now.
type StoredDoc struct {
	ID       string
	Envelope Envelope
	Version  store.Version
}

// ReadAll returns every signed document of the config index, without the
// watch documents, sorted by id. Documents that are not envelopes are
// returned in bad.
func ReadAll(ctx context.Context, c *store.Client, prefix string) (docs []StoredDoc, bad []string, err error) {
	found, err := c.SearchDocs(ctx, ConfigIndex(prefix), map[string]any{"bool": map[string]any{
		"must_not": []any{map[string]any{"term": map[string]any{"kind": "watch"}}}}})
	if err != nil {
		return nil, nil, err
	}
	for _, d := range found {
		var e Envelope
		if json.Unmarshal(d.Source, &e) != nil || e.ID != d.ID {
			bad = append(bad, d.ID)
			continue
		}
		docs = append(docs, StoredDoc{ID: d.ID, Envelope: e, Version: d.Version})
	}
	slices.SortFunc(docs, func(a, b StoredDoc) int { return strings.Compare(a.ID, b.ID) })
	slices.Sort(bad)
	return docs, bad, nil
}

// Resign signs every document in docs again with k, at revision rev,
// written by by on node, and makes the keyring name k as the only key and
// self (selfID) as the only member: the other servers get the new key
// from an admin (export-key, import-key). It returns the sealed values it
// emptied, as "<doc> <path>". Afterwards every watch document is bumped,
// so running servers read everything again.
func Resign(ctx context.Context, c *store.Client, prefix string, docs []StoredDoc, k *ClusterKey, rev int64, by, node, at, selfID string, self KeyringMember) ([]string, error) {
	index := ConfigIndex(prefix)
	var dropped []string
	var errs []error
	sawKeyring := false
	for _, d := range docs {
		e := d.Envelope
		body := e.Body
		if !e.Deleted && body != "" {
			var out []string
			var err error
			if body, out, err = dropSealed(body, k.ID()); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", d.ID, err))
				continue
			}
			for _, p := range out {
				dropped = append(dropped, d.ID+" "+p)
			}
		}
		if d.ID == KeyringDocID {
			sawKeyring = true
			var kr KeyringBody
			if err := json.Unmarshal([]byte(body), &kr); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", d.ID, err))
				continue
			}
			resetKeyring(&kr, k, at, self, selfID)
			raw, err := encodeBody(&kr)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			body = raw
		}
		e.Body, e.Rev, e.UpdatedAt, e.UpdatedBy, e.WriteID, e.MAC = body, rev, at, By{User: by, Node: node}, "", ""
		if err := Sign(k, d.ID, &e); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := c.PutIf(ctx, index, d.ID, &e, d.Version, false); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.ID, err))
		}
	}
	if !sawKeyring {
		kr := KeyringBody{}
		resetKeyring(&kr, k, at, self, selfID)
		raw, err := encodeBody(&kr)
		if err == nil {
			e := Envelope{Kind: "keyring", ID: KeyringDocID, Format: 1, Rev: rev, UpdatedAt: at, UpdatedBy: By{User: by, Node: node}, Body: raw}
			if err = Sign(k, KeyringDocID, &e); err == nil {
				_, err = c.Create(ctx, index, KeyringDocID, &e, false)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", KeyringDocID, err))
		}
	}
	h := NewHub(Options{NodeName: node})
	h.Use(c, prefix)
	watches, err := c.SearchVersions(ctx, index, map[string]any{"term": map[string]any{"kind": "watch"}})
	if err != nil {
		errs = append(errs, err)
	}
	for _, w := range watches {
		if _, err := h.bump(ctx, w.ID, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return dropped, errors.Join(errs...)
}

// resetKeyring makes kr name k as the only key and self as the only
// member.
func resetKeyring(kr *KeyringBody, k *ClusterKey, at string, self KeyringMember, selfID string) {
	kr.Active = k.ID()
	kr.Keys = []KeyInfo{{KID: k.ID(), CreatedAt: at, CreatedBy: self.Name}}
	kr.Members = map[string]KeyringMember{selfID: self}
	kr.Next = nil
}

// dropSealed empties every sealed value in the JSON text body that is
// not sealed with the key kid, and returns the new text and the paths of
// what it emptied. Numbers are kept as written.
func dropSealed(body, kid string) (string, []string, error) {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", nil, err
	}
	var paths []string
	v = dropIn(v, "", kid, &paths)
	if len(paths) == 0 {
		return body, nil, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", nil, err
	}
	slices.Sort(paths)
	return strings.TrimSuffix(buf.String(), "\n"), paths, nil
}

func dropIn(v any, path, kid string, paths *[]string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = dropIn(x, path+"."+k, kid, paths)
		}
	case []any:
		for i, x := range t {
			t[i] = dropIn(x, fmt.Sprintf("%s[%d]", path, i), kid, paths)
		}
	case string:
		if rest, ok := strings.CutPrefix(t, "enc:v1:"); ok && !strings.HasPrefix(rest, kid+":") {
			*paths = append(*paths, strings.TrimPrefix(path, "."))
			return ""
		}
	}
	return v
}
