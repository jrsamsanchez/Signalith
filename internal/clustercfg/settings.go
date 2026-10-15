package clustercfg

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// The settings of the Settings page that every server shares
// (config.SharedKeys) are kept in one document, settings: one value per
// setting, each with its own revision, so two admins who change different
// settings never conflict and two who change the same one do. A password
// or key is sealed with the cluster key for its setting and the address
// it is sent to (config.SharedField). The shared agent tokens of older
// setups (ingest.tokens) are one list, each token tagged with the server
// and the source (signalith.yaml or the environment) that brought it, so
// every server accepts every one. A server's own settings are kept in its
// nodecfg document, which any server reads and changes, with the shared
// values it could not use. Layer turns both into the config package's
// Shared layer, and Save writes an edit checked with
// config.CheckEditShared back.

// The settings document's id and kind.
const (
	SettingsID   = "settings"
	SettingsKind = "settings"
)

// SettingsBody is the body of the settings document.
type SettingsBody struct {
	// Values holds the shared settings by key, but ingest.tokens.
	Values map[string]SettingValue `json:"values"`
	// IngestTokens are the shared agent tokens of older setups.
	IngestTokens []IngestToken `json:"ingest_tokens,omitempty"`
	// Reset holds, by key, the last change of each setting taken back to
	// its default, whose entry left Values: its revision goes on counting
	// from there (see shared.ResetMark).
	Reset        map[string]shared.ResetMark `json:"reset,omitempty"`
	shared.Extra `json:"-"`
}

// Rev is the revision of setting key: of its value, or of the change that
// took it back to its default; 0 for one never changed.
func (b *SettingsBody) Rev(key string) int64 {
	if v, ok := b.Values[key]; ok {
		return v.Rev
	}
	return b.Reset[key].Rev
}

// changedFrom says who changed setting key last: its value, or its reset.
func (b *SettingsBody) changedFrom(key string) shared.From {
	if v, ok := b.Values[key]; ok {
		return v.From
	}
	return b.Reset[key].From
}

// set sets setting key to v, at the revision after Rev, and returns it.
func (b *SettingsBody) set(key string, v SettingValue) int64 {
	v.Rev, v.Extra = b.Rev(key)+1, b.Values[key].Extra
	if b.Values == nil {
		b.Values = map[string]SettingValue{}
	}
	b.Values[key] = v
	delete(b.Reset, key)
	return v.Rev
}

// ResetValue takes setting key back to its default, as from says,
// keeping its revision counting, and returns the new revision; 0 when it
// was at its default already.
func (b *SettingsBody) ResetValue(key string, from shared.From) int64 {
	if _, ok := b.Values[key]; !ok {
		return 0
	}
	rev := b.Rev(key) + 1
	delete(b.Values, key)
	if b.Reset == nil {
		b.Reset = map[string]shared.ResetMark{}
	}
	b.Reset[key] = shared.ResetMark{Rev: rev, From: from, Extra: b.Reset[key].Extra}
	return rev
}

// SettingValue is the value of one shared setting.
type SettingValue struct {
	// Value is the value as JSON. A password or key is in Secret instead,
	// sealed with the cluster key (config.SharedField), with SentTo, the
	// only address it is sent to.
	Value  json.RawMessage `json:"value,omitempty"`
	Secret string          `json:"secret,omitempty"`
	SentTo string          `json:"sent_to,omitempty"`
	// Rev counts the changes to this setting: a page that saves a change
	// names the revision it read, and is refused when it moved on.
	Rev          int64       `json:"rev"`
	From         shared.From `json:"from"`
	shared.Extra `json:"-"`
}

// MarshalJSON writes the value with the fields this version does not
// know.
func (v SettingValue) MarshalJSON() ([]byte, error) {
	type plain SettingValue
	return shared.MarshalExtra(plain(v), v.Extra)
}

// UnmarshalJSON reads the value, keeping the fields this version does
// not know.
func (v *SettingValue) UnmarshalJSON(data []byte) error {
	type plain SettingValue
	var p plain
	extra, err := shared.UnmarshalExtra(data, &p)
	*v = SettingValue(p)
	v.Extra = extra
	return err
}

// IngestToken is one shared agent token of an older setup.
type IngestToken struct {
	// Secret is the token, sealed with the cluster key for
	// config.SharedField("ingest.tokens", "").
	Secret string `json:"secret"`
	// Node is the node id of the server whose signalith.yaml (Source
	// yaml) or environment (env) has it, and Name its name then.
	Node         string    `json:"node"`
	Name         string    `json:"name,omitempty"`
	Source       string    `json:"source"`
	At           time.Time `json:"at,omitzero"`
	shared.Extra `json:"-"`
}

// from says where the token came from, for Add data: "signalith.yaml on
// siem-b" or "the environment of siem-b".
func (t IngestToken) from() string {
	server := cmp.Or(t.Name, t.Node)
	if t.Source == FromEnv {
		return "the environment of " + server
	}
	return "signalith.yaml on " + server
}

// MarshalJSON writes the token with the fields this version does not
// know.
func (t IngestToken) MarshalJSON() ([]byte, error) {
	type plain IngestToken
	return shared.MarshalExtra(plain(t), t.Extra)
}

// UnmarshalJSON reads the token, keeping the fields this version does
// not know.
func (t *IngestToken) UnmarshalJSON(data []byte) error {
	type plain IngestToken
	var p plain
	extra, err := shared.UnmarshalExtra(data, &p)
	*t = IngestToken(p)
	t.Extra = extra
	return err
}

// defaults is the configuration with every setting at its default, for
// the types of the settings' values.
var defaults = sync.OnceValue(config.Default)

// valueOf reads a setting's value from JSON as a value of its type, or as
// what JSON says when it is not one (the config package then warns of
// it).
func valueOf(key string, raw json.RawMessage) any {
	if v := defaults().Value(key); v != nil {
		nv := reflect.New(reflect.TypeOf(v))
		if json.Unmarshal(raw, nv.Interface()) == nil {
			return nv.Elem().Interface()
		}
	}
	var v any
	if json.Unmarshal(raw, &v) == nil {
		return v
	}
	return string(raw)
}

// pageEntryOf is one of a server's own settings in its nodecfg as the
// config package holds it. A server's own settings have no passwords or
// keys, so Secret is not read.
func pageEntryOf(key string, pv shared.PageValue) *config.PageEntry {
	e := &config.PageEntry{SentTo: pv.SentTo, ChangedBy: pv.From.By, ChangedAt: pv.From.At,
		Refused: pv.Refused, RefusedAt: pv.RefusedAt, CheckedAt: pv.CheckedAt}
	if err := e.Value.Encode(valueOf(key, pv.Value)); err != nil {
		_ = e.Value.Encode(string(pv.Value))
	}
	return e
}

// pageValueOf is the reverse of pageEntryOf, the value changed on node.
func pageValueOf(key string, e *config.PageEntry, node string) (shared.PageValue, error) {
	if e.Secret != nil {
		return shared.PageValue{}, fmt.Errorf("%s: a server's own settings have no passwords or keys", key)
	}
	var v any = new(any)
	if d := defaults().Value(key); d != nil {
		v = reflect.New(reflect.TypeOf(d)).Interface()
	}
	if err := e.Value.Decode(v); err != nil {
		return shared.PageValue{}, fmt.Errorf("%s: %w", key, err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return shared.PageValue{}, err
	}
	return shared.PageValue{Value: raw, SentTo: e.SentTo, From: shared.From{Source: FromPage, Node: node, By: e.ChangedBy, At: e.ChangedAt.UTC()},
		Refused: e.Refused, RefusedAt: e.RefusedAt, CheckedAt: e.CheckedAt}, nil
}

func sharedValueOf(v SettingValue) config.SharedValue {
	return config.SharedValue{Value: v.Value, Secret: v.Secret, SentTo: v.SentTo, Rev: v.Rev,
		From: config.Source{Kind: v.From.Source, Node: v.From.Node, By: v.From.By, At: v.From.At}}
}

func settingValueOf(v config.SharedValue) SettingValue {
	return SettingValue{Value: v.Value, Secret: v.Secret, SentTo: v.SentTo, Rev: v.Rev,
		From: shared.From{Source: v.From.Kind, Node: v.From.Node, By: v.From.By, At: v.From.At.UTC()}}
}

// RefusalHash stands for a shared value in a server's refusal of it
// (nodecfg refused): a keyed hash under the cluster key, so a password
// cannot be guessed from it. A new cluster key makes another, and the
// server tries the shared value again.
func RefusalHash(keys *shared.KeySet, key string, v config.SharedValue) string {
	var k *shared.ClusterKey
	if keys != nil {
		k = keys.Active()
	}
	if k == nil {
		return config.SharedHash(key, v)
	}
	h, err := shared.SeenHash(k, "refused:"+key, struct {
		Value  json.RawMessage `json:"value"`
		Secret string          `json:"secret"`
		SentTo string          `json:"sent_to"`
	}{v.Value, v.Secret, v.SentTo})
	if err != nil {
		return config.SharedHash(key, v)
	}
	return h
}

// sealFor seals a shared password or key with the active cluster key.
func sealFor(keys *shared.KeySet, key, plain, sentTo string) (string, error) {
	var k *shared.ClusterKey
	if keys != nil {
		k = keys.Active()
	}
	if k == nil {
		return "", errors.New("this server has no cluster key")
	}
	return k.SecretsKey().Seal(config.SharedField(key, sentTo), plain)
}

// openFor opens a shared password or key with any cluster key there is.
func openFor(keys *shared.KeySet, key, sealed, sentTo string) (string, error) {
	return opener(keys).Open(config.SharedField(key, sentTo), sealed)
}

// Layer is the shared layer of the server self (its name) for the config
// package: the shared settings of the settings document, the cluster's
// name from the cluster document cb, and the server's own settings and
// refusals from its nodecfg nc. cb and nc may be nil.
func Layer(d *Docs, cb *shared.ClusterBody, nc *shared.NodeCfg, self string) *config.Shared {
	keys := d.Hub().Keys()
	sh := &config.Shared{Cluster: map[string]config.SharedValue{}, Server: map[string]*config.PageEntry{},
		Refused: map[string]config.SharedRefusal{}, Self: self}
	if b, ok := d.Settings().Get(); ok {
		for k, v := range b.Values {
			sh.Cluster[k] = sharedValueOf(v)
		}
		for k, m := range b.Reset {
			if sh.Revs == nil {
				sh.Revs = map[string]int64{}
			}
			sh.Revs[k] = m.Rev
		}
		if len(b.IngestTokens) > 0 {
			list := make([]string, 0, len(b.IngestTokens))
			for _, t := range b.IngestTokens {
				list = append(list, t.Secret)
				sh.TokenFrom = append(sh.TokenFrom, t.from())
			}
			raw, _ := json.Marshal(list)
			sh.Cluster["ingest.tokens"] = config.SharedValue{Value: raw}
		}
	}
	if cb != nil && cb.Name != "" {
		raw, _ := json.Marshal(cb.Name)
		sh.Cluster["cluster.name"] = config.SharedValue{Value: raw}
	}
	if nc != nil {
		for k, pv := range nc.Values {
			sh.Server[k] = pageEntryOf(k, pv)
		}
		for k, r := range nc.Refused {
			sh.Refused[k] = config.SharedRefusal{Hash: r.Hash, Kept: r.Kept, Reason: r.Reason, At: r.At}
		}
	}
	sh.Open = func(key, sealed, sentTo string) (string, error) { return openFor(keys, key, sealed, sentTo) }
	sh.Seal = func(key, plain, sentTo string) (string, error) { return sealFor(keys, key, plain, sentTo) }
	sh.Hash = func(key string, v config.SharedValue) string { return RefusalHash(keys, key, v) }
	return sh
}

// NodeCfgOf reads the nodecfg document of server nodeID: this server's
// from its own copy, another's from OpenSearch now.
func NodeCfgOf(ctx context.Context, rt *shared.Runtime, nodeID string) (*shared.NodeCfg, error) {
	if nodeID == rt.Self().NodeID {
		nc, _ := rt.NodeCfg().Get()
		if nc == nil {
			nc = &shared.NodeCfg{}
		}
		return nc, nil
	}
	nc, _, _, err := shared.RemoteNodeCfg(rt.Hub(), nodeID).Read(ctx)
	return nc, err
}

// MutateNodeCfg changes the nodecfg document of server nodeID with fn:
// this server's through its own copy, so it hears of the change, and
// another's with a compare-and-set in OpenSearch.
func MutateNodeCfg(ctx context.Context, rt *shared.Runtime, nodeID, by string, fn func(*shared.NodeCfg) error) error {
	if nodeID == rt.Self().NodeID {
		_, err := rt.NodeCfg().Mutate(ctx, by, fn)
		return err
	}
	return shared.RemoteNodeCfg(rt.Hub(), nodeID).Mutate(ctx, by, fn)
}

// stale is the *shared.StaleError of a setting changed since it was read.
func stale(f shared.From) error {
	e := &shared.StaleError{By: f.By, Node: f.Node}
	if !f.At.IsZero() {
		e.At = f.At.UTC().Format(time.RFC3339)
	}
	return e
}

// Save writes an edit of the shared settings (res.Scope cluster) or of
// one server's own settings (server), checked with config.CheckEditShared
// against base, the layer of server (a node id) as Layer gave it. Each
// setting it changes is refused with a *shared.StaleError when it moved
// on since: since base, or since versions (by key), the revisions the
// page read. Changes to different settings never conflict. A shared
// value server could no longer use, tried again (Retry), is written to
// its nodecfg. It returns the new revision of each setting written, 0 for
// one taken back to its default. settings.yaml (scope bootstrap) is not
// its to write.
func Save(ctx context.Context, rt *shared.Runtime, d *Docs, by, server string, base *config.Shared,
	res *config.SharedEditResult, versions map[string]int64) (map[string]int64, error) {
	if !res.OK() {
		return nil, errors.New("the change has problems; it cannot be saved")
	}
	next := res.Shared
	revs := map[string]int64{}
	switch res.Scope {
	case config.ScopeCluster:
		var values, refusals []string
		name := false
		for _, k := range res.Touched {
			if !sameEntry(base.Cluster, next.Cluster, k) {
				if k == "cluster.name" {
					name = true
				} else {
					values = append(values, k)
				}
			}
			if !sameEntry(base.Refused, next.Refused, k) {
				refusals = append(refusals, k)
			}
		}
		if len(values) > 0 {
			if _, err := d.Settings().Mutate(ctx, by, func(b *SettingsBody) error {
				clear(revs)
				if b.Values == nil {
					b.Values = map[string]SettingValue{}
				}
				for _, k := range values {
					want, listed := versions[k]
					if rev := b.Rev(k); rev != base.Rev(k) || listed && rev != want {
						return stale(b.changedFrom(k))
					}
					nv, ok := next.Cluster[k]
					if !ok {
						revs[k] = b.ResetValue(k, shared.From{Source: FromPage, Node: rt.Self().Name, By: by, At: time.Now().UTC()})
						continue
					}
					revs[k] = b.set(k, settingValueOf(nv))
				}
				return nil
			}); err != nil {
				return nil, err
			}
		}
		if name {
			n := ""
			if v, ok := next.Cluster["cluster.name"]; ok {
				if err := json.Unmarshal(v.Value, &n); err != nil {
					return revs, fmt.Errorf("cluster.name: %w", err)
				}
			}
			if _, err := rt.Cluster().Mutate(ctx, by, func(b *shared.ClusterBody) error {
				b.Name = n
				return nil
			}); err != nil {
				return revs, err
			}
			revs["cluster.name"] = 0
		}
		if len(refusals) > 0 {
			if err := MutateNodeCfg(ctx, rt, server, by, func(n *shared.NodeCfg) error {
				for _, k := range refusals {
					r, ok := next.Refused[k]
					if !ok {
						delete(n.Refused, k)
						continue
					}
					if n.Refused == nil {
						n.Refused = map[string]shared.Refusal{}
					}
					n.Refused[k] = shared.Refusal{Hash: r.Hash, Kept: r.Kept, Reason: r.Reason, At: r.At, Extra: n.Refused[k].Extra}
				}
				return nil
			}); err != nil {
				return revs, err
			}
		}
	case config.ScopeServer:
		var keys []string
		for _, k := range res.Touched {
			if !sameEntry(base.Server, next.Server, k) {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			return revs, nil
		}
		err := MutateNodeCfg(ctx, rt, server, by, func(n *shared.NodeCfg) error {
			clear(revs)
			if n.Values == nil {
				n.Values = map[string]shared.PageValue{}
			}
			for _, k := range keys {
				cur, had := n.Values[k]
				want, listed := versions[k]
				old := base.Server[k]
				if listed && n.ValueRev(k) != want || had != (old != nil) || had && !reflect.DeepEqual(*pageEntryOf(k, cur), *old) {
					return stale(n.ValueFrom(k))
				}
				e := next.Server[k]
				if e == nil {
					revs[k] = n.ResetValue(k, shared.From{Source: FromPage, Node: rt.Self().Name, By: by, At: time.Now().UTC()})
					continue
				}
				pv, err := pageValueOf(k, e, rt.Self().Name)
				if err != nil {
					return err
				}
				if had && cur.From.By == pv.From.By && cur.From.At.Equal(pv.From.At) {
					// Tried again, not changed: it still came from where it did.
					pv.From = cur.From
				}
				revs[k] = n.SetValue(k, pv)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("the settings of scope %q are kept in settings.yaml, not in OpenSearch", res.Scope)
	}
	return revs, nil
}

// sameEntry reports whether a and b hold the same entry for k, or none.
func sameEntry[V any](a, b map[string]V, k string) bool {
	x, inA := a[k]
	y, inB := b[k]
	return inA == inB && reflect.DeepEqual(x, y)
}

// sameSecret reports whether two sealed values hold the same password or
// key for the same address.
func sameSecret(keys *shared.KeySet, key string, a, b SettingValue) bool {
	if a.SentTo != b.SentTo || (a.Secret == "") != (b.Secret == "") {
		return false
	}
	if a.Secret == b.Secret {
		return true
	}
	x, err1 := openFor(keys, key, a.Secret, a.SentTo)
	y, err2 := openFor(keys, key, b.Secret, b.SentTo)
	return err1 == nil && err2 == nil && x == y
}

// sameSetting reports whether two values of a shared setting are the
// same value, wherever they came from.
func sameSetting(keys *shared.KeySet, key string, a, b SettingValue) bool {
	if s, ok := config.Lookup(key); ok && s.Type == config.TypeSecret {
		return sameSecret(keys, key, a, b)
	}
	return bytes.Equal(compact(a.Value), compact(b.Value))
}

// compact is JSON without its spaces, to compare.
func compact(raw json.RawMessage) []byte {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return raw
	}
	return b.Bytes()
}
