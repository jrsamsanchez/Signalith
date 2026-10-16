package clustercfg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// RetentionBody is the body of <prefix>_config/retention: the retention
// policies every server enforces, with where values applied from a
// server's signalith.yaml came from, and the confirmation hold.
type RetentionBody struct {
	// Days is retention.days: the default policy's keep_days until one
	// is saved.
	Days     *int                        `json:"days"`
	Default  *retention.Policy           `json:"default"`
	Policies map[string]retention.Policy `json:"policies"`
	Guard    *retention.Guard            `json:"guard"`
	// Confirm, while set, holds every step but the disk guard's until an
	// admin confirms the policies (their import found that the servers'
	// own policies differed).
	Confirm *Confirm `json:"confirm"`
	// StoreID is the shared archive folder's id, once one is made.
	StoreID string `json:"store_id"`
	// From says, by "days", "default", "guard" or "policies.<category>",
	// where values not set on the page came from.
	From         map[string]From `json:"from,omitempty"`
	shared.Extra `json:"-"`
}

// Confirm is why the retention policies wait to be confirmed: the
// servers whose own policies differed from the imported ones, by name,
// with their policies' fingerprints.
type Confirm struct {
	Reason  string            `json:"reason"`
	Servers map[string]string `json:"servers,omitempty"`
	At      string            `json:"at"`
}

// Reasons for a hold.
const (
	ConfirmImport = "import"
	ConfirmMerge  = "merge"
)

// saved turns a body into the retention package's settings.
func (b *RetentionBody) saved() retention.Saved {
	s := retention.Saved{Policies: maps.Clone(b.Policies)}
	if b.Days != nil {
		d := *b.Days
		s.Days = &d
	}
	if b.Default != nil {
		p := *b.Default
		s.Default = &p
	}
	if b.Guard != nil {
		g := *b.Guard
		s.Guard = &g
	}
	if len(b.From) > 0 {
		s.From = map[string]retention.Provenance{}
		for k, f := range b.From {
			s.From[k] = retention.Provenance{Source: f.Source, Node: f.Node, At: f.At}
		}
	}
	return s
}

// set writes the retention package's settings into the body.
func (b *RetentionBody) set(s retention.Saved) {
	b.Days, b.Default, b.Guard, b.Policies = s.Days, s.Default, s.Guard, s.Policies
	if len(b.Policies) == 0 {
		b.Policies = nil
	}
	b.From = nil
	for k, p := range s.From {
		if b.From == nil {
			b.From = map[string]From{}
		}
		b.From[k] = From{Source: p.Source, Node: p.Node, At: p.At}
	}
}

// HoldText says why policies wait to be confirmed, for the page.
func (c *Confirm) HoldText() string {
	names := slices.Sorted(maps.Keys(c.Servers))
	who := "the other servers"
	if len(names) > 0 {
		who = strings.Join(names, ", ")
	}
	if c.Reason == ConfirmMerge {
		return fmt.Sprintf("A server that joined (%s) had retention policies of its own that differ from the shared ones. "+
			"Until they are confirmed, retention only runs the disk guard: it freezes, archives and deletes nothing else.", who)
	}
	return fmt.Sprintf("When this server's retention policies became the shared ones, %s had different policies of its own. "+
		"Until they are confirmed, retention only runs the disk guard: it freezes, archives and deletes nothing else.", who)
}

// PolicyStore is the shared retention policies, for retention.Manager.
type PolicyStore struct {
	Docs *Docs
	Log  *slog.Logger
}

// writeTimeout bounds a change of the shared policies.
const writeTimeout = 30 * time.Second

// ErrPoliciesUnavailable is shared policies that cannot be read now.
var ErrPoliciesUnavailable = errors.New("the shared retention policies cannot be read from OpenSearch right now, so retention is paused")

// Get implements retention.PolicyStore.
func (p *PolicyStore) Get() (retention.Saved, error) {
	body, ok := p.Docs.Retention().Get()
	if !ok {
		return retention.Saved{}, ErrPoliciesUnavailable
	}
	return body.saved(), nil
}

// Update implements retention.PolicyStore.
func (p *PolicyStore) Update(change func(*retention.Saved)) error {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	_, err := p.Docs.Retention().Mutate(ctx, "", func(b *RetentionBody) error {
		s := b.saved()
		change(&s)
		b.set(s)
		return nil
	})
	return err
}

// ETag implements retention.VersionedStore.
func (p *PolicyStore) ETag() string { return p.Docs.Retention().ETag() }

// UpdateIf implements retention.VersionedStore: a change made since the
// page read the policies gives a *shared.StaleError.
func (p *PolicyStore) UpdateIf(etag string, change func(*retention.Saved)) error {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	doc := p.Docs.Retention()
	if _, ok := doc.Get(); !ok {
		return ErrPoliciesUnavailable
	}
	// The change applies to the revision the page read, as SaveIf checked
	// it, not to this server's copy, which may be older.
	_, err := doc.MutateIf(ctx, "", etag, func(b *RetentionBody) error {
		s := b.saved()
		change(&s)
		b.set(s)
		return nil
	})
	return err
}

// Hold implements retention.Manager.Hold.
func (p *PolicyStore) Hold() (bool, string) {
	body, ok := p.Docs.Retention().Get()
	if !ok || body.Confirm == nil {
		return false, ""
	}
	return true, body.Confirm.HoldText()
}

// Confirm ends the hold, by the user by.
func (p *PolicyStore) Confirm(ctx context.Context, by string) error {
	held := false
	_, err := p.Docs.Retention().Mutate(ctx, by, func(b *RetentionBody) error {
		held = b.Confirm != nil
		if !held {
			return retention.ErrNoHold
		}
		b.Confirm = nil
		return nil
	})
	if err == nil && p.Log != nil {
		p.Log.Info("retention.confirm: the shared retention policies were confirmed, so runs enforce them in full", "audit", true, "by", by)
	}
	return err
}
