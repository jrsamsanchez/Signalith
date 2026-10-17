package clusterauth

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// TenantsID is the shared document that lists the tenants of a
// multi-tenant install, once the cluster keeps tenants (Docs.Tenants):
// which exist and which are turned off are then the same on every
// server, whichever runs them.
const TenantsID = "tenants"

// TenantsBody is the list of tenants. Kept is set by every write, so a
// list emptied on purpose is told apart from none written yet.
type TenantsBody struct {
	Tenants      []tenants.Tenant `json:"tenants"`
	Kept         bool             `json:"kept"`
	shared.Extra `json:"-"`
}

// trackTenants makes the tenants document on h.
func trackTenants(h *shared.Hub) *shared.Doc[TenantsBody] {
	doc := shared.NewDoc[TenantsBody](h, TenantsID, TenantsID, 1)
	doc.Validate = func(b *TenantsBody) error { return tenants.CheckList(b.Tenants) }
	return doc
}

// TenantList returns the list of tenants kept in the shared settings, for
// tenants.Registry.UseShared.
func (d *Docs) TenantList() tenants.Shared { return tenantList{d} }

type tenantList struct{ d *Docs }

func (t tenantList) doc() *shared.Doc[TenantsBody] {
	t.d.mu.Lock()
	defer t.d.mu.Unlock()
	return t.d.tenantDoc
}

func (t tenantList) On() bool { return t.d.TenantsOn() && t.doc() != nil }

func (t tenantList) List() ([]tenants.Tenant, error) {
	doc := t.doc()
	if doc == nil {
		return nil, errNotRead
	}
	for _, p := range t.d.Hub().Problems() {
		if p.ID == TenantsID {
			return nil, fmt.Errorf("the shared list of tenants cannot be used: %s", p.Reason)
		}
	}
	b, ok := doc.Get()
	switch {
	case ok && b.Kept:
		return b.Tenants, nil
	case ok || doc.Missing():
		return nil, nil
	}
	return nil, errNotRead
}

// errNotRead is the shared list of tenants before it was read: no
// tenant is used until it is.
var errNotRead = errors.New("the shared list of tenants is not read yet")

func (t tenantList) Mutate(ctx context.Context, by string, fn func([]tenants.Tenant) ([]tenants.Tenant, error)) error {
	doc := t.doc()
	if doc == nil || !t.d.TenantsOn() {
		return tenants.ErrNotShared
	}
	_, err := doc.Mutate(ctx, by, func(b *TenantsBody) error {
		list, err := fn(slices.Clone(b.Tenants))
		if err != nil {
			return err
		}
		if list == nil {
			list = []tenants.Tenant{}
		}
		b.Tenants, b.Kept = list, true
		return nil
	})
	return err
}

// ImportTenants adds the tenants of local that the shared list does not
// have yet, as the importer of the founder's list does (the shared list
// keeps whether one is turned off). It needs the cluster at
// shared.LevelTenants, which the importer waits for.
func (d *Docs) ImportTenants(ctx context.Context, by string, local []tenants.Tenant) error {
	doc := tenantList{d}.doc()
	if doc == nil {
		return errors.New("the shared settings are not read yet")
	}
	_, err := doc.Mutate(ctx, by, func(b *TenantsBody) error {
		for _, t := range local {
			if !slices.ContainsFunc(b.Tenants, func(s tenants.Tenant) bool { return s.ID == t.ID }) {
				b.Tenants = append(b.Tenants, t)
			}
		}
		if b.Tenants == nil {
			b.Tenants = []tenants.Tenant{}
		}
		b.Kept = true
		return tenants.CheckList(b.Tenants)
	})
	return err
}

// TenantsKept returns the shared list of tenants, and false when none was
// written yet.
func (d *Docs) TenantsKept() ([]tenants.Tenant, bool) {
	doc := tenantList{d}.doc()
	if doc == nil {
		return nil, false
	}
	b, ok := doc.Get()
	return b.Tenants, ok && b.Kept
}
