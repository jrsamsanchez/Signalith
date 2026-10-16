package clusterauth

import (
	"context"
	"errors"
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

func (t tenantList) List() ([]tenants.Tenant, bool) {
	doc := t.doc()
	if doc == nil {
		return nil, false
	}
	b, ok := doc.Get()
	if !ok || !b.Kept {
		return nil, false
	}
	return b.Tenants, true
}

func (t tenantList) Mutate(ctx context.Context, by string, local []tenants.Tenant, fn func([]tenants.Tenant) ([]tenants.Tenant, error)) error {
	doc := t.doc()
	if doc == nil || !t.d.TenantsOn() {
		return tenants.ErrNotShared
	}
	_, err := doc.Mutate(ctx, by, func(b *TenantsBody) error {
		if !b.Kept {
			b.Tenants = slices.Clone(local)
		}
		list, err := fn(slices.Clone(b.Tenants))
		if err != nil {
			return err
		}
		if list == nil {
			return errors.New("no list of tenants")
		}
		b.Tenants, b.Kept = list, true
		return nil
	})
	return err
}
