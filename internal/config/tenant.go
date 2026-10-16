package config

import (
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// TenantsFile returns the file that lists the tenants of a multi-tenant
// install, in the state folder.
func (c *Config) TenantsFile() string { return tenants.File(c.StateDir()) }

// TenantDir returns the folder that keeps tenant id's files.
func (c *Config) TenantDir(id string) string { return tenants.Dir(c.StateDir(), id) }

// ForTenant returns a copy of c for tenant id's data: its own index prefix
// (tenants.Prefix) and its own folders under TenantDir, whatever c names
// for the default tenant's files. What c gives agents and devices to send
// with, the ingest tokens of signalith.yaml and the environment, syslog
// and Microsoft 365, stays with the default tenant: a tenant's agents send
// with tokens made in that tenant. The default tenant's copy is c itself.
func (c *Config) ForTenant(id string) *Config {
	if id == "" || id == tenants.Default {
		return c
	}
	t := *c
	dir := c.TenantDir(id)
	t.OpenSearch.IndexPrefix = tenants.Prefix(c.OpenSearch.IndexPrefix, id)
	t.Lookups.Dir = filepath.Join(dir, "lookups")
	t.Detections.Dir = filepath.Join(dir, "detections")
	t.Dashboards.Dir = filepath.Join(dir, "dashboards")
	t.Retention.ArchiveDir = filepath.Join(dir, "archive")
	t.Response.ScriptsDir = filepath.Join(dir, "scripts")
	t.Intel.FeedsFile = ""
	t.Notify.File = ""
	t.Response.File = ""
	t.Playbooks.File = ""
	// Shared ingest tokens are the default tenant's.
	t.Ingest.Tokens = nil
	t.envTokens, t.sharedTokenFrom = nil, nil
	t.Syslog.UDP, t.Syslog.TCP, t.Syslog.TLS = "", "", ""
	t.M365 = M365{}
	return &t
}
