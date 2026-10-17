package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// TenantsFile returns the file that lists the tenants of a multi-tenant
// install, in the state folder.
func (c *Config) TenantsFile() string { return tenants.File(c.StateDir()) }

// TenantsDir returns the folder that holds every tenant's folder.
func (c *Config) TenantsDir() string { return filepath.Dir(c.TenantDir("x")) }

// TenantDir returns the folder that keeps tenant id's files.
func (c *Config) TenantDir(id string) string { return tenants.Dir(c.StateDir(), id) }

// What a tenant's config takes from the configuration in use. Each of
// Config's sections is one or the other (TestTenantSectionsAreClassified):
//
//   - sharedSections are the server's: how it listens, reaches OpenSearch
//     (but for the index prefix, which is the tenant's), searches, signs
//     people in, talks to an AI model, scans and joins a cluster. A
//     tenant's config shares them with the default tenant's, read only.
//   - tenantSections are the tenant's own: its folders, retention, intel
//     feeds, notifications, response actions, playbooks and ticketing
//     connections, and what it receives events with. ForTenant sets
//     them, and copies what they hold by reference, so no change to one
//     tenant's reaches another's.
var (
	sharedSections = []string{"Server", "OpenSearch", "Search", "Auth", "Assistant", "Vulns", "Cluster"}
	tenantSections = []string{"Retention", "Ingest", "Syslog", "Detections", "Lookups", "Dashboards", "Intel", "M365", "Okta", "Notify", "Response", "Playbooks", "Ticketing"}
)

// ForTenant returns a copy of c for tenant id's data: its own index prefix
// (tenants.Prefix) and its own folders under TenantDir, whatever c names
// for the default tenant's files. What c gives agents and devices to send
// with, the ingest tokens of signalith.yaml and the environment, syslog,
// Microsoft 365 and Okta, stays with the default tenant: a tenant's agents send
// with tokens made in that tenant. So do the intel feeds signalith.yaml
// lists: a tenant adds its own. The default tenant's copy is c itself.
func (c *Config) ForTenant(id string) *Config {
	if id == "" || id == tenants.Default {
		return c
	}
	t := *c
	dir := c.TenantDir(id)
	t.OpenSearch.IndexPrefix = tenants.Prefix(c.OpenSearch.IndexPrefix, id)

	t.Retention = c.Retention
	t.Retention.ArchiveDir = filepath.Join(dir, "archive")
	t.Ingest = Ingest{MaxEventAge: c.Ingest.MaxEventAge, URLQuery: c.Ingest.URLQuery}
	t.envTokens, t.sharedTokenFrom = nil, nil
	t.Syslog = Syslog{}
	t.Detections = c.Detections
	t.Detections.Dir = filepath.Join(dir, "detections")
	t.Lookups = Lookups{Dir: filepath.Join(dir, "lookups")}
	t.Dashboards = c.Dashboards
	t.Dashboards.Dir = filepath.Join(dir, "dashboards")
	t.Intel = Intel{AllowLoopbackFeeds: c.Intel.AllowLoopbackFeeds}
	t.M365 = M365{}
	t.Okta = Okta{}
	t.Notify = Notify{}
	t.Response = Response{ScriptsDir: filepath.Join(dir, "scripts")}
	t.Playbooks = Playbooks{}
	// Its Jira and ServiceNow connections are in its own folder, never
	// the file ticketing.file names for the default tenant.
	t.Ticketing = Ticketing{}
	// Nothing a tenant section holds by reference is the default tenant's.
	tv := reflect.ValueOf(&t).Elem()
	for _, n := range tenantSections {
		f := tv.FieldByName(n)
		f.Set(deepCopy(f))
	}
	return &t
}

// deepCopy returns a copy of v that shares no pointer, slice or map with
// it, through exported fields (Config's sections keep none unexported).
func deepCopy(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		n := reflect.New(v.Type().Elem())
		n.Elem().Set(deepCopy(v.Elem()))
		return n
	case reflect.Struct:
		n := reflect.New(v.Type()).Elem()
		n.Set(v)
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				n.Field(i).Set(deepCopy(v.Field(i)))
			}
		}
		return n
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		n := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := range v.Len() {
			n.Index(i).Set(deepCopy(v.Index(i)))
		}
		return n
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		n := reflect.MakeMapWithSize(v.Type(), v.Len())
		for it := v.MapRange(); it.Next(); {
			n.SetMapIndex(it.Key(), deepCopy(it.Value()))
		}
		return n
	}
	return v
}

// tenantFolderProblems refuses folders of the default tenant inside the
// tenants' folder, and, once there are tenants, folders that hold it: the
// detections library, for one, reads the folders inside its own, and must
// never read a tenant's.
func (c *Config) tenantFolderProblems() []string {
	root := filepath.Clean(c.TenantsDir())
	_, err := os.Stat(c.TenantsFile())
	inUse := err == nil
	var p []string
	for _, f := range []struct{ key, dir string }{
		{"lookups.dir", c.LookupsDir()}, {"detections.dir", c.DetectionsDir()}, {"dashboards.dir", c.DashboardsDir()},
		{"retention.archive_dir", c.ArchiveDir()}, {"response.scripts_dir", c.ResponseScriptsDir()},
	} {
		if f.dir == "" {
			continue
		}
		d := filepath.Clean(f.dir)
		switch {
		case samePath(d, root) || within(root, d):
			p = append(p, fmt.Sprintf("%s %q is inside %s, which keeps the tenants' files", f.key, f.dir, root))
		case inUse && within(d, root):
			p = append(p, fmt.Sprintf("%s %q holds %s, which keeps the tenants' files; use a folder of its own", f.key, f.dir, root))
		}
	}
	return p
}

// within reports whether path is inside the folder dir.
func within(dir, path string) bool {
	if runtime.GOOS == "windows" {
		dir, path = strings.ToLower(dir), strings.ToLower(path)
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == "." {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}
