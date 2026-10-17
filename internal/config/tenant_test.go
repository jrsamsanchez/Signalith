package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// A tenant's config keeps every file and index of its own apart from the
// default tenant's, and none of the ways agents and devices send to the
// default tenant.
func TestForTenant(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	forgetStateDirs()
	t.Cleanup(forgetStateDirs)
	c := Default()
	c.path = filepath.Join(t.TempDir(), "signalith.yaml")
	c.Ingest.Tokens = []string{"default-tenant-token"}
	c.envTokens = []string{"SIGNALITH_INGEST_TOKEN"}
	c.Syslog.UDP = ":514"
	c.M365.TenantID = "contoso"
	c.Notify.File = "/etc/signalith/notify.yaml"
	if c.ForTenant("default") != c || c.ForTenant("") != c {
		t.Fatal("the default tenant's config is not the config itself")
	}
	a := c.ForTenant("acme")
	if a.OpenSearch.IndexPrefix != "signalith.t.acme" {
		t.Errorf("prefix %q", a.OpenSearch.IndexPrefix)
	}
	dir := c.TenantDir("acme")
	if !strings.HasPrefix(dir, c.StateDir()) {
		t.Errorf("tenant folder %q is outside the state folder %q", dir, c.StateDir())
	}
	for name, p := range map[string]string{
		"lookups": a.LookupsDir(), "detections": a.DetectionsDir(), "dashboards": a.DashboardsDir(),
		"archive": a.ArchiveDir(), "scripts": a.ResponseScriptsDir(), "feeds": a.IntelFeedsFile(),
		"notify": a.NotifyFile(), "response": a.ResponseFile(), "playbooks": a.PlaybooksFile(),
	} {
		if !strings.HasPrefix(p, dir+string(filepath.Separator)) {
			t.Errorf("%s: %q is outside the tenant's folder %q", name, p, dir)
		}
	}
	if len(a.Ingest.Tokens) != 0 || len(a.envTokens) != 0 || a.Syslog.Enabled() || a.M365.TenantID != "" {
		t.Errorf("the tenant has the default tenant's intake: tokens %v, syslog %v, m365 %q", a.Ingest.Tokens, a.Syslog.Enabled(), a.M365.TenantID)
	}
	// The original is untouched.
	if c.OpenSearch.IndexPrefix != "signalith" || len(c.Ingest.Tokens) != 1 || !c.Syslog.Enabled() {
		t.Error("ForTenant changed the default tenant's config")
	}
}

func TestIndexPrefixMustNotLookLikeATenant(t *testing.T) {
	c := Default()
	c.OpenSearch.IndexPrefix = "signalith.t.acme"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), ".t.") {
		t.Errorf("a prefix with .t. was accepted: %v", err)
	}
}

// Every section of Config is either the server's, shared with tenants, or
// each tenant's own; a new section must be put in one of the two lists.
func TestTenantSectionsAreClassified(t *testing.T) {
	known := map[string]bool{}
	for _, n := range append(slices.Clone(sharedSections), tenantSections...) {
		if known[n] {
			t.Errorf("%s is listed twice", n)
		}
		known[n] = true
	}
	ct := reflect.TypeOf(Config{})
	for i := range ct.NumField() {
		f := ct.Field(i)
		if !f.IsExported() {
			continue
		}
		if !known[f.Name] {
			t.Errorf("Config.%s is neither in sharedSections nor in tenantSections (config/tenant.go)", f.Name)
		}
		delete(known, f.Name)
	}
	for n := range known {
		t.Errorf("%s is listed but Config has no such section", n)
	}
}

// A tenant's sections hold nothing by reference that the configuration in
// use holds too, so changing one never changes the other.
func TestTenantSectionsAreCopies(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	forgetStateDirs()
	t.Cleanup(forgetStateDirs)
	c := Default()
	c.path = filepath.Join(t.TempDir(), "signalith.yaml")
	// Fill every pointer, slice and map of the tenant sections.
	cv := reflect.ValueOf(c).Elem()
	for _, n := range tenantSections {
		fill(cv.FieldByName(n))
	}
	a := c.ForTenant("acme")
	av := reflect.ValueOf(a).Elem()
	for _, n := range tenantSections {
		if p := shares(cv.FieldByName(n), av.FieldByName(n), n); p != "" {
			t.Errorf("the tenant's config shares %s with the default tenant's", p)
		}
	}
}

// fill gives every nil pointer, empty slice and nil map in v a value.
func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i))
			}
		}
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fill(v.Elem())
	case reflect.Slice:
		if v.Len() == 0 {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		}
	case reflect.Map:
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
	}
}

// shares returns the path of a pointer, slice or map a and b both hold,
// or "".
func shares(a, b reflect.Value, path string) string {
	switch a.Kind() {
	case reflect.Struct:
		for i := range a.NumField() {
			if a.Type().Field(i).IsExported() {
				if p := shares(a.Field(i), b.Field(i), path+"."+a.Type().Field(i).Name); p != "" {
					return p
				}
			}
		}
	case reflect.Pointer:
		if !a.IsNil() && !b.IsNil() {
			if a.Pointer() == b.Pointer() {
				return path
			}
			return shares(a.Elem(), b.Elem(), path)
		}
	case reflect.Slice, reflect.Map:
		if a.Len() > 0 && b.Len() > 0 && a.Pointer() == b.Pointer() {
			return path
		}
	}
	return ""
}

func TestTenantFoldersStayApart(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	forgetStateDirs()
	t.Cleanup(forgetStateDirs)
	base := func() *Config {
		c := Default()
		c.path = filepath.Join(t.TempDir(), "signalith.yaml")
		c.Lookups.Dir = filepath.Join(state, "lookups")
		c.Detections.Dir = filepath.Join(state, "detections")
		c.Dashboards.Dir = filepath.Join(state, "dashboards")
		return c
	}
	if p := base().tenantFolderProblems(); len(p) != 0 {
		t.Fatalf("usual folders: %v", p)
	}
	c := base()
	c.Detections.Dir = filepath.Join(state, "tenants", "acme", "detections")
	if p := c.tenantFolderProblems(); len(p) != 1 || !strings.Contains(p[0], "detections.dir") {
		t.Errorf("a folder inside the tenants' folder: %v", p)
	}
	c = base()
	c.Dashboards.Dir = state
	if p := c.tenantFolderProblems(); len(p) != 0 {
		t.Errorf("a folder that holds the tenants' folder is refused before there are tenants: %v", p)
	}
	if err := os.WriteFile(c.TenantsFile(), []byte(`{"version":1,"tenants":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := c.tenantFolderProblems(); len(p) != 1 || !strings.Contains(p[0], "dashboards.dir") {
		t.Errorf("a folder that holds the tenants' folder: %v", p)
	}
}
