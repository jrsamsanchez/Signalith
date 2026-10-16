package config

import (
	"path/filepath"
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
