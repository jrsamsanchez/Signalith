// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Each setting Validate checks names itself and how to fix it.
func TestValidateRefusals(t *testing.T) {
	if err := validConfig(t).Validate(); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	for _, c := range []struct {
		change func(c *Config)
		want   string
	}{
		{func(c *Config) { c.Server.Listen = "nope" }, "server.listen \"nope\" must be host:port"},
		{func(c *Config) { c.Server.Listen = ":70000" }, "server.listen port \"70000\" must be 1-65535"},
		{func(c *Config) { c.Server.MaxConnections = -1 }, "server.max_connections cannot be negative"},
		{func(c *Config) { c.Ingest.MaxConcurrent = 2000 }, "ingest.max_concurrent must be 0-1024"},
		{func(c *Config) { c.Server.SharedAddresses = []string{"not-an-ip"} }, "server.shared_addresses[0]"},
		{func(c *Config) { c.Server.PublicURL = "ftp://siem.example.com" }, "server.public_url"},
		{func(c *Config) { c.Server.NodeURL = "nope://x" }, "server.node_url"},
		{func(c *Config) { c.Cluster.Name = "two\nlines" }, "cluster.name must be at most 100 characters"},
		{func(c *Config) { c.Cluster.OpenSearchURL = "https://user:pw@os:9200" }, "cluster.opensearch_url"},
		{func(c *Config) { c.Cluster.Role = "boss" }, "cluster.role \"boss\""},
		{func(c *Config) { c.Cluster.NodeName = "-bad" }, "cluster.node_name \"-bad\""},
		{func(c *Config) { c.OpenSearch.IndexPrefix = "Bad Prefix" }, "opensearch.index_prefix must be lowercase"},
		{func(c *Config) { c.OpenSearch.Shards = -1 }, "opensearch.shards"},
		{func(c *Config) { c.OpenSearch.RolloverGB = MaxRolloverGB + 1 }, "opensearch.rollover_gb"},
		{func(c *Config) { c.Search.MaxEvents = 0 }, "search.max_events must be between 1 and 100000"},
		{func(c *Config) { c.Search.SummaryDays = -1 }, "search.summary_days"},
		{func(c *Config) { c.Retention.Days = -1 }, "retention.days cannot be negative"},
		{func(c *Config) { c.Retention.Days = 1 << 20 }, "retention.days must be at most"},
		{func(c *Config) { c.Retention.Interval = "1m" }, "retention.interval \"1m\""},
		{func(c *Config) { c.Auth.AdminUser = "" }, "auth.admin_user is required"},
		{func(c *Config) { c.Auth.AdminPasswordHash = "" }, "auth.admin_password_hash is empty"},
		{func(c *Config) { c.Auth.AdminPasswordHash = "not-a-hash" }, "is not a bcrypt hash"},
		{func(c *Config) { c.Auth.SessionTimeout = "1m" }, "auth.session_timeout \"1m\""},
		{func(c *Config) { c.Auth.SessionMaxAge = "100d" }, "auth.session_max_age \"100d\""},
		{func(c *Config) { c.Detections.Dir = "" }, "detections.dir is required"},
		{func(c *Config) { c.Lookups.Dir = "" }, "lookups.dir is required"},
		{func(c *Config) { c.Dashboards.Dir = "" }, "dashboards.dir is required"},
		{func(c *Config) { c.Dashboards.StaleAfter = "1m" }, "dashboards.stale_after \"1m\""},
		{func(c *Config) { c.Assistant.Provider = "anthropic"; c.Assistant.APIKey = "" }, "assistant.api_key is required for anthropic"},
		{func(c *Config) { c.Assistant.Provider = "openai"; c.Assistant.Model = "" }, "assistant.model is required for openai"},
		{func(c *Config) { c.Assistant.Provider = "other" }, "assistant.provider \"other\""},
		{func(c *Config) { c.Assistant.URL = "ftp://x" }, "assistant.url"},
		{func(c *Config) { c.M365.Cloud = "moon" }, "m365.cloud \"moon\""},
		{func(c *Config) { c.M365.TenantID = "not an id" }, "m365.tenant_id"},
		{func(c *Config) { c.Okta.Domain = "not a domain" }, "okta.domain"},
		{func(c *Config) { c.Vulns.NVDURL = "ftp://x" }, "vulns.nvd_url"},
		{func(c *Config) { c.Vulns.KEVURL = "ftp://x" }, "vulns.kev_url"},
		{func(c *Config) { c.Vulns.OSVURL = "ftp://x" }, "vulns.osv_url"},
		{func(c *Config) { c.Detections.MaxFindingsPerRun = 0 }, "detections.max_findings_per_run"},
		{func(c *Config) { c.Detections.SearchBudget = -1 }, "detections.search_budget"},
		{func(c *Config) { c.Detections.CatchUp = "30d" }, "detections.catch_up \"30d\""},
		{func(c *Config) { c.Assistant.RequestTimeout = "1s" }, "assistant.request_timeout \"1s\""},
		{func(c *Config) { c.Detections.ContentUpdates = "hourly" }, "detections.content_updates must be manual or daily"},
		{func(c *Config) { c.Detections.Sync = "push" }, "detections.sync must be inbox or mirror"},
		{func(c *Config) { c.Detections.ContentURL = "http://content.example.com" }, "detections.content_url"},
		{func(c *Config) { c.Ingest.Tokens = []string{"short"} }, "ingest.tokens[0] is shorter than 16 characters"},
		{func(c *Config) { c.Ingest.MaxEventAge = "1m" }, "ingest.max_event_age \"1m\""},
		{func(c *Config) { c.Auth.MFARequired = "sometimes" }, "auth.mfa_required \"sometimes\""},
		{func(c *Config) { c.Ingest.URLQuery = "hide" }, "ingest.url_query \"hide\""},
	} {
		cfg := validConfig(t)
		c.change(cfg)
		err := cfg.Validate()
		var ve *ValidationError
		if !errors.As(err, &ve) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q, got %v", c.want, err)
		}
	}
}

// The break-glass password of a member is read from the state folder, and
// a file that does not hold a hash says how to set it again.
func TestReadAdminLocalHash(t *testing.T) {
	dir := t.TempDir()
	if h, err := ReadAdminLocalHash(dir); err != nil || h != "" {
		t.Errorf("no file: %q, %v", h, err)
	}
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(AdminLocalHashFileIn(dir), []byte(h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadAdminLocalHash(dir); err != nil || got != h {
		t.Errorf("hash: %q, %v", got, err)
	}
	if err := os.WriteFile(AdminLocalHashFileIn(dir), []byte("plain text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAdminLocalHash(dir); err == nil || !strings.Contains(err.Error(), "signalith passwd -local") {
		t.Errorf("not a hash: %v", err)
	}
	// A folder where the file should be cannot be read.
	other := t.TempDir()
	if err := os.Mkdir(AdminLocalHashFileIn(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAdminLocalHash(other); err == nil {
		t.Error("a folder was read as the hash file")
	}
}
