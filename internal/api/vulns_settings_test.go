package api

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// An NVD API key saved on the Settings page goes into use for CVE lookups
// at once, and the scanner setup check looks again.
func TestNVDKeyFromSettingsAppliesAtOnce(t *testing.T) {
	nvd := vulnscan.NewNVD("", "")
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) {
		s.Vulns = &Vulns{Scanner: &vulnscan.Scanner{NVD: nvd}, report: &vulnscan.Report{Server: "old"}}
	})
	code, out, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"vulns.nvd_api_key":"nvd-key-123"}}`, "admin", "s3cret-pass", nil)
	if code != 200 || !strings.Contains(strings.Join(anyStrings(out["applied"]), " "), "vulns.nvd_api_key") {
		t.Fatalf("save %d %v", code, out)
	}
	if !nvd.HasKey() || nvd.URL != vulnscan.DefaultNVDURL || nvd.APIKey != "nvd-key-123" {
		t.Errorf("in use: %q %q", nvd.URL, nvd.APIKey)
	}
	if srv.Vulns.report != nil {
		t.Error("the setup check was not cleared")
	}
	// A mirror and the key apply together, as the key is entered for it.
	code, out, _ = call(t, ts, "PUT", "/api/settings",
		`{"values":{"vulns.nvd_url":"https://nvd-mirror.example/rest/json/cves/2.0","vulns.nvd_api_key":"mirror-key"}}`, "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("save mirror %d %v", code, out)
	}
	if nvd.URL != "https://nvd-mirror.example/rest/json/cves/2.0" || nvd.APIKey != "mirror-key" {
		t.Errorf("mirror in use: %q %q", nvd.URL, nvd.APIKey)
	}
}

func anyStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
