package datamodel

import "testing"

func TestMalwareModel(t *testing.T) {
	var names []string
	for _, m := range Models {
		names = append(names, m.Name)
	}
	at := func(name string) int {
		for i, n := range names {
			if n == name {
				return i
			}
		}
		return -1
	}
	if c, mw, r := at("Change"), at("Malware"), at("Risk"); mw != c+1 || r <= mw {
		t.Errorf("Malware is not right after Change, before Risk: %v", names)
	}
	m, ok := Get("malware")
	if !ok {
		t.Fatal("no Malware model")
	}
	if IndexName("signalith", m.Name, "2026.10.13") != "signalith-malware-2026.10.13" {
		t.Error("index name")
	}
	seen := map[string]bool{}
	for _, f := range m.Fields {
		if f.Description == "" {
			t.Errorf("field %s has no description", f.Name)
		}
		if seen[f.Name] {
			t.Errorf("field %s twice", f.Name)
		}
		seen[f.Name] = true
		switch f.Type {
		case "string", "number", "ip":
		default:
			t.Errorf("field %s has type %s", f.Name, f.Type)
		}
	}
	for _, want := range []string{"type", "action", "category", "severity", "dest", "dest_ip", "file_sha256", "rule", "rule_id", "exclusion", "signature_age_days", "detection_source"} {
		if !seen[want] {
			t.Errorf("Malware has no %s field", want)
		}
	}
}

func TestEveryFieldHasADescription(t *testing.T) {
	for _, m := range Models {
		if m.Description == "" {
			t.Errorf("model %s has no description", m.Name)
		}
		for _, f := range m.Fields {
			if f.Description == "" {
				t.Errorf("%s.%s has no description", m.Name, f.Name)
			}
		}
	}
}

func TestVulnerabilitiesModel(t *testing.T) {
	var names []string
	for _, m := range Models {
		names = append(names, m.Name)
	}
	at := func(name string) int {
		for i, n := range names {
			if n == name {
				return i
			}
		}
		return -1
	}
	if v, r := at("Vulnerabilities"), at("Risk"); v < 0 || r != v+1 {
		t.Errorf("Vulnerabilities is not right before Risk: %v", names)
	}
	m, ok := Get("vulnerabilities")
	if !ok {
		t.Fatal("no Vulnerabilities model")
	}
	seen := map[string]bool{}
	for _, f := range m.Fields {
		if seen[f.Name] {
			t.Errorf("field %s twice", f.Name)
		}
		seen[f.Name] = true
	}
	for _, want := range []string{"category", "dest", "dest_ip", "dest_port", "cve", "cvss", "severity", "known_exploited"} {
		if !seen[want] {
			t.Errorf("Vulnerabilities has no %s field", want)
		}
	}
}

func TestNetworkModels(t *testing.T) {
	want := map[string][]string{
		"Network_Traffic":     {"action", "src", "src_port", "dest", "dest_host", "dest_port", "transport", "user", "process_name", "bytes", "app", "bytes_in", "bytes_out", "packets_in", "packets_out", "duration", "direction", "conn_state", "session_id", "community_id", "vlan"},
		"Network_Resolution":  {"query", "answer", "reply_code", "process_name", "process_path", "dest", "src", "src_port", "dest_ip", "dest_port", "transport", "query_type", "reply_code_id", "ttl", "session_id", "community_id"},
		"Intrusion_Detection": {"action", "ids_type", "category", "severity", "severity_id", "src", "src_port", "dest", "dest_port", "dest_host", "transport", "app", "url", "direction", "mitre", "reason", "session_id", "community_id"},
		"Web":                 {"http_method", "url", "url_domain", "uri_path", "uri_query", "status", "http_user_agent", "http_referrer", "http_content_type", "bytes_in", "bytes_out", "src", "src_port", "dest", "dest_port", "dest_host", "user", "direction", "session_id", "community_id"},
		"Certificates":        {"ssl_version", "ssl_cipher", "ssl_server_name", "ssl_subject", "ssl_subject_common_name", "ssl_issuer", "ssl_issuer_common_name", "ssl_serial", "ssl_hash", "ssl_start_time", "ssl_end_time", "ssl_validation_status", "ssl_self_signed", "ja3", "ja3s", "ja4", "src", "src_port", "dest", "dest_port", "dest_host", "direction", "session_id", "community_id"},
		"File_Transfers":      {"file_name", "file_size", "file_hash", "file_md5", "file_sha1", "file_sha256", "mime_type", "app", "src", "dest", "url", "direction", "session_id", "community_id"},
	}
	for name, fields := range want {
		m, ok := Get(name)
		if !ok {
			t.Errorf("no %s model", name)
			continue
		}
		seen := map[string]bool{}
		for _, f := range m.Fields {
			if seen[f.Name] {
				t.Errorf("%s.%s twice", name, f.Name)
			}
			seen[f.Name] = true
		}
		for _, f := range fields {
			if !seen[f] {
				t.Errorf("%s has no %s field", name, f)
			}
		}
	}
	// The new models come right after Network_Resolution, in this order.
	var names []string
	for _, m := range Models {
		names = append(names, m.Name)
	}
	for i, n := range names {
		if n == "Network_Resolution" {
			if i+4 >= len(names) || names[i+1] != "Intrusion_Detection" || names[i+2] != "Web" || names[i+3] != "Certificates" || names[i+4] != "File_Transfers" {
				t.Errorf("models after Network_Resolution: %v", names)
			}
		}
	}
}

// TestFieldTypesAgree checks that a field name has one type in every
// model: each name is mapped once in the index template, so a number in
// one model and text in another would turn one of them away. ip and
// string are both mapped as keywords.
func TestFieldTypesAgree(t *testing.T) {
	kind := func(typ string) string {
		if typ == "ip" {
			return "string"
		}
		return typ
	}
	first := map[string]string{}
	where := map[string]string{}
	check := func(model string, fs []Field) {
		for _, f := range fs {
			k := kind(f.Type)
			if prev, ok := first[f.Name]; ok && prev != k {
				t.Errorf("%s.%s is %s, but %s has it as %s", model, f.Name, f.Type, where[f.Name], prev)
				continue
			}
			first[f.Name] = k
			where[f.Name] = model
		}
	}
	check("Common", Common)
	for _, m := range Models {
		check(m.Name, m.Fields)
	}
}
