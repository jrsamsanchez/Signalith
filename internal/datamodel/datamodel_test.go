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
