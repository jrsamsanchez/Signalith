package respond

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestBodyEscapesValues(t *testing.T) {
	tmpl := `{"ip": "{{.ip}}", "reason": "{{ .reason }}", "case": "{{.case_id}}"}`
	nasty := `x", "admin": true, "y": "{{.ip}}` + "\n</script>\\"
	v := Values{"ip": "203.0.113.7", "reason": nasty, "case_id": "{{.reason}}"}
	out := expandBody(tmpl, BodyJSON, v)
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("body %s is not JSON: %v", out, err)
	}
	if len(got) != 3 || got["reason"] != nasty || got["ip"] != "203.0.113.7" || got["case"] != "{{.reason}}" {
		t.Errorf("body = %v", got)
	}
	if strings.Contains(out, "</script>") {
		t.Errorf("HTML is not escaped: %s", out)
	}
	// A form body query-escapes.
	if f := expandBody("ip={{.ip}}&note={{.reason}}", BodyForm, Values{"ip": "1.2.3.4", "reason": "a&b=c"}); f != "ip=1.2.3.4&note=a%26b%3Dc" {
		t.Errorf("form = %s", f)
	}
}

func TestURLEscapesValues(t *testing.T) {
	tmpl := "https://fw.example.lan/api/alias/{{.user}}/add?ip={{.ip}}&r={{.reason}}"
	v := Values{"user": "../../admin?x=1#y", "ip": "1.2.3.4&evil=1", "reason": "a b/c"}
	out := expandURL(tmpl, v)
	u, err := url.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "fw.example.lan" || u.Query().Get("ip") != "1.2.3.4&evil=1" || u.Query().Get("evil") != "" || u.Query().Get("r") != "a b/c" {
		t.Errorf("url = %s (%v)", out, u.Query())
	}
	if u.EscapedPath() != "/api/alias/..%2F..%2Fadmin%3Fx=1%23y/add" || u.Fragment != "" {
		t.Errorf("path = %s fragment %q", u.EscapedPath(), u.Fragment)
	}
}

func TestCheckTemplates(t *testing.T) {
	for _, bad := range []string{
		"https://{{.domain}}/api",            // the host
		"https://fw.example.lan{{.ip}}/api",  // still the authority
		"https://fw.example.lan:{{.ip}}/api", // the port
		"https://fw/api/{{.password}}",       // unknown placeholder
		"https://fw/api/{{ printf \"x\" }}",  // template code
		"https://fw/api/{{.ip}",              // half a placeholder
		"ftp://fw/api/{{.ip}}",               // scheme
		"https://user:pw@fw/api/{{.ip}}",     // credentials
		"fw.example.lan/{{.ip}}",             // no scheme
	} {
		if err := checkURLTemplate(bad); err == nil {
			t.Errorf("checkURLTemplate(%q) = nil", bad)
		}
	}
	for _, good := range []string{"https://fw.example.lan/api/firewall/alias_util/add/blocked", "http://10.0.0.1:8080/x/{{.ip}}?r={{.reason}}"} {
		if err := checkURLTemplate(good); err != nil {
			t.Errorf("checkURLTemplate(%q) = %v", good, err)
		}
	}
	c := Connector{Name: "x", Kind: KindHTTP, Target: TargetIP, URL: "https://fw/api", Body: `{"ip": {{.ip}}}`}
	c.Normalize()
	if !hasProblem(c.Problems(), "body") {
		t.Errorf("a placeholder outside quotes in JSON is accepted: %v", c.Problems())
	}
	c.Body = `{"ip": "{{.ip}}"}`
	if p := c.Problems(); len(p) != 0 {
		t.Errorf("problems %v", p)
	}
	c.Body = `{"ip": "1.2.3.4"}`
	if !hasProblem(c.Problems(), "url") {
		t.Error("an action that never sends its target is accepted")
	}
}

func hasProblem(list []Problem, field string) bool {
	for _, p := range list {
		if p.Field == field {
			return true
		}
	}
	return false
}
