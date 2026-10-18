package api

import (
	"testing"
)

// stepIDs returns the ids of a setup guide reply's steps, and which are
// done.
func stepIDs(t *testing.T, body map[string]any) ([]string, map[string]bool) {
	t.Helper()
	raw, _ := body["steps"].([]any)
	var ids []string
	done := map[string]bool{}
	for _, r := range raw {
		s := r.(map[string]any)
		id := s["id"].(string)
		ids = append(ids, id)
		done[id] = s["done"] == true
	}
	return ids, done
}

func TestSetupGuide(t *testing.T) {
	ts, _ := newUsersServer(t, nil)
	admin := func(method, path, body string) (int, map[string]any, string) {
		return call(t, ts, method, path, body, "admin", adminPass, nil)
	}

	// A new admin is asked, and sees the admin's steps.
	code, body, _ := admin("GET", "/api/me/setup", "")
	if code != 200 || body["ask"] != true || body["state"] != "" {
		t.Fatalf("first GET = %d %v", code, body)
	}
	ids, done := stepIDs(t, body)
	want := []string{"mfa", "data", "team", "security", "ai", "search"}
	if len(ids) != len(want) {
		t.Fatalf("admin steps = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("admin steps = %v, want %v", ids, want)
		}
	}
	if done["team"] || done["search"] {
		t.Errorf("done = %v before anything was done", done)
	}

	// Ask me later: not asked again until tomorrow.
	code, body, _ = admin("PUT", "/api/me/setup", `{"state":"later","skipped":["ai"]}`)
	if code != 200 || body["ask"] != false || body["state"] != "later" || body["until"] == nil {
		t.Fatalf("later = %d %v", code, body)
	}
	if _, body, _ = admin("GET", "/api/me/setup", ""); body["ask"] != false || len(body["skipped"].([]any)) != 1 {
		t.Errorf("after later, GET = %v", body)
	}

	// Unknown states and malformed steps are refused.
	for _, bad := range []string{`{"state":"soon"}`, `{"state":"started","skipped":["<b>"]}`, `not json`} {
		if code, _, _ := admin("PUT", "/api/me/setup", bad); code != 400 {
			t.Errorf("PUT %s = %d, want 400", bad, code)
		}
	}

	// Another user makes the team step done, and has a guide of their own.
	if code, body, _ := admin("POST", "/api/users", `{"username":"vic","role":"viewer","password":"a-long-enough-pass-1"}`); code != 201 {
		t.Fatalf("create viewer = %d %v", code, body)
	}
	if _, body, _ = admin("GET", "/api/me/setup", ""); !func() bool { _, d := stepIDs(t, body); return d["team"] }() {
		t.Errorf("team not done with a second user: %v", body)
	}
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"a-long-enough-pass-1","new_password":"another-long-pass-2"}`,
		"vic", "a-long-enough-pass-1", nil); code != 200 {
		t.Fatalf("viewer's own password = %d %v", code, body)
	}
	viewer := func(method, path, body string) (int, map[string]any, string) {
		return call(t, ts, method, path, body, "vic", "another-long-pass-2", nil)
	}
	code, body, _ = viewer("GET", "/api/me/setup", "")
	if code != 200 || body["ask"] != true || body["state"] != "" {
		t.Fatalf("viewer GET = %d %v", code, body)
	}
	ids, _ = stepIDs(t, body)
	if len(ids) != 3 || ids[0] != "mfa" || ids[1] != "findings" || ids[2] != "search" {
		t.Errorf("viewer steps = %v", ids)
	}
	// Opening a step's page from the guide checks off a step the server
	// cannot check; once every step is settled it is not asked.
	code, body, _ = viewer("PUT", "/api/me/setup", `{"state":"started","opened":["findings","search"],"skipped":["mfa"]}`)
	if _, d := stepIDs(t, body); code != 200 || !d["findings"] || !d["search"] || body["ask"] != false {
		t.Errorf("viewer started = %d %v", code, body)
	}
	if code, body, _ = viewer("PUT", "/api/me/setup", `{"state":"","opened":["findings","search"],"skipped":["mfa"]}`); code != 200 || body["ask"] != false {
		t.Errorf("viewer with every step settled is asked: %d %v", code, body)
	}
	// Don't ask again sticks.
	if code, body, _ = admin("PUT", "/api/me/setup", `{"state":"never"}`); code != 200 || body["ask"] != false || body["state"] != "never" {
		t.Errorf("never = %d %v", code, body)
	}
}
