// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/notify"
)

// Turning the audit alerts off, removing their channel or sending it
// elsewhere used to tell the channel that was watching nothing at all.
func TestNotifySaveTellsTheChannelItsAuditAlertsAreGone(t *testing.T) {
	var mu sync.Mutex
	var got []string
	rc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.URL.Path+" "+string(b))
		mu.Unlock()
	}))
	defer rc.Close()
	received := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := got
		got = nil
		return out
	}
	ts, n := newNotifyServer(t, nil)
	n.AuditFrom = func() string { return "server" }
	hook := func(path string) string {
		return `{"id":"hook","name":"SOAR","type":"webhook","url":"` + rc.URL + path + `","allow_loopback":true}`
	}
	on := `"audit_alerts":[{"id":"builtin_signin","enabled":true,"channels":["hook"]},{"id":"settings_change","enabled":true,"channels":["hook"]}]`
	save := func(body string) {
		t.Helper()
		if code, out := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/notify", body); code != 200 {
			t.Fatalf("save: %d %v", code, out)
		}
	}
	// Turning them on, and a save that changes nothing, send nothing.
	save(`{"channels":[` + hook("/watching") + `],"rules":[],` + on + `}`)
	save(`{"channels":[{"id":"hook","name":"SOAR renamed","type":"webhook","allow_loopback":true}],"rules":[]}`)
	if msgs := received(); len(msgs) != 0 {
		t.Fatalf("nothing was taken away, yet the channel got %q", msgs)
	}

	// One alert off: the channel hears which, from whom and from where.
	save(`{"channels":[{"id":"hook","name":"SOAR","type":"webhook","allow_loopback":true}],"rules":[],"audit_alerts":[{"id":"settings_change","enabled":true,"channels":["hook"]}]}`)
	msgs := received()
	if len(msgs) != 1 || !strings.HasPrefix(msgs[0], "/watching ") || !strings.Contains(msgs[0], "Built-in admin signs in") ||
		strings.Contains(msgs[0], "Settings change") || !strings.Contains(msgs[0], `"user":"admin"`) || !strings.Contains(msgs[0], `"source_ip":"127.0.0.1"`) ||
		!strings.Contains(msgs[0], `"urgency":"critical"`) || !strings.Contains(msgs[0], `"server":"siem-a"`) {
		t.Fatalf("after one alert was turned off the channel got %q", msgs)
	}

	// The address changed: the last message goes to the old address, and
	// none to the new one.
	save(`{"channels":[` + hook("/elsewhere") + `],"rules":[]}`)
	msgs = received()
	if len(msgs) != 1 || !strings.HasPrefix(msgs[0], "/watching ") || !strings.Contains(msgs[0], "address was changed") {
		t.Fatalf("after the address was changed: %q", msgs)
	}
	save(`{"channels":[` + hook("/watching") + `],"rules":[]}`)
	received()

	// The channel removed, and its alerts with it.
	save(`{"channels":[],"rules":[]}`)
	msgs = received()
	if len(msgs) != 1 || !strings.HasPrefix(msgs[0], "/watching ") || !strings.Contains(msgs[0], "This channel was removed") {
		t.Fatalf("after the channel was removed: %q", msgs)
	}
	if set, _ := n.Settings.Settings(); len(set.Channels) != 0 {
		t.Errorf("the channel is still there: %+v", set.Channels)
	}
	list, _ := n.Deliveries.Recent(context.Background(), 10)
	if len(list) != 4 || list[0].Kind != notify.KindAudit || list[0].Status != notify.StatusSent {
		t.Errorf("deliveries %+v", list)
	}

	// A channel that cannot be reached is still removed.
	save(`{"channels":[` + hook("/watching") + `],"rules":[],` + on + `}`)
	rc.Close()
	save(`{"channels":[],"rules":[]}`)
	if set, _ := n.Settings.Settings(); len(set.Channels) != 0 {
		t.Errorf("a dead channel could not be removed: %+v", set.Channels)
	}
}

func TestNotifyHealthShowsAuditAlertWarning(t *testing.T) {
	var srv *Server
	ts, n := newNotifyServer(t, func(s *Server) { srv = s })
	warning := ""
	n.AuditFrom = func() string { return "server" }
	n.AuditWarning = func() string { return warning }
	code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/notify", "")
	if code != 200 || body["audit_warning"] != nil {
		t.Fatalf("with no warning: %d %v", code, body["audit_warning"])
	}
	warning = "Audit alerts may be missing: 202 were let go."
	n.clearHealth()
	_, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/notify", "")
	if body["audit_warning"] != warning {
		t.Errorf("the page's warning: %v", body["audit_warning"])
	}
	if w := srv.notifyWarnings(context.Background()); len(w) != 1 || w[0] != warning {
		t.Errorf("the Health page's warnings: %q", w)
	}
}
