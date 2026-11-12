// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// newIntakeServer is newSensorServer that also hands back what was
// stored, and with this computer as a trusted proxy that names clients in
// X-Forwarded-For.
func newIntakeServer(t *testing.T) (*httptest.Server, *Server, *fakeOS) {
	t.Helper()
	fake := ostest.New(t)
	var srv *Server
	ts, fos := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
		s.Config.Ingest.HEC = true
		s.Tokens = &agenttokens.Registry{Client: store.New(store.Config{URL: fake.URL}), Prefix: "it", Log: s.Log}
		s.Agents = &agentinv.Inventory{}
		s.Install = &ClusterInstall{}
		s.Users = users.NewMemory()
	})
	if err := srv.Tokens.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return ts, srv, fos
}

const intakeOTLP = `{"resourceLogs":[{"resource":{"attributes":[{"key":"host.name","value":{"stringValue":"app-1"}}]},"scopeLogs":[{"logRecords":[{"body":{"stringValue":"hi"}}]}]}]}`

// A token is taken only on the routes its kind of agent sends to; one
// with no purpose everywhere (ING-03).
func TestAgentTokenPurposePerIntake(t *testing.T) {
	ts, s, fos := newIntakeServer(t)
	isJSON := map[string]string{"Content-Type": "application/json"}
	for _, c := range []struct {
		purpose          string
		ingest, otlp     int
		hec              int
		refusedByPurpose bool
	}{
		{"linux", 200, 403, 200, true},
		{"windows", 200, 403, 200, true},
		{"sensor", 200, 403, 200, true},
		{"agent", 200, 403, 200, true},
		{"otel", 403, 200, 200, true},
		{"osquery", 403, 403, 200, true},
		{"", 200, 200, 200, false},
	} {
		_, secret := makeToken(t, ts, "Purpose "+c.purpose, c.purpose)
		n := len(fos.bulk)
		code, body := agentSend(t, ts.URL, "/api/ingest", secret, `[{"msg":"x"}]`, nil)
		if code != c.ingest || (code == 403 && !strings.Contains(body, "purpose_mismatch")) {
			t.Errorf("%q on /api/ingest: %d %s", c.purpose, code, body)
		}
		if code, body := agentSend(t, ts.URL, "/api/otlp/v1/logs", secret, intakeOTLP, isJSON); code != c.otlp {
			t.Errorf("%q on OTLP: %d %s", c.purpose, code, body)
		}
		if code, body := agentSend(t, ts.URL, "/services/collector/event", secret, `{"event":"x"}`, nil); code != c.hec {
			t.Errorf("%q on HEC: %d %s", c.purpose, code, body)
		}
		stored := 0
		for _, ok := range []int{c.ingest, c.otlp, c.hec} {
			if ok == 200 {
				stored++
			}
		}
		if got := len(fos.bulk) - n; got != stored {
			t.Errorf("%q: %d events stored, want %d", c.purpose, got, stored)
		}
	}
	refused := s.Pipeline.RefusedSenders(time.Now().Add(-time.Hour))
	if len(refused) == 0 || refused[0].Reason != ingest.RefusedPurpose {
		t.Errorf("refused senders: %+v", refused)
	}
}

// Events sent with a computer's own key name the computer, and events in
// another computer's name are marked; so are events in an enrolled
// computer's name sent with a token (ING-03).
func TestHostKeyEventsNameTheComputer(t *testing.T) {
	ts, _, fos := newIntakeServer(t)
	_, line := makeToken(t, ts, "Web servers", "agent")
	code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "web-01", "{}", nil)
	var e agentproto.Enrolled
	if code != 200 || json.Unmarshal([]byte(body), &e) != nil {
		t.Fatalf("enroll: %d %s", code, body)
	}
	for _, c := range []struct{ token, host, want string }{
		{e.Key, "web-01", "Web servers @ web-01"},
		{e.Key, "dc-01", "Web servers @ web-01" + ingest.HostMismatch},
		{line, "web-01", "Web servers" + ingest.HostMismatch},
		{line, "web-02", "Web servers"},
	} {
		if code, body := agentSend(t, ts.URL, "/api/ingest", c.token, `[{"msg":"x","host":"`+c.host+`"}]`, nil); code != 200 {
			t.Fatalf("send for %s: %d %s", c.host, code, body)
		}
		if got := fos.bulk[len(fos.bulk)-1].Doc[ingest.TokenField]; got != c.want {
			t.Errorf("host %s: %s = %v, want %q", c.host, ingest.TokenField, got, c.want)
		}
	}
}

// Behind a trusted proxy, OTLP and HEC events, the token's last use and
// the Agents row record the client the proxy names, not the proxy
// (ING-04).
func TestOTLPRecordsClientBehindProxy(t *testing.T) {
	ts, s, fos := newIntakeServer(t)
	id, secret := makeToken(t, ts, "Collectors", "otel")
	h := map[string]string{"Content-Type": "application/json", "X-Forwarded-For": "198.51.100.7"}
	// What the sender claims about its origin is dropped.
	forged := strings.Replace(intakeOTLP, `"attributes":[`, `"attributes":[{"key":"signalith.token","value":{"stringValue":"forged"}},`, 1)
	if code, body := agentSend(t, ts.URL, "/api/otlp/v1/logs", secret, forged, h); code != 200 {
		t.Fatalf("otlp: %d %s", code, body)
	}
	doc := fos.bulk[len(fos.bulk)-1].Doc
	if doc[ingest.SenderField] != "198.51.100.7" || doc[ingest.TokenField] != "Collectors" || doc[ingest.IntakeField] != "otlp" ||
		doc[ingest.TokenPurposeField] != "otel" || doc["signalith.token"] != nil {
		t.Errorf("OTLP doc = %v", doc)
	}
	if code, body := agentSend(t, ts.URL, "/services/collector/event", secret, `{"event":"x"}`, map[string]string{"X-Forwarded-For": "198.51.100.8"}); code != 200 {
		t.Fatalf("hec: %d %s", code, body)
	}
	if got := fos.bulk[len(fos.bulk)-1].Doc[ingest.SenderField]; got != "198.51.100.8" {
		t.Errorf("HEC sender = %v", got)
	}
	list, _, _ := s.agents().List(t.Context())
	found := false
	for _, a := range list {
		if a.TokenID == id && a.Name == "app-1" {
			found = true
			if !slices.Contains(a.Addresses, "198.51.100.7") || a.Local {
				t.Errorf("agents row: %+v", a)
			}
		}
	}
	if !found {
		t.Errorf("no row for app-1: %+v", list)
	}
}
