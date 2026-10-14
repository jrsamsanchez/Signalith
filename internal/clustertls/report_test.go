package clustertls

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/cluster"
)

func beat(id, name string, seen time.Time, st *cluster.TLSStatus) cluster.Heartbeat {
	return cluster.Heartbeat{NodeID: id, Name: name, HeartbeatAt: seen, TLS: st}
}

// While none is published: the candidates, without a server that has
// its own certificate files, and lists of agents capped with whole
// counts.
func TestReportChoice(t *testing.T) {
	now := time.Now()
	a := makeCA(t, "a", now.AddDate(-1, 0, 0))
	b := makeCA(t, "b", now)
	corp := makeCA(t, "corp", now)
	hbs := []cluster.Heartbeat{
		beat("n_b", "siem-b", now, &cluster.TLSStatus{Mode: ModeAuto, CASHA256: b.fp, CACertPEM: string(b.pem), CoversShared: true}),
		beat("n_a", "siem-a", now, &cluster.TLSStatus{Mode: ModeAuto, CASHA256: a.fp, CACertPEM: string(a.pem), CoversShared: true}),
		beat("n_c", "siem-c", now, &cluster.TLSStatus{Mode: ModeFiles, CASHA256: corp.fp, CACertPEM: string(corp.pem), CoversShared: false}),
		beat("n_old", "siem-old", now.Add(-48*time.Hour), &cluster.TLSStatus{Mode: ModeAuto}),
		beat("n_v", "siem-v", now, nil),
	}
	var agents []agentinv.Agent
	for i := range MaxListed + 5 {
		agents = append(agents, agent(fmt.Sprintf("ag%03d", i), []string{agentinv.Pin(b.fp)}, nil, now))
	}
	r := BuildReport(ReportInput{Heartbeats: hbs, Founder: "n_a", Self: "n_a", Agents: agents, Now: now})
	if r.Published || r.CA != nil {
		t.Fatalf("published %+v", r.CA)
	}
	if len(r.Candidates) != 2 {
		t.Fatalf("candidates %+v", r.Candidates)
	}
	c := r.Candidates[0]
	if !c.Preselected || c.CASHA256 != b.fp || c.AgentCount != MaxListed+5 || len(c.Agents) != MaxListed {
		t.Errorf("first: preselected %v fp %s agents %d/%d", c.Preselected, c.CASHA256, len(c.Agents), c.AgentCount)
	}
	if o := r.Candidates[1]; o.BreakCount != MaxListed+5 || len(o.Breaks) != MaxListed || o.CASHA256 != a.fp {
		t.Errorf("second: breaks %d/%d", len(o.Breaks), o.BreakCount)
	}
	names := []string{}
	for _, s := range r.Servers {
		names = append(names, s.Name)
	}
	if !slices.Equal(names, []string{"siem-a", "siem-b", "siem-c", "siem-v"}) {
		t.Errorf("servers %v", names)
	}
	if !r.Servers[0].Self || r.Servers[1].Self {
		t.Error("self")
	}
	sc := r.Servers[2]
	if len(sc.Warnings) != 2 || !strings.Contains(sc.Warnings[0], "shared address") || !strings.Contains(sc.Warnings[1], "own certificate files") {
		t.Errorf("siem-c warnings %q", sc.Warnings)
	}
	if sv := r.Servers[3]; sv.Reported || len(sv.Warnings) != 1 {
		t.Errorf("siem-v %+v", sv)
	}
	// Find: by fingerprint in any form, server name or node id.
	for _, what := range []string{strings.ToLower(strings.ReplaceAll(a.fp, ":", "")), "siem-a", "n_a"} {
		if c, ok := r.Find(what); !ok || c.CASHA256 != a.fp {
			t.Errorf("find %q", what)
		}
	}
	for _, what := range []string{"", "siem-c", corp.fp} {
		if _, ok := r.Find(what); ok {
			t.Errorf("found %q", what)
		}
	}
	// The files server keeps its own whatever is chosen: its root does
	// not hold the importer back.
	if roots := Roots(FromHeartbeats(hbs, "n_a", now), now); len(roots) != 2 {
		t.Errorf("roots %v", roots)
	}
}

// Once one is published: what it is, the retired ones newest first, and
// each server's state.
func TestReportPublished(t *testing.T) {
	now := time.Now()
	a := makeCA(t, "a", now, "siem-a.example.com")
	b := makeCA(t, "b", now)
	c := makeCA(t, "c", now)
	exp := now.AddDate(0, 0, 90)
	body := &Body{CACertPEM: string(a.pem), CASHA256: a.fp, Names: []string{"agents.lan"}, PublishedBy: "siem-a", PublishedAt: now,
		Retired: []RetiredCA{{CACertPEM: string(b.pem), Server: "siem-b", RetiredAt: now.Add(-time.Hour)}, {CACertPEM: string(c.pem), Server: "siem-c", RetiredAt: now}}}
	hbs := []cluster.Heartbeat{
		beat("n_a", "siem-a", now, &cluster.TLSStatus{Mode: ModeAuto, CASHA256: a.fp, Cluster: true, CoversShared: true, Names: []string{"siem-a.example.com"}, LeafExpires: &exp}),
		beat("n_b", "siem-b", now, &cluster.TLSStatus{Mode: ModeAuto, CASHA256: b.fp, CoversShared: true, ChangePending: true,
			AdoptError: "a change of this server's certificate authority is in progress"}),
		beat("n_c", "siem-c", now, &cluster.TLSStatus{Mode: ModeAuto, CASHA256: a.fp, Cluster: true, CoversShared: true, Outside: []string{"siem-c.corp"}}),
	}
	r := BuildReport(ReportInput{Body: body, Heartbeats: hbs, Agents: []agentinv.Agent{agent("x", nil, nil, now)}, Now: now})
	if !r.Published || r.CA == nil || r.CA.CASHA256 != a.fp || r.CA.Subject != "a" || !slices.Equal(r.CA.Names, []string{"agents.lan"}) || len(r.Candidates) != 0 {
		t.Fatalf("report %+v", r)
	}
	if len(r.Retired) != 2 || r.Retired[0].Server != "siem-c" || r.Retired[1].CASHA256 != b.fp {
		t.Errorf("retired %+v", r.Retired)
	}
	if sa := r.Servers[0]; !sa.Cluster || len(sa.Warnings) != 0 || sa.LeafExpires == nil {
		t.Errorf("siem-a %+v", sa)
	}
	if sb := r.Servers[1]; sb.Cluster || sb.Problem == "" || len(sb.Warnings) != 1 || !strings.Contains(sb.Warnings[0], "in progress") {
		t.Errorf("siem-b %+v", sb)
	}
	if sc := r.Servers[2]; len(sc.Warnings) != 1 || !strings.Contains(sc.Warnings[0], "siem-c.corp") {
		t.Errorf("siem-c %+v", sc)
	}
}
