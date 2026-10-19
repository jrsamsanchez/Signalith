package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

func render(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMessageKinds(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	if FindingsLink(" ") != "" || ApprovalsLink("") != "" || ApprovalsLink("https://siem.example.com/") != "https://siem.example.com/#approvals" {
		t.Error("links")
	}
	var mitre []string
	for i := range maxMITRE + 5 {
		mitre = append(mitre, fmt.Sprintf("T%04d", 1000+i))
	}
	f := &findings.Finding{ID: "f1", DetectionID: "brute-force", Severity: "high", Created: now, MITRE: mitre, Sample: "demo"}
	m := NewMessage(f, "https://siem.example.com/#findings")
	if m.Title != "brute-force" || len(m.MITRE) != maxMITRE || !m.Sample {
		t.Fatalf("message = %+v", m)
	}
	if !strings.Contains(m.headline(), "(sample data)") {
		t.Errorf("headline = %q", m.headline())
	}

	slack := Channel{ID: "s", Name: "#soc", Type: TypeSlack}
	slackApp := Channel{ID: "s2", Name: "#soc", Type: TypeSlack, SigningSecret: "sign-123456"}
	teams := Channel{ID: "t", Name: "SOC", Type: TypeTeams}
	app := Channel{ID: "a", Name: "SOC app", Type: TypeTeamsApp, AppID: "00000000-0000-0000-0000-000000000001", AppPassword: "pw-123456", ApproveInChat: true}

	sum := summaryMessage(7, "https://siem.example.com/#findings", now)
	if sum.headline() != "And 7 more new findings" || len(sum.facts()) != 1 || sum.facts()[0].Value != "7" {
		t.Errorf("summary = %q %v", sum.headline(), sum.facts())
	}
	if txt := sum.text("#soc"); !strings.Contains(txt, "too many to send one message each") {
		t.Errorf("summary text = %q", txt)
	}
	if wb := sum.webhookBody(now); wb.Summary == nil || wb.Summary.Count != 7 {
		t.Errorf("summary webhook = %+v", wb)
	}
	for _, body := range []string{render(t, sum.slackBody(slack)), render(t, sum.teamsBody(teams))} {
		if !strings.Contains(body, "too many to send one message each") {
			t.Errorf("summary body = %s", body)
		}
	}

	ap := ApprovalMessage(f, "Playbook X waits for approval to: block 203.0.113.7.", "https://siem.example.com/#approvals", "run-1", 2)
	if ap.Kind != KindApproval || ap.RunID != "run-1" || ap.Step != 2 {
		t.Fatalf("approval = %+v", ap)
	}
	if txt := ap.text("#soc"); !strings.Contains(txt, "Approve or reject: https://siem.example.com/#approvals") || !strings.Contains(txt, "within 24 hours") {
		t.Errorf("approval text = %q", txt)
	}
	if wb := ap.webhookBody(now); wb.Approval == nil || wb.Approval.Link != ap.Link {
		t.Errorf("approval webhook = %+v", wb)
	}
	if hint := ap.approvalHint(slackApp); !strings.HasPrefix(hint, "Reject it here") {
		t.Errorf("slack app hint = %q", hint)
	}
	card := render(t, ap.teamsBody(app))
	for _, want := range []string{`"style":"positive"`, `"style":"destructive"`, "Approve or reject it here", "Action.OpenUrl"} {
		if !strings.Contains(card, want) {
			t.Errorf("approval card lacks %s: %s", want, card)
		}
	}

	tm := TestMessage("", now)
	for _, c := range []Channel{slackApp, app} {
		var body string
		if c.Type == TypeSlack {
			body = render(t, tm.slackBody(c))
		} else {
			body = render(t, tm.teamsCard(c))
		}
		if !strings.Contains(body, "carry buttons to acknowledge findings") {
			t.Errorf("%s test body = %s", c.Type, body)
		}
	}
	if body := render(t, tm.teamsCard(teams)); strings.Contains(body, "carry buttons") || strings.Contains(body, "actions") {
		t.Errorf("plain Teams test body = %s", body)
	}

	// No MITRE techniques: an empty list, not null, for webhooks.
	plain := NewMessage(&findings.Finding{ID: "f2", Title: "Login", Created: now}, "")
	if wb := render(t, plain.webhookBody(now)); !strings.Contains(wb, `"mitre":[]`) {
		t.Errorf("webhook = %s", wb)
	}
	if got := cut("abcdef", 4); got != "abc…" {
		t.Errorf("cut = %q", got)
	}
}

func TestRiskScoreAndRuleSummary(t *testing.T) {
	for v, want := range map[any]float64{float32(2.5): 2.5, int64(7): 7, " 12.5 ": 12.5, 3: 3, 4.5: 4.5} {
		f := &findings.Finding{Result: map[string]any{"risk_score": v}}
		if got, ok := RiskScore(f); !ok || got != want {
			t.Errorf("RiskScore(%T %v) = %v %v", v, v, got, ok)
		}
	}
	for _, v := range []any{"high", true, nil} {
		if _, ok := RiskScore(&findings.Finding{Result: map[string]any{"risk_score": v}}); ok {
			t.Errorf("RiskScore(%v) read", v)
		}
	}
	if _, ok := RiskScore(nil); ok {
		t.Error("nil finding scored")
	}
	if TypeLabel("pager") != "pager" || joinAnd(nil) != "" {
		t.Error("labels")
	}
	r := Rule{Detections: []string{"a", "b"}}
	if got := r.Summary(Settings{}); !strings.Contains(got, " from a and b ") {
		t.Errorf("summary = %q", got)
	}
	r = Rule{MinUrgency: "odd", Detections: []string{"a", "b", "c"}}
	if got := r.Summary(Settings{}); !strings.HasPrefix(got, "Findings from a, b and c") {
		t.Errorf("odd urgency summary = %q", got)
	}
}
