package ruledraft

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/nlq"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// Model is an AI model that answers a conversation.
type Model interface {
	Chat(ctx context.Context, system string, msgs []assistant.Message, maxTokens int) (string, error)
	Name() string
}

// aiRule is the rule as the model writes it.
type aiRule struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Query       string   `json:"query"`
	Schedule    string   `json:"schedule"`
	Lookback    string   `json:"lookback"`
	Severity    string   `json:"severity"`
	MITRE       []string `json:"mitre"`
	RiskScore   int      `json:"risk_score"`
	RiskObjects []struct {
		Field string `json:"field"`
		Type  string `json:"type"`
	} `json:"risk_objects"`
	GroupBy  []string `json:"group_by"`
	Guidance string   `json:"guidance"`
	Notes    string   `json:"notes"`
}

// AI asks the model to draft the detection. offline is the offline draft,
// offered as a hint and kept for its similar detections. The model only
// ever sees the description and the offline draft, never event data. A
// draft that does not validate is sent back once with its problems.
func AI(ctx context.Context, m Model, description string, offline *Draft) (*Draft, error) {
	msgs := []assistant.Message{{Role: "user", Content: aiPrompt(description, offline)}}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		reply, err := m.Chat(ctx, aiSystem(), msgs, 1500)
		if err != nil {
			return nil, err
		}
		dr, err := fromAI(reply, description)
		if err == nil {
			if offline != nil {
				dr.Similar = offline.Similar
			}
			return dr, nil
		}
		lastErr = err
		msgs = append(msgs, assistant.Message{Role: "assistant", Content: reply},
			assistant.Message{Role: "user", Content: fmt.Sprintf("That rule has problems: %v. Reply with the corrected JSON object only.", err)})
	}
	return nil, fmt.Errorf("the model's rule was not valid: %v", lastErr)
}

func fromAI(reply, description string) (*Draft, error) {
	var r aiRule
	if err := json.Unmarshal([]byte(jsonObject(reply)), &r); err != nil {
		return nil, fmt.Errorf("reply is not a JSON object: %v", err)
	}
	q, err := query.Parse(strings.TrimSpace(r.Query))
	if err != nil {
		return nil, fmt.Errorf("query: %v", err)
	}
	q.Earliest, q.Latest = "", ""
	d := &detect.Detection{
		Title: strings.TrimSpace(r.Title), Description: strings.TrimSpace(r.Description), Query: q.String(),
		Schedule: strings.TrimSpace(r.Schedule), Lookback: strings.TrimSpace(r.Lookback),
		Severity: strings.ToLower(strings.TrimSpace(r.Severity)), Guidance: strings.TrimSpace(r.Guidance),
		Tags: []string{"plain-english"},
	}
	if d.Description == "" {
		d.Description = description
	}
	dr := &Draft{Source: "ai", Confidence: 1}
	cat := detect.ATTACK()
	for _, id := range r.MITRE {
		id = strings.ToUpper(strings.TrimSpace(id))
		if _, ok := cat.Technique(id); ok && !slices.Contains(d.MITRE, id) {
			d.MITRE = append(d.MITRE, id)
		} else if !ok {
			dr.warn(fmt.Sprintf("The model named ATT&CK technique %q, which is not in the matrix, so it was left out.", id))
		}
	}
	if len(r.RiskObjects) > 0 && r.RiskScore > 0 {
		d.Risk = &detect.Risk{Score: min(r.RiskScore, 1000)}
		for _, o := range r.RiskObjects {
			d.Risk.Objects = append(d.Risk.Objects, detect.RiskObject{Field: strings.TrimSpace(o.Field), Type: strings.ToLower(strings.TrimSpace(o.Type))})
		}
	}
	for _, f := range r.GroupBy {
		if f = strings.TrimSpace(f); f != "" {
			d.Throttle.Fields = append(d.Throttle.Fields, f)
		}
	}
	if len(d.Throttle.Fields) > 0 {
		d.Throttle.Window = "1h"
	}
	d.Title = strings.ReplaceAll(d.Title, "\n", " ")
	if len(d.Title) > 200 {
		d.Title = d.Title[:200]
	}
	d.ID = Slug(d.Title)
	d.Defaults()
	if err := d.Validate(); err != nil {
		return nil, err
	}
	dr.Detection = d
	dr.Steps = []nlq.Step{{Meaning: "written by the AI model from your description"}}
	if n := strings.TrimSpace(r.Notes); n != "" {
		dr.warn(n)
	}
	return dr, nil
}

// jsonObject cuts the JSON object out of a reply that may wrap it in a
// code fence or a sentence.
func jsonObject(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j < i {
		return s
	}
	return s[i : j+1]
}

func aiSystem() string {
	return `You write detections for Signalith, a SIEM. A detection is a query that runs on a schedule over a lookback window; each result row becomes a finding.
Reply with one JSON object only, no explanation and no code fences, with these keys:
  title: short finding title; may use $field$ tokens for values from the result row, such as "Brute force from $src$"
  description: one or two sentences on what it detects
  query: a Signalith query WITHOUT earliest= or latest= (the lookback sets the time range)
  schedule: how often it runs, like 5m, 15m or 1h (at least 1m)
  lookback: how far back each run searches, at least the schedule and at most 90d, like 15m or 1h; a threshold "in 5 minutes" means lookback 5m
  severity: one of ` + strings.Join(findings.Severities, ", ") + `
  mitre: ATT&CK technique IDs such as T1110 or T1059.001 (only real ones)
  risk_score: risk added per result, 1 to 100 (low 15, medium 30, high 50, critical 80)
  risk_objects: the result fields that name a user or system, as [{"field": "user", "type": "user"}, {"field": "dest", "type": "system"}]; type is user, system or other; after stats only the by fields exist
  group_by: fields that make two results the same finding, usually the stats by fields or the user and system
  guidance: how an analyst should triage a finding, one to three sentences
  notes: anything the person should check, such as fields their data may lack; empty if none
Prefer the data models below over raw text searches. For thresholds use stats ... by ... | where.

` + assistant.QueryReference()
}

func aiPrompt(description string, offline *Draft) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Detect: %s\n", description)
	if offline != nil && offline.Detection != nil && offline.Source == "rules" {
		fmt.Fprintf(&b, "A keyword-based drafter suggested this query, which may be incomplete or wrong:\n%s\n", offline.Detection.Query)
	}
	if offline != nil && len(offline.Similar) > 0 {
		b.WriteString("Similar detections already exist (for reference):\n")
		for _, s := range offline.Similar[:min(3, len(offline.Similar))] {
			fmt.Fprintf(&b, "- %s\n", s.Title)
		}
	}
	b.WriteString("Reply with the JSON object only.")
	return b.String()
}
