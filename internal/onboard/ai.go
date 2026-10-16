package onboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// AILines is how many lines of a sample Refine sends to the model, and
// aiBytes how many bytes at most.
const (
	AILines = 20
	aiBytes = 8 << 10
)

// Chatter is the AI model (assistant.Client).
type Chatter interface {
	Chat(ctx context.Context, system string, msgs []assistant.Message, maxTokens int) (string, error)
}

// AISample is the part of a sample Refine sends: its first AILines
// lines, at most aiBytes in all, each cut to 1,000 bytes.
func AISample(lines []string) []string {
	var out []string
	size := 0
	for _, l := range lines {
		if len(out) >= AILines {
			break
		}
		if len(l) > 1000 {
			l = l[:1000]
		}
		if size+len(l) > aiBytes {
			break
		}
		size += len(l)
		out = append(out, l)
	}
	return out
}

// aiReply is the part of a parser the model may suggest.
type aiReply struct {
	Sourcetype    string    `json:"sourcetype"`
	VendorProduct string    `json:"vendor_product"`
	Model         string    `json:"model"`
	Header        string    `json:"header"`
	Format        string    `json:"format"`
	Delimiter     *string   `json:"delimiter"`
	KVSeparator   string    `json:"kv_separator"`
	Columns       []string  `json:"columns"`
	Pattern       string    `json:"pattern"`
	TimeField     string    `json:"time_field"`
	TimeFormat    string    `json:"time_format"`
	Mappings      []Mapping `json:"mappings"`
	Explanation   string    `json:"explanation"`
}

// Refine asks the model to improve a suggested parser for the sample. The
// model sees the lines AISample picks, the current parser, the data
// models and the formats; its answer must pass the same checks as an
// admin's parser, and one that does not is sent back once with the
// problem. It returns the parser and the model's short explanation.
func Refine(ctx context.Context, m Chatter, lines []string, current Parser) (Parser, string, error) {
	sample := AISample(lines)
	if len(sample) == 0 {
		return current, "", errors.New("the sample is empty")
	}
	cur, _ := json.MarshalIndent(aiView(current), "", "  ")
	user := "Sample lines:\n```\n" + strings.Join(sample, "\n") + "\n```\n\nCurrent parser (from Signalith's own heuristics):\n```json\n" + string(cur) + "\n```"
	msgs := []assistant.Message{{Role: "user", Content: user}}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		reply, err := m.Chat(ctx, aiSystemPrompt(), msgs, 2000)
		if err != nil {
			return current, "", err
		}
		p, why, err := applyReply(ctx, reply, current, lines)
		if err == nil {
			return p, why, nil
		}
		lastErr = err
		msgs = append(msgs, assistant.Message{Role: "assistant", Content: reply},
			assistant.Message{Role: "user", Content: "That parser does not work: " + err.Error() + "\nReply again with corrected JSON only."})
	}
	return current, "", fmt.Errorf("the AI model's suggestion did not pass Signalith's checks: %w", lastErr)
}

func aiView(p Parser) aiReply {
	d := p.Delimiter
	return aiReply{Sourcetype: p.Sourcetype, VendorProduct: p.VendorProduct, Model: p.Model, Header: p.Header, Format: p.Format,
		Delimiter: &d, KVSeparator: p.KVSeparator, Columns: p.Columns, Pattern: p.Pattern, TimeField: p.TimeField,
		TimeFormat: p.TimeFormat, Mappings: p.Mappings}
}

// applyReply reads the model's JSON onto the current parser and checks
// that the result compiles and reads the sample.
func applyReply(ctx context.Context, reply string, current Parser, lines []string) (Parser, string, error) {
	js := jsonObject(reply)
	var r aiReply
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		return current, "", fmt.Errorf("the reply is not the JSON object asked for (%v)", err)
	}
	p := current
	set := func(dst *string, v string) {
		if v = strings.TrimSpace(v); v != "" {
			*dst = v
		}
	}
	set(&p.Sourcetype, r.Sourcetype)
	set(&p.VendorProduct, r.VendorProduct)
	set(&p.Model, r.Model)
	if r.Format != "" {
		p.Format = strings.ToLower(strings.TrimSpace(r.Format))
		p.Header = strings.ToLower(strings.TrimSpace(r.Header))
		p.Delimiter, p.KVSeparator, p.Columns, p.Pattern = "", r.KVSeparator, r.Columns, r.Pattern
		if r.Delimiter != nil {
			p.Delimiter = *r.Delimiter
		}
	}
	p.TimeField, p.TimeFormat = strings.TrimSpace(r.TimeField), strings.TrimSpace(r.TimeFormat)
	if r.Mappings != nil {
		p.Mappings = r.Mappings
	}
	c, err := Compile(p)
	if err != nil {
		return current, "", err
	}
	p = c.P
	pv, err := c.Run(ctx, lines, time.Now())
	if err != nil {
		return current, "", err
	}
	if p.Format == FormatRegex && pv.Parsed*2 < pv.Lines {
		return current, "", fmt.Errorf("the pattern reads only %d of the %d sample lines", pv.Parsed, pv.Lines)
	}
	why := strings.TrimSpace(r.Explanation)
	if len(why) > 600 {
		why = why[:600] + "…"
	}
	return p, why, nil
}

// jsonObject returns the JSON object in a reply, without code fences or
// words around it.
func jsonObject(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j < i {
		return s
	}
	return s[i : j+1]
}

func aiSystemPrompt() string {
	var b strings.Builder
	b.WriteString(`You help an administrator bring a log format into Signalith, a SIEM whose field names follow the Splunk Common Information Model. You get sample lines of the log and the parser Signalith's heuristics suggested. Improve the parser so the events land in the right data model with the right field names, which lets the built-in detections use them.

Reply with one JSON object only, no other text:
{
  "sourcetype": "vendor:product, lowercase, letters digits : _ . -",
  "vendor_product": "Vendor Product",
  "model": "one data model name from the list below",
  "header": "syslog when every line starts with a syslog header (priority, time, host, program), else empty",
  "format": "json | kv | csv | cef | leef | regex | text",
  "delimiter": "for csv: , ; | or a tab; for kv: empty for spaces, or , ; |",
  "kv_separator": "for kv: = or :",
  "columns": ["for csv: the column names, in order"],
  "pattern": "for regex: an RE2 regular expression (Go syntax) with named groups (?P<name>...) whose names are fields; no look-around or backreferences",
  "time_field": "the field holding the event time, or empty",
  "time_format": "one of the time formats below, or empty",
  "mappings": [{"from": "field the parser reads", "to": "data model field"}],
  "explanation": "one or two plain sentences on what you changed and why"
}

Rules: prefer a structured format (json, kv, csv, cef, leef) over regex when the lines are structured. In a regex, name groups with the data model's field names directly where you can, and the rest with short lowercase names. Map fields to data model fields only when the meaning matches. Use action values the data model expects (success or failure for Authentication; allowed or blocked for Network_Traffic) only through mappings of the field that holds the outcome; Signalith converts common words itself.

`)
	b.WriteString("Data models and their fields:\n")
	for _, m := range datamodel.Models {
		if m.Name == datamodel.RiskModel {
			continue
		}
		names := make([]string, 0, len(m.Fields))
		for _, f := range m.Fields {
			names = append(names, f.Name)
		}
		fmt.Fprintf(&b, "- %s (%s): %s\n", m.Name, m.Description, strings.Join(names, ", "))
	}
	b.WriteString("Every model also takes: host, vendor_product, signature, signature_id.\n\nTime formats:\n")
	for _, f := range TimeFormats {
		fmt.Fprintf(&b, "- %s, such as %s\n", f.Name, f.Example)
	}
	return b.String()
}
