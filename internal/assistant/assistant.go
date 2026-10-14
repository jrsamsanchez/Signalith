// Package assistant asks an AI model to write a Signalith query for a
// question the offline translator could not fully understand. It is off
// unless configured, and it sends only the question, the query language
// reference and the data model field list, never events.
//
// Two kinds of endpoint are supported: Anthropic's Messages API, and any
// OpenAI-compatible chat completions API, which includes local model
// servers such as Ollama, LM Studio and vLLM for air-gapped installs.
package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/redact"
)

// Providers are the supported endpoint kinds.
const (
	Anthropic = "anthropic"
	OpenAI    = "openai"
)

// DefaultModel and DefaultURL are used when the config leaves them empty.
var (
	DefaultModel = map[string]string{Anthropic: "claude-sonnet-5-5"}
	DefaultURL   = map[string]string{Anthropic: "https://api.anthropic.com", OpenAI: "https://api.openai.com/v1"}
)

// Client calls one model.
type Client struct {
	Provider string
	URL      string
	Model    string
	APIKey   string
	HTTP     *http.Client
}

// New returns a client, or nil when provider is empty (the assistant is
// off).
func New(provider, url, model, apiKey string) *Client {
	if provider == "" {
		return nil
	}
	if url == "" {
		url = DefaultURL[provider]
	}
	if model == "" {
		model = DefaultModel[provider]
	}
	if id, ok := ModelID(provider, model); ok {
		model = id
	}
	return &Client{Provider: provider, URL: BaseURL(provider, url), Model: strings.TrimSpace(model), APIKey: apiKey,
		HTTP: &http.Client{Timeout: 3 * time.Minute, CheckRedirect: sameOriginRedirects}}
}

// BaseURL is the address requests are made under: Anthropic's paths
// start with /v1 themselves, so a trailing /v1 is dropped; an
// OpenAI-compatible address without a path, such as
// http://localhost:11434, gets the /v1 that Ollama, LM Studio and vLLM
// all serve under.
func BaseURL(provider, raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	switch provider {
	case Anthropic:
		u = strings.TrimSuffix(u, "/v1")
	case OpenAI:
		if p, err := neturl.Parse(u); err == nil && p.Host != "" && (p.Path == "" || p.Path == "/") {
			u += "/v1"
		}
	}
	return u
}

// sameOriginRedirects follows a redirect only to the same scheme, host and
// port. Go would otherwise send the x-api-key header (and the question)
// wherever the redirect points, including over plain http.
func sameOriginRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("stopped after 5 redirects")
	}
	if origin(req.URL) != origin(via[0].URL) {
		return fmt.Errorf("the AI model's address redirected to %s; Signalith only follows redirects within the same host, "+
			"so the API key is not sent elsewhere. Set assistant.url to the final address", redact.URL(req.URL.String()))
	}
	return nil
}

// origin is a URL's scheme, host and port, with the default port filled in.
func origin(u *neturl.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// Name describes the model for the UI.
func (c *Client) Name() string { return c.Model }

// Translate asks the model for a query. draft is the offline translator's
// attempt, offered as a hint. The returned query always parses: a reply
// that does not is sent back once with the parser's error.
func (c *Client) Translate(ctx context.Context, question, draft string) (string, error) {
	msgs := []Message{{Role: "user", Content: userPrompt(question, draft)}}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		reply, err := c.Chat(ctx, SystemPrompt(), msgs, 600)
		if err != nil {
			return "", err
		}
		q := cleanReply(reply)
		if _, err := query.Parse(q); err == nil {
			return q, nil
		} else {
			lastErr = err
			msgs = append(msgs, Message{Role: "assistant", Content: reply},
				Message{Role: "user", Content: fmt.Sprintf("That query does not parse: %v. Reply with a corrected query only.", err)})
		}
	}
	return "", fmt.Errorf("the model's query did not parse: %v", lastErr)
}

// Message is one turn of a conversation: Role is "user" or "assistant".
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Chat sends a conversation with a system prompt and returns the model's
// reply. maxTokens bounds the reply's length.
func (c *Client) Chat(ctx context.Context, system string, msgs []Message, maxTokens int) (string, error) {
	var path string
	var body any
	hdr := http.Header{"Content-Type": {"application/json"}}
	switch c.Provider {
	case Anthropic:
		path = "/v1/messages"
		// Current Claude models think before they answer, out of the same
		// max_tokens, and refuse a temperature, so neither is narrowed.
		// Only the tokens used are billed.
		body = map[string]any{"model": c.Model, "max_tokens": maxTokens + thinkingRoom, "system": system, "messages": msgs}
		hdr.Set("x-api-key", c.APIKey)
		hdr.Set("anthropic-version", "2023-06-01")
	case OpenAI:
		path = "/chat/completions"
		all := append([]Message{{Role: "system", Content: system}}, msgs...)
		body = map[string]any{"model": c.Model, "messages": all, "temperature": 0}
		if c.APIKey != "" {
			hdr.Set("Authorization", "Bearer "+c.APIKey)
		}
	default:
		return "", fmt.Errorf("unknown assistant provider %q", c.Provider)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	data, err := c.do(ctx, http.MethodPost, path, hdr, b)
	var ae *APIError
	if c.Provider == OpenAI && errors.As(err, &ae) && ae.Status == http.StatusBadRequest && strings.Contains(strings.ToLower(ae.Message), "temperature") {
		// Some models, such as OpenAI's reasoning models, take only their
		// own temperature.
		delete(body.(map[string]any), "temperature")
		if b, err = json.Marshal(body); err != nil {
			return "", err
		}
		data, err = c.do(ctx, http.MethodPost, path, hdr, b)
	}
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("unexpected reply from the AI model: %v", err)
	}
	for _, c := range out.Content {
		if c.Type == "text" {
			return c.Text, nil
		}
	}
	if len(out.Choices) > 0 {
		return out.Choices[0].Message.Content, nil
	}
	return "", errors.New("the AI model returned no text")
}

// thinkingRoom is added to an Anthropic request's max_tokens for the
// model's thinking.
const thinkingRoom = 8000

// APIError is an answer from the model's service other than 200 OK.
type APIError struct {
	Status int
	// StatusText is such as "404 Not Found".
	StatusText string
	// Message is the service's own error message, shortened.
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("the AI model returned %s: %s", e.StatusText, e.Message)
}

// UnknownModel reports whether the service said it has no such model.
func (e *APIError) UnknownModel() bool {
	m := strings.ToLower(e.Message)
	if e.Status != http.StatusNotFound && e.Status != http.StatusBadRequest {
		return false
	}
	return strings.Contains(m, "model") && (e.Status == http.StatusNotFound || strings.Contains(m, "not found") ||
		strings.Contains(m, "does not exist") || strings.Contains(m, "invalid model") || strings.Contains(m, "unknown model"))
}

// do makes one request under c.URL and returns the answer's body.
func (c *Client) do(ctx context.Context, method, path string, hdr http.Header, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header = hdr.Clone()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// Go's error repeats the request URL, which may hold a key.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			ue.URL = redact.URL(ue.URL)
		}
		return nil, fmt.Errorf("could not reach the AI model at %s: %w", redact.URL(c.URL), err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(data))
		var e struct {
			Error json.RawMessage `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && len(e.Error) > 0 {
			// {"error": {"message": ...}}, or Ollama's {"error": "..."}.
			var obj struct {
				Message string `json:"message"`
			}
			var str string
			if json.Unmarshal(e.Error, &obj) == nil && obj.Message != "" {
				msg = obj.Message
			} else if json.Unmarshal(e.Error, &str) == nil && str != "" {
				msg = str
			}
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, &APIError{Status: resp.StatusCode, StatusText: resp.Status, Message: msg}
	}
	return data, nil
}

// cleanReply strips code fences and explanations around the query.
func cleanReply(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			rest = rest[:j]
		}
		s = rest
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "Query:"))
}

func userPrompt(question, draft string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Question: %s\n", question)
	if draft != "" {
		fmt.Fprintf(&b, "A keyword-based translator suggested this, which may be incomplete or wrong:\n%s\n", draft)
	}
	b.WriteString("Reply with the query only.")
	return b.String()
}

// SystemPrompt describes the query language and data models.
func SystemPrompt() string {
	return "You write queries for Signalith, a SIEM. Translate the analyst's question into one Signalith query and reply with the query only, no explanation and no code fences.\n\n" +
		QueryReference()
}

// QueryReference describes the query language, the data models and their
// fields, with examples.
func QueryReference() string {
	var b strings.Builder
	b.WriteString(`Query language (SPL-like, but only what is listed here exists):
- A search, then zero or more commands each after "|".
- Search terms: datamodel=Name, field=value (case-insensitive exact), field=val* (wildcards * ?), field!=value, field>10 (also >= < <=), field IN (a, b), bare words or "quoted phrases" (text anywhere in the raw event), NOT term, ( ... ), a OR b (OR binds tighter than the implicit AND).
- Time: earliest=-24h latest=now. Units s m h d w mon y; snap with @d @h @w, e.g. earliest=-1d@d latest=@d for yesterday. Leave time out unless the question names a period.
- Commands: ` + strings.Join(query.Commands, ", ") + `.
  stats <aggs> [by f1, f2]   aggs: ` + strings.Join(query.AggFuncs, ", ") + ` as count, count(f), dc(f), sum(f), avg(f), min(f), max(f), each optionally "as name"
  timechart [span=1h] <agg> [by field]
  top [limit=N] field [by field]
  where <expression on result columns>
  sort [-]field, ...    ("-" is descending)
  head N
  table f1, f2
  rename f as g
  enrich [fields]   adds asset and identity context columns
  intel [fields]    adds threat intel columns (<field>_intel_source, _intel_type, _intel_weight) for values that are known indicators
  threatmatch [fields]   keeps only events whose IP, domain, URL, hash or email fields match threat intel; must come right after the search
- Quote values with spaces or symbols. Windows paths need no doubled backslashes inside quotes.

Data models and their fields (every event also has: `)
	var common []string
	for _, f := range datamodel.Common {
		common = append(common, f.Name)
	}
	b.WriteString(strings.Join(common, ", ") + "):\n")
	for _, m := range datamodel.Models {
		fmt.Fprintf(&b, "- %s: %s\n", m.Name, m.Description)
		for _, f := range m.Fields {
			fmt.Fprintf(&b, "    %s (%s): %s", f.Name, f.Type, f.Description)
			if len(f.Examples) > 0 {
				fmt.Fprintf(&b, "; values like %s", strings.Join(f.Examples, ", "))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString(`
Notes: Windows process names include .exe (powershell.exe). In Authentication, src is where the logon came from and dest is the system logged on to. Risk events are only searched with datamodel=Risk.
In Malware, type is threat, rule or health; malware not removed is action IN (allowed, failed, restored).

Examples:
Q: top 10 sources of failed logins this week
datamodel=Authentication action=failure earliest=@w | top limit=10 src
Q: users who logged on to more than 3 systems today
datamodel=Authentication action=success earliest=@d | stats dc(dest) as systems by user | where systems > 3 | sort -systems
Q: encoded powershell
datamodel=Endpoint process_name IN (powershell.exe, pwsh.exe) process IN ("* -enc *", "* -encodedcommand *")
`)
	return b.String()
}
