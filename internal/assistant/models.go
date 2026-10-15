package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"
)

// Model is a model a provider offers: ID is what requests name, Name what
// people read.
type Model struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// anthropicModels are Anthropic's current models, newest tier first, for
// when its model list can't be read.
var anthropicModels = []Model{
	{"claude-opus-5-5", "Claude Opus 5.5"},
	{"claude-sonnet-5-5", "Claude Sonnet 5.5"},
	{"claude-haiku-5-5", "Claude Haiku 5.5"},
	{"claude-fable-5-1", "Claude Fable 5.1"},
}

// openAIModels are some of OpenAI's chat models, for when its model list
// can't be read.
var openAIModels = []Model{
	{"gpt-5", "GPT-5"},
	{"gpt-5-mini", "GPT-5 mini"},
	{"gpt-4.1", "GPT-4.1"},
	{"gpt-4.1-mini", "GPT-4.1 mini"},
}

// KnownModels lists the models Signalith knows of for a provider at an
// address, for when the service's own list can't be read. Models on
// someone's own hardware are whatever they installed, so there are none.
func KnownModels(provider, url string) []Model {
	switch {
	case provider == Anthropic:
		return append([]Model(nil), anthropicModels...)
	case provider == OpenAI && isOpenAI(url):
		return append([]Model(nil), openAIModels...)
	}
	return nil
}

// isOpenAI reports whether an address is OpenAI's own service; empty is.
func isOpenAI(url string) bool {
	if strings.TrimSpace(url) == "" {
		return true
	}
	u, err := neturl.Parse(strings.TrimSpace(url))
	return err == nil && strings.EqualFold(u.Hostname(), "api.openai.com")
}

var (
	notID   = regexp.MustCompile(`[\s.]+`)
	oSeries = regexp.MustCompile(`^o\d`)
)

// ModelID turns a model's name as people write it, such as "Opus 5.5" or
// "Claude Sonnet 5.5", into Anthropic's ID for it, and reports whether it
// changed it. Only names of models it knows are turned.
func ModelID(provider, model string) (string, bool) {
	m := strings.TrimSpace(model)
	if provider != Anthropic || m == "" {
		return model, false
	}
	for _, k := range anthropicModels {
		if k.ID == m {
			return model, false
		}
	}
	id := strings.ToLower(notID.ReplaceAllString(m, "-"))
	if !strings.HasPrefix(id, "claude-") {
		id = "claude-" + id
	}
	for _, k := range anthropicModels {
		if k.ID == id {
			return id, true
		}
	}
	return model, false
}

// ListModels asks the service which models it offers: Anthropic's
// /v1/models, or an OpenAI-compatible /models, which Ollama, LM Studio and
// vLLM also answer. Only chat models are listed for OpenAI itself.
func (c *Client) ListModels(ctx context.Context) ([]Model, error) {
	hdr := http.Header{}
	path := "/models"
	switch c.Provider {
	case Anthropic:
		path = "/v1/models?limit=1000"
		hdr.Set("x-api-key", c.APIKey)
		hdr.Set("anthropic-version", "2023-06-01")
	case OpenAI:
		if c.APIKey != "" {
			hdr.Set("Authorization", "Bearer "+c.APIKey)
		}
	default:
		return nil, fmt.Errorf("unknown assistant provider %q", c.Provider)
	}
	data, err := c.do(ctx, http.MethodGet, path, hdr, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("unexpected model list from the AI model's service: %v", err)
	}
	openai := c.Provider == OpenAI && isOpenAI(c.URL)
	var models []Model
	seen := map[string]bool{}
	for _, m := range out.Data {
		if m.ID == "" || seen[m.ID] || (openai && !chatModel(m.ID)) {
			continue
		}
		seen[m.ID] = true
		name := m.DisplayName
		if name == "" {
			name = m.ID
		}
		models = append(models, Model{ID: m.ID, Name: name})
	}
	return models, nil
}

// chatModel reports whether one of OpenAI's models answers chat
// completions with text: its list also has embeddings, speech, images
// and the like.
func chatModel(id string) bool {
	id = strings.ToLower(id)
	if !strings.HasPrefix(id, "gpt-") && !strings.HasPrefix(id, "chatgpt-") && !oSeries.MatchString(id) {
		return false
	}
	for _, not := range []string{"audio", "realtime", "tts", "transcribe", "search", "image", "embedding", "instruct", "codex"} {
		if strings.Contains(id, not) {
			return false
		}
	}
	return true
}
