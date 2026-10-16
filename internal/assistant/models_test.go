package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestModelIDTurnsNamesIntoIDs(t *testing.T) {
	for in, want := range map[string]string{
		"Opus 5.5": "claude-opus-5-5", "Claude Sonnet 5.5": "claude-sonnet-5-5", " haiku 5.5 ": "claude-haiku-5-5",
		"Fable 5.1": "claude-fable-5-1",
	} {
		if got, ok := ModelID(Anthropic, in); !ok || got != want {
			t.Errorf("ModelID(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"claude-opus-5-5", "claude-opus-4-8", "Opus 9", ""} {
		if got, ok := ModelID(Anthropic, in); ok || got != in {
			t.Errorf("ModelID(%q) = %q, %v; want it unchanged", in, got, ok)
		}
	}
	if _, ok := ModelID(OpenAI, "Opus 5.5"); ok {
		t.Error("ModelID changed an OpenAI-compatible model")
	}
	if c := New(Anthropic, "", "Opus 5.5", "k"); c.Model != "claude-opus-5-5" {
		t.Errorf("New kept the model's name: %q", c.Model)
	}
}

func TestBaseURL(t *testing.T) {
	for _, tc := range []struct{ provider, in, want string }{
		{Anthropic, "https://api.anthropic.com", "https://api.anthropic.com"},
		{Anthropic, "https://api.anthropic.com/v1/", "https://api.anthropic.com"},
		{OpenAI, "http://localhost:11434", "http://localhost:11434/v1"},
		{OpenAI, "http://localhost:11434/v1/", "http://localhost:11434/v1"},
		{OpenAI, "https://openrouter.ai/api/v1", "https://openrouter.ai/api/v1"},
	} {
		if got := BaseURL(tc.provider, tc.in); got != tc.want {
			t.Errorf("BaseURL(%s, %q) = %q, want %q", tc.provider, tc.in, got, tc.want)
		}
	}
}

// Current Claude models refuse a temperature, and think out of max_tokens.
func TestAnthropicSendsNoTemperature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["temperature"]; ok {
			t.Error("temperature sent")
		}
		if n, _ := body["max_tokens"].(float64); n < 4000 {
			t.Errorf("max_tokens %v leaves no room to think", n)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "thinking", "text": ""}, {"type": "text", "text": "ok"}}})
	}))
	defer srv.Close()
	got, err := New(Anthropic, srv.URL, "", "k").Chat(context.Background(), "s", []Message{{Role: "user", Content: "q"}}, 600)
	if err != nil || got != "ok" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestOpenAIRetriesWithoutTemperature(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["temperature"]; ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"Unsupported value: 'temperature' does not support 0 with this model."}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": "ok"}}}})
	}))
	defer srv.Close()
	got, err := New(OpenAI, srv.URL+"/v1", "gpt-5", "k").Chat(context.Background(), "s", []Message{{Role: "user", Content: "q"}}, 600)
	if err != nil || got != "ok" || calls != 2 {
		t.Fatalf("got %q, %v after %d calls", got, err, calls)
	}
}

func TestUnknownModel(t *testing.T) {
	for _, body := range []string{
		`{"type":"error","error":{"type":"not_found_error","message":"model: Opus 5.5"}}`,
		`{"error":"model \"llama9\" not found, try pulling it first"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(body))
		}))
		_, err := New(Anthropic, srv.URL, "x", "k").Chat(context.Background(), "s", []Message{{Role: "user", Content: "q"}}, 10)
		srv.Close()
		var ae *APIError
		if !errors.As(err, &ae) || !ae.UnknownModel() {
			t.Errorf("%s: err = %v, want an unknown model", body, err)
		}
	}
}

func TestListModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			if r.Header.Get("x-api-key") != "k" && r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"claude-opus-5-5","display_name":"Claude Opus 5.5"},{"id":"llama3.1:latest"}],"has_more":false}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	got, err := New(Anthropic, srv.URL, "", "k").ListModels(context.Background())
	if err != nil || len(got) != 2 || got[0] != (Model{"claude-opus-5-5", "Claude Opus 5.5"}) || got[1] != (Model{"llama3.1:latest", "llama3.1:latest"}) {
		t.Fatalf("Anthropic: %v, %v", got, err)
	}
	// An OpenAI-compatible server at its root, as Ollama is often entered.
	got, err = New(OpenAI, srv.URL, "", "x").ListModels(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatalf("OpenAI-compatible: %v, %v", got, err)
	}
	if _, err := New(Anthropic, srv.URL, "", "bad").ListModels(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad key: %v", err)
	}
}

func TestOpenAIListsChatModelsOnly(t *testing.T) {
	for id, want := range map[string]bool{"gpt-5": true, "gpt-4.1-mini": true, "o3": true, "text-embedding-3-large": false,
		"gpt-4o-audio-preview": false, "tts-1": false, "dall-e-3": false, "gpt-image-1": false} {
		if chatModel(id) != want {
			t.Errorf("chatModel(%q) = %v", id, !want)
		}
	}
	if KnownModels(OpenAI, "http://localhost:11434/v1") != nil || len(KnownModels(OpenAI, "")) == 0 || len(KnownModels(Anthropic, "")) == 0 {
		t.Error("KnownModels")
	}
}
