package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// failPages is the settings file of a config whose reads, writes,
// backups or checks fail as the test says.
type failPages struct {
	config.PageFile
	readErr, writeErr, backupErr, checkErr error
}

func (p failPages) Read() (*config.PageSettings, error) {
	if p.readErr != nil {
		return nil, p.readErr
	}
	return p.PageFile.Read()
}

func (p failPages) Write(ps *config.PageSettings) error {
	if p.writeErr != nil {
		return p.writeErr
	}
	return p.PageFile.Write(ps)
}

func (p failPages) Backup() (string, error) {
	if p.backupErr != nil {
		return "", p.backupErr
	}
	return p.PageFile.Backup()
}

func (p failPages) CheckEdit(e config.Edit) (*config.EditResult, error) {
	if p.checkErr != nil {
		return nil, p.checkErr
	}
	return p.PageFile.CheckEdit(e)
}

// A settings file that cannot be checked, written or kept a copy of
// before a reset refuses the save, and says which.
func TestPutSettingsPageStoreFailures(t *testing.T) {
	for _, c := range []struct {
		name  string
		pages func(config.PageFile) failPages
		body  string
		want  string
	}{
		{"check", func(f config.PageFile) failPages { return failPages{PageFile: f, checkErr: errDown} }, `{"values":{"search.max_events":5000}}`, errDown.Error()},
		{"write", func(f config.PageFile) failPages { return failPages{PageFile: f, writeErr: errDown} }, `{"values":{"search.max_events":5000}}`, "could not save the settings file"},
		{"backup", func(f config.PageFile) failPages {
			return failPages{PageFile: f, readErr: errors.New("not laid out as Signalith writes it"), backupErr: errDown}
		}, `{"reset_all":true}`, "could not keep a copy of the settings file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ts, _, _ := newSettingsServer(t, "", func(s *Server) { s.Pages = c.pages(config.PageFile{Config: s.Config.Path()}) })
			code, out := do(t, ts, "PUT", "/api/settings", c.body, true)
			if msg, _ := out["error"].(string); code != http.StatusInternalServerError || !strings.Contains(msg, c.want) {
				t.Errorf("%d %v", code, out)
			}
		})
	}
}

// movingSettings is shared settings this server's own are moving into:
// not in use yet, but a save waits for the move and goes where they are.
type movingSettings struct {
	*memSettings
	moved    bool
	released atomic.Int32
}

func (m *movingSettings) Shared() bool { return false }

func (m *movingSettings) HoldFile() (bool, func()) {
	return m.moved, func() { m.released.Add(1) }
}

// A save made once the settings moved goes to the shared settings; one
// made before goes to the file, and the hold is let go either way.
func TestPutSettingsWhileMoving(t *testing.T) {
	ms := &movingSettings{memSettings: newMemSettings(), moved: true}
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings = ms })
	code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"search.max_events":4321}}`, true)
	if code != http.StatusOK {
		t.Fatalf("moved: %d %v", code, out)
	}
	ms.memSettings.mu.Lock()
	_, inShared := ms.memSettings.sh.Cluster["search.max_events"]
	ms.memSettings.mu.Unlock()
	if !inShared || ms.released.Load() != 1 {
		t.Errorf("moved save: shared %v, released %d", inShared, ms.released.Load())
	}

	ms2 := &movingSettings{memSettings: newMemSettings()}
	ts, srv, _ = newSettingsServer(t, "", func(s *Server) { s.Settings = ms2 })
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"search.max_events":4322}}`, true); code != http.StatusOK {
		t.Fatalf("not moved: %d %v", code, out)
	}
	p, err := (config.PageFile{Config: srv.Config.Path()}).Read()
	if err != nil || !strings.Contains(strings.Join(p.Keys(), ","), "search.max_events") || ms2.released.Load() != 1 {
		t.Errorf("not moved save: %v %v, released %d", p, err, ms2.released.Load())
	}
}

// The assistant test names the setting to fill in before it asks.
func TestTestAssistantFields(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "", nil)
	test := func(body string) (int, map[string]any) {
		t.Helper()
		return do(t, ts, "POST", "/api/settings/test/assistant", body, true)
	}
	if code, _ := test(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	for body, key := range map[string]string{
		`{"values":{"assistant.provider":"openai","assistant.url":"http://127.0.0.1:1/v1"}}`: "assistant.model",
		`{"values":{"assistant.provider":"anthropic"}}`:                                      "assistant.api_key",
	} {
		code, out := test(body)
		if fields, _ := out["fields"].(map[string]any); code != http.StatusBadRequest || fields[key] == nil {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
}

// A failed assistant test is worded by what failed, and names the
// setting it points at.
func TestExplainAssistant(t *testing.T) {
	for _, c := range []struct {
		err   error
		field string
		want  string
	}{
		{context.DeadlineExceeded, "assistant.request_timeout", "within the answer time limit (2m)"},
		{&assistant.APIError{Status: http.StatusForbidden, StatusText: "403 Forbidden"}, "assistant.api_key", "refused the API key"},
		{&assistant.APIError{Status: http.StatusNotFound, StatusText: "404 Not Found", Message: "no such page"}, "assistant.url", "not found"},
		{fmt.Errorf("could not reach http://127.0.0.1:1: connection refused"), "assistant.url", "Could not reach"},
		{errors.New("the answer did not parse"), "assistant.model", "A larger model may do better"},
		{errors.New("something else"), "", "Something else"},
	} {
		msg, field := explainAssistant(c.err, "m", 2*time.Minute)
		if field != c.field || !strings.Contains(msg, c.want) {
			t.Errorf("%v: %q %q", c.err, msg, field)
		}
	}
}
