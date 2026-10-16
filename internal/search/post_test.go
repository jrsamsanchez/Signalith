package search

import (
	"context"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestRunCommands(t *testing.T) {
	docs := []map[string]any{
		{"@timestamp": "2026-01-01T12:00:00Z", "file": map[string]any{"name": "a.exe"}, "message": "raw a"},
		{"@timestamp": "2026-01-01T12:01:00Z", "file": map[string]any{"name": "payload"}},
	}
	q, err := query.Parse(`* | rex field=file.name "\.(?<ext>[^.]*)$" | where isnull(ext) | stats count by file.name`)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := RunCommands(context.Background(), docs, q.Commands)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["file.name"] != "payload" || rows[0]["count"] != int64(1) {
		t.Errorf("rows %v", rows)
	}
	// Each event's time and raw text are named as a search names them.
	q, _ = query.Parse(`* | where isnotnull(_time) AND _raw="raw a"`)
	if rows, err := RunCommands(context.Background(), docs, q.Commands); err != nil || len(rows) != 1 {
		t.Errorf("rows %v, %v", rows, err)
	}
	q, _ = query.Parse(`* | lookup local host OUTPUT owner`)
	if _, err := RunCommands(context.Background(), docs, q.Commands); err == nil {
		t.Error("a lookup ran without its table")
	}
}
