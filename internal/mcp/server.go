// Package mcp is a read-only Model Context Protocol server for Signalith.
// AI tools such as Claude Desktop start it (signalith mcp) and talk to it
// over standard input and output; it answers their tool calls by reading
// from a Signalith server's API as a Signalith user, so the user's role
// decides what it may see. It has no tool that changes anything.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
)

// Protocol versions this server speaks, newest first. A client asking for
// another gets the newest, and may then disconnect.
var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// maxMessage is the largest message read from the client.
const maxMessage = 4 << 20

// Tool is one tool the AI tool may call.
type Tool struct {
	Name        string
	Title       string
	Description string
	// Schema is the JSON Schema of the arguments.
	Schema map[string]any
	// Call runs the tool. Its result is sent to the model as JSON text; an
	// error is sent as the tool's error message.
	Call func(ctx context.Context, args json.RawMessage) (any, error)
}

// Server answers MCP requests with its tools.
type Server struct {
	Name, Version string
	// Instructions tell the model what the server is for.
	Instructions string
	Tools        []Tool
	Log          *slog.Logger

	wmu     sync.Mutex
	w       io.Writer
	mu      sync.Mutex
	running map[string]context.CancelFunc // calls in flight, by request ID
	wg      sync.WaitGroup
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeNoMethod       = -32601
	codeInvalidParams  = -32602
)

// Serve reads newline-delimited JSON-RPC messages from r and writes the
// answers to w until r ends or ctx is done. Tool calls run concurrently,
// so a slow search does not hold up a ping or a cancellation.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	s.w = w
	s.running = map[string]context.CancelFunc{}
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		s.wg.Wait()
	}()
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLarge, err := readLine(br)
		switch {
		case tooLarge:
			s.send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeInvalidRequest, "the message is too large"}})
		case len(bytes.TrimSpace(line)) > 0:
			s.handleLine(ctx, line)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

// readLine reads one line. A line over maxMessage is skipped and
// reported as too large.
func readLine(br *bufio.Reader) (line []byte, tooLarge bool, err error) {
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxMessage {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			return nil, true, err
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, false, err
		}
	}
}

func (s *Server) handleLine(ctx context.Context, line []byte) {
	line = bytes.TrimSpace(line)
	if line[0] == '[' {
		// A batch (protocol 2025-03-26). Each answer is sent on its own,
		// which clients accept as well.
		var batch []json.RawMessage
		if err := json.Unmarshal(line, &batch); err != nil || len(batch) == 0 {
			s.send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeParse, "the message is not valid JSON-RPC"}})
			return
		}
		for _, m := range batch {
			s.handleMessage(ctx, m)
		}
		return
	}
	s.handleMessage(ctx, line)
}

func (s *Server) handleMessage(ctx context.Context, msg []byte) {
	var req request
	if err := json.Unmarshal(msg, &req); err != nil {
		s.send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeParse, "the message is not valid JSON"}})
		return
	}
	notification := len(req.ID) == 0 || string(req.ID) == "null"
	if notification {
		if req.Method == "notifications/cancelled" {
			var p struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			if json.Unmarshal(req.Params, &p) == nil {
				s.mu.Lock()
				if c := s.running[string(p.RequestID)]; c != nil {
					c()
				}
				s.mu.Unlock()
			}
		}
		// Other notifications (initialized and so on) need nothing.
		return
	}
	if req.Method == "" {
		// A response to a request of ours; this server sends none.
		return
	}
	switch req.Method {
	case "initialize":
		s.reply(req.ID, s.initialize(req.Params))
	case "ping":
		s.reply(req.ID, struct{}{})
	case "tools/list":
		s.reply(req.ID, map[string]any{"tools": s.toolList()})
	case "tools/call":
		s.startCall(ctx, req)
	case "resources/list":
		s.reply(req.ID, map[string]any{"resources": []any{}})
	case "prompts/list":
		s.reply(req.ID, map[string]any{"prompts": []any{}})
	default:
		s.send(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{codeNoMethod, "method not found: " + req.Method}})
	}
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
		ClientInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	}
	_ = json.Unmarshal(params, &p)
	version := protocolVersions[0]
	if slices.Contains(protocolVersions, p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	s.Log.Info("AI tool connected", "client", p.ClientInfo.Name, "client_version", p.ClientInfo.Version, "protocol", version)
	out := map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
	}
	if s.Instructions != "" {
		out["instructions"] = s.Instructions
	}
	return out
}

func (s *Server) toolList() []map[string]any {
	out := make([]map[string]any, 0, len(s.Tools))
	for _, t := range s.Tools {
		m := map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.Schema,
			// Every tool only reads, and only from the Signalith server.
			"annotations": map[string]any{"title": t.Title, "readOnlyHint": true, "destructiveHint": false,
				"idempotentHint": true, "openWorldHint": false},
		}
		if t.Title != "" {
			m["title"] = t.Title
		}
		out = append(out, m)
	}
	return out
}

func (s *Server) tool(name string) *Tool {
	for i := range s.Tools {
		if s.Tools[i].Name == name {
			return &s.Tools[i]
		}
	}
	return nil
}

func (s *Server) startCall(ctx context.Context, req request) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.send(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{codeInvalidParams, "params: " + err.Error()}})
		return
	}
	t := s.tool(p.Name)
	if t == nil {
		s.send(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{codeInvalidParams, "unknown tool: " + p.Name}})
		return
	}
	if len(p.Arguments) == 0 || string(p.Arguments) == "null" {
		p.Arguments = json.RawMessage("{}")
	}
	ctx, cancel := context.WithCancel(ctx)
	key := string(req.ID)
	s.mu.Lock()
	s.running[key] = cancel
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.running, key)
			s.mu.Unlock()
			cancel()
		}()
		res, err := t.Call(ctx, p.Arguments)
		if ctx.Err() != nil && err != nil {
			// Cancelled: the client expects no answer.
			return
		}
		if err != nil {
			s.Log.Info("tool call failed", "tool", t.Name, "error", err)
			s.reply(req.ID, toolResult(err.Error(), true))
			return
		}
		text, err := json.MarshalIndent(res, "", " ")
		if err != nil {
			s.reply(req.ID, toolResult(err.Error(), true))
			return
		}
		s.reply(req.ID, toolResult(string(text), false))
	}()
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isError}
}

func (s *Server) reply(id json.RawMessage, result any) {
	s.send(response{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *Server) send(r response) {
	b, err := json.Marshal(r)
	if err != nil {
		b, _ = json.Marshal(response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{-32603, fmt.Sprint("could not write the answer: ", err)}})
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		s.Log.Warn("could not write to the AI tool", "error", err)
	}
}
