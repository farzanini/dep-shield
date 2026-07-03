// Package mcp implements a minimal Model Context Protocol server over the stdio
// transport, so AI agents can call dep-shield's scanners as MCP tools.
//
// Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout. Exactly one JSON
// message per line. stdout is reserved for protocol messages — all logging must
// go to stderr, or the agent's client will fail to parse the stream.
//
// Only the handful of methods an agent needs are implemented: initialize,
// tools/list, tools/call, and ping, plus the initialized/cancelled
// notifications (which get no reply).
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"go.uber.org/zap"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2024-11-05"

// Tool is one agent-callable capability.
type Tool struct {
	Name        string
	Description string
	// InputSchema is a JSON Schema object describing the tool's arguments.
	InputSchema map[string]any
	// Handler runs the tool and returns text content for the agent. A returned
	// error is reported to the agent as an tool-call result with isError=true
	// (not a protocol-level error), so the agent can read the message.
	Handler func(ctx context.Context, args json.RawMessage) (string, error)
}

// Server serves a set of Tools over the stdio transport.
type Server struct {
	Name    string
	Version string
	Tools   []Tool
	Log     *zap.Logger
}

// ── JSON-RPC wire types ───────────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParseError    = -32700
	codeMethodNotFound = -32601
	codeInvalidParams = -32602
)

// Serve runs the read/dispatch/write loop until in reaches EOF or ctx is done.
// Requests are handled sequentially, which keeps stdout writes uninterleaved.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Log == nil {
		s.Log = zap.NewNop()
	}
	reader := bufio.NewReader(in)
	enc := json.NewEncoder(out) // Encode writes compact JSON followed by '\n'

	s.Log.Info("mcp server started", zap.Int("tools", len(s.Tools)))

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, err := reader.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			if resp, ok := s.handle(ctx, trimmed); ok {
				if encErr := enc.Encode(resp); encErr != nil {
					return fmt.Errorf("writing response: %w", encErr)
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading request: %w", err)
		}
	}
}

// handle processes one message. The bool is false for notifications, which
// receive no response.
func (s *Server) handle(ctx context.Context, line []byte) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: codeParseError, Message: "parse error"}}, true
	}

	// A message without an id is a notification: handle side effects, no reply.
	isNotification := len(req.ID) == 0

	result, rpcErr := s.dispatch(ctx, req.Method, req.Params)
	if isNotification {
		return rpcResponse{}, false
	}

	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	return resp, true
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "notifications/initialized", "notifications/cancelled":
		return nil, nil // notifications — dispatch result is discarded
	case "tools/list":
		return map[string]any{"tools": s.toolDescriptors()}, nil
	case "tools/call":
		return s.callTool(ctx, params)
	default:
		return nil, &rpcError{Code: codeMethodNotFound, Message: "method not found: " + method}
	}
}

func (s *Server) toolDescriptors() []map[string]any {
	out := make([]map[string]any, 0, len(s.Tools))
	for _, t := range s.Tools {
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": schema,
		})
	}
	return out
}

func (s *Server) callTool(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	for _, t := range s.Tools {
		if t.Name != p.Name {
			continue
		}
		text, err := t.Handler(ctx, p.Arguments)
		if err != nil {
			s.Log.Warn("tool call failed", zap.String("tool", p.Name), zap.Error(err))
			return toolResult(err.Error(), true), nil
		}
		return toolResult(text, false), nil
	}
	return nil, &rpcError{Code: codeInvalidParams, Message: "unknown tool: " + p.Name}
}

// toolResult builds the MCP tools/call result payload.
func toolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}
