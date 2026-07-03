package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestServeProtocol(t *testing.T) {
	srv := &Server{
		Name:    "test",
		Version: "0",
		Tools: []Tool{{
			Name:        "echo",
			Description: "echo back the arguments",
			InputSchema: map[string]any{"type": "object"},
			Handler: func(_ context.Context, args json.RawMessage) (string, error) {
				return "hello:" + string(args), nil
			},
		}},
	}

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, // notification: no reply
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"bogus"}`,
	}, "\n") + "\n"

	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	// Collect responses keyed by id.
	byID := map[float64]map[string]any{}
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad response line %q: %v", sc.Text(), err)
		}
		id, ok := m["id"].(float64)
		if !ok {
			t.Fatalf("response without numeric id: %v", m)
		}
		byID[id] = m
	}

	// The notification must NOT have produced a response.
	if len(byID) != 5 {
		t.Fatalf("got %d responses, want 5 (notification gets none): %v", len(byID), byID)
	}

	// initialize
	initRes := byID[1]["result"].(map[string]any)
	if initRes["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v", initRes["protocolVersion"])
	}

	// tools/list contains echo
	tools := byID[2]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "echo" {
		t.Errorf("tools/list = %v", tools)
	}

	// tools/call echo succeeds
	call := byID[3]["result"].(map[string]any)
	if call["isError"] != false {
		t.Errorf("echo isError = %v, want false", call["isError"])
	}
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.HasPrefix(text, "hello:") {
		t.Errorf("echo text = %q", text)
	}

	// unknown tool -> protocol error
	if _, hasErr := byID[4]["error"]; !hasErr {
		t.Errorf("unknown tool should return an error: %v", byID[4])
	}

	// unknown method -> method-not-found
	if e, ok := byID[5]["error"].(map[string]any); !ok || e["code"].(float64) != codeMethodNotFound {
		t.Errorf("bogus method error = %v", byID[5]["error"])
	}
}
