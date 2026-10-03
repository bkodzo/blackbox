package format

import (
	"reflect"
	"strings"
	"testing"
)

const chatRequest = `{
  "model": "test-model",
  "stream": false,
  "messages": [
    {"role": "system", "content": "You are a file helper."},
    {"role": "user", "content": "Summarize ./docs"},
    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "list_dir", "arguments": "{\"path\":\"./docs\"}"}}]},
    {"role": "tool", "tool_call_id": "call_1", "content": "a.md"}
  ],
  "tools": [{"type": "function", "function": {"name": "list_dir", "parameters": {}}},
            {"type": "function", "function": {"name": "read_file", "parameters": {}}}]
}`

func TestChatResponse(t *testing.T) {
	resp := `{"id":"x","model":"test-model-v2","system_fingerprint":"fp_1",
	  "choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant",
	    "tool_calls":[{"id":"call_2","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"./docs/a.md\"}"}}]}}],
	  "usage":{"prompt_tokens":40,"completion_tokens":12,"total_tokens":52}}`
	p := Parse([]byte(chatRequest), []byte(resp), false)

	if p.Format != Chat {
		t.Fatalf("format %q", p.Format)
	}
	rq := p.Request
	if rq.Model != "test-model" || len(rq.Messages) != 4 || rq.SystemSHA256 == "" || rq.ToolsSHA256 == "" {
		t.Fatalf("request %+v", rq)
	}
	if !reflect.DeepEqual(rq.Tools, []string{"list_dir", "read_file"}) {
		t.Fatalf("tools %v", rq.Tools)
	}
	if got := rq.Messages[2].ToolCallIDs; !reflect.DeepEqual(got, []string{"call_1"}) {
		t.Fatalf("assistant tool call ids %v", got)
	}
	if got := rq.Messages[3].ToolResultFor; !reflect.DeepEqual(got, []string{"call_1"}) {
		t.Fatalf("tool result ids %v", got)
	}
	want := Response{
		Model: "test-model-v2", FinishReason: "tool_calls", SystemFingerprint: "fp_1",
		ToolCalls: []ToolCall{{"call_2", "read_file", `{"path":"./docs/a.md"}`}},
		Input:     40, Output: 12, Total: 52,
	}
	if !reflect.DeepEqual(p.Response, want) {
		t.Fatalf("response\n got %+v\nwant %+v", p.Response, want)
	}
}

func TestChatStream(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"model":"test-model","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		`data: {"model":"test-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_9","function":{"name":"read_file","arguments":""}}]}}]}`,
		`data: {"model":"test-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":"}}]}}]}`,
		`data: {"model":"test-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"a.md\"}"}}]}}]}`,
		`data: {"model":"test-model","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: {"model":"test-model","choices":[],"usage":{"prompt_tokens":30,"completion_tokens":9}}`,
		`data: [DONE]`,
	}, "\n\n")
	p := Parse([]byte(chatRequest), []byte(stream), true)
	if p.Format != Chat || p.Response.Chunks != 6 || p.Response.FinishReason != "tool_calls" {
		t.Fatalf("parsed %+v", p)
	}
	if want := []ToolCall{{"call_9", "read_file", `{"path":"a.md"}`}}; !reflect.DeepEqual(p.Response.ToolCalls, want) {
		t.Fatalf("tool calls %+v", p.Response.ToolCalls)
	}
	if p.Response.Input != 30 || p.Response.Output != 9 || p.Response.Total != 39 {
		t.Fatalf("usage %+v", p.Response)
	}
}

const blocksRequest = `{
  "model": "test-model", "max_tokens": 512, "system": "You are a file helper.",
  "messages": [
    {"role": "user", "content": "Summarize ./docs"},
    {"role": "assistant", "content": [{"type": "tool_use", "id": "tu_1", "name": "list_dir", "input": {"path": "./docs"}}]},
    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu_1", "content": "a.md"}]}
  ],
  "tools": [{"name": "list_dir", "input_schema": {}}]
}`

func TestBlocksResponse(t *testing.T) {
	resp := `{"type":"message","model":"test-model","stop_reason":"tool_use",
	  "content":[{"type":"text","text":"Reading it."},{"type":"tool_use","id":"tu_2","name":"read_file","input":{"path": "a.md"}}],
	  "usage":{"input_tokens":50,"output_tokens":20}}`
	p := Parse([]byte(blocksRequest), []byte(resp), false)
	if p.Format != Blocks || p.Response.FinishReason != "tool_use" || p.Response.Total != 70 {
		t.Fatalf("parsed %+v", p)
	}
	if want := []ToolCall{{"tu_2", "read_file", `{"path":"a.md"}`}}; !reflect.DeepEqual(p.Response.ToolCalls, want) {
		t.Fatalf("tool calls %+v", p.Response.ToolCalls)
	}
	rq := p.Request
	if rq.SystemSHA256 == "" || !reflect.DeepEqual(rq.Tools, []string{"list_dir"}) {
		t.Fatalf("request %+v", rq)
	}
	if !reflect.DeepEqual(rq.Messages[1].ToolCallIDs, []string{"tu_1"}) || !reflect.DeepEqual(rq.Messages[2].ToolResultFor, []string{"tu_1"}) {
		t.Fatalf("messages %+v", rq.Messages)
	}
}

func TestBlocksStream(t *testing.T) {
	stream := strings.Join([]string{
		"event: message_start",
		`data: {"type":"message_start","message":{"model":"test-model","usage":{"input_tokens":50,"output_tokens":1}}}`,
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_3","name":"read_file","input":{}}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\": "}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"a.md\"}"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":15}}`,
		`data: {"type":"message_stop"}`,
	}, "\n")
	p := Parse([]byte(blocksRequest), []byte(stream), true)
	if p.Format != Blocks || p.Response.FinishReason != "tool_use" || p.Response.Input != 50 || p.Response.Output != 15 {
		t.Fatalf("parsed %+v", p)
	}
	if want := []ToolCall{{"tu_3", "read_file", `{"path":"a.md"}`}}; !reflect.DeepEqual(p.Response.ToolCalls, want) {
		t.Fatalf("tool calls %+v", p.Response.ToolCalls)
	}
}

func TestErrorResponseFallsBackToRequestShape(t *testing.T) {
	errBody := []byte(`{"error":{"message":"model not found"}}`)
	if f := Parse([]byte(chatRequest), errBody, false).Format; f != Chat {
		t.Fatalf("chat request: %q", f)
	}
	if f := Parse([]byte(blocksRequest), errBody, false).Format; f != Blocks {
		t.Fatalf("blocks request: %q", f)
	}
}

func TestUnknownFormat(t *testing.T) {
	p := Parse([]byte(`{"prompt":"hi"}`), []byte(`{"text":"hello"}`), false)
	if p.Format != Unknown {
		t.Fatalf("format %q", p.Format)
	}
	p = Parse([]byte("not json"), []byte("also not json"), false)
	if p.Format != Unknown {
		t.Fatalf("format %q", p.Format)
	}
}

func TestMessageHashIgnoresSerialization(t *testing.T) {
	a := Parse([]byte(`{"messages":[{"role":"user","content":"hi"}]}`), nil, false)
	b := Parse([]byte(`{"messages":[ { "content" : "hi", "role" : "user" } ]}`), nil, false)
	if a.Request.Messages[0].SHA256 != b.Request.Messages[0].SHA256 {
		t.Fatal("same message hashed differently")
	}
	c := Parse([]byte(`{"messages":[{"role":"user","content":"hi!"}]}`), nil, false)
	if a.Request.Messages[0].SHA256 == c.Request.Messages[0].SHA256 {
		t.Fatal("different messages hashed the same")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(chatRequest), []byte(`{"choices":[]}`), false)
	f.Add([]byte(blocksRequest), []byte("data: {\"type\":\"message_start\"}\n"), true)
	f.Add([]byte(`{"messages":[{"content":[{"type":"tool_result"}]}]}`), []byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":-1}]}}]}"), true)
	f.Fuzz(func(t *testing.T, req, resp []byte, sse bool) {
		Parse(req, resp, sse) // must never panic
	})
}

func TestTextToolCalls(t *testing.T) {
	cases := []struct {
		name, text string
		want       []ToolCall
	}{
		{"bare call", `{"name":"list_dir","parameters":{"path":"."}}`,
			[]ToolCall{{Name: "list_dir", Arguments: `{"path":"."}`}}},
		{"two calls in prose", `Sure. {"name": "rm", "parameters": {"path": "notes.md"}}; {"name": "rm", "parameters": {"path": "plan.txt"}} Done.`,
			[]ToolCall{{Name: "rm", Arguments: `{"path":"notes.md"}`}, {Name: "rm", Arguments: `{"path":"plan.txt"}`}}},
		{"wrapped and string arguments", "```json\n{\"function\":{\"name\":\"run_shell\",\"arguments\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}\n```",
			[]ToolCall{{Name: "run_shell", Arguments: `{"cmd":"ls"}`}}},
		{"plain prose", "Use {braces} carefully, and {not json either.", nil},
		{"object without arguments", `{"name":"report","pages":3}`, nil},
		{"name is a sentence", `{"name":"delete all the files","arguments":{}}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := findTextToolCalls(c.text); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestTextIsCollectedFromEveryShape(t *testing.T) {
	call := `{\"name\":\"rm\",\"parameters\":{\"path\":\"a.md\"}}`
	chat := `{"choices":[{"finish_reason":"stop","message":{"content":"` + call + `"}}]}`
	parts := `{"choices":[{"message":{"content":[{"type":"text","text":"` + call + `"}]}}]}`
	blocks := `{"type":"message","content":[{"type":"text","text":"` + call + `"}]}`
	chatStream := "data: {\"choices\":[{\"delta\":{\"content\":\"{\\\"name\\\":\\\"rm\\\",\"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"\\\"parameters\\\":{\\\"path\\\":\\\"a.md\\\"}}\"}}]}\n\n"
	blockStream := "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + call + "\"}}\n"

	for name, tc := range map[string]struct {
		resp string
		sse  bool
	}{"chat": {chat, false}, "parts": {parts, false}, "blocks": {blocks, false}, "chat stream": {chatStream, true}, "block stream": {blockStream, true}} {
		p := Parse(nil, []byte(tc.resp), tc.sse)
		if len(p.Response.TextToolCalls) != 1 || p.Response.TextToolCalls[0].Name != "rm" {
			t.Errorf("%s: text %q, calls %+v", name, p.Response.Text, p.Response.TextToolCalls)
		}
	}
}
