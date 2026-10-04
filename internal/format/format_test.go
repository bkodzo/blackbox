package format

import (
	"reflect"
	"strings"
	"testing"
	"time"
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
	if got := rq.Messages[2].ToolCalls; !reflect.DeepEqual(got, []ToolCall{{"call_1", "list_dir", `{"path":"./docs"}`}}) {
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
	if !reflect.DeepEqual(rq.Messages[1].ToolCalls, []ToolCall{{"tu_1", "list_dir", `{"path":"./docs"}`}}) || !reflect.DeepEqual(rq.Messages[2].ToolResultFor, []string{"tu_1"}) {
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
			if got, _ := findTextToolCalls(c.text); !reflect.DeepEqual(got, c.want) {
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

func TestCacheMarkersDoNotChangeMessageHashes(t *testing.T) {
	a := Parse([]byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`), nil, false)
	b := Parse([]byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`), nil, false)
	if a.Request.Messages[0].SHA256 != b.Request.Messages[0].SHA256 {
		t.Fatal("a moved cache marker changed the message hash")
	}
}

func TestOnlyLeadingSystemMessagesAreTheSystemPrompt(t *testing.T) {
	base := `{"role":"system","content":"Be careful."},{"role":"user","content":"hi"}`
	a := Parse([]byte(`{"messages":[`+base+`]}`), nil, false)
	b := Parse([]byte(`{"messages":[`+base+`,{"role":"system","content":"Tool output follows."}]}`), nil, false)
	if a.Request.SystemSHA256 == "" || a.Request.SystemSHA256 != b.Request.SystemSHA256 {
		t.Fatal("a mid-conversation system message changed the system prompt hash")
	}
}

func TestCanonicalArgs(t *testing.T) {
	if CanonicalArgs(`{"b": 1, "a": "x"}`) != CanonicalArgs(`{"a":"x","b":1}`) {
		t.Fatal("equal arguments compared unequal")
	}
	if CanonicalArgs("not json") != "not json" {
		t.Fatal("non-JSON arguments were changed")
	}
}

func TestSchemaDescriptionIsNotATextToolCall(t *testing.T) {
	text := `The tool looks like {"name":"read_file","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}`
	if got, _ := findTextToolCalls(text); got != nil {
		t.Fatalf("schema description reported as a call: %+v", got)
	}
}

func TestNumbersCompareByValue(t *testing.T) {
	if CanonicalArgs(`{"limit":1.0}`) != CanonicalArgs(`{"limit":1}`) || CanonicalArgs(`{"n":1e2}`) != CanonicalArgs(`{"n":100}`) {
		t.Fatal("equal numbers compared unequal")
	}
	if CanonicalArgs(`{"n":0.1}`) == CanonicalArgs(`{"n":0.10000001}`) {
		t.Fatal("different numbers compared equal")
	}
}

func TestAnnotationsInsideArgumentsAreKept(t *testing.T) {
	if CanonicalArgs(`{"cache_control":"no-store"}`) == CanonicalArgs(`{"cache_control":"public"}`) {
		t.Fatal("a cache_control argument was stripped")
	}
	a := Parse([]byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"c","function":{"name":"set_header","arguments":"{\"cache_control\":\"no-store\"}"}}]}]}`), nil, false)
	b := Parse([]byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"c","function":{"name":"set_header","arguments":"{\"cache_control\":\"public\"}"}}]}]}`), nil, false)
	if a.Request.Messages[0].SHA256 == b.Request.Messages[0].SHA256 {
		t.Fatal("changing a tool argument named cache_control did not change the message hash")
	}
}

func TestStreamedCallsWithoutIndexStaySeparate(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"id":"a","function":{"name":"list_dir","arguments":"{}"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"id":"b","function":{"name":"read_file","arguments":"{}"}}]}}]}`,
	}, "\n\n")
	p := Parse(nil, []byte(stream), true)
	want := []ToolCall{{"a", "list_dir", "{}"}, {"b", "read_file", "{}"}}
	if !reflect.DeepEqual(p.Response.ToolCalls, want) {
		t.Fatalf("calls %+v", p.Response.ToolCalls)
	}
}

func TestOtherTextCallShapes(t *testing.T) {
	got, _ := findTextToolCalls(`{"action":"run_shell","action_input":"ls"} and {"tool":"read_file","tool_input":{"path":"a"}}`)
	want := []ToolCall{{Name: "run_shell", Arguments: "ls"}, {Name: "read_file", Arguments: `{"path":"a"}`}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestCodeBeforeACallDoesNotHideIt(t *testing.T) {
	code := strings.Repeat("{x} ", 200)
	got, _ := findTextToolCalls(code + `{"name":"rm","parameters":{"path":"/"}}`)
	if len(got) != 1 || got[0].Name != "rm" {
		t.Fatalf("got %+v", got)
	}
}

// Third review.

func TestHugeExponentsStayShort(t *testing.T) {
	start := time.Now()
	out := CanonicalArgs(`[` + strings.Repeat(`1e1000000,`, 1000) + `1]`)
	// Before the fix this was over 1 GB; the time limit is generous so slow
	// or race-instrumented runners do not make the test flaky.
	if len(out) > 20000 || time.Since(start) > 5*time.Second {
		t.Fatalf("canonicalizing 10 KB of exponents produced %d bytes in %v", len(out), time.Since(start))
	}
}

func TestCanonicalNumbers(t *testing.T) {
	equal := [][2]string{
		{"1", "1.0"}, {"100", "1e2"}, {"1.5", "15e-1"}, {"0", "-0.0"}, {"0.001", "1E-3"},
		{"1" + strings.Repeat("0", 80), "1e80"}, {"1." + strings.Repeat("0", 70), "1"},
	}
	for _, p := range equal {
		if canonicalNumber(p[0]) != canonicalNumber(p[1]) {
			t.Errorf("%s and %s differ: %s vs %s", p[0], p[1], canonicalNumber(p[0]), canonicalNumber(p[1]))
		}
	}
	different := [][2]string{{"1", "-1"}, {"0.1", "0.10000001"}, {"9007199254740993", "9007199254740992"}, {"1e400", "1e401"}}
	for _, p := range different {
		if canonicalNumber(p[0]) == canonicalNumber(p[1]) {
			t.Errorf("%s and %s compared equal", p[0], p[1])
		}
	}
}

func TestDuplicateKeysAreNotMerged(t *testing.T) {
	if CanonicalArgs(`{"cmd":"rm -rf /","cmd":"ls"}`) == CanonicalArgs(`{"cmd":"ls"}`) {
		t.Fatal("a duplicate key hid a different value")
	}
	if CanonicalArgs(`{"a":{"x":1,"x":2}}`) == CanonicalArgs(`{"a":{"x":2}}`) {
		t.Fatal("a nested duplicate key hid a different value")
	}
}

func TestInvalidTextIsNotMerged(t *testing.T) {
	backslash := string(rune(92))
	a := `{"s":"` + backslash + `ud800"}`
	b := `{"s":"` + backslash + `udfff"}`
	if CanonicalArgs(a) == CanonicalArgs(b) {
		t.Fatal("different lone surrogates compared equal")
	}
	if CanonicalArgs("{\"s\":\"\xff\"}") == CanonicalArgs("{\"s\":\"\xfe\"}") {
		t.Fatal("different invalid bytes compared equal")
	}
}

func TestNestedTextCalls(t *testing.T) {
	text := `{"tool_calls":[{"type":"function","function":{"name":"run_shell","arguments":"{\"cmd\":\"ls\"}"}}]} ` +
		`{"thought":"go","action":{"name":"read_file","arguments":{"path":"a"}}}`
	got, partial := findTextToolCalls(text)
	if partial || len(got) != 2 || got[0].Name != "run_shell" || got[1].Name != "read_file" {
		t.Fatalf("got %+v partial %v", got, partial)
	}
}

func TestJunkBeforeACallDoesNotHideIt(t *testing.T) {
	got, partial := findTextToolCalls(strings.Repeat(`{"`, 1024) + ` {"name":"run_shell","arguments":{"cmd":"rm"}}`)
	if partial || len(got) != 1 || got[0].Name != "run_shell" {
		t.Fatalf("got %+v partial %v", got, partial)
	}
}

func TestHostileTextIsCheapAndFlagged(t *testing.T) {
	start := time.Now()
	_, partial := findTextToolCalls(strings.Repeat(`{"a":`, 13000)) // about 64 KB of unterminated nesting
	// Unbounded, this took seconds per reply; the limit leaves room for slow
	// or race-instrumented runners.
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("scan took %v", elapsed)
	}
	if !partial {
		t.Fatal("an incomplete scan was not reported")
	}
	if _, partial := findTextToolCalls(strings.Repeat("x", maxTextScan+1)); !partial {
		t.Fatal("text beyond the scan limit was not reported")
	}
}

func TestStreamWithAFreshIDPerChunk(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"id":"a1","function":{"name":"run_shell","arguments":"{\"cmd\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"id":"a2","function":{"arguments":"\"ls\"}"}}]}}]}`,
	}, "\n\n")
	p := Parse(nil, []byte(stream), true)
	if want := []ToolCall{{"a1", "run_shell", `{"cmd":"ls"}`}}; !reflect.DeepEqual(p.Response.ToolCalls, want) {
		t.Fatalf("calls %+v", p.Response.ToolCalls)
	}
}

func TestStreamCallsWithoutIndexOrID(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"list_dir","arguments":"{}"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"list_dir","arguments":"{\"path\":\"a\"}"}}]}}]}`,
	}, "\n\n")
	p := Parse(nil, []byte(stream), true)
	if len(p.Response.ToolCalls) != 2 || p.Response.ToolCalls[1].Arguments != `{"path":"a"}` {
		t.Fatalf("calls %+v", p.Response.ToolCalls)
	}
}

func TestStreamRepeatingNameEveryChunk(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"run_shell","arguments":"{\"cmd\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"run_shell","arguments":"\"ls\"}"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"run_shell","arguments":""}}]}}]}`,
	}, "\n\n")
	p := Parse(nil, []byte(stream), true)
	if want := []ToolCall{{"c", "run_shell", `{"cmd":"ls"}`}}; !reflect.DeepEqual(p.Response.ToolCalls, want) {
		t.Fatalf("calls %+v", p.Response.ToolCalls)
	}
}

func TestNestedCacheMarkersInToolResults(t *testing.T) {
	a := Parse([]byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"ok"}]}]}]}`), nil, false)
	b := Parse([]byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"ok","cache_control":{"type":"ephemeral"}}]}]}]}`), nil, false)
	if a.Request.Messages[0].SHA256 != b.Request.Messages[0].SHA256 {
		t.Fatal("a cache marker inside a tool result changed the hash")
	}
}
