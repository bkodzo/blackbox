// Package format extracts audit fields from model API traffic.
//
// Formats are recognized by the shape of the JSON, never by who served it.
// Two response shapes are understood:
//
//   - "chat":   responses carry a choices array (streamed as choice deltas)
//   - "blocks": responses carry typed content blocks (streamed as block events)
//
// Requests are parsed with one shape-tolerant reader that handles both. Any
// exchange that matches neither shape is reported as "unknown"; the caller
// still records its full bytes.
package format

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Format names.
const (
	Chat    = "chat"
	Blocks  = "blocks"
	Unknown = "unknown"
)

// Message is the part of a request message that session checks need.
type Message struct {
	Role          string
	SHA256        string   // hash of the message's canonical JSON
	ToolCallIDs   []string // tool calls this (assistant) message contains
	ToolResultFor []string // tool call IDs this message returns results for
}

// Request is what the agent asked for.
type Request struct {
	Model        string
	Stream       bool
	Messages     []Message
	SystemSHA256 string
	Tools        []string
	ToolsSHA256  string
}

// ToolCall is a tool invocation requested by the model.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// Response is what the model returned.
type Response struct {
	Model             string
	FinishReason      string
	SystemFingerprint string
	ToolCalls         []ToolCall
	Text              string     // assistant text, concatenated across parts and chunks
	TextToolCalls     []ToolCall // tool calls the model wrote as text instead of making them
	Input, Output     int        // token usage
	Total             int
	Chunks            int // stream events, 0 for non-streamed responses
}

// Parsed is the result of reading one exchange.
type Parsed struct {
	Format   string
	Request  Request
	Response Response
}

// Parse reads an exchange. sse reports whether resp is a server-sent event
// stream. Parsing never fails; unrecognized parts are left empty.
func Parse(req, resp []byte, sse bool) Parsed {
	p := Parsed{Format: Unknown}
	var hasMessages, blockHints bool
	p.Request, hasMessages, blockHints = parseRequest(req)

	if sse {
		p.Format = parseStream(resp, &p.Response)
	} else {
		p.Format = parseBody(resp, &p.Response)
	}
	if p.Format == Unknown && hasMessages {
		// Typically an error response. Fall back to the request's shape.
		p.Format = Chat
		if blockHints {
			p.Format = Blocks
		}
	}
	if p.Response.Total == 0 {
		p.Response.Total = p.Response.Input + p.Response.Output
	}
	p.Response.TextToolCalls = findTextToolCalls(p.Response.Text)
	return p
}

type rawRequest struct {
	Model    string            `json:"model"`
	Stream   bool              `json:"stream"`
	System   json.RawMessage   `json:"system"`
	Messages []json.RawMessage `json:"messages"`
	Tools    []json.RawMessage `json:"tools"`
}

type rawMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCallID string          `json:"tool_call_id"`
	ToolCalls  []struct {
		ID string `json:"id"`
	} `json:"tool_calls"`
}

type rawBlock struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	ToolUseID string `json:"tool_use_id"`
}

func parseRequest(body []byte) (r Request, hasMessages, blockHints bool) {
	var raw rawRequest
	if json.Unmarshal(body, &raw) != nil {
		return r, false, false
	}
	r.Model, r.Stream = raw.Model, raw.Stream
	hasMessages = raw.Messages != nil
	blockHints = len(raw.System) > 0

	sys := sha256.New()
	sysSeen := false
	if len(raw.System) > 0 {
		sys.Write(canonical(raw.System))
		sysSeen = true
	}

	r.Messages = make([]Message, 0, len(raw.Messages))
	for _, m := range raw.Messages {
		var rm rawMessage
		json.Unmarshal(m, &rm)
		c := canonical(m)
		msg := Message{Role: rm.Role, SHA256: hexSum(c)}
		for _, tc := range rm.ToolCalls {
			msg.ToolCallIDs = append(msg.ToolCallIDs, tc.ID)
		}
		if rm.ToolCallID != "" {
			msg.ToolResultFor = append(msg.ToolResultFor, rm.ToolCallID)
		}
		var blocks []rawBlock
		if json.Unmarshal(rm.Content, &blocks) == nil {
			for _, b := range blocks {
				switch b.Type {
				case "tool_use":
					msg.ToolCallIDs = append(msg.ToolCallIDs, b.ID)
					blockHints = true
				case "tool_result":
					msg.ToolResultFor = append(msg.ToolResultFor, b.ToolUseID)
					blockHints = true
				}
			}
		}
		if rm.Role == "system" || rm.Role == "developer" {
			sys.Write(c)
			sysSeen = true
		}
		r.Messages = append(r.Messages, msg)
	}
	if sysSeen {
		r.SystemSHA256 = hex.EncodeToString(sys.Sum(nil))
	}

	if len(raw.Tools) > 0 {
		all := sha256.New()
		for _, t := range raw.Tools {
			var td struct {
				Name     string `json:"name"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			}
			json.Unmarshal(t, &td)
			name := td.Function.Name
			if name == "" {
				name = td.Name
			}
			r.Tools = append(r.Tools, name)
			all.Write(canonical(t))
		}
		r.ToolsSHA256 = hex.EncodeToString(all.Sum(nil))
	}
	return r, hasMessages, blockHints
}

// usage accepts every common spelling of token counts.
type usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func (u *usage) apply(r *Response) {
	if u == nil {
		return
	}
	// Streams report cumulative counts, sometimes more than once.
	r.Input = max(r.Input, u.PromptTokens, u.InputTokens)
	r.Output = max(r.Output, u.CompletionTokens, u.OutputTokens)
	r.Total = max(r.Total, u.TotalTokens)
}

type chatToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type contentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// body covers non-streamed responses of both shapes.
type body struct {
	Type              string `json:"type"`
	Model             string `json:"model"`
	SystemFingerprint string `json:"system_fingerprint"`
	Usage             *usage `json:"usage"`
	Choices           []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   json.RawMessage `json:"content"`
			ToolCalls []chatToolCall  `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	StopReason string         `json:"stop_reason"`
	Content    []contentBlock `json:"content"`
}

func parseBody(b []byte, r *Response) string {
	var v body
	if json.Unmarshal(b, &v) != nil {
		return Unknown
	}
	r.Model, r.SystemFingerprint = v.Model, v.SystemFingerprint
	v.Usage.apply(r)
	switch {
	case v.Choices != nil:
		for _, c := range v.Choices {
			if c.FinishReason != "" {
				r.FinishReason = c.FinishReason
			}
			r.Text += textOf(c.Message.Content)
			for _, tc := range c.Message.ToolCalls {
				r.ToolCalls = append(r.ToolCalls, ToolCall{tc.ID, tc.Function.Name, tc.Function.Arguments})
			}
		}
		return Chat
	case v.Type == "message" || v.Content != nil:
		r.FinishReason = v.StopReason
		for _, c := range v.Content {
			switch c.Type {
			case "text":
				r.Text += c.Text
			case "tool_use":
				r.ToolCalls = append(r.ToolCalls, ToolCall{c.ID, c.Name, string(compact(c.Input))})
			}
		}
		return Blocks
	}
	return Unknown
}

// event covers stream events of both shapes.
type event struct {
	Type              string `json:"type"`
	Model             string `json:"model"`
	SystemFingerprint string `json:"system_fingerprint"`
	Usage             *usage `json:"usage"`
	Choices           []struct {
		FinishReason string `json:"finish_reason"`
		Delta        struct {
			Content   string         `json:"content"`
			ToolCalls []chatToolCall `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
	Message *struct {
		Model string `json:"model"`
		Usage *usage `json:"usage"`
	} `json:"message"`
	Index        int          `json:"index"`
	ContentBlock contentBlock `json:"content_block"`
	Delta        struct {
		StopReason  string `json:"stop_reason"`
		PartialJSON string `json:"partial_json"`
		Text        string `json:"text"`
	} `json:"delta"`
}

func parseStream(b []byte, r *Response) string {
	format := Unknown
	// Tool calls arrive in pieces keyed by index; arguments are concatenated.
	calls := map[int]*ToolCall{}
	var order []int
	call := func(i int) *ToolCall {
		c, ok := calls[i]
		if !ok {
			c = &ToolCall{}
			calls[i] = c
			order = append(order, i)
		}
		return c
	}
	args := map[int]*bytes.Buffer{}
	var text strings.Builder

	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20)
	for sc.Scan() {
		data, ok := bytes.CutPrefix(sc.Bytes(), []byte("data:"))
		if !ok {
			continue
		}
		data = bytes.TrimSpace(data)
		var e event
		if json.Unmarshal(data, &e) != nil {
			continue // e.g. the "[DONE]" sentinel
		}
		r.Chunks++
		if e.Model != "" {
			r.Model = e.Model
		}
		if e.SystemFingerprint != "" {
			r.SystemFingerprint = e.SystemFingerprint
		}
		e.Usage.apply(r)

		if e.Choices != nil {
			format = Chat
			for _, c := range e.Choices {
				if c.FinishReason != "" {
					r.FinishReason = c.FinishReason
				}
				text.WriteString(c.Delta.Content)
				for _, d := range c.Delta.ToolCalls {
					tc := call(d.Index)
					if d.ID != "" {
						tc.ID = d.ID
					}
					if d.Function.Name != "" {
						tc.Name = d.Function.Name
					}
					tc.Arguments += d.Function.Arguments
				}
			}
			continue
		}
		switch e.Type {
		case "message_start":
			format = Blocks
			if e.Message != nil {
				if e.Message.Model != "" {
					r.Model = e.Message.Model
				}
				e.Message.Usage.apply(r)
			}
		case "content_block_start":
			format = Blocks
			if e.ContentBlock.Type == "tool_use" {
				tc := call(e.Index)
				tc.ID, tc.Name = e.ContentBlock.ID, e.ContentBlock.Name
				args[e.Index] = &bytes.Buffer{}
			}
		case "content_block_delta":
			if buf, ok := args[e.Index]; ok {
				buf.WriteString(e.Delta.PartialJSON)
			}
			text.WriteString(e.Delta.Text)
		case "message_delta":
			format = Blocks
			if e.Delta.StopReason != "" {
				r.FinishReason = e.Delta.StopReason
			}
		}
	}

	r.Text = text.String()
	for _, i := range order {
		tc := calls[i]
		if buf, ok := args[i]; ok {
			tc.Arguments = string(compact(buf.Bytes()))
		}
		r.ToolCalls = append(r.ToolCalls, *tc)
	}
	return format
}

// canonical re-encodes JSON with sorted keys and no insignificant space, so
// equal values hash equally regardless of how a client serialized them.
func canonical(b []byte) []byte {
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return b
	}
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return out
}

func compact(b []byte) []byte {
	if len(b) == 0 {
		return []byte("{}")
	}
	var buf bytes.Buffer
	if json.Compact(&buf, b) != nil {
		return b
	}
	return buf.Bytes()
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
