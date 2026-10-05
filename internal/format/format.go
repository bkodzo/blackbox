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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
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
	SHA256        string     // hash of the message's canonical JSON
	TextSHA256    string     // hash of the message's text, "" if it has none
	ToolCalls     []ToolCall // calls in an assistant message; Arguments are canonical
	ToolResultFor []string   // tool call IDs this message returns results for
}

// Request is what the agent asked for.
type Request struct {
	Model        string
	Stream       bool
	Messages     []Message
	SystemSHA256 string
	Tools        []string
	ToolsSHA256  string
	// CaseVariantKeys lists keys that differ from a known field only in
	// letter case. blackbox's parser matches them case-insensitively, but a
	// model server may not, so the two could read different content.
	CaseVariantKeys []string
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
	Text              string     // assistant text without inline reasoning, concatenated across parts and chunks
	FullText          string     // assistant text as returned, including any inline think sections
	TextToolCalls     []ToolCall // tool calls the model wrote as text instead of making them
	TextScanPartial   bool       // the text was too long or complex to scan completely
	Reasoning         string     // the model's reasoning, when the server returns it
	ReasoningRedacted int        // reasoning blocks the server returned only in encrypted form
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
	// Some models write their reasoning inline, between think tags, even when
	// the server also returns a reasoning field. Keep the reply as returned
	// for comparison, and the visible part for the text call search.
	p.Response.FullText = p.Response.Text
	visible, inline := splitThinking(p.Response.Text)
	p.Response.Text = visible
	if inline != "" {
		if p.Response.Reasoning != "" {
			p.Response.Reasoning += "\n\n"
		}
		p.Response.Reasoning += inline
	}
	p.Response.TextToolCalls, p.Response.TextScanPartial = findTextToolCalls(p.Response.Text)
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
	ToolCalls  []chatToolCall  `json:"tool_calls"`
}

type rawBlock struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
}

func parseRequest(body []byte) (r Request, hasMessages, blockHints bool) {
	var raw rawRequest
	if json.Unmarshal(body, &raw) != nil {
		return r, false, false
	}
	r.CaseVariantKeys = caseVariantKeys(body)
	r.Model, r.Stream = raw.Model, raw.Stream
	hasMessages = raw.Messages != nil
	blockHints = len(raw.System) > 0

	sys := sha256.New()
	sysSeen := false
	if len(raw.System) > 0 {
		sys.Write(canonicalMessage(raw.System))
		sysSeen = true
	}

	leading := true // system messages count as the system prompt only before the conversation starts
	r.Messages = make([]Message, 0, len(raw.Messages))
	for _, m := range raw.Messages {
		var rm rawMessage
		json.Unmarshal(m, &rm)
		c := canonicalMessage(m)
		msg := Message{Role: rm.Role, SHA256: hexSum(c)}
		msg.TextSHA256 = TextHash(textOf(rm.Content))
		for _, tc := range rm.ToolCalls {
			msg.ToolCalls = append(msg.ToolCalls, ToolCall{tc.ID, tc.Function.Name, CanonicalArgs(tc.Function.Arguments)})
		}
		if rm.ToolCallID != "" {
			msg.ToolResultFor = append(msg.ToolResultFor, rm.ToolCallID)
		}
		var blocks []rawBlock
		if json.Unmarshal(rm.Content, &blocks) == nil {
			for _, b := range blocks {
				switch b.Type {
				case "tool_use":
					msg.ToolCalls = append(msg.ToolCalls, ToolCall{b.ID, b.Name, string(canonical(compact(b.Input)))})
					blockHints = true
				case "tool_result":
					msg.ToolResultFor = append(msg.ToolResultFor, b.ToolUseID)
					blockHints = true
				}
			}
		}
		if leading && (rm.Role == "system" || rm.Role == "developer") {
			sys.Write(c)
			sysSeen = true
		} else {
			leading = false
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
			all.Write(canonicalMessage(t))
		}
		r.ToolsSHA256 = hex.EncodeToString(all.Sum(nil))
	}
	return r, hasMessages, blockHints
}

// CanonicalArgs normalizes tool call arguments so that the same arguments
// serialized differently compare equal. Non-JSON arguments are returned as is.
func CanonicalArgs(args string) string {
	if !json.Valid([]byte(args)) {
		return args
	}
	return string(canonical([]byte(args)))
}

// TextHash is the hash used for comparing reply text, "" for empty text.
// Text is hashed as given: agent-supplied text is never filtered, so nothing
// can be hidden from the comparison. The model's side is hashed both with and
// without its inline reasoning (see ReplyHashes).
func TextHash(text string) string {
	if text = strings.TrimSpace(text); text == "" {
		return ""
	}
	return hexSum([]byte(text))
}

// ReplyHashes returns the hashes an echo of a model reply may match: the
// reply as returned, and the reply with its inline reasoning removed (agents
// often strip it before sending a reply back).
func ReplyHashes(full, visible string) (asReturned, withoutReasoning string) {
	return TextHash(full), TextHash(visible)
}

var thinkTags = regexp.MustCompile(`(?s)<think>(.*?)</think>`)

// splitThinking separates reasoning a model wrote between think tags from
// the rest of its reply. Some chat templates open the think section in the
// prompt, so the reply starts inside it and only the closing tag appears.
func splitThinking(text string) (visible, reasoning string) {
	var parts []string
	open, end := strings.Index(text, "<think>"), strings.Index(text, "</think>")
	if end >= 0 && (open < 0 || end < open) {
		parts = append(parts, strings.TrimSpace(text[:end]))
		text = text[end+len("</think>"):]
	}
	if strings.Contains(text, "<think>") {
		for _, m := range thinkTags.FindAllStringSubmatch(text, -1) {
			parts = append(parts, strings.TrimSpace(m[1]))
		}
		text = thinkTags.ReplaceAllString(text, "")
	}
	return text, strings.Join(parts, "\n\n")
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
	Type     string          `json:"type"`
	Text     string          `json:"text"`
	Thinking string          `json:"thinking"`
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
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
			reasoningFields
		} `json:"message"`
	} `json:"choices"`
	StopReason string         `json:"stop_reason"`
	Content    []contentBlock `json:"content"`
}

// reasoningFields are the names chat-shaped servers use for reasoning.
type reasoningFields struct {
	ReasoningContent string `json:"reasoning_content"`
	Reasoning        string `json:"reasoning"`
}

func (f reasoningFields) text() string {
	if f.ReasoningContent != "" {
		return f.ReasoningContent
	}
	return f.Reasoning
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
			r.Reasoning += c.Message.text()
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
			case "thinking":
				r.Reasoning += c.Thinking
			case "redacted_thinking":
				r.ReasoningRedacted++
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
			reasoningFields
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
		Thinking    string `json:"thinking"`
	} `json:"delta"`
}

func parseStream(b []byte, r *Response) string {
	format := Unknown
	// Tool calls arrive in pieces keyed by index; arguments are concatenated.
	calls := map[int]*ToolCall{}
	var order []int
	// Chat deltas are keyed by index, but some servers send every call at
	// index 0 (or omit it). A new ID at an index that already has a different
	// ID starts a new call.
	slot := map[int]int{}
	nextSlot := 0
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
	var text, reasoning strings.Builder

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
				reasoning.WriteString(c.Delta.text())
				for _, d := range c.Delta.ToolCalls {
					key, ok := slot[d.Index]
					if !ok || startsNewCall(calls[key], d) {
						key = nextSlot
						nextSlot++
						slot[d.Index] = key
					}
					tc := call(key)
					if tc.ID == "" {
						tc.ID = d.ID
					}
					if tc.Name == "" {
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
			if e.ContentBlock.Type == "redacted_thinking" {
				r.ReasoningRedacted++
			}
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
			reasoning.WriteString(e.Delta.Thinking)
		case "message_delta":
			format = Blocks
			if e.Delta.StopReason != "" {
				r.FinishReason = e.Delta.StopReason
			}
		}
	}

	r.Text, r.Reasoning = text.String(), reasoning.String()
	for _, i := range order {
		tc := calls[i]
		if buf, ok := args[i]; ok {
			tc.Arguments = string(compact(buf.Bytes()))
		}
		r.ToolCalls = append(r.ToolCalls, *tc)
	}
	return format
}

// annotationKeys are fields clients attach to messages, content blocks, and
// tool definitions for transport purposes, such as cache markers that move
// from turn to turn. They do not change what was said, so they are left out
// of those hashes. They are never removed from tool arguments or results.
var annotationKeys = []string{"cache_control"}

// startsNewCall reports whether a streamed tool call delta begins a new call
// rather than continuing cur. Servers differ: some reuse index 0 for every
// call, some repeat the ID or name in every chunk, some send a fresh ID per
// chunk. A new call carries its name, and starts after the previous call's
// arguments are complete.
func startsNewCall(cur *ToolCall, d chatToolCall) bool {
	name := d.Function.Name
	switch {
	case name == "":
		return false
	case d.ID != "" && cur.ID != "" && d.ID != cur.ID && cur.Name != "":
		return true
	case cur.Name != "" && json.Valid([]byte(cur.Arguments)):
		return name != cur.Name || strings.HasPrefix(strings.TrimSpace(d.Function.Arguments), "{")
	}
	return false
}

// canonical re-encodes JSON with sorted keys, no insignificant space, and
// numbers in one form, so equal content hashes equally regardless of how a
// client serialized it.
func canonical(b []byte) []byte { return canonicalize(b, nil) }

// canonicalMessage is canonical for a message, system prompt, or tool
// definition: annotation fields on the object itself and on its content
// blocks are dropped.
func canonicalMessage(b []byte) []byte { return canonicalize(b, stripAnnotations) }

func canonicalize(b []byte, strip func(any)) []byte {
	if !decodesFaithfully(b) {
		// Decoding would merge distinct inputs (duplicate keys, invalid
		// text), so hash the bytes as sent rather than risk hiding a change.
		return compact(b)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return b
	}
	if strip != nil {
		strip(v)
	}
	out, err := json.Marshal(normalizeNumbers(v))
	if err != nil {
		return b
	}
	return out
}

// stripAnnotations removes annotation keys from an object (or each object
// in an array, such as a list of system blocks), from the blocks in its
// content array, and from the blocks inside those blocks' own content (as in
// a tool result). It does not reach tool arguments or other values.
func stripAnnotations(v any) {
	switch v := v.(type) {
	case []any:
		for _, x := range v {
			if m, ok := x.(map[string]any); ok {
				dropKeys(m)
			}
		}
	case map[string]any:
		dropKeys(v)
		for _, block := range contentBlocks(v) {
			dropKeys(block)
			for _, inner := range contentBlocks(block) {
				dropKeys(inner)
			}
		}
	}
}

func contentBlocks(m map[string]any) []map[string]any {
	content, _ := m["content"].([]any)
	var blocks []map[string]any
	for _, x := range content {
		if b, ok := x.(map[string]any); ok {
			blocks = append(blocks, b)
		}
	}
	return blocks
}

// decodesFaithfully reports whether decoding b keeps every distinction in
// it. Duplicate keys (only the last survives) and invalid UTF-8 or lone
// surrogates (all become U+FFFD) would make different inputs look equal.
func decodesFaithfully(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	hasReplacement := bytes.ContainsRune(b, utf8.RuneError) || bytes.Contains(bytes.ToLower(b), []byte(`\ufffd`))
	type frame struct {
		object    bool
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err != nil {
			return true // end of input, or malformed: the full decode decides
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{object: true, keys: map[string]bool{}, expectKey: true})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			default:
				stack = stack[:len(stack)-1]
			}
		case string:
			if !hasReplacement && strings.ContainsRune(t, utf8.RuneError) {
				return false
			}
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
				// Keys equal apart from case collide in a struct decode.
				k := strings.ToLower(t)
				if stack[n-1].keys[k] {
					return false
				}
				stack[n-1].keys[k], stack[n-1].expectKey = true, false
				continue
			}
		}
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true // a value ended; a key comes next
		}
	}
}

func dropKeys(m map[string]any) {
	for _, k := range annotationKeys {
		delete(m, k)
	}
}

// normalizeNumbers rewrites every number in one canonical form, so 1, 1.0,
// and 1e0 compare equal while distinct values stay distinct.
func normalizeNumbers(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			v[k] = normalizeNumbers(x)
		}
	case []any:
		for i, x := range v {
			v[i] = normalizeNumbers(x)
		}
	case json.Number:
		return json.Number(canonicalNumber(string(v)))
	}
	return v
}

// canonicalNumber writes a JSON number as its significant digits and a
// power of ten ("15e-1" for 1.5, "1e2" for 100, "0" for any zero). It works
// on the digits as text, so the cost is linear in the input and a number like
// 1e1000000 stays short.
func canonicalNumber(n string) string {
	s := strings.ToLower(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	mant, expText, hasExp := strings.Cut(s, "e")
	var exp int64
	if hasExp {
		e, err := strconv.ParseInt(expText, 10, 64)
		if err != nil || e > 1<<40 || e < -(1<<40) {
			return n // absurd exponent: keep as written
		}
		exp = e
	}
	whole, frac, _ := strings.Cut(mant, ".")
	digits := strings.TrimLeft(whole+frac, "0")
	exp -= int64(len(frac))
	if digits == "" {
		return "0"
	}
	trimmed := strings.TrimRight(digits, "0")
	exp += int64(len(digits) - len(trimmed))
	out := trimmed
	if exp != 0 {
		out += "e" + strconv.FormatInt(exp, 10)
	}
	if neg {
		out = "-" + out
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

// knownFields are the request fields blackbox reads. A key that equals one
// of them only when case is ignored is ambiguous.
var knownFields = map[string]bool{
	"model": true, "stream": true, "system": true, "messages": true, "tools": true,
	"role": true, "content": true, "tool_calls": true, "tool_call_id": true,
	"type": true, "id": true, "name": true, "input": true, "tool_use_id": true,
	"function": true, "arguments": true, "parameters": true, "text": true,
}

// caseVariantKeys finds keys in a request that match a known field only
// when letter case is ignored, or that collide with another key in the same
// object that way. It returns at most a few, in order of appearance.
func caseVariantKeys(b []byte) []string {
	var found []string
	type frame struct {
		object    bool
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	dec := json.NewDecoder(bytes.NewReader(b))
	for len(found) < 5 {
		tok, err := dec.Token()
		if err != nil {
			return found
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{object: true, keys: map[string]bool{}, expectKey: true})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			default:
				stack = stack[:len(stack)-1]
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
				k := strings.ToLower(t)
				if (k != t && knownFields[k]) || stack[n-1].keys[k] {
					if !slices.Contains(found, t) {
						found = append(found, t)
					}
				}
				stack[n-1].keys[k], stack[n-1].expectKey = true, false
				continue
			}
		}
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	return found
}
