package format

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Small models often write a tool call into their reply text instead of
// making a structured call. Agents usually ignore it, but an auditor needs
// to see that the model tried. Detection is a heuristic: a JSON object with a
// tool-like name and arguments.
const (
	maxTextScan   = 64 << 10 // bytes of reply text examined
	maxCandidates = 64       // '{' positions tried, bounding work on hostile text
)

var toolName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)

func findTextToolCalls(text string) []ToolCall {
	if len(text) > maxTextScan {
		text = text[:maxTextScan]
	}
	var out []ToolCall
	for i, tries := 0, 0; i < len(text) && tries < maxCandidates; tries++ {
		j := strings.IndexByte(text[i:], '{')
		if j < 0 {
			break
		}
		i += j
		dec := json.NewDecoder(strings.NewReader(text[i:]))
		var obj map[string]json.RawMessage
		if dec.Decode(&obj) != nil {
			i++
			continue
		}
		if tc, ok := asToolCall(obj); ok {
			out = append(out, tc)
		}
		i += int(dec.InputOffset())
	}
	return out
}

// asToolCall accepts {"name":..., "arguments"|"parameters"|"input":...},
// optionally wrapped as {"function": {...}}.
func asToolCall(obj map[string]json.RawMessage) (ToolCall, bool) {
	if fn, ok := obj["function"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(fn, &inner) == nil {
			obj = inner
		}
	}
	var name string
	if json.Unmarshal(obj["name"], &name) != nil || !toolName.MatchString(name) {
		return ToolCall{}, false
	}
	for _, key := range []string{"arguments", "parameters", "input"} {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return ToolCall{Name: name, Arguments: s}, true
		}
		if len(raw) > 0 && raw[0] == '{' {
			return ToolCall{Name: name, Arguments: string(compact(raw))}, true
		}
	}
	return ToolCall{}, false
}

// textOf returns the text of a message content field, which is either a
// string or an array of parts with a text field.
func textOf(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.Text)
	}
	return b.String()
}
