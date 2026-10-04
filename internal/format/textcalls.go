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
	maxCandidates = 1024     // failed decodes allowed, bounding work on hostile text
)

var toolName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)

func findTextToolCalls(text string) []ToolCall {
	if len(text) > maxTextScan {
		text = text[:maxTextScan]
	}
	var out []ToolCall
	// Only failed decodes count against the budget: a successful decode
	// consumes its bytes, so the total work stays bounded by maxTextScan.
	for i, failures := 0, 0; i < len(text) && failures < maxCandidates; {
		j := strings.IndexByte(text[i:], '{')
		if j < 0 {
			break
		}
		i += j
		if !startsObject(text[i+1:]) {
			i++ // braces in prose or code: not worth a decode, and not counted
			continue
		}
		dec := json.NewDecoder(strings.NewReader(text[i:]))
		var obj map[string]json.RawMessage
		if dec.Decode(&obj) != nil {
			failures++
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

// toolShapes are the field pairs models use when writing a call as JSON:
// a name field and an arguments field.
var toolShapes = []struct {
	name string
	args []string
}{
	{"name", []string{"arguments", "parameters", "input"}},
	{"action", []string{"action_input"}},
	{"tool", []string{"tool_input"}},
}

// asToolCall accepts any of toolShapes, optionally wrapped as
// {"function": {...}}.
func asToolCall(obj map[string]json.RawMessage) (ToolCall, bool) {
	if fn, ok := obj["function"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(fn, &inner) == nil {
			obj = inner
		}
	}
	for _, shape := range toolShapes {
		if tc, ok := matchShape(obj, shape.name, shape.args); ok {
			return tc, true
		}
	}
	return ToolCall{}, false
}

func matchShape(obj map[string]json.RawMessage, nameKey string, argKeys []string) (ToolCall, bool) {
	var name string
	if json.Unmarshal(obj[nameKey], &name) != nil || !toolName.MatchString(name) {
		return ToolCall{}, false
	}
	for _, key := range argKeys {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return ToolCall{Name: name, Arguments: s}, true
		}
		if len(raw) > 0 && raw[0] == '{' {
			if isSchema(raw) {
				return ToolCall{}, false // a tool definition being described, not a call
			}
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

// isSchema reports whether an arguments object is a JSON Schema, which means
// the model is describing a tool rather than calling it.
func isSchema(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	_, props := obj["properties"]
	var typ string
	json.Unmarshal(obj["type"], &typ)
	return props && typ == "object"
}

// startsObject reports whether s, the text after a '{', can continue a JSON
// object with at least one key.
func startsObject(s string) bool {
	s = strings.TrimLeft(s, " \t\r\n")
	return strings.HasPrefix(s, `"`)
}
