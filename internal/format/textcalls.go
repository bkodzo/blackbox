package format

import (
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"
)

// Small models often write a tool call into their reply text instead of
// making a structured call. Agents usually ignore it, but an auditor needs
// to see that the model tried. Detection is a heuristic: a JSON object with a
// tool-like name and arguments, at the top level or nested inside other JSON.
const (
	maxTextScan = 64 << 10 // bytes of reply text examined
	maxScanWork = 4 << 20  // bytes the decoder may read in total, bounding work on hostile text
	maxNesting  = 6        // levels of JSON searched for nested calls
	readChunk   = 256      // the decoder reads in small steps, so failed candidates stay cheap
)

var toolName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)

// findTextToolCalls returns the calls found in text, and whether the scan
// was cut short by its size or work limits.
func findTextToolCalls(text string) (calls []ToolCall, partial bool) {
	if len(text) > maxTextScan {
		text, partial = text[:maxTextScan], true
	}
	var work int64
	for i := 0; i < len(text); {
		j := strings.IndexByte(text[i:], '{')
		if j < 0 {
			break
		}
		i += j
		if !startsObject(text[i+1:]) {
			i++ // braces in prose or code: not worth a decode
			continue
		}
		if work >= maxScanWork {
			return calls, true
		}
		r := &meteredReader{r: strings.NewReader(text[i:]), n: &work}
		dec := json.NewDecoder(r)
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			i++
			continue
		}
		if collectCalls(raw, 0, &calls) {
			partial = true
		}
		i += int(dec.InputOffset())
	}
	return calls, partial
}

// meteredReader hands the decoder small chunks and counts what it reads.
type meteredReader struct {
	r io.Reader
	n *int64
}

func (m *meteredReader) Read(p []byte) (int, error) {
	n, err := m.r.Read(p[:min(len(p), readChunk)])
	*m.n += int64(n)
	return n, err
}

// collectCalls finds tool call shapes in a JSON value and reports whether
// the depth limit cut the search short. A call's own name and arguments are
// not searched, so its arguments are never counted as more calls, but its
// other fields are, so a decoy call cannot hide a real one inside it.
func collectCalls(raw json.RawMessage, depth int, out *[]ToolCall) (cut bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		skip := map[string]bool{}
		if tc, used, ok := asToolCallFields(obj); ok {
			*out = append(*out, tc)
			for _, k := range used {
				skip[k] = true
			}
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			if !skip[k] && isContainer(obj[k]) {
				keys = append(keys, k)
			}
		}
		if len(keys) > 0 && depth >= maxNesting {
			return true
		}
		slices.Sort(keys) // a stable order for the results
		for _, k := range keys {
			cut = collectCalls(obj[k], depth+1, out) || cut
		}
		return cut
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		var elems []json.RawMessage
		for _, x := range arr {
			if isContainer(x) {
				elems = append(elems, x)
			}
		}
		if len(elems) > 0 && depth >= maxNesting {
			return true
		}
		for _, x := range elems {
			cut = collectCalls(x, depth+1, out) || cut
		}
	}
	return cut
}

// isContainer reports whether raw is a JSON object or array.
func isContainer(raw json.RawMessage) bool {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		}
		return false
	}
	return false
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

// asToolCallFields accepts any of toolShapes, optionally wrapped as
// {"function": {...}}, and returns the fields of obj that make up the call.
func asToolCallFields(obj map[string]json.RawMessage) (ToolCall, []string, bool) {
	if fn, ok := obj["function"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(fn, &inner) == nil {
			if tc, _, ok := asToolCallFields(inner); ok {
				return tc, []string{"function"}, true
			}
		}
	}
	for _, shape := range toolShapes {
		if tc, ok := matchShape(obj, shape.name, shape.args); ok {
			return tc, append([]string{shape.name}, shape.args...), true
		}
	}
	return ToolCall{}, nil, false
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
