// Package risk classifies tools by how much harm a call could do, and says
// how to describe a call in plain language.
package risk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Levels.
const (
	Low     = "low"
	Medium  = "medium"
	High    = "high"
	Unknown = "unknown"
)

// Rule describes one tool.
type Rule struct {
	Risk     string `json:"risk"`
	Category string `json:"category,omitempty"` // e.g. read, write, execute, external
	Says     string `json:"says,omitempty"`     // e.g. "read the file {path}"
}

// Map is keyed by tool name.
type Map map[string]Rule

// Load reads a JSON risk map. A missing path yields an empty map.
func Load(path string) (Map, error) {
	if path == "" {
		return Map{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Map
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // a misspelled field must not silently drop a rule
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for name, r := range m {
		switch r.Risk {
		case Low, Medium, High:
		default:
			return nil, fmt.Errorf("%s: tool %q: risk must be low, medium, or high", path, name)
		}
	}
	return m, nil
}

// Lookup returns the rule for a tool, or an Unknown rule if it is not listed.
func (m Map) Lookup(tool string) Rule {
	if r, ok := m[tool]; ok {
		return r
	}
	return Rule{Risk: Unknown}
}
