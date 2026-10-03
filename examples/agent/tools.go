package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// maxRead caps how much of a file read_file returns.
const maxRead = 16 << 10

const toolDefs = `[
  {"type": "function", "function": {
    "name": "list_dir",
    "description": "List the files and folders in a directory.",
    "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "Directory path, e.g. ."}}, "required": ["path"]}}},
  {"type": "function", "function": {
    "name": "read_file",
    "description": "Read a text file.",
    "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "File path"}}, "required": ["path"]}}},
  {"type": "function", "function": {
    "name": "get_time",
    "description": "Get the current date and time.",
    "parameters": {"type": "object", "properties": {}}}}
]`

// runTool executes a tool and returns its output, or an error message the
// model can read. os.Root keeps every path inside the working directory.
func runTool(root *os.Root, name, args string) string {
	var a struct {
		Path string `json:"path"`
	}
	if args != "" {
		if err := json.Unmarshal([]byte(args), &a); err != nil {
			return "error: arguments are not valid JSON"
		}
	}
	switch name {
	case "list_dir":
		entries, err := fs.ReadDir(root.FS(), clean(a.Path))
		if err != nil {
			return "error: " + err.Error()
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() {
				n += "/"
			}
			names = append(names, n)
		}
		sort.Strings(names)
		return strings.Join(names, "\n")
	case "read_file":
		f, err := root.Open(clean(a.Path))
		if err != nil {
			return "error: " + err.Error()
		}
		defer f.Close()
		b := make([]byte, maxRead)
		n, _ := f.Read(b)
		return string(b[:n])
	case "get_time":
		return time.Now().Format(time.RFC1123)
	}
	return "error: unknown tool " + name
}

// clean turns a model-supplied path into a slash-separated path relative to
// the root. Cleaning against "/" removes leading ../ segments; os.Root also
// refuses symlinks that point outside the directory.
func clean(p string) string {
	p = strings.TrimPrefix(path.Clean("/"+strings.TrimSpace(p)), "/")
	if p == "" {
		return "."
	}
	return p
}
