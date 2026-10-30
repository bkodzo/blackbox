// Command corpus writes a blackbox log of simulated organisation-scale agent
// traffic, for measuring how agent audit logs grow and what in them repeats.
//
// Many users run many agents. Each agent has its own system prompt and tool
// definitions. Each task is a session of model calls in which the agent
// resends the whole conversation every call, as real agents do. Tool results
// are drawn from a pool of shared documents (popular documents are read by
// many people) or are unique to the call. Text comes from real files, so it
// compresses like real text rather than like random bytes.
//
// Exchanges go through blackbox's own recorder, so the log has exactly the
// format the gateway writes.
//
//	go run ./research/storage/corpus -out /tmp/corpus -users 20 -tasks 20
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/recorder"
)

var (
	out     = flag.String("out", "corpus", "directory to write the log into")
	users   = flag.Int("users", 20, "people using agents")
	tasks   = flag.Int("tasks", 20, "agent tasks per person")
	agents  = flag.Int("agents", 8, "kinds of agent in the organisation")
	meanLen = flag.Float64("calls", 12, "mean model calls per task")
	shared  = flag.Float64("shared", 0.5, "share of tool results that are shared documents")
	source  = flag.String("text", ".", "directory whose .md and .go files supply the text")
	seed    = flag.Uint64("seed", 1, "random seed")
)

var rng *rand.Rand

func main() {
	flag.Parse()
	rng = rand.New(rand.NewPCG(*seed, 11))
	paras := loadText(*source)
	if len(paras) < 50 {
		log.Fatalf("only %d paragraphs of text under %s", len(paras), *source)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	keyPath, pubPath := filepath.Join(*out, "key.ed25519"), filepath.Join(*out, "key.pub")
	if _, err := ledger.GenerateKey(keyPath, pubPath); err != nil {
		log.Fatal(err)
	}
	key, _ := ledger.LoadPrivateKey(keyPath)
	l, err := ledger.Open(filepath.Join(*out, "corpus.jsonl"), key, ledger.Options{CheckpointPath: filepath.Join(*out, "corpus.checkpoints.jsonl")})
	if err != nil {
		log.Fatal(err)
	}
	rec := recorder.New(l, "corpus", recorder.Options{})

	kinds := makeAgents(*agents, paras)
	docs := makeDocs(400, paras)
	start := time.Now().Add(-24 * time.Hour)
	calls := 0
	for u := range *users {
		favourite := []int{rng.IntN(len(kinds)), rng.IntN(len(kinds)), rng.IntN(len(kinds))}
		for t := range *tasks {
			a := kinds[favourite[rng.IntN(len(favourite))]]
			s := &session{rec: rec, agent: a, id: fmt.Sprintf("u%d-t%d", u, t), user: fmt.Sprintf("user-%d", u),
				at: start.Add(time.Duration(rng.IntN(24*3600)) * time.Second)}
			calls += s.run(paras, docs)
		}
	}
	rec.Close()
	if err := l.Close(); err != nil {
		log.Fatal(err)
	}
	os.Remove(keyPath)
	fi, _ := os.Stat(filepath.Join(*out, "corpus.jsonl"))
	log.Printf("%d calls, %.1f MB", calls, float64(fi.Size())/1e6)
}

// loadText splits every .md and .go file under dir into paragraphs.
func loadText(dir string) []string {
	var paras []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && (d.Name() == ".git" || d.Name() == "tools" || d.Name() == "research") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".md") && !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, para := range strings.Split(string(b), "\n\n") {
			if para = strings.TrimSpace(para); len(para) > 80 {
				paras = append(paras, para)
			}
		}
		return nil
	})
	return paras
}

// text returns about n bytes of paragraphs chosen at random.
func text(paras []string, n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(paras[rng.IntN(len(paras))])
		b.WriteString("\n\n")
	}
	return b.String()
}

type agentKind struct {
	name   string
	system string
	tools  []any
	names  []string
}

func makeAgents(n int, paras []string) []agentKind {
	var kinds []agentKind
	for i := range n {
		a := agentKind{name: fmt.Sprintf("agent-%d", i), system: text(paras, 1500+rng.IntN(5000))}
		for j := range 4 + rng.IntN(8) {
			name := fmt.Sprintf("tool_%d_%d", i, j)
			a.names = append(a.names, name)
			props := map[string]any{}
			for k := range 1 + rng.IntN(4) {
				props[fmt.Sprintf("arg%d", k)] = map[string]any{"type": "string", "description": text(paras, 60+rng.IntN(200))}
			}
			a.tools = append(a.tools, map[string]any{"type": "function", "function": map[string]any{
				"name": name, "description": text(paras, 100+rng.IntN(400)),
				"parameters": map[string]any{"type": "object", "properties": props},
			}})
		}
		kinds = append(kinds, a)
	}
	return kinds
}

// makeDocs builds documents that several people's agents may read.
func makeDocs(n int, paras []string) []string {
	docs := make([]string, n)
	for i := range docs {
		docs[i] = text(paras, size())
	}
	return docs
}

// size is a heavy-tailed tool result size: mostly small, sometimes large.
func size() int {
	return int(math.Min(60_000, 200*math.Exp(rng.NormFloat64()*1.3+1.5)))
}

type session struct {
	rec   *recorder.Recorder
	agent agentKind
	id    string
	user  string
	at    time.Time
	msgs  []any
}

func (s *session) run(paras, docs []string) int {
	s.msgs = []any{msg("system", s.agent.system), msg("user", text(paras, 60+rng.IntN(400)))}
	n := max(2, int(rng.ExpFloat64()**meanLen))
	for i := range n {
		if i == n-1 {
			s.call(msg("assistant", text(paras, 100+rng.IntN(800))))
			break
		}
		var calls, results []any
		for c := range 1 + rng.IntN(2) {
			id := fmt.Sprintf("call_%s_%d_%d", s.id, i, c)
			calls = append(calls, map[string]any{"id": id, "type": "function", "function": map[string]any{
				"name": s.agent.names[rng.IntN(len(s.agent.names))], "arguments": fmt.Sprintf(`{"arg0":"%s"}`, randomHex(6)),
			}})
			content := text(paras, size())
			if rng.Float64() < *shared {
				content = docs[zipf(len(docs))]
			}
			results = append(results, map[string]any{"role": "tool", "tool_call_id": id, "content": content})
		}
		reply := map[string]any{"role": "assistant", "content": nil, "tool_calls": calls}
		s.call(reply)
		s.msgs = append(s.msgs, reply)
		s.msgs = append(s.msgs, results...)
	}
	return n
}

// zipf picks an index in [0, n) where low indexes are much more popular:
// the index is log-uniform, so a few documents are read by many people.
func zipf(n int) int {
	return min(n-1, int(math.Pow(float64(n), rng.Float64()))-1)
}

// call records one request carrying the whole conversation so far.
func (s *session) call(reply map[string]any) {
	req, _ := json.Marshal(map[string]any{"model": "m", "messages": s.msgs, "tools": s.agent.tools})
	resp, _ := json.Marshal(map[string]any{"model": "m",
		"choices": []any{map[string]any{"index": 0, "message": reply}},
		"usage":   map[string]int{"prompt_tokens": len(req) / 4, "completion_tokens": 50}})
	c := &record.LLMCall{
		Type: record.TypeLLMCall, Agent: record.Agent{ID: s.agent.name}, Session: record.Session{ID: s.id},
		Principal: s.user, Identity: "self_declared",
		Request:  record.Request{Method: "POST", Path: "/v1/chat/completions", Body: body(req)},
		Upstream: record.Upstream{URL: "http://model-server.internal:8000/v1/chat/completions"},
		Timing:   record.Timing{ReceivedAt: s.at, CompletedAt: s.at.Add(time.Second)},
	}
	c.Response.Status, c.Response.ContentType, c.Response.Body = 200, "application/json", body(resp)
	s.rec.Submit(record.Exchange{Call: c, Req: req, Resp: resp})
	s.at = s.at.Add(time.Duration(2+rng.IntN(30)) * time.Second)
}

func msg(role, content string) map[string]any {
	return map[string]any{"role": role, "content": content}
}

func body(b []byte) record.Body {
	sum := sha256.Sum256(b)
	return record.Body{SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(b)), Text: string(b)}
}

func randomHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.UintN(256))
	}
	return hex.EncodeToString(b)
}
