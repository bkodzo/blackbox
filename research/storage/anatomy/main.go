// Command anatomy reads a blackbox log and reports where its bytes go and
// how much of them repeat, within a session and across the whole log. It
// compares the log's size with general-purpose compression and with storing
// each distinct message once.
//
//	go run ./research/storage/anatomy -log corpus/corpus.jsonl
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/bkodzo/blackbox/internal/ledger"
)

var logPath = flag.String("log", "corpus.jsonl", "blackbox log to measure")

// Byte categories, in the order they are reported.
const (
	catMetadata = "gateway metadata and seal"
	catEscaping = "JSON escaping of bodies"
	catFraming  = "request framing (model name, brackets)"
	catTools    = "tool definitions"
	catHistory  = "history resent from earlier in the session"
	catSystem   = "system prompt, first time in the session"
	catEcho     = "model reply echoed back, first time"
	catToolNew  = "tool result, first time in the session"
	catUserNew  = "user message, first time in the session"
	catResponse = "response bodies"
)

var order = []string{catMetadata, catEscaping, catFraming, catTools, catHistory, catSystem, catEcho, catToolNew, catUserNew, catResponse}

type counter struct{ n int64 }

func (c *counter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func main() {
	flag.Parse()
	f, err := os.Open(*logPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	bytesBy := map[string]int64{}
	var total, calls, refs int64
	sessionSeen := map[string]map[[32]byte]bool{}
	globalSeen := map[[32]byte]bool{}
	var uniqueContent int64        // distinct messages, tool definition sets, and responses, stored once
	var metadataOnly int64         // each line without its bodies
	var newInSessionGlobally int64 // first time in the session, but seen elsewhere in the log

	// Streams for the compression baselines.
	var whole, store, meta counter
	gzWhole, _ := gzip.NewWriterLevel(&whole, gzip.DefaultCompression)
	gzStore, _ := gzip.NewWriterLevel(&store, gzip.DefaultCompression)
	gzMeta, _ := gzip.NewWriterLevel(&meta, gzip.DefaultCompression)
	var perEntry int64

	// Growth: request size and new bytes by position of the call in its session.
	posReq := map[int][]int64{}
	posNew := map[int][]int64{}
	posInSession := map[string]int{}

	br := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		total += int64(len(line))
		gzWhole.Write(line)
		perEntry += gzipSize(line)

		e, err := ledger.ParseEntry(bytes.TrimSuffix(line, []byte{'\n'}))
		if err != nil {
			log.Fatal(err)
		}
		var rec struct {
			Type    string `json:"type"`
			Session struct {
				ID string `json:"id"`
			} `json:"session"`
			Request struct {
				Body struct {
					Text string `json:"text"`
				} `json:"body"`
			} `json:"request"`
			Response struct {
				Body struct {
					Text string `json:"text"`
				} `json:"body"`
			} `json:"response"`
		}
		json.Unmarshal(e.Rec, &rec)
		if rec.Type != "llm_call" {
			bytesBy[catMetadata] += int64(len(line))
			metadataOnly += int64(len(line))
			gzMeta.Write(line)
			continue
		}
		calls++
		req, resp := rec.Request.Body.Text, rec.Response.Body.Text
		encReq, encResp := encLen(req), encLen(resp)
		lineMeta := int64(len(line)) - encReq - encResp
		bytesBy[catMetadata] += lineMeta
		bytesBy[catEscaping] += (encReq - int64(len(req)) - 2) + (encResp - int64(len(resp)) - 2)
		metadataOnly += lineMeta
		gzMeta.Write(stripBodies(line, req, resp))

		bytesBy[catResponse] += int64(len(resp))
		uniqueContent += int64(len(resp))
		gzStore.Write([]byte(resp))

		var r struct {
			Messages []json.RawMessage `json:"messages"`
			Tools    json.RawMessage   `json:"tools"`
		}
		json.Unmarshal([]byte(req), &r)
		seen := sessionSeen[rec.Session.ID]
		if seen == nil {
			seen = map[[32]byte]bool{}
			sessionSeen[rec.Session.ID] = seen
		}
		accounted := int64(len(r.Tools))
		bytesBy[catTools] += int64(len(r.Tools))
		if h := sha256.Sum256(r.Tools); !globalSeen[h] {
			globalSeen[h] = true
			uniqueContent += int64(len(r.Tools))
			gzStore.Write(r.Tools)
		}
		refs++
		var newBytes int64
		for _, m := range r.Messages {
			h := sha256.Sum256(m)
			n := int64(len(m))
			accounted += n
			refs++
			if seen[h] {
				bytesBy[catHistory] += n
				continue
			}
			newBytes += n
			var role struct {
				Role string `json:"role"`
			}
			json.Unmarshal(m, &role)
			switch role.Role {
			case "system":
				bytesBy[catSystem] += n
			case "assistant":
				bytesBy[catEcho] += n
			case "tool":
				bytesBy[catToolNew] += n
			default:
				bytesBy[catUserNew] += n
			}
			if globalSeen[h] {
				newInSessionGlobally += n
			} else {
				globalSeen[h] = true
				uniqueContent += n
				gzStore.Write(m)
			}
		}
		for _, m := range r.Messages {
			seen[sha256.Sum256(m)] = true
		}
		bytesBy[catFraming] += int64(len(req)) - accounted

		pos := posInSession[rec.Session.ID] + 1
		posInSession[rec.Session.ID] = pos
		posReq[pos] = append(posReq[pos], int64(len(req)))
		posNew[pos] = append(posNew[pos], newBytes)
	}
	gzWhole.Close()
	gzStore.Close()
	gzMeta.Close()

	fmt.Printf("Log: %s\n%d model calls, %d sessions, %s, %s per call\n\n", *logPath, calls, len(sessionSeen), mb(total), kb(total/max(calls, 1)))

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "Where the bytes go\tbytes\tshare\t")
	var sum int64
	for _, c := range order {
		sum += bytesBy[c]
		fmt.Fprintf(tw, "%s\t%s\t%5.1f%%\t\n", c, mb(bytesBy[c]), pct(bytesBy[c], total))
	}
	fmt.Fprintf(tw, "(accounted for)\t%s\t%5.1f%%\t\n", mb(sum), pct(sum, total))
	tw.Flush()
	fmt.Printf("\nOf the bytes that were new to their session, %s (%.1f%%) had already appeared in another session.\n",
		mb(newInSessionGlobally), pct(newInSessionGlobally, newInSessionGlobally+uniqueContent))

	// Storing each distinct message once: metadata, one 8-byte reference per
	// message and tool set, and the distinct content.
	dedup := metadataOnly + refs*8 + uniqueContent
	dedupGz := meta.n + refs*8 + store.n
	fmt.Println()
	tw = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "Storing it\tsize\tvs raw\t")
	for _, row := range []struct {
		name string
		n    int64
	}{
		{"raw log", total},
		{"gzip each entry", perEntry},
		{"gzip the whole log", whole.n},
		{"each message stored once", dedup},
		{"each message stored once, then gzip", dedupGz},
	} {
		fmt.Fprintf(tw, "%s\t%s\t%6.1fx smaller\t\n", row.name, mb(row.n), float64(total)/float64(max(row.n, 1)))
	}
	tw.Flush()

	fmt.Println("\nGrowth within a session (averages by call position)")
	tw = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "call\tsessions\trequest size\tnew in this call\t")
	var positions []int
	for p := range posReq {
		positions = append(positions, p)
	}
	sort.Ints(positions)
	for _, p := range positions {
		if p > 5 && p%5 != 0 {
			continue
		}
		if len(posReq[p]) < 5 {
			break
		}
		fmt.Fprintf(tw, "%d\t%d\t%s\t%s\t\n", p, len(posReq[p]), kb(avg(posReq[p])), kb(avg(posNew[p])))
	}
	tw.Flush()
}

func encLen(s string) int64 {
	b, _ := json.Marshal(s)
	return int64(len(b))
}

// stripBodies removes the two body texts from a line, leaving the metadata.
func stripBodies(line []byte, req, resp string) []byte {
	for _, s := range []string{req, resp} {
		b, _ := json.Marshal(s)
		line = bytes.Replace(line, b, []byte(`""`), 1)
	}
	return line
}

func gzipSize(b []byte) int64 {
	var c counter
	w, _ := gzip.NewWriterLevel(&c, gzip.DefaultCompression)
	w.Write(b)
	w.Close()
	return c.n
}

func avg(v []int64) int64 {
	var s int64
	for _, x := range v {
		s += x
	}
	return s / int64(len(v))
}

func pct(a, b int64) float64 { return 100 * float64(a) / float64(max(b, 1)) }
func mb(n int64) string      { return fmt.Sprintf("%.1f MB", float64(n)/1e6) }
func kb(n int64) string      { return fmt.Sprintf("%.1f KB", float64(n)/1e3) }
