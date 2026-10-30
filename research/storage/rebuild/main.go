// Command rebuild tests whether a log can be stored with each distinct
// message once and still give back every request byte for byte.
//
// Each request is split into a skeleton (everything except the messages and
// the tool list, kept exactly, with references in their place) and the
// messages and tool list themselves, kept once each in a store keyed by
// their exact bytes. Every request is then rebuilt from the two and compared
// with the original. The skeleton is what exactness costs on top of the
// store.
//
// It also measures what would erode the saving with real agents: history
// resent with different formatting (same content, different bytes, so not
// deduplicated by bytes), and model replies echoed back in a form that
// differs from the bytes the model server returned.
//
//	go run ./research/storage/rebuild -log corpus/corpus.jsonl
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/bkodzo/blackbox/internal/format"
	"github.com/bkodzo/blackbox/internal/ledger"
)

var logPath = flag.String("log", "corpus.jsonl", "blackbox log to test")

// refSize is what a reference to a stored item costs in the skeleton.
const refSize = 8

// piece is part of a skeleton: literal bytes, or a reference to the store.
type piece struct {
	lit []byte
	ref [32]byte
}

func main() {
	flag.Parse()
	f, err := os.Open(*logPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	store := map[[32]byte][]byte{}
	canonSeen := map[[32]byte]bool{} // canonical forms of stored messages
	type reply struct{ raw, canon [32]byte }
	lastReply := map[string]reply{} // per session, the last reply the server returned
	sessionSeen := map[string]map[[32]byte]bool{}

	var requests, exact, skipped int64
	var raw, skeleton, refs, storeBytes int64
	var reserialized, reserializedBytes int64
	var echoExact, echoCanon, echoDiffer int64

	br := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		e, err := ledger.ParseEntry(bytes.TrimSuffix(line, []byte{'\n'}))
		if err != nil {
			log.Fatal(err)
		}
		var rec struct {
			Type    string `json:"type"`
			Session struct {
				ID           string `json:"id"`
				Conversation string `json:"conversation"`
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
			continue
		}
		sid := rec.Session.ID + "|" + rec.Session.Conversation
		req := []byte(rec.Request.Body.Text)
		pieces, msgs, err := split(req)
		if err != nil {
			skipped++ // not a JSON object with messages; stored as is
			continue
		}
		requests++
		raw += int64(len(req))
		seen := sessionSeen[sid]
		if seen == nil {
			seen = map[[32]byte]bool{}
			sessionSeen[sid] = seen
		}
		for _, p := range pieces {
			if p.lit != nil {
				skeleton += int64(len(p.lit))
				continue
			}
			refs++
		}
		for h, m := range msgs {
			if _, ok := store[h]; ok {
				continue
			}
			ch := canonHash(m.raw)
			if canonSeen[ch] {
				reserialized++
				reserializedBytes += int64(len(m.raw))
			}
			store[h] = m.raw
			canonSeen[ch] = true
			storeBytes += int64(len(m.raw))
		}
		// Echoes: an assistant message new to the session should be the
		// reply the server returned last.
		if last, ok := lastReply[sid]; ok {
			for h, m := range msgs {
				if seen[h] || m.role != "assistant" {
					continue
				}
				switch {
				case h == last.raw:
					echoExact++
				case canonHash(m.raw) == last.canon:
					echoCanon++
				default:
					echoDiffer++
				}
			}
		}
		for h := range msgs {
			seen[h] = true
		}
		if bytes.Equal(rebuild(pieces, store), req) {
			exact++
		}

		var resp struct {
			Choices []struct {
				Message json.RawMessage `json:"message"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(rec.Response.Body.Text), &resp) == nil && len(resp.Choices) > 0 && len(resp.Choices[0].Message) > 0 {
			m := resp.Choices[0].Message
			lastReply[sid] = reply{sha256.Sum256(m), canonHash(m)}
		}
	}

	fmt.Printf("Log: %s\n\n", *logPath)
	fmt.Printf("Requests rebuilt byte for byte: %d of %d (%d others were not JSON with messages and would be stored as is)\n\n", exact, requests, skipped)
	resid := skeleton + refs*refSize
	fmt.Printf("Raw requests:            %s\n", mb(raw))
	fmt.Printf("Stored once:             %s (%d distinct messages and tool lists)\n", mb(storeBytes), len(store))
	fmt.Printf("Skeletons:               %s literal + %s of references = %s, %.2f%% of raw, %s per request\n",
		mb(skeleton), mb(refs*refSize), mb(resid), pct(resid, raw), byteStr(resid/max(requests, 1)))
	fmt.Printf("Together:                %s, %.1fx smaller than raw\n\n", mb(storeBytes+resid), float64(raw)/float64(max(storeBytes+resid, 1)))
	fmt.Printf("Resent with different formatting (same content, new bytes): %d messages, %s\n", reserialized, mb(reserializedBytes))
	total := echoExact + echoCanon + echoDiffer
	fmt.Printf("Replies echoed back: %d; same bytes as returned %d (%.0f%%), same content in other bytes %d (%.0f%%), different %d (%.0f%%)\n",
		total, echoExact, pct(echoExact, total), echoCanon, pct(echoCanon, total), echoDiffer, pct(echoDiffer, total))
}

type message struct {
	raw  []byte
	role string
}

// split returns the skeleton of a request and the messages and tool list it
// refers to, keyed by the hash of their exact bytes.
func split(req []byte) ([]piece, map[[32]byte]message, error) {
	dec := json.NewDecoder(bytes.NewReader(req))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil, errors.New("not an object")
	}
	var pieces []piece
	msgs := map[[32]byte]message{}
	last := 0 // bytes of req already in pieces
	cut := func(start, end int, b []byte) {
		h := sha256.Sum256(b)
		pieces = append(pieces, piece{lit: req[last:start]}, piece{ref: h})
		last = end
		var role struct {
			Role string `json:"role"`
		}
		json.Unmarshal(b, &role)
		msgs[h] = message{raw: b, role: role.Role}
	}
	found := false
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, _ := t.(string)
		switch key {
		case "messages":
			if t, err := dec.Token(); err != nil || t != json.Delim('[') {
				return nil, nil, errors.New("messages is not an array")
			}
			for dec.More() {
				var m json.RawMessage
				if err := dec.Decode(&m); err != nil {
					return nil, nil, err
				}
				end := int(dec.InputOffset())
				cut(end-len(m), end, m)
			}
			dec.Token() // ]
			found = true
		case "tools":
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, nil, err
			}
			end := int(dec.InputOffset())
			cut(end-len(v), end, v)
		default:
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, nil, err
			}
		}
	}
	if !found {
		return nil, nil, errors.New("no messages")
	}
	pieces = append(pieces, piece{lit: req[last:]})
	return pieces, msgs, nil
}

func rebuild(pieces []piece, store map[[32]byte][]byte) []byte {
	var b bytes.Buffer
	for _, p := range pieces {
		if p.lit != nil {
			b.Write(p.lit)
		} else {
			b.Write(store[p.ref])
		}
	}
	return b.Bytes()
}

func canonHash(b []byte) [32]byte { return sha256.Sum256([]byte(format.CanonicalArgs(string(b)))) }

func pct(a, b int64) float64 { return 100 * float64(a) / float64(max(b, 1)) }
func mb(n int64) string      { return fmt.Sprintf("%.1f MB", float64(n)/1e6) }
func byteStr(n int64) string { return fmt.Sprintf("%d bytes", n) }
