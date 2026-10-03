package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"time"
)

// Version is the entry and checkpoint format version.
const Version = 2

// Every hash and signature is prefixed with a tag naming its purpose, so a
// signature made for one kind of message can never be accepted as another.
const (
	tagEntry      = "blackbox/entry/v2\x00"
	tagEntrySig   = "blackbox/entry-sig/v2\x00"
	tagCheckpoint = "blackbox/checkpoint/v2\x00"
)

// Entry is one line of the log: a record plus the fields that seal it.
type Entry struct {
	V    int             `json:"v"`
	Seq  uint64          `json:"seq"`
	Kid  string          `json:"kid"`  // ID of the signing key
	Prev string          `json:"prev"` // hash of the previous entry
	Hash string          `json:"hash"`
	Sig  string          `json:"sig"`
	Rec  json.RawMessage `json:"rec"`
}

// GenesisPrev is the prev hash of the first entry.
var GenesisPrev = hex.EncodeToString(make([]byte, sha256.Size))

// KeyID is a short, stable identifier for a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// writeField writes a length-prefixed field so adjacent fields can never be
// shifted into each other.
func writeField(h hash.Hash, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	h.Write(n[:])
	h.Write(b)
}

func entryHash(seq uint64, kid string, prev, rec []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(tagEntry))
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	h.Write(s[:])
	writeField(h, []byte(kid))
	writeField(h, prev)
	writeField(h, rec)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

func entrySigMessage(sum []byte) []byte {
	return append([]byte(tagEntrySig), sum...)
}

// appendLine encodes e as a log line. It is built by hand so rec is copied
// verbatim and every entry has exactly one encoding.
func (e *Entry) appendLine(b []byte) []byte {
	b = append(b, `{"v":`...)
	b = strconv.AppendInt(b, int64(e.V), 10)
	b = append(b, `,"seq":`...)
	b = strconv.AppendUint(b, e.Seq, 10)
	b = append(b, `,"kid":"`...)
	b = append(b, e.Kid...)
	b = append(b, `","prev":"`...)
	b = append(b, e.Prev...)
	b = append(b, `","hash":"`...)
	b = append(b, e.Hash...)
	b = append(b, `","sig":"`...)
	b = append(b, e.Sig...)
	b = append(b, `","rec":`...)
	b = append(b, e.Rec...)
	return append(b, "}\n"...)
}

// errNotCanonical means a line parsed but is not byte-for-byte the encoding
// blackbox writes: duplicate, renamed, extra, or reformatted fields. Such a
// line could be read differently by other JSON parsers, so it is rejected.
var errNotCanonical = errors.New("entry is not in canonical form (extra, duplicate, or reformatted fields)")

// ParseEntry parses one line (without its trailing newline) and requires it
// to be exactly the bytes blackbox would have written for that entry.
func ParseEntry(line []byte) (Entry, error) {
	var e Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return Entry{}, err
	}
	if e.V != Version {
		return Entry{}, fmt.Errorf("unsupported entry version %d", e.V)
	}
	if len(e.Rec) == 0 || e.Rec[0] != '{' {
		return Entry{}, errors.New("record is not a JSON object")
	}
	if want := e.appendLine(nil); !bytes.Equal(want[:len(want)-1], line) {
		return Entry{}, errNotCanonical
	}
	return e, nil
}

// check recomputes the entry's hash from its own fields and verifies its
// signature. It returns the decoded hash, or a reason the entry is invalid.
func (e *Entry) check(pub ed25519.PublicKey, kid string) ([]byte, string) {
	if e.Kid != kid {
		return nil, fmt.Sprintf("signed with a different key (key ID %s, expected %s)", e.Kid, kid)
	}
	prev, err := hex.DecodeString(e.Prev)
	if err != nil || len(prev) != sha256.Size {
		return nil, "malformed prev hash"
	}
	sum := entryHash(e.Seq, e.Kid, prev, e.Rec)
	if hex.EncodeToString(sum[:]) != e.Hash {
		return nil, "contents were modified (hash mismatch)"
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Sig)
	if err != nil || !ed25519.Verify(pub, entrySigMessage(sum[:]), sig) {
		return nil, "signature is invalid (not written by this gateway's key)"
	}
	return sum[:], ""
}

// Checkpoint is a signed statement that a log, identified by the hash of its
// first entry, had a given entry at a given sequence number at a given time.
// Every field except the signature is covered by the signature.
type Checkpoint struct {
	V    int    `json:"v"`
	Log  string `json:"log"` // hash of entry 1
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	Time string `json:"ts"` // RFC 3339, UTC
	Kid  string `json:"kid"`
	Sig  string `json:"sig"`
}

func (c *Checkpoint) message() ([]byte, error) {
	logID, err := hex.DecodeString(c.Log)
	if err != nil || len(logID) != sha256.Size {
		return nil, errors.New("malformed log ID")
	}
	head, err := hex.DecodeString(c.Hash)
	if err != nil || len(head) != sha256.Size {
		return nil, errors.New("malformed hash")
	}
	h := sha256.New()
	h.Write([]byte(tagCheckpoint))
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], c.Seq)
	h.Write(s[:])
	writeField(h, logID)
	writeField(h, head)
	writeField(h, []byte(c.Time))
	writeField(h, []byte(c.Kid))
	return h.Sum([]byte(tagCheckpoint)), nil
}

func newCheckpoint(key ed25519.PrivateKey, kid, logID string, e *Entry, now time.Time) (Checkpoint, error) {
	c := Checkpoint{V: Version, Log: logID, Seq: e.Seq, Hash: e.Hash, Time: now.UTC().Format(time.RFC3339Nano), Kid: kid}
	msg, err := c.message()
	if err != nil {
		return c, err
	}
	c.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))
	return c, nil
}

func (c *Checkpoint) appendLine(b []byte) []byte {
	b = append(b, `{"v":`...)
	b = strconv.AppendInt(b, int64(c.V), 10)
	b = append(b, `,"log":"`...)
	b = append(b, c.Log...)
	b = append(b, `","seq":`...)
	b = strconv.AppendUint(b, c.Seq, 10)
	b = append(b, `,"hash":"`...)
	b = append(b, c.Hash...)
	b = append(b, `","ts":`...)
	b = strconv.AppendQuote(b, c.Time)
	b = append(b, `,"kid":"`...)
	b = append(b, c.Kid...)
	b = append(b, `","sig":"`...)
	b = append(b, c.Sig...)
	return append(b, "\"}\n"...)
}

func parseCheckpoint(line []byte) (Checkpoint, error) {
	var c Checkpoint
	if err := json.Unmarshal(line, &c); err != nil {
		return c, err
	}
	if c.V != Version {
		return c, fmt.Errorf("unsupported checkpoint version %d", c.V)
	}
	if want := c.appendLine(nil); !bytes.Equal(want[:len(want)-1], line) {
		return c, errors.New("checkpoint is not in canonical form")
	}
	return c, nil
}

// verify checks the checkpoint's signature.
func (c *Checkpoint) verify(pub ed25519.PublicKey, kid string) error {
	if c.Kid != kid {
		return fmt.Errorf("checkpoint at seq %d was signed with a different key", c.Seq)
	}
	msg, err := c.message()
	if err != nil {
		return fmt.Errorf("checkpoint at seq %d: %w", c.Seq, err)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(c.Sig)
	if err != nil || !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("checkpoint at seq %d has an invalid signature (forged checkpoint)", c.Seq)
	}
	return nil
}
