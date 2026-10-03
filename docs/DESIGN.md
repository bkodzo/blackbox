# Design

This document explains how blackbox works and why it is built the way it is.

## Goals

1. Record every exchange between an agent and a model server without changing
   the agent beyond its base URL.
2. Make the record tamper-evident: editing, deleting, reordering, or truncating
   entries, or rebuilding the log, must be detectable.
3. Never forward traffic that is not being recorded.
4. Flag agent behaviour an auditor should look at.
5. Stay small: one binary, no database, no third-party Go modules, and no
   assumptions about which model or provider is behind the gateway.

## Request path

```
agent --> proxy --> model server
            |
            | exchange (bytes, hashes, timing)
            v
         recorder --> format parser --> conversation checks --> ledger
```

The proxy is a standard reverse proxy. It forwards every path to the configured
upstream and does not interpret payloads. While the response streams back to
the agent, the proxy copies the bytes into a buffer and a running SHA-256. When
the exchange ends it hands it to the recorder and returns.

The recorder runs on its own goroutine. It parses the payloads, runs the
conversation checks, encodes the record, and appends it to the ledger. None of
that happens on the request path. The queue between the proxy and the recorder
is bounded by bytes (256 MiB by default). When it is full the proxy blocks: the
gateway slows down rather than dropping records or growing without limit.

## The log

### Entry format

Each line of the log is one entry:

```
{"v":2,"seq":42,"kid":"<key id>","prev":"<hex>","hash":"<hex>","sig":"<base64>","rec":{...}}
```

- `hash = SHA-256("blackbox/entry/v2", seq, kid, prev, rec bytes)`, with each
  variable-length field length-prefixed.
- `sig = Ed25519(private key, "blackbox/entry-sig/v2" + hash)`.

The tags make every hash and signature specific to its purpose, so a signature
made for one kind of message (an entry, a checkpoint) can never be accepted as
another. The key ID records which key signed the entry, which leaves room for
key rotation.

### One encoding per entry

The envelope is written by hand around the record bytes. On read, an entry is
accepted only if re-encoding its parsed fields reproduces the line byte for
byte. This rejects duplicate keys, differently cased keys, escaped keys, extra
fields, added whitespace, uppercase hex, and padded base64. Without this rule,
a line could pass verification while other JSON parsers, such as `jq` or a
dashboard, read different content from it.

### Why a hash chain is not enough

A hash chain detects edits, deletions, and reordering, because each entry
commits to the one before it. It does not stop someone who can write the file
from editing an entry and recomputing every hash after it. Signatures close
that gap: rebuilding the chain requires the private key.

### Checkpoints

Neither chaining nor signatures detect entries removed from the end of the log,
because what remains is still a valid, signed prefix. Checkpoints cover that.

After a durable flush, at most every 1,000 entries or 5 minutes, the ledger
writes a checkpoint to a separate file and, by default, to stdout so a copy
leaves the machine:

```
{"v":2,"log":"<hash of entry 1>","seq":42,"hash":"<hex>","ts":"<time>","kid":"<key id>","sig":"<base64>"}
```

The signature covers every field, so neither the sequence number nor the time
can be altered. Verification treats these as tampering:

- the log is shorter than a checkpoint (entries were removed);
- an entry differs from the checkpoint for its sequence number;
- two checkpoints disagree about the same sequence number (the log was
  truncated and rewritten after a checkpoint was shipped);
- a checkpoint names a different log.

The gateway also refuses to start on a log that is shorter than, or disagrees
with, its own latest checkpoint, so it never extends a chain over a gap.

### Durability and group commit

Calling fsync after every entry is slow, especially on macOS, where Go uses
`F_FULLFSYNC` (about 5 ms per call). The ledger uses group commit:

- Appends encode the entry into an in-memory buffer under a lock.
- A background flusher swaps the buffer out, then writes and fsyncs it without
  holding the lock. It runs every 50 ms, or sooner once 64 entries are pending.
- The buffer is bounded (64 MiB by default). When it is full, appends wait
  for the flusher, so a slow disk slows the gateway instead of growing memory.

The write happens outside the lock as well as the fsync, because on some
systems a write blocks while an fsync of the same file is in progress.

The agent receives its response before the record is written. A hard crash can
therefore lose the calls still queued in the recorder and the entries in the
current 50 ms batch. `--sync always` fsyncs every entry, which removes the
batch window but not the queue. The loss is visible: the next `gateway_start`
records that the previous run did not stop cleanly, and `verify` warns about it.

### Crash recovery

If the log ends without a newline at startup, the gateway never discards the
trailing bytes:

- If they are the complete, validly signed next entry, the newline is added
  and the entry kept.
- Otherwise they are an interrupted write. They are moved to a
  `.torn-<time>` file next to the log, and their size, file name, and SHA-256
  are recorded in the `gateway_start` entry, so the removal is itself signed
  and visible to `verify`.

### Verification

`blackbox verify` makes one streaming pass with bounded memory. It reads
entries in batches of 1,024, checks encoding, sequence numbers, and back-links
in order, then recomputes hashes and checks signatures in parallel across all
cores, and reports the first problem in log order. Exit codes are distinct:
0 intact, 1 tampered, 2 intact with warnings, 3 usage or I/O error.

## Failure handling

### Fail closed

If a record cannot be written (disk full, I/O error), the ledger stops
accepting appends, the proxy refuses new requests with 503, the health
endpoint reports the failure, and the gateway shuts down with a non-zero exit
code so a supervisor notices. Agents are never served unrecorded. `--fail-open`
keeps forwarding instead, for deployments that prefer availability; the gap is
then visible as missing records and an unclean stop.

### Shutdown

On SIGINT or SIGTERM the gateway stops accepting connections and gives calls
in flight a grace period (30 s by default). Calls still running when it ends,
such as long streams, are cancelled and recorded with the error class
`gateway_shutdown`. Only after every call has been handed to the recorder and
written does the gateway write `gateway_stop`, which counts calls recorded,
calls that could not be recorded, and calls cancelled.

### Limits

| Limit | Default | Why |
|---|---|---|
| Request size | 64 MiB | Larger requests get 413 and are recorded as refused |
| Stored body size | 32 MiB | Bodies beyond this are truncated in the log; hashes cover every byte |
| Request body read | 1 minute | A slow client cannot hold a request open indefinitely |
| Upstream response headers | 10 minutes | A model server that never answers frees its slot |
| Idle connections | 2 minutes | |

## Format parsing

blackbox does not know or care which provider is upstream. The parser
recognizes payloads by shape:

- **chat**: responses with a `choices` array, streamed as choice deltas.
- **blocks**: responses with typed content blocks, streamed as block events.

Anything that matches neither shape is recorded as `unknown`, with its full
bytes and hashes; only the convenience fields stay empty.

The parser also scans reply text for tool calls written as text, a common
failure of small models: a JSON object with a tool-like name and arguments
that is not a JSON Schema (which would mean the model is describing a tool, not
calling it). The work is bounded to 64 KB of text and 64 candidates per reply.

## Conversation checks

The tracker follows conversations using only hashes and tool call identities,
never message content. Message hashes are computed over canonical JSON (sorted
keys, no insignificant whitespace, no transport annotations such as cache
markers), so reformatting does not trigger false alarms.

Calls are grouped by the `X-Blackbox-Session` header when it is sent. Calls
without it are grouped by conversation: a hash of the opening messages, plus
the rule that a request continues a conversation if the previous request's
messages are a prefix of it. Retries and parallel runs of the same task become
separate branches. State for the last hour is rebuilt from the log at startup,
so a restart does not reset the checks.

For each call the tracker checks that:

- the history sent last turn is sent again unchanged, or with older turns
  dropped (`history_truncated`), and not otherwise changed
  (`history_rewritten`);
- the reply the agent echoes back contains exactly the tool calls the model
  returned, with the same names and arguments, and the same text
  (`history_rewritten`);
- every new tool result answers a call the model made in this conversation
  (`orphan_tool_result`), and links it to the entry where the call was made;
  results with no earlier turn to check against are flagged as
  `unverifiable_tool_result` rather than trusted;
- the tools and leading system prompt have not changed.

Servers that return tool calls without IDs are handled by matching the agent's
echoed calls by name and arguments and adopting the IDs the agent assigned.

Single-call checks cover model substitution (a served name must equal the
requested one or add only a version suffix), aborted streams, high-risk tools,
and tool calls written as text.

## Storage of bodies

Request and response bodies are stored verbatim as text, or as base64 if they
are not valid UTF-8, so their SHA-256 can be recomputed from the log alone.
Every turn stores the whole conversation, so storage grows with the square of
a conversation's length; storing messages once by hash is planned.

## Performance

Measured on an Apple M3 with the benchmarks in `internal/recorder` and
`internal/ledger`, with conversation checks running on every call:

| Measure | Result |
|---|---|
| Added latency per call | about 0.17 ms |
| Throughput through the gateway | about 6,500 calls/s |
| Recording pipeline per call (off the request path) | about 100 us |
| Ledger append, including every fsync | about 18 us (55,000 entries/s) |
| `--sync always` append | about 5 ms |
| Verification | about 230 MB/s |

Model calls take hundreds of milliseconds or more, so the gateway adds well
under one percent to an agent's run time.

## Not yet built

- A web dashboard for auditors and managers.
- Auditing tool execution itself, by proxying tool servers.
- Key rotation: a signed hand-over entry and verification against a key set.
- Segmented log files with an index, for large logs and the dashboard.
- Storing each message once, referenced by hash.
- Roles, access logging, and exportable evidence bundles.
