# Design

This document explains how blackbox works and why it is built the way it is.

## Goals

1. Record every exchange between an agent and a model server without changing
   the agent beyond its base URL.
2. Make the record tamper-evident: editing, deleting, reordering, or truncating
   entries, or rebuilding the log, must be detectable.
3. Flag agent behaviour an auditor should look at.
4. Stay small: one binary, no database, no third-party Go modules, and no
   assumptions about which model or provider is behind the gateway.

## Request path

```
agent --> proxy --> model server
            |
            | capture (bytes, hashes, timing)
            v
         recorder --> format parser --> session checks --> ledger
```

The proxy is a standard reverse proxy. It forwards every path to the configured
upstream and does not interpret payloads. While the response streams back to
the agent, the proxy copies the bytes into a buffer and a running SHA-256. When
the exchange ends it hands a capture to the recorder and returns.

The recorder runs on its own goroutine. It parses the payloads, runs the session
checks, encodes the record, and appends it to the ledger. None of that happens
on the request path, so the agent never waits for parsing, signing, or disk
I/O. The queue between the proxy and the recorder is bounded. If it fills, the
proxy blocks: the gateway slows down rather than dropping audit records.

## The log

### Entry format

Each line of the log is one entry:

```
{"seq":42,"prev":"<hex>","hash":"<hex>","sig":"<base64>","rec":{...}}
```

- `hash = SHA-256(seq as 8 big-endian bytes, prev hash, rec bytes)`
- `sig = Ed25519(private key, hash)`

The envelope is written by hand around the record bytes. The record is
serialized once, and verification hashes the bytes exactly as they appear on
disk. Nothing is re-encoded, so there is no canonical JSON to get wrong: any
change to the bytes, even whitespace, changes the hash.

### Why a hash chain is not enough

A hash chain detects edits, deletions, and reordering, because each entry
commits to the one before it. It does not stop someone who can write the file
from editing an entry and recomputing every hash after it. The result is a
perfectly consistent chain.

Signatures close that gap. Each entry's hash is signed with the gateway's
Ed25519 key. Rebuilding the chain requires the private key; without it, every
rebuilt entry fails signature verification.

### Why checkpoints are needed too

Neither chaining nor signatures detect entries removed from the end of the log,
because what remains is still a valid, signed prefix. Checkpoints cover that.

After each durable flush, and at most every 1,000 entries or 5 minutes, the
ledger writes a checkpoint: the sequence number, hash, and signature of the
newest durable entry. Checkpoints go to a separate file and, by default, to
stdout so they can be shipped to another machine. If the log is shorter than
any checkpoint, verification reports how many entries were removed.

A checkpoint reuses the entry's own signature, so it cannot be forged without
the key either.

### Durability and group commit

Calling fsync after every entry is slow, especially on macOS, where Go uses
`F_FULLFSYNC` (about 5 ms per call). The ledger uses group commit instead:

- Appends encode the entry into an in-memory buffer under a lock.
- A background flusher swaps the buffer out, then writes and fsyncs it without
  holding the lock. It runs every 50 ms, or sooner once 64 entries are pending.

The write happens outside the lock as well as the fsync, because on some
systems a write blocks while an fsync of the same file is in progress.

The tradeoff: a hard crash can lose up to about 50 ms of entries. That loss is
visible rather than silent. The next `gateway_start` entry records whether the
previous run shut down cleanly, and `verify` warns when a start is not preceded
by a stop. `--sync always` fsyncs every entry for deployments that need it.

### Torn writes

If the process dies in the middle of writing a line, the file ends with an
incomplete entry. On startup the ledger removes those bytes and reports how many
it removed; the count is recorded in the `gateway_start` entry. `verify` on a
log that has not been reopened reports the torn tail as a warning, not as
tampering.

### Verification

`blackbox verify` makes one streaming pass with bounded memory. It reads entries
in batches of 1,024, checks sequence numbers and back-links in order (cheap),
then recomputes hashes and checks signatures in parallel across all cores
(expensive), and reports the first problem in log order. On an Apple M3 it
verifies about 240 MB/s.

## Format parsing

blackbox does not know or care which provider is upstream. The parser
recognizes payloads by shape:

- **chat**: responses with a `choices` array, streamed as choice deltas.
- **blocks**: responses with typed content blocks, streamed as block events.

Requests are read by one tolerant parser that understands both. Anything that
matches neither shape is recorded as `unknown`, with its full bytes and hashes;
only the convenience fields stay empty. Adding a shape means adding a parser,
not changing the proxy or the log.

The parser also scans reply text for tool calls written as text, a common
failure of small models. This is a heuristic (a JSON object with a tool-like
name and arguments) with bounded work: at most 64 KB of text and 64 candidate
objects per reply.

## Session checks

The session tracker follows each session across calls using only hashes and
tool call IDs, never message content. Message hashes are computed over
canonical JSON (sorted keys, no insignificant whitespace), so a client that
serializes the same message differently does not trigger a false alarm.

For each call it checks that:

- every message sent last turn is sent again unchanged (`history_rewritten`,
  `history_truncated`);
- the reply echoed back by the agent contains the tool calls the model actually
  returned (`history_rewritten`);
- every new tool result answers a tool call the model issued in this session
  (`orphan_tool_result`), and links it to the entry where the call was made;
- the tools and system prompt have not changed (`toolset_changed`,
  `system_prompt_changed`).

Single-call checks cover model substitution, aborted streams, high-risk tools,
and tool calls written as text. Sessions idle for an hour are forgotten.

## Storage of bodies

Request and response bodies are stored verbatim as text, or as base64 if they
are not valid UTF-8, so their SHA-256 can be recomputed from the log alone.
Bodies over 32 MiB are truncated in the log, but their hash and byte count
always cover every byte.

## Performance

Measured on an Apple M3 with the benchmarks in `internal/recorder`:

| Measure | Result |
|---|---|
| Added latency per call | about 0.14 ms |
| Throughput through the gateway | about 10,600 calls/s |
| Recording pipeline per call (off the request path) | about 85 us |
| Ledger append, group commit | about 16 us |
| Verification | about 240 MB/s |

Model calls take hundreds of milliseconds or more, so the gateway adds well
under one percent to an agent's run time.

## Not yet built

- A web dashboard for auditors and managers.
- Auditing of tool execution itself, by proxying tool servers.
- Roles, access logging, and exportable evidence bundles.
- Anchoring checkpoints in an external transparency log.
