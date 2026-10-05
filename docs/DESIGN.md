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
byte, every hash and key ID is lowercase hex of the exact length, and the
signature is strict standard base64. This rejects duplicate keys, differently
cased keys, escaped keys, extra fields, added whitespace, uppercase hex, and
alternative base64 encodings. Checkpoints are held to the same rules, and their
time must be a canonical RFC 3339 UTC timestamp. Without this rule,
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

After a durable flush, at least every 100 entries or 30 seconds while entries
are being written (both configurable), the ledger
writes a checkpoint to a separate file and, by default, to stdout so a copy
leaves the machine. The stdout copy is written from its own goroutine; if the
reader stalls or the pipe closes, lines are counted as dropped and shutdown
waits at most two seconds for it. The checkpoint file always has every line.

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
with, its own latest checkpoint, so it never extends a chain over a gap. These
checks run before any crash repair, so a log that is refused is left exactly as
it was found. A checkpoint file is required.

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

If a record cannot be written (disk full, I/O error), whether by the recorder
or by a background flush, the ledger stops accepting appends, the proxy refuses
new requests with 503, the health endpoint reports the failure, calls in flight
are cancelled at once, and the gateway exits with a non-zero code so a
supervisor notices. A call that was already being served when the failure
happened can finish its response unrecorded; no new call starts. `--fail-open`
keeps forwarding instead, for deployments that prefer availability; the gap is
then visible as missing records and an unclean stop. The `gateway_start`
entry is on disk before the first request is served.

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
| Requests in flight | 32 | More get 503 |
| Requests per client address | 8 | More get 503, so one client cannot take every slot |
| Request size | 32 MiB | Larger requests get 413 and are recorded as refused |
| Stored body size | 32 MiB | Bodies beyond this are truncated in the log; hashes cover every byte |
| Request body read | 1 minute | A slow client cannot hold a request open indefinitely |
| Upstream response headers | 10 minutes | A model server that never answers frees its slot |
| Response progress | 5 minutes | A response that stalls, or a client that stops reading, is cancelled and recorded, freeing its slot |
| Idle connections | 2 minutes | |
| Protocol upgrades | refused | Traffic after a switch to another protocol could not be recorded; `--allow-upgrades` permits it |

Requests refused for capacity were never forwarded, so they are counted in
`gateway_stop` rather than recorded one by one; otherwise a flood of requests
could grow the log without limit. Memory for bodies is bounded by roughly
`max_in_flight x (max_request_bytes + max_body_bytes)` for calls in flight
(2 GiB with the defaults, reached only if every slot carries a maximum-size
request and response), plus 256 MiB of exchanges waiting to be recorded and
64 MiB of entries waiting to be written. Lower the limits on small hosts.

Shutdown waits a bounded time for calls in flight and for the recorder, so a
disk that stops responding cannot keep the process from exiting; the gateway
then exits with an error and without writing `gateway_stop`.

## Format parsing

blackbox does not know or care which provider is upstream. The parser
recognizes payloads by shape:

- **chat**: responses with a `choices` array, streamed as choice deltas.
- **blocks**: responses with typed content blocks, streamed as block events.

Anything that matches neither shape is recorded as `unknown`, with its full
bytes and hashes; only the convenience fields stay empty.

The parser also scans reply text for tool calls written as text, a common
failure of small models: a JSON object with a tool-like name and arguments,
at the top level or nested inside other JSON, that is not a JSON Schema (which
would mean the model is describing a tool, not calling it). The work is bounded
to 64 KB of text and 4 MB of decoding per reply; a scan cut short by either
limit is flagged (`text_scan_partial`), so hostile text cannot hide a call
silently. When tools were offered, only calls naming an offered tool or one in
the risk map count; the rest are counted in `ignored_text_calls`.

The parser also extracts the model's reasoning when the server returns it: a
separate reasoning field in chat-shaped responses, thinking blocks in
block-shaped ones (streamed or not), or text the model wrote between think
tags. The record keeps a preview, the length, and a hash; the full text stays
in the response body, so it is not stored twice. Reasoning a server keeps
private, or returns only encrypted, cannot be recorded, since the gateway sees
only what crosses the wire; encrypted blocks are counted. Inline reasoning is
left out of reply text comparisons and of the text call search, so a call the
model only considered is not reported as an attempt.

Canonical hashing compares numbers by value in linear time, so `1.0` equals
`1` and a number like `1e1000000` stays short. JSON that decoding would
silently merge, such as duplicate keys or invalid UTF-8, is hashed as sent.

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
so a restart does not reset the checks; the start of that hour is found by
binary search, so the cost does not grow with the size of the log.

For each call the tracker checks that:

- the history sent last turn is sent again unchanged, or with older turns
  dropped while keeping the opening (`history_truncated`), and not otherwise
  changed (`history_rewritten`). Without a session ID, conversations are
  related only through a model reply blackbox has verified: a request that
  diverges from every branch after such a reply is checked against the
  closest one, and one whose first model reply differs from every reply the
  model gave to that opening is flagged. Example replies an agent writes into
  its prompt do not relate conversations;
- the messages added since the last turn contain exactly one model message,
  the echo of the model's last reply, placed first; results sent without it,
  messages placed before it, or further messages attributed to the model are
  flagged (`history_rewritten`);
- the echo contains exactly the tool calls the model returned, with the same
  names and canonical arguments, and the same text (`history_rewritten`);
- every new tool result answers a call the model made in this conversation
  (`orphan_tool_result`) and has not been answered before
  (`duplicate_tool_result`), and is linked to the entry where the call was
  made; results with no earlier turn to check against are flagged as
  `unverifiable_tool_result` rather than trusted;
- the tools and leading system prompt have not changed, and no system or
  developer message was added mid-conversation;
- no key in the parts of the request the parser reads (the request itself,
  messages, content blocks, tool calls, tool definitions) would be read by Go's
  decoder as a field it is not exactly named after (`ambiguous_request`). Go
  matches names with Unicode case folding, so `Tool_Calls` or `tool_call` with
  a long s would be read as `tool_calls`, while a model server reading exact
  keys would not. The check asks the decoder itself, so it cannot drift from
  what the parser actually does. Tool arguments and schemas are not checked;
  the parser never reads their keys as fields.

Reasoning the agent echoes back (in reasoning fields or thinking blocks) must
match reasoning the model returned. Text before a closing think tag with no
opening tag is treated as reasoning for comparisons but is still searched for
tool calls written as text, so a stray tag cannot hide one.

Text the agent sends is always compared as sent. A model reply written with
inline reasoning may be echoed with or without that reasoning, and both forms
are accepted, but text the agent adds inside think tags is never ignored.

Servers that return tool calls without IDs are handled by matching the agent's
echoed calls by name and arguments and adopting the IDs the agent assigned. An
agent that runs a call the model only wrote as text is allowed when the model
made no real calls, and flagged as `text_tool_call_executed`.

Tracked state is bounded: at most 32 branches per conversation opening and
10,000 conversations in total, evicting the least recently used. A call that
gets no reply leaves the conversation unchanged, so a retry is checked against
the last turn that succeeded. Conversations without a session ID that share
only their opening, such as different tasks started with the same context
message, are treated as unrelated.

Single-call checks cover model substitution (a served name must equal the
requested one or add only a version suffix), aborted streams, high-risk tools,
and tool calls written as text.

## Storage of bodies

Request and response bodies are stored verbatim as text, or as base64 if they
are not valid UTF-8, so their SHA-256 can be recomputed from the log alone.
Every turn stores the whole conversation, so storage grows with the square of
a conversation's length; storing messages once by hash is planned.

## Not yet built

- A web dashboard for auditors and managers.
- Auditing tool execution itself, by proxying tool servers.
- Key rotation: a signed hand-over entry and verification against a key set.
- Segmented log files with an index, for large logs and the dashboard.
- Storing each message once, referenced by hash.
- Roles, access logging, and exportable evidence bundles.
- Redaction of bodies and reasoning, keeping their hashes.
