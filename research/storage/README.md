# Storage research: deduplicating agent audit logs

## Problem

Agents call a model repeatedly within a task, and each request carries the
full conversation so far: system prompt, tool definitions, every earlier
message, and every tool result. blackbox records each request verbatim, so
the log stores that shared history again on every call. Log size therefore
grows with the square of task length, not with the amount of new content.
For an organisation of a few hundred people using agents daily, this is on
the order of 2 TB a year.

This study measures how much of an agent audit log is redundant, and whether
it can be stored once without weakening the guarantee that every request can
be reproduced byte for byte and verified against its signature.

## Summary of results

- About 95% of the log is content already present earlier in the log.
- Storing each distinct message once, with a small per-request skeleton that
  references the messages, reduces the log 14x; adding gzip gives 52x.
  Compressing the log as it is today gives 3.6x.
- Every request was reconstructed byte for byte from the stored pieces. The
  skeletons add under 1% of the original size.
- Real agents re-serialize model replies before sending them back, but resend
  their own history unchanged, so deduplication still applies.
- The added work is about 0.4 ms per request to split and hash, and 0.01 ms to
  reconstruct.

## Method

The study uses three programs in this directory.

- [corpus](corpus/main.go) generates a log of simulated organisational
  traffic. Simulated users run several agent types, each with its own system
  prompt and tool definitions. Each task is a session in which the agent
  resends the whole conversation on every call. Tool results are drawn from
  real files, either from a pool of shared documents with a skewed popularity
  distribution or as content unique to the call. Exchanges pass through
  blackbox's recorder, so the log has the gateway's exact format.
- [anatomy](anatomy/main.go) attributes every byte of a log to a category
  (gateway metadata, escaping, tool definitions, resent history, content new
  to the session, responses) and compares storage schemes: per-entry gzip,
  whole-log gzip, and storing each distinct message once.
- [rebuild](rebuild/main.go) tests lossless reconstruction. Each request is
  split into a skeleton (all bytes except the messages and tool list, kept
  verbatim, with 8-byte references in their place) and a content store keyed
  by the SHA-256 of each message's exact bytes. Every request is then rebuilt
  and compared with the original. The program also reports the time taken and
  how agents re-encode echoed replies.

```
go run ./research/storage/corpus -out /tmp/corpus -users 20 -tasks 10 -text "$(go env GOROOT)/src"
go run ./research/storage/anatomy -log /tmp/corpus/corpus.jsonl
go run ./research/storage/rebuild -log /tmp/corpus/corpus.jsonl
```

## Results

### Composition of the log

Simulated organisation: 20 users, 10 tasks each, 2,372 model calls, 238 MB,
about 100 KB per call. Text was drawn from the Go standard library source
(157 MB of varied files), so content new to a session is genuinely new.

| Category | Share |
|---|---|
| History resent from earlier in the session | 53.8% |
| Tool definitions, resent with every call | 30.7% |
| Escaping of request and response bodies stored as JSON strings | 8.4% |
| Tool results new to the session | 4.2% |
| Gateway metadata and signatures | 1.7% |
| System prompts, replies, user messages, responses | 1.2% |

Request size grows from 36 KB at the first call of a session to 215 KB at
the fortieth, while each call adds about 5 KB of new content.

The escaping overhead is a separate finding: a JSON request stored inside a
JSON string has every quotation mark escaped. Storing bodies as embedded JSON
would remove this 8% even without deduplication.

### Storage schemes

| Scheme | Size | Reduction |
|---|---|---|
| Current format | 238.0 MB | 1x |
| gzip per entry | 67.8 MB | 3.5x |
| gzip of the whole log | 65.3 MB | 3.6x |
| Each distinct message stored once | 16.8 MB | 14x |
| Each distinct message stored once, then gzip | 4.6 MB | 52x |

General-purpose compression recovers little because DEFLATE, the algorithm
behind gzip, finds repeats only within a 32 KB window, and resent history
lies further back than that. Reductions were stable from 5 to 40 users, which
indicates the saving comes mainly from redundancy within sessions rather than
across users.

### Byte-exact reconstruction

Signatures cover the exact request bytes, so any storage scheme must
reproduce them exactly.

| Traffic | Reconstructed exactly | Skeleton overhead |
|---|---|---|
| Simulated organisation | 2,372 of 2,372 | 0.36% (320 bytes per request) |
| Python agent using the standard library, through a blackbox gateway | 440 of 440 | 0.58% (133 bytes per request) |
| Python agent using the most widely used client library, three echo styles | 741 of 741 | 0.55% (125 bytes per request) |

The Python agents ran against replies recorded from a real model server and
replayed byte for byte, so the server's encoding is authentic.

### How agents echo replies

None of the 981 replies that agents sent back matched the bytes the server
returned. Agents decode the reply and encode it again; some add fields with
null values or drop fields such as `index`. Once an agent has encoded a
message, however, it resends it with identical bytes on every later call:
no message was re-encoded differently between calls. The cost of
re-encoding is therefore one additional stored copy per reply, and replies
account for a few percent of the log.

Across these 1,181 calls, blackbox's session checks raised no false history
or tool-result anomalies, since they compare messages by content rather than
by encoding.

### Effect of session length

The reduction depends on how many calls a session makes, because resent
history grows with every call. The simulated organisation was regenerated
with different average session lengths (10 users, 10 tasks each):

| Mean calls per session | gzip | Stored once | Stored once, then gzip |
|---|---|---|---|
| 2 | 3.9x | 6.9x | 24.5x |
| 4 | 3.8x | 8.0x | 30.0x |
| 8 | 3.9x | 12.3x | 46.7x |
| 16 | 3.6x | 15.9x | 55.6x |
| 32 | 3.7x | 27.1x | 86.6x |

gzip stays near 4x regardless of length, while deduplication improves as
sessions grow. Even two-call sessions benefit in this workload, because tool
definitions and system prompts repeat across every session of an agent.

### A real agent against a local model

A working agent built on the client library answered twelve questions about
this repository, calling a local 3-billion-parameter model through a
blackbox gateway and executing its tool calls (list a directory, read a
file, search the code). The model rarely made more than two calls before
answering, so sessions were short: 22 calls averaging 7 KB.

| Scheme | Reduction |
|---|---|
| gzip of the whole log | 5.1x |
| Each distinct message stored once | 1.3x |
| Each distinct message stored once, then gzip | 5.4x |

All 22 requests were reconstructed exactly and no history was re-encoded
between calls. With requests this small and sessions this short, gateway
metadata is a quarter of the log and there is little history to remove, so
deduplication adds almost nothing over gzip. The workload that motivates
this study, agents running tens to hundreds of calls with large contexts,
could not be reproduced with the models available locally; a larger
tool-capable model is needed to measure it directly.

### Cost

Splitting and hashing a request took 388 microseconds on average (231 MB/s);
reconstruction from memory took 9 microseconds. At 90,000 calls a day this
is about 35 seconds of CPU time per day.

## Limitations and next steps

- **Simulated workload.** Session lengths, tool definition sizes, and tool
  result sizes are assumptions. The only real agent traffic measured so far
  came from a small local model with short sessions, where the method gives
  little over gzip. Measurements from long-running production agents are
  needed to confirm the larger reductions.
- **Agent frameworks.** Only standard-library Python and the most common
  client library were tested. Frameworks that rebuild the conversation from
  their own objects on each call could re-encode history between calls and
  reduce the saving.
- **Storage architecture.** A content store needs a home other than the
  gateway: sealed segments moved to storage the organisation controls, with
  the signature chain committing to message hashes. Retrieval latency for a
  single call from that storage has not been measured.
