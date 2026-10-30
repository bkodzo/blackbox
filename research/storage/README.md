# Storage research: how agent audit logs grow

**Question.** An organisation where hundreds of people use agents every day
produces a large audit log. How much of it is new information, and how small
could it be stored while every request can still be rebuilt byte for byte and
verified?

## Method

- [corpus](corpus/main.go) simulates organisation traffic: people run agents,
  each agent has its own system prompt and tool definitions, and each task is
  a session in which the agent resends the whole conversation on every call,
  as real agents do. Tool results come from a pool of shared documents
  (popular ones are read by many people) or are unique to the call. Text is
  taken from real files. Exchanges go through blackbox's own recorder, so the
  log has exactly the gateway's format.
- [anatomy](anatomy/main.go) reads a log and attributes every byte: gateway
  metadata, JSON escaping of the stored bodies, tool definitions, history
  resent within a session, content new to the session, and responses. It then
  compares general-purpose compression with storing each distinct message
  once.

```
go run ./research/storage/corpus -out /tmp/corpus -users 20 -tasks 10 -text "$(go env GOROOT)/src"
go run ./research/storage/anatomy -log /tmp/corpus/corpus.jsonl
```

## First results

20 people, 10 tasks each, text from the Go standard library source (157 MB of
varied real files): 2,372 calls, 238 MB, 100 KB per call.

| Where the bytes go | Share |
|---|---|
| History resent from earlier in the session | 53.8% |
| Tool definitions, sent with every call | 30.7% |
| JSON escaping of the stored bodies | 8.4% |
| Tool results new to the session | 4.2% |
| Gateway metadata and seal | 1.7% |
| Everything else (system prompts, replies, user messages, responses) | 1.2% |

| Storing it | Size | Smaller by |
|---|---|---|
| Raw log | 238.0 MB | 1x |
| gzip each entry | 67.8 MB | 3.5x |
| gzip the whole log | 65.3 MB | 3.6x |
| Each distinct message stored once | 16.8 MB | 14.2x |
| Each distinct message stored once, then gzip | 4.6 MB | 51.8x |

Requests grow from 36 KB at the first call of a session to 215 KB at the
fortieth, while each call adds about 5 KB of new content. Storage therefore
grows with the square of session length, and general-purpose compression
cannot remove the repetition: gzip only looks 32 KB back, and the repeated
history is further away than that. The ratios stayed the same from 5 to 40
people, so most of the saving comes from repetition within sessions.

## Rebuilding exact bytes

The gateway hashes the exact request bytes, so a deduplicated log must give
them back exactly. [rebuild](rebuild/main.go) splits each request into a
skeleton (everything except the messages and the tool list, kept verbatim,
with 8-byte references in their place) and the messages and tool lists, kept
once each in a store keyed by their exact bytes. It then rebuilds every
request and compares it with the original.

| Traffic | Requests rebuilt exactly | Skeleton, share of raw |
|---|---|---|
| Simulated organisation (above) | 2,372 of 2,372 | 0.36% (320 bytes per request) |
| A Python agent using `json.dumps`, through the gateway, against replies recorded byte for byte from a local model server | 440 of 440 | 0.58% (133 bytes per request) |

Exactness is nearly free: the skeletons are under 1% of the raw requests.

The Python run also shows how real agents echo replies. None of 360 echoed
replies had the bytes the server returned: agents parse the reply and write
it again in their own format, and some build their own message from its
fields. But once an agent has written a message, it resends it with the same
bytes on every later turn, so the history still deduplicates. The cost of
real agents is therefore one extra stored copy of each model reply, which is
small because replies are a few percent of the bytes.

## What this does not show yet

- **The corpus is simulated.** Session lengths, tool definition sizes, and
  tool result sizes are assumptions. Traffic from real agents with real tasks
  is still to be measured.
- **Other agent frameworks.** Only a minimal standard-library Python agent
  and blackbox's demo agent were tested. Frameworks that rebuild the whole
  conversation from their own objects on every turn may change formatting
  between turns, which would erode the saving.
- **Costs.** Gateway CPU per call, verification time, and the time to open one
  call from an archive are not measured yet.
