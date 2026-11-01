# Storage research: making agent logs much smaller

## The problem in one paragraph

An AI agent works in steps, and at every step it sends the model the whole
conversation so far. Step 20 carries steps 1 to 19 again. blackbox saves
every request exactly as sent, so it saves those repeats too, and the log
grows very fast. For a company where a few hundred people use agents every
day, that is roughly 2 TB a year.

**Question:** how much of the log is really new, and can we store it in a way
that is much smaller but still lets us prove exactly what was sent?

## Short answer

About 95% of the log is repeated text. Storing each message once, and keeping
a short note of which messages each request used, makes the log about 14
times smaller, or about 50 times smaller with ordinary compression on top.
Every request can still be rebuilt exactly, byte for byte, which is what the
proof needs. The extra notes cost less than 1% of the original size.

## How we tested it

Three small programs in this folder:

- [corpus](corpus/main.go) **makes realistic company traffic.** It pretends
  to be many people running many kinds of agent. Each agent has its own
  instructions and list of tools, and each task is a conversation where the
  whole history is sent again at every step. Tool results come from real
  files: some are shared documents many people read, others are one-offs.
  The traffic goes through blackbox's own recorder, so the log looks exactly
  like a real one.
- [anatomy](anatomy/main.go) **measures what is inside a log:** how much is
  history sent again, how much is the agent's list of tools sent again, and
  how much is new. It then compares ways of storing it.
- [rebuild](rebuild/main.go) **checks nothing is lost.** It stores each
  message once, keeps a small "skeleton" of each request (everything except
  the messages, plus short references to them), rebuilds every request from
  those pieces, and checks it is identical to the original.

To run them:

```
go run ./research/storage/corpus -out /tmp/corpus -users 20 -tasks 10 -text "$(go env GOROOT)/src"
go run ./research/storage/anatomy -log /tmp/corpus/corpus.jsonl
go run ./research/storage/rebuild -log /tmp/corpus/corpus.jsonl
```

## What we found

### 1. Almost everything is repeated

Simulated company: 20 people, 10 tasks each, 2,372 model calls, 238 MB, about
100 KB per call. Text came from the Go standard library source code (157 MB
of varied real files), so new content really is new.

| What the bytes are | Share of the log |
|---|---|
| Conversation history sent again | 54% |
| The agent's list of tools, sent with every call | 31% |
| Extra characters from storing one JSON text inside another (every quote gets a backslash) | 8% |
| New tool results | 4% |
| blackbox's own details and signatures | 2% |
| Everything else (instructions, replies, user messages) | 1% |

A conversation's requests grow from about 36 KB at the first step to about
215 KB at the fortieth, while each step adds only about 5 KB of new content.
So storage grows much faster than the work being done: doubling the length
of conversations roughly quadruples the log.

### 2. Ordinary compression does not fix it

| How it is stored | Size | Smaller by |
|---|---|---|
| As today | 238.0 MB | 1x |
| Zip each entry | 67.8 MB | 3.5x |
| Zip the whole log | 65.3 MB | 3.6x |
| Each message stored once | 16.8 MB | 14x |
| Each message stored once, then zipped | 4.6 MB | 52x |

Zip only looks back a short distance (32 KB) for repeats, and the repeated
history is further back than that, so zip cannot see it. Storing each
message once removes the repeats directly. The results stayed the same from
5 to 40 people, so the saving comes from inside conversations and does not
depend on company size.

### 3. Nothing is lost

blackbox has to be able to show exactly what an agent sent, byte for byte,
because the signatures cover the exact bytes. Every request was rebuilt from
the stored pieces and compared with the original.

| Traffic | Rebuilt exactly | Skeleton size |
|---|---|---|
| Simulated company | 2,372 of 2,372 | 0.36% of the original (about 320 bytes per request) |
| A plain Python agent, through a real blackbox gateway | 440 of 440 | 0.58% (about 130 bytes per request) |
| The most widely used Python client library, three common coding styles | 741 of 741 | about 0.55% (about 125 bytes per request) |

The Python runs used replies recorded earlier from a real model server,
played back byte for byte, so the server's format is real.

### 4. Real agents rewrite the model's replies, and that is fine

When an agent passes the model's reply back into the conversation, it almost
never uses the exact bytes the server sent: 0 of 981 replies matched. Python
agents read the reply and write it out again in their own format, and some
add extra empty fields. But once an agent has written a message, it sends it
again with the same bytes at every later step, so the history still
deduplicates. The cost is one extra stored copy of each reply, and replies
are only a few percent of the log.

blackbox's own checks were not fooled by any of these styles: across 1,181
calls they raised no false alarms about rewritten history, because they
compare what messages say, not how they are formatted.

### 5. It is cheap to do

Splitting a request into its stored pieces takes about 0.4 milliseconds;
rebuilding one takes about 0.01 milliseconds. For a company making 90,000
model calls a day, that is about 35 seconds of computer time per day.

## What is still open

- **Real workloads.** The company traffic is simulated: how long
  conversations run and how big tools and files are were our assumptions.
  Real logs from real teams would confirm or correct the numbers.
- **More agent tools.** We tested plain Python and the most common client
  library. Larger agent frameworks might reformat history between steps,
  which would reduce the saving.
- **Where the data lives.** The log should not stay on the gateway forever.
  The next design step is moving older data to storage the organisation owns,
  and measuring how fast one call can be opened from there.
