# Architecture

blackbox sits between an AI agent and the model it talks to. It passes every
request through untouched, writes an exact, signed copy of each exchange to a
log, and flags behaviour an auditor should look at. These diagrams show how.
[DESIGN.md](DESIGN.md) has the full reasoning behind each choice.

## Where it sits

![The agent sends calls to blackbox, which forwards them to the model server and streams replies back. Inside blackbox, the proxy hands a copy of each exchange to the recorder, which appends signed entries to the audit log. Checkpoints go to another machine, and auditors read and verify the log.](images/overview.svg)

The agent changes one setting: it sends its calls to blackbox instead of to
the model server. The request and the reply pass straight through the proxy;
the recorder works on a copy, so the agent never waits for it. The only things
that leave blackbox are the forwarded calls, the checkpoint copies, and the log
an auditor reads.

## The life of one call

![Request path: receive, forward to the model, and stream the reply back while copying and hashing it. Then a hand-off through a bounded queue to the background: parse, check, sign, write in batches, and checkpoint.](images/call-lifecycle.svg)

The top row is everything the agent waits for, kept to copying and hashing
bytes. Understanding the reply, checking it, signing it, and writing it happen
in the background after the agent already has its answer. If the disk fails,
the background cannot finish, so blackbox refuses new requests rather than let
agents run unrecorded. If the queue fills up, the top row slows down instead of
dropping records.

## Why the log cannot be quietly edited

![Four entries, each storing the previous entry's hash. A checkpoint of entry 4 is copied elsewhere. When entry 3 is edited, its recomputed hash no longer matches the stored one, and verify reports tampering at entry 3.](images/tamper-evident-log.svg)

Every entry carries the hash of the entry before it and is signed with the
gateway's private key. Change one byte and the chain breaks at that point.
Recomputing every hash after an edit does not help, because only the private
key can sign. Checkpoints copied to another machine catch entries cut from the
end of the log.

## How a forged tool result is caught

![Turn 1: blackbox remembers that the model asked for call c1, list_dir. Turn 2: the agent echoes call c1, which matches; returns a result for c1, which answers it; and adds a result for forged-1, which matches no call and is flagged as orphan_tool_result.](images/forged-tool-result.svg)

blackbox remembers what the model actually said in each turn and checks every
new message against it: earlier messages must come back unchanged, the model's
reply must be echoed exactly once and first, and each tool call can be answered
only once. A result for a call the model never made, like the forged approval
in the [demo](../examples/agent), is flagged. blackbox never blocks a call; it
records and flags.

## Where each part lives

| Folder | Role |
|---|---|
| `internal/proxy` | Receives calls, forwards them, copies and hashes the bytes; enforces size limits and timeouts |
| `internal/recorder` | Takes each finished call off the request path and turns it into a record |
| `internal/format` | Reads the model, token usage, tool calls, and reasoning from the common response shapes |
| `internal/session` | Remembers each conversation and applies the checks above |
| `internal/ledger` | The log itself: chaining, signatures, checkpoints, verification, crash recovery |
| `internal/record`, `internal/risk` | The record schema and the risk map |
| `cmd/blackbox` | The commands: `init`, `serve`, `verify`, `sessions`, `show` |
| `examples/agent` | A small demo agent with safe tools and a mode that forges a tool result |
