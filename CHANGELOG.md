# Changelog

## v0.1.0

First release.

- Gateway that forwards any HTTP path to a model server and records every
  exchange, including streamed responses, with exact bytes and SHA-256 hashes.
- Append-only log with hash chaining, domain-separated Ed25519 signatures on
  every entry, a single valid encoding per entry, and signed checkpoints written
  to a separate file and stdout.
- Detection of edited, re-encoded, removed, reordered, and truncated entries,
  of logs rewritten after a checkpoint, and of forged checkpoints.
- Crash recovery that never discards log bytes: a complete final entry is
  kept, and an interrupted write is moved to a quarantine file and recorded.
- Fails closed: if the log cannot be written, new requests are refused, calls
  in flight are cancelled, and the gateway exits. `--fail-open` is available.
- Group commit with bounded buffers, a byte-bounded recording queue, request
  size, in-flight, and per-client limits, read, upstream, and response progress
  timeouts, and a bounded shutdown that records calls cancelled at the end of
  the grace period and counts requests refused for capacity.
- An exclusive lock on the log, so two gateways can never write the same log
  and fork its chain.
- Bounded parsing and tracking: requests with too many JSON values are
  recorded but not parsed, and the message hashes kept for conversations are
  capped.
- Protocol upgrades are refused by default, since their traffic cannot be
  recorded.
- `blackbox verify`: single streaming pass, parallel signature checks, plain
  language results, and exit codes for intact, tampered, warnings, and errors.
- Extraction of model, token usage, tool calls, and system prompt and tool
  hashes from the two common response shapes, streamed or not.
- Conversation tracking with or without a session header, rebuilt from the log
  at startup, with anomaly flags: orphan, duplicate, and unverifiable tool
  results, rewritten or truncated history (including changed tool call
  arguments, reply text, and replies attributed to the model that it never
  sent), changed tools or system prompt, model substitution, aborted streams,
  high-risk tools, tool calls written as text or run from text, reasoning
  echoed back that the model never returned, and requests with keys that the
  parser and a model server could read differently. These checks are
  best-effort review flags; the signed log is the guarantee.
- Extraction of the model's reasoning (reasoning fields, thinking blocks, or
  inline think tags), shown by `blackbox show`.
- Risk map for classifying tools by level and category.
- `blackbox init`, `serve`, `sessions`, and `show` commands, with escaping of
  terminal control characters in recorded text.
- Demo agent with sandboxed read-only tools and a forged-result mode.
- Binaries for macOS, Linux, and Windows and a container image, signed with
  keyless cosign, with SBOMs and build provenance.
