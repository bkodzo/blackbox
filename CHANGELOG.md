# Changelog

## v0.3.0

- Dashboard: activity charts and the most used tools on the overview, a
  printable report for a session or a date range, and `--export` to save
  every page as static files.
- A live demo of the dashboard on a scripted sample log and a tampered copy,
  published by the `demo` workflow.
- The dashboard's index takes about 40 percent less memory per entry.

## v0.2.0

- `blackbox dashboard`: a read-only web view of the log with overview,
  sessions, flags, entry, and integrity pages. It follows the log as the
  gateway writes it, reaches its integrity verdict with the same code as
  `blackbox verify`, and needs only the log, checkpoints, and public key.
- Built with Go 1.27.3, for its certificate verification fix.

## v0.1.1

- The checkpoint file is locked like the log, so two gateways can no longer
  write one checkpoint file, and both locks follow symlinks.
- When the recorder misses the shutdown deadline, the log is still closed, so
  entries already written are flushed and covered by a final checkpoint.
- `blackbox verify` reports a log that ends in a clean shutdown no checkpoint
  covers as a warning instead of tampering. A crash while the final
  checkpoint was written, or a checkpoint copy collected from stdout that is
  behind, caused intact logs to be reported as tampered.
- A checkpoint file that holds no checkpoints although the log has entries is
  reported at startup and by `blackbox verify` (`checkpoints_empty`), as a
  missing one already was.

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
- Parsing and checks that take time linear in the size of each exchange,
  including long streamed tool call arguments, trimmed histories, and large
  echoed replies, with at most five anomalies of each kind listed per call.
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
