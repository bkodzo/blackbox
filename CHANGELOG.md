# Changelog

## v0.1.0

First release.

- Gateway that forwards any HTTP path to a model server and records every
  exchange, including streamed responses, with exact bytes and SHA-256 hashes.
- Append-only log with hash chaining, Ed25519 signatures on every entry, and
  signed checkpoints written to a separate file and stdout.
- Group commit with writes and fsyncs off the append path; `--sync always` for
  per-entry durability; recovery of incomplete final lines after a crash.
- `blackbox verify`: single streaming pass, parallel signature checks, plain
  language results, and exit codes for intact, tampered, and warnings.
- Extraction of model, token usage, tool calls, and system prompt and tool
  hashes from the two common response shapes, streamed or not.
- Session tracking with anomaly flags: orphan tool results, rewritten or
  truncated history, changed tools or system prompt, model substitution,
  aborted streams, high-risk tools, and tool calls written as text.
- Risk map for classifying tools by level and category.
- `blackbox init`, `serve`, `sessions`, and `show` commands.
- Demo agent with sandboxed read-only tools and a forged-result mode.
- Binaries for macOS, Linux, and Windows, and a container image.
