# blackbox

blackbox is an audit gateway for AI agents. It sits between an agent and any
model server and records every prompt, tool call, and response in a signed,
append-only log. It does not depend on a particular model or provider.

Status: early development. The log is in place; the gateway, CLI, and
dashboard are in progress.

## How the log detects tampering

Each entry stores the hash of the previous entry and is signed with the
gateway's Ed25519 key. Signed checkpoints are written to a separate file.
Verification fails if a record is edited, deleted, reordered, or removed from
the end of the log, or if the chain is rebuilt with a different key.

## License

MIT
